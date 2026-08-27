from ldap_shell.ldap_modules.base_module import ArgumentType, ModuleArgument
from ldap_shell.runner import CommandRunner  # noqa: E402


class _FakeModule:
    def __init__(self, args_dict, domain_dumper, client, log=None):
        self.args_dict = args_dict
        self.log = log

    @classmethod
    def get_arguments(cls):
        return [
            ModuleArgument('target', ArgumentType.USER, 'target', True),
            ModuleArgument('extra', ArgumentType.STRING, 'extra', False),
        ]

    def __call__(self):
        return f"ran:{self.args_dict.get('target')}"


def _runner():
    runner = CommandRunner.__new__(CommandRunner)
    runner.domain_dumper = None
    runner.client = None
    runner.modules = {'get_acl': _FakeModule}
    runner.identchars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
    return runner


def test_parseline_and_quoted_args():
    runner = _runner()
    cmd, args, raw = runner.parseline('get_acl "Domain Admins"')
    assert cmd == 'get_acl'
    assert args == '"Domain Admins"'
    parsed = runner.parse_args(cmd, args)
    assert parsed['target'] == 'Domain Admins'


def test_missing_required_argument():
    runner = _runner()
    result = runner.execute('get_acl', capture=True)
    assert result.ok is False
    assert 'target' in (result.error or '')


def test_unknown_module():
    runner = _runner()
    result = runner.execute('nope', capture=True)
    assert result.ok is False
    assert 'not found' in result.error


def test_execute_success_and_stop_on_error():
    runner = _runner()
    results = runner.execute_many(['get_acl admin', 'missing', 'get_acl other'], capture=True)
    assert results[0].ok is True
    assert results[0].data == 'ran:admin'
    assert results[1].ok is False
    assert len(results) == 2
