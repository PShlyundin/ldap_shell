from types import SimpleNamespace

from ldap_shell.completers.base import highlight_match
from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule
from ldap_shell.utils import current_domain, current_sam, parse_hashes
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.security_utils import SecurityUtils
from tests.test_runner import _FakeModule, _runner


def test_escape_filter_none_and_wildcard():
    assert LdapUtils.escape_filter(None) == ''
    assert '*' not in LdapUtils.sam_filter('a*b')
    assert LdapUtils.escape_filter(12) == '12'


def test_looks_like_dn_more_cases():
    assert not LdapUtils.looks_like_dn(None)
    assert LdapUtils.looks_like_dn('CN=x,OU=y,DC=lab')
    assert not LdapUtils.looks_like_dn('just-a-name')


def test_resolve_dn_empty():
    assert LdapUtils.resolve_dn(None, None, '') is None
    assert LdapUtils.resolve_dn(None, None, None) is None


def test_get_domain_name_and_uuid_roundtrip():
    dn = 'CN=john,CN=Users,DC=lab,DC=local'
    assert LdapUtils.get_domain_name(dn).lower() == 'lab.local'
    uuid = 'A1B2C3D4-E5F6-7890-ABCD-EF1234567890'
    raw = LdapUtils.string_to_bin(uuid)
    assert len(raw) == 16
    assert LdapUtils.bin_to_string(raw).replace('-', '').lower() == uuid.replace('-', '').lower()


def test_string_to_bin_rejects_garbage():
    try:
        LdapUtils.string_to_bin('not-a-uuid')
    except ValueError:
        return
    raise AssertionError('expected ValueError')


def test_current_sam_and_domain():
    client = SimpleNamespace(user=r'DOMAIN\alice')
    assert current_sam(client) == 'alice'
    assert current_domain(client) == 'DOMAIN'
    client.user = 'u:CORP\\bob'
    assert current_sam(client) == 'bob'
    assert current_domain(client) == 'CORP'
    client.user = 'CN=admin,CN=Users,DC=lab,DC=local'
    assert current_sam(client) == 'admin'
    client.user = ''
    assert current_sam(client) == ''
    assert current_domain(client) == ''


def test_parse_hashes_empty_lm():
    lm, nt = parse_hashes(':' + 'ab' * 16)
    assert lm == 'aad3b435b51404eeaad3b435b51404ee'
    assert nt == 'ab' * 16
    assert parse_hashes(None) == (None, None)
    assert parse_hashes('') == (None, None)


def test_password_minimum_length():
    assert len(SecurityUtils.generate_password(4)) == 8


def test_highlight_no_match_still_escapes():
    assert '&lt;' in highlight_match('<x>', 'zzz')
    assert highlight_match('plain', '') == 'plain'


def test_describe_mask_unknown_is_hex():
    names = AceUtils.describe_mask(0x1)
    assert names == ['0x1']


def test_runner_skips_comments_and_handles_exit():
    runner = _runner()
    results = runner.execute_many(['', '# ignore', 'get_acl admin', 'exit', 'get_acl other'], capture=True)
    assert [item.command for item in results] == ['get_acl admin', 'exit']
    assert results[1].data == {'exit': True}


def test_runner_question_mark_is_help():
    runner = _runner()
    cmd, args, raw = runner.parseline('? get_acl')
    assert cmd == 'help'
    assert 'get_acl' in args


def test_runner_drops_extra_args():
    runner = _runner()
    parsed = runner.parse_args('get_acl', 'one two three')
    assert parsed == {'target': 'one', 'extra': 'two'}


def test_runner_unclosed_quote_falls_back():
    runner = _runner()
    parsed = runner.parse_args('get_acl', '"still-open')
    assert parsed['target'] == '"still-open'


def test_runner_empty_and_false_result():
    runner = _runner()
    empty = runner.execute('   ', capture=True)
    assert empty.ok is True

    class _Fail(_FakeModule):
        def __call__(self):
            return False

    runner.modules['get_acl'] = _Fail
    failed = runner.execute('get_acl x', capture=True)
    assert failed.ok is False
    assert failed.error == 'Command failed'


def test_list_commands_shape():
    runner = _runner()
    commands = runner.list_commands()
    assert commands[0]['name'] == 'get_acl'
    assert commands[0]['arguments'][0]['required'] is True


def test_module_argument_types_from_pydantic():
    from pydantic import BaseModel

    from ldap_shell.ldap_modules.base_module import arg_field

    class Sample(BaseLdapModule):
        class ModuleArgs(BaseModel):
            user: str = arg_field(description='u', arg_type=ArgumentType.USER)
            note: str = arg_field('x', description='n', arg_type=ArgumentType.STRING)

    args = Sample.get_arguments()
    assert [item.name for item in args] == ['user', 'note']
    assert args[0].required is True
    assert args[1].required is False
    assert args[0].arg_type is ArgumentType.USER
    assert Sample.get_args_required() == ['user', '[note]']
    extra = Sample.ModuleArgs.model_fields['user'].json_schema_extra
    assert extra['arg_type'] is ArgumentType.USER
