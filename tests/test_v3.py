import re
from pathlib import Path

from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.module_loader import ModuleLoader

ROOT = Path(__file__).resolve().parents[1]


def test_version_is_3():
    setup = (ROOT / 'setup.py').read_text()
    pyproject = (ROOT / 'pyproject.toml').read_text()
    assert "version='3.0.0'" in setup
    assert 'version = "3.0.0"' in pyproject


def test_module_loader_includes_new_commands():
    names = ModuleLoader.list_modules()
    for required in (
        'whoami', 'get_acl', 'get_writable', 'get_delegation', 'get_trusts',
        'restore', 'set_attr', 'get_asreproast', 'get_privileged_accounts',
        'add_sid_history', 'get_kerberoast', 'set_delegation', 'set_keycred',
    ):
        assert required in names


def test_describe_mask_generic_all():
    names = AceUtils.describe_mask(0x000F01FF)
    assert 'GenericAll' in names


def test_arg_field_does_not_emit_pydantic_extra_kwarg_warning():
    import warnings

    from pydantic import BaseModel
    from pydantic.warnings import PydanticDeprecatedSince20

    from ldap_shell.ldap_modules.base_module import ArgumentType, arg_field

    with warnings.catch_warnings():
        warnings.simplefilter('error', PydanticDeprecatedSince20)

        class Sample(BaseModel):
            user: str = arg_field(description='u', arg_type=ArgumentType.USER)

    assert Sample.model_fields['user'].json_schema_extra['arg_type'] is ArgumentType.USER


def test_kerberoast_and_delegation_args():
    roast = ModuleLoader.load_module('get_kerberoast')
    names = [arg.name for arg in roast.get_arguments()]
    assert names == ['target']
    assert roast.get_arguments()[0].required is False

    deleg = ModuleLoader.load_module('set_delegation')
    assert [arg.name for arg in deleg.get_arguments()] == ['target', 'action', 'spn']
    source = (ROOT / 'ldap_shell/ldap_modules/get_kerberoast/ldap_module.py').read_text()
    assert 'servicePrincipalName=*' in source
    assert 'objectCategory=person' in source


def test_modules_call_arg_field_not_field_arg_type():
    for path in (ROOT / 'ldap_shell/ldap_modules').glob('*/ldap_module.py'):
        text = path.read_text()
        if 'arg_type=' not in text:
            continue
        assert 'arg_field(' in text
        assert re.search(r'\bField\s*\(', text) is None
