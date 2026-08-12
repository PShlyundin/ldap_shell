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
        'restore', 'set_attr',
    ):
        assert required in names


def test_describe_mask_generic_all():
    names = AceUtils.describe_mask(0x000F01FF)
    assert 'GenericAll' in names
