import string

from ldap_shell.completers.base import highlight_match
from ldap_shell.utils import parse_credentials, parse_hashes
from ldap_shell.utils.module_loader import ModuleLoader
from ldap_shell.utils.security_utils import SecurityUtils


def test_password_meets_complexity():
    password = SecurityUtils.generate_password(16)
    assert len(password) == 16
    assert any(c in string.ascii_uppercase for c in password)
    assert any(c in string.ascii_lowercase for c in password)
    assert any(c in string.digits for c in password)
    assert any(c in '!@#$%^&*' for c in password)


def test_ntlm_hash_is_stable():
    digest = SecurityUtils.calculate_ntlm('Password123!')
    assert digest == '2b576acbe6bcfda7294d6bd18041b8fe'


def test_parse_credentials_and_hashes():
    assert parse_credentials('lab.local/admin:Secret') == ('lab.local', 'admin', 'Secret')
    assert parse_hashes('aabb' * 8)[0] == 'aad3b435b51404eeaad3b435b51404ee'
    lm, nt = parse_hashes('11' * 16 + ':' + '22' * 16)
    assert lm == '11' * 16
    assert nt == '22' * 16


def test_module_loader_skips_template():
    names = ModuleLoader.list_modules()
    assert 'set_genericall' in names
    assert 'template' not in names


def test_html_highlight_escapes_entities():
    rendered = highlight_match('admin<script>', 'admin')
    assert '<script>' not in rendered
    assert '&lt;script&gt;' in rendered
    assert '<b>' in rendered
