from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_no_utcnow_in_vendored_krb5():
    kerberos = (ROOT / 'ldap_shell/krb5/kerberos_v5.py').read_text()
    pkinit = (ROOT / 'ldap_shell/utils/myPKINIT.py').read_text()
    assert 'utcnow' not in kerberos
    assert 'utcnow' not in pkinit


def test_get_ntlm_uses_cryptography_pkcs12():
    source = (ROOT / 'ldap_shell/ldap_modules/get_ntlm/ldap_module.py').read_text()
    assert 'serialize_key_and_certificates' in source
    assert 'crypto.PKCS12()' not in source


def test_epa_extra_is_optional():
    pyproject = (ROOT / 'pyproject.toml').read_text()
    setup = (ROOT / 'setup.py').read_text()
    readme = (ROOT / 'README.md').read_text()
    session = (ROOT / 'ldap_shell/session.py').read_text()
    assert 'ldap3-bleeding-edge' in pyproject
    assert 'epa' in pyproject
    assert 'ldap3-bleeding-edge' in setup
    assert '.[epa]' in readme
    assert 'ldap_shell[epa]' in session
    assert 'ldap3>=2.9.1,<3' in pyproject
