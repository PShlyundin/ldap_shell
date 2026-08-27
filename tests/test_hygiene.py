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
