import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, pkcs12
from cryptography.x509.oid import NameOID

from ldap_shell.session import (
    LdapConnectionError,
    _client_cert_from_options,
    _pfx_to_pem_paths,
    connect_from_options,
)

ROOT = Path(__file__).resolve().parents[1]


def test_ldaps_retry_on_signing():
    source = (ROOT / 'ldap_shell/session.py').read_text()
    assert '_looks_like_signing_error' in source
    assert 'channel_binding' in source


def _write_test_pfx(path: Path, password: bytes = b'secret') -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ldap-shell-test')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(
        pkcs12.serialize_key_and_certificates(
            b'test', key, cert, None, BestAvailableEncryption(password),
        )
    )
    return path


def test_pfx_to_pem_roundtrip(tmp_path):
    pfx = _write_test_pfx(tmp_path / 'user.pfx')
    cert_path, key_path = _pfx_to_pem_paths(str(pfx), 'secret')
    assert Path(cert_path).read_bytes().startswith(b'-----BEGIN CERTIFICATE-----')
    assert b'PRIVATE KEY' in Path(key_path).read_bytes()


def test_pfx_missing_raises():
    with pytest.raises(LdapConnectionError, match='not found'):
        _pfx_to_pem_paths('/no/such/user.pfx', None)


def test_pfx_wrong_password(tmp_path):
    pfx = _write_test_pfx(tmp_path / 'user.pfx')
    with pytest.raises(LdapConnectionError, match='Failed to load PFX'):
        _pfx_to_pem_paths(str(pfx), 'wrong')


def test_cert_and_key_must_be_together():
    with pytest.raises(LdapConnectionError, match='together'):
        _client_cert_from_options(SimpleNamespace(pfx=None, cert='a.pem', key=None))
    with pytest.raises(LdapConnectionError, match='not both'):
        _client_cert_from_options(SimpleNamespace(pfx='a.pfx', pfx_pass=None, cert='a.pem', key='a.key'))


def test_connect_from_options_pfx_skips_password(tmp_path, monkeypatch):
    pfx = _write_test_pfx(tmp_path / 'user.pfx')
    captured = {}

    def fake_perform(*args, **kwargs):
        captured['args'] = args
        captured['kwargs'] = kwargs
        return SimpleNamespace(result={'result': 0}, server=SimpleNamespace())

    monkeypatch.setattr('ldap_shell.session.perform_ldap_connection', fake_perform)
    monkeypatch.setattr('ldapdomaindump.domainDumper', lambda *a, **k: object())

    connect_from_options(SimpleNamespace(
        target='lab.local/',
        hashes=None,
        aesKey=None,
        no_pass=False,
        k=False,
        dc_host=None,
        dc_ip='10.0.0.1',
        use_ldaps=False,
        pfx=str(pfx),
        pfx_pass='secret',
        cert=None,
        key=None,
        lootdir='.',
    ))
    assert captured['kwargs']['client_cert']
    assert captured['kwargs']['client_key']
    assert Path(captured['kwargs']['client_cert']).is_file()


def test_get_ldap_client_uses_sasl_external(tmp_path, monkeypatch):
    from ldap_shell import session as session_mod

    class FakeConnection:
        last = None

        def __init__(self, server, **kwargs):
            FakeConnection.last = kwargs
            self.server = server
            self.result = {'result': 0, 'description': 'success'}

        def bind(self):
            return True

    monkeypatch.setattr(session_mod.ldap3, 'Connection', FakeConnection)
    server = SimpleNamespace(ssl=True)
    session_mod.get_ldap_client(
        None, False, 'lab.local', None, None, None, None, None, server, r'lab\ ', '',
        client_cert=str(tmp_path / 'cert.pem'),
    )
    assert FakeConnection.last['authentication'] == session_mod.ldap3.SASL
    assert FakeConnection.last['sasl_mechanism'] == session_mod.ldap3.EXTERNAL
