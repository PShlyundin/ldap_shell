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
    _decode_upn_othername,
    _ldap_ports,
    _looks_like_starttls_fallback,
    _ntlm_connection_kwargs,
    _pfx_to_pem_paths,
    adopt_ldap_connection,
    connect_from_options,
    perform_ldap_connection,
    username_from_x509,
)

ROOT = Path(__file__).resolve().parents[1]


def test_adopt_ldap_connection_replaces_state():
    class _Conn:
        def __init__(self, user, bound=True):
            self.user = user
            self.bound = bound
            self.unbound = False

        def unbind(self):
            self.unbound = True
            self.bound = False

    dst = _Conn('old')
    src = _Conn('new')
    adopt_ldap_connection(dst, src)
    assert dst.user == 'new'
    assert dst.unbound is False


def test_gc_ports():
    assert _ldap_ports(False, False) == (389, 636)
    assert _ldap_ports(True, False) == (389, 636)
    assert _ldap_ports(False, True) == (3268, 3269)
    assert _ldap_ports(True, True) == (3268, 3269)


def test_ldaps_retry_on_signing():
    source = (ROOT / 'ldap_shell/session.py').read_text()
    assert '_looks_like_signing_error' in source
    assert 'channel_binding' in source
    assert '_try_starttls' in source
    assert 'session_security' in source


def test_ntlm_kwargs_stock_ldap3_has_no_epa():
    tls = _ntlm_connection_kwargs(r'domain\user', 'pass', server_ssl=True)
    plain = _ntlm_connection_kwargs(r'domain\user', 'pass', server_ssl=False)
    assert 'channel_binding' not in tls
    assert 'session_security' not in tls
    assert 'session_security' not in plain


def test_ntlm_kwargs_follow_ldap3_features(monkeypatch):
    monkeypatch.setattr(
        'ldap_shell.session._connection_features',
        lambda: {'channel_binding': True, 'session_security': True},
    )
    monkeypatch.setattr('ldap_shell.session._channel_binding_value', lambda: 'tls-server-end-point')
    monkeypatch.setattr('ldap_shell.session._session_security_value', lambda: 'ENCRYPT')
    plain = _ntlm_connection_kwargs(r'domain\user', 'pass', server_ssl=False)
    assert plain['session_security'] == 'ENCRYPT'
    assert 'channel_binding' not in plain
    tls = _ntlm_connection_kwargs(r'domain\user', 'pass', server_ssl=True)
    assert tls['channel_binding'] == 'tls-server-end-point'
    assert 'session_security' not in tls
    starttls = _ntlm_connection_kwargs(r'domain\user', 'pass', server_ssl=False, start_tls=True)
    assert starttls['channel_binding'] == 'tls-server-end-point'
    assert 'session_security' not in starttls


def test_starttls_fallback_after_signing(monkeypatch):
    calls = []

    def fake_client(*args, **kwargs):
        calls.append(kwargs)
        if not kwargs.get('start_tls'):
            raise LdapConnectionError('LDAP bind failed: strongerAuthRequired (code 8)')
        return SimpleNamespace(result={'result': 0})

    monkeypatch.setattr('ldap_shell.session.get_ldap_client', fake_client)
    client = perform_ldap_connection(
        'dc.lab.local', 'lab.local', 'user', 'pass', False, False,
        None, None, None, None, None,
    )
    assert client.result['result'] == 0
    assert any(item.get('start_tls') for item in calls)


def test_starttls_auth_error_does_not_fall_through(monkeypatch):
    def fake_client(*args, **kwargs):
        if not kwargs.get('start_tls'):
            raise LdapConnectionError('LDAP bind failed: strongerAuthRequired (code 8)')
        raise LdapConnectionError('LDAP bind failed: invalidCredentials (code 49)')

    monkeypatch.setattr('ldap_shell.session.get_ldap_client', fake_client)
    with pytest.raises(LdapConnectionError, match='invalidCredentials'):
        perform_ldap_connection(
            'dc.lab.local', 'lab.local', 'user', 'pass', False, False,
            None, None, None, None, None,
        )


def test_starttls_transport_error_is_fallback():
    from ldap3.core.exceptions import LDAPSocketOpenError

    assert _looks_like_starttls_fallback(LDAPSocketOpenError('boom'))
    assert _looks_like_starttls_fallback(LdapConnectionError('Failed to start TLS: boom'))
    assert not _looks_like_starttls_fallback(LdapConnectionError('invalidCredentials (code 49)'))


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


def test_decode_upn_and_username_from_cert():
    assert _decode_upn_othername(b'\x0c\x0falice@lab.local') == 'alice@lab.local'
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'alice')])
    now = datetime.datetime.now(datetime.timezone.utc)
    from cryptography.x509.oid import ObjectIdentifier

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(ObjectIdentifier('1.3.6.1.4.1.311.20.2.3'), b'\x0c\x0falice@lab.local'),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    assert username_from_x509(cert) == ('alice', 'lab.local')


def test_pkinit_sets_kerberos_and_skips_external(tmp_path, monkeypatch):
    pfx = _write_test_pfx(tmp_path / 'user.pfx')
    captured = {}

    def fake_pkinit(options, domain, username, kdc_host):
        captured['pkinit'] = (domain, username, kdc_host)
        return str(tmp_path / 'user.ccache')

    def fake_perform(*args, **kwargs):
        captured['kerberos'] = args[4]
        captured['client_cert'] = kwargs.get('client_cert')
        return SimpleNamespace(result={'result': 0}, server=SimpleNamespace())

    monkeypatch.setattr('ldap_shell.session.pkinit_ccache_from_options', fake_pkinit)
    monkeypatch.setattr('ldap_shell.session.perform_ldap_connection', fake_perform)
    monkeypatch.setattr('ldapdomaindump.domainDumper', lambda *a, **k: object())

    connect_from_options(SimpleNamespace(
        target='lab.local/alice',
        hashes=None,
        aesKey=None,
        no_pass=False,
        k=False,
        dc_host='dc.lab.local',
        dc_ip='10.0.0.1',
        use_ldaps=False,
        pfx=str(pfx),
        pfx_pass='secret',
        cert=None,
        key=None,
        cert_auth='pkinit',
        lootdir='.',
    ))
    assert captured['pkinit'] == ('lab.local', 'alice', 'dc.lab.local')
    assert captured['kerberos'] is True
    assert captured['client_cert'] is None


def test_pkinit_auto_falls_back_to_external(tmp_path, monkeypatch):
    pfx = _write_test_pfx(tmp_path / 'user.pfx')
    captured = {}

    def fake_pkinit(*args, **kwargs):
        raise LdapConnectionError('PKINIT is not supported by this KDC')

    def fake_perform(*args, **kwargs):
        captured['client_cert'] = kwargs.get('client_cert')
        captured['kerberos'] = args[4]
        return SimpleNamespace(result={'result': 0}, server=SimpleNamespace())

    monkeypatch.setattr('ldap_shell.session.pkinit_ccache_from_options', fake_pkinit)
    monkeypatch.setattr('ldap_shell.session.perform_ldap_connection', fake_perform)
    monkeypatch.setattr('ldapdomaindump.domainDumper', lambda *a, **k: object())

    connect_from_options(SimpleNamespace(
        target='lab.local/alice',
        hashes=None,
        aesKey=None,
        no_pass=False,
        k=False,
        dc_host='dc.lab.local',
        dc_ip='10.0.0.1',
        use_ldaps=False,
        pfx=str(pfx),
        pfx_pass='secret',
        cert=None,
        key=None,
        cert_auth='auto',
        lootdir='.',
    ))
    assert captured['kerberos'] is False
    assert captured['client_cert']


def test_anonymous_bind_skips_ntlm(monkeypatch):
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
    session_mod.get_ldap_client(
        None, False, 'lab.local', None, None, None, None, None,
        SimpleNamespace(ssl=False), r'lab.local\ ', '',
    )
    assert FakeConnection.last == {}


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
