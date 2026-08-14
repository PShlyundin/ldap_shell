"""LDAP connection helpers shared by the interactive shell, inline CLI and MCP."""
import datetime
import inspect
import logging
import os
import ssl
import sys
import tempfile
from binascii import unhexlify
from getpass import getpass
from pathlib import Path
from typing import Optional, Tuple

import ldap3
import ldapdomaindump
from ldap3.core.exceptions import LDAPSocketOpenError
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue

from ldap_shell.krb5 import constants
from ldap_shell.krb5.asn1 import TGS_REP, AP_REQ, seq_set, Authenticator
from ldap_shell.krb5.ccache import CCache
from ldap_shell.krb5.kerberos_v5 import getKerberosTGT, getKerberosTGS
from ldap_shell.krb5.types import Principal, Ticket, KerberosTime
from ldap_shell.utils.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap_shell.utils import parse_credentials, parse_hashes

log = logging.getLogger('ldap-shell')

# PKCS#12 is unpacked to temp PEMs; keep the directories alive for the process.
_CERT_TEMPDIRS: list = []


class LdapConnectionError(Exception):
    """Raised when an LDAP bind or socket connection fails."""


def adopt_ldap_connection(dst, src) -> None:
    """Replace dst in-place so objects that already hold it see the new bind."""
    try:
        if getattr(dst, 'bound', False):
            dst.unbind()
    except Exception:
        pass
    dst.__dict__.update(src.__dict__)


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _tls_versions():
    versions = []
    for name in ('PROTOCOL_TLSv1_2', 'PROTOCOL_TLSv1_1', 'PROTOCOL_TLSv1'):
        version = getattr(ssl, name, None)
        if version is not None:
            versions.append((name, version))
    return versions


def _make_tls(version, client_cert=None, client_key=None):
    """Build an ldap3 Tls object, optionally with a client certificate."""
    kwargs = {
        'validate': ssl.CERT_NONE,
        'version': version,
        'ciphers': 'ALL:@SECLEVEL=0',
    }
    if client_cert and client_key:
        kwargs['local_certificate_file'] = client_cert
        kwargs['local_private_key_file'] = client_key
    return ldap3.Tls(**kwargs)


def _pfx_password_bytes(password):
    """Normalize a PFX password to bytes, or None when the PFX has no password."""
    if password is None or password == '':
        return None
    if isinstance(password, bytes):
        return password
    return password.encode()


def _pfx_to_pem_paths(pfx_path: str, password=None) -> Tuple[str, str]:
    """Unpack a PKCS#12 file to temp PEM cert/key paths used by ldap3.Tls."""
    path = Path(pfx_path)
    if not path.is_file():
        raise LdapConnectionError(f'PFX not found: {pfx_path}')
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        pkcs12,
    )

    try:
        key, cert, _extra = pkcs12.load_key_and_certificates(
            path.read_bytes(), _pfx_password_bytes(password)
        )
    except Exception as exc:
        raise LdapConnectionError(f'Failed to load PFX {pfx_path}: {exc}') from exc
    if key is None or cert is None:
        raise LdapConnectionError(f'PFX {pfx_path} does not contain both a private key and a certificate')

    tmp = tempfile.TemporaryDirectory(prefix='ldap_shell_cert_')
    _CERT_TEMPDIRS.append(tmp)
    cert_file = Path(tmp.name) / 'cert.pem'
    key_file = Path(tmp.name) / 'key.pem'
    cert_file.write_bytes(cert.public_bytes(Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
    )
    return str(cert_file), str(key_file)


def _client_cert_from_options(options) -> Tuple[Optional[str], Optional[str]]:
    """Return (cert_pem, key_pem) from -pfx or -cert/-key, or (None, None)."""
    pfx = getattr(options, 'pfx', None)
    cert = getattr(options, 'cert', None)
    key = getattr(options, 'key', None)
    if pfx and (cert or key):
        raise LdapConnectionError('Use either -pfx or -cert/-key, not both')
    if (cert and not key) or (key and not cert):
        raise LdapConnectionError('-cert and -key must be used together')
    if pfx:
        return _pfx_to_pem_paths(pfx, getattr(options, 'pfx_pass', None))
    if cert:
        cert_path = Path(cert)
        key_path = Path(key)
        if not cert_path.is_file():
            raise LdapConnectionError(f'Certificate not found: {cert}')
        if not key_path.is_file():
            raise LdapConnectionError(f'Private key not found: {key}')
        return str(cert_path), str(key_path)
    return None, None


_UPN_OID = '1.3.6.1.4.1.311.20.2.3'
_DEFAULT_DH = {
    'p': int(
        '00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef'
        '9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386b'
        'fb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff',
        16,
    ),
    'g': 2,
}


def _decode_upn_othername(value: bytes) -> str:
    """Decode a UPN OtherName payload (UTF8String / BMPString / raw UTF-8)."""
    if not value:
        return ''
    if value[0] in (0x0C, 0x1E, 0x13):
        idx = 1
        length = value[idx]
        idx += 1
        if length & 0x80:
            nbytes = length & 0x7F
            length = int.from_bytes(value[idx:idx + nbytes], 'big')
            idx += nbytes
        payload = value[idx:idx + length]
        if value[0] == 0x1E:
            return payload.decode('utf-16-be', errors='replace')
        return payload.decode('utf-8', errors='replace')
    return value.decode('utf-8', errors='replace')


def username_from_x509(cert) -> Tuple[Optional[str], Optional[str]]:
    """Return (username, domain) from a certificate UPN SAN or CN."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        upn_oid = ObjectIdentifier(_UPN_OID)
        for name in san.value:
            if isinstance(name, x509.OtherName) and name.type_id == upn_oid:
                upn = _decode_upn_othername(name.value)
                if '@' in upn:
                    user, domain = upn.split('@', 1)
                    return user, domain
                if upn:
                    return upn, None
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cns:
        return cns[0].value, None
    return None, None


def _x509_from_options(options):
    """Load the client certificate object from -pfx or -cert."""
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509 import load_pem_x509_certificate

    pfx = getattr(options, 'pfx', None)
    if pfx:
        path = Path(pfx)
        if not path.is_file():
            raise LdapConnectionError(f'PFX not found: {pfx}')
        try:
            _key, cert, _extra = pkcs12.load_key_and_certificates(
                path.read_bytes(), _pfx_password_bytes(getattr(options, 'pfx_pass', None))
            )
        except Exception as exc:
            raise LdapConnectionError(f'Failed to load PFX {pfx}: {exc}') from exc
        if cert is None:
            raise LdapConnectionError(f'PFX {pfx} does not contain a certificate')
        return cert
    cert_path = getattr(options, 'cert', None)
    if cert_path:
        path = Path(cert_path)
        if not path.is_file():
            raise LdapConnectionError(f'Certificate not found: {cert_path}')
        return load_pem_x509_certificate(path.read_bytes())
    return None


def _write_ccache(data: bytes) -> str:
    """Persist a ccache blob in a process-lifetime temp directory."""
    tmp = tempfile.TemporaryDirectory(prefix='ldap_shell_ccache_')
    _CERT_TEMPDIRS.append(tmp)
    path = Path(tmp.name) / 'user.ccache'
    path.write_bytes(data)
    return str(path)


def pkinit_ccache_from_options(options, domain: str, username: str, kdc_host: str) -> str:
    """Get a TGT via PKINIT and return the ccache path."""
    from minikerberos.common.ccache import CCACHE
    from minikerberos.common.target import KerberosTarget
    from minikerberos.network.clientsocket import KerberosClientSocket

    from ldap_shell.utils.myPKINIT import myPKINIT

    if not kdc_host:
        raise LdapConnectionError('PKINIT requires -dc-host (DNS name of the KDC)')
    if not username:
        raise LdapConnectionError('PKINIT requires a username (target or UPN in the certificate)')

    pfx = getattr(options, 'pfx', None)
    if pfx:
        ini = myPKINIT.from_pfx_data(
            Path(pfx).read_bytes(),
            _pfx_password_bytes(getattr(options, 'pfx_pass', None)),
            _DEFAULT_DH,
        )
    else:
        ini = myPKINIT.from_pem(options.cert, options.key, _DEFAULT_DH)

    req = ini.build_asreq(domain, username)
    try:
        res = KerberosClientSocket(KerberosTarget(kdc_host)).sendrecv(req)
    except Exception as exc:
        raise LdapConnectionError(f'PKINIT AS-REQ to {kdc_host} failed: {exc}') from exc

    native = getattr(res, 'native', None) or {}
    if native.get('error-code') == 15:
        raise LdapConnectionError('PKINIT is not supported by this KDC')
    if native.get('error-code'):
        raise LdapConnectionError(f'PKINIT AS-REP error {native.get("error-code")}: {native}')

    try:
        encasrep, _session_key, _cipher = ini.decrypt_asrep(native)
        cache = CCACHE()
        cache.add_tgt(native, encasrep)
        return _write_ccache(cache.to_bytes())
    except LdapConnectionError:
        raise
    except Exception as exc:
        raise LdapConnectionError(f'Failed to build TGT from PKINIT AS-REP: {exc}') from exc


def _format_bind_error(result) -> str:
    if not result:
        return 'LDAP bind failed'
    description = result.get('description') or 'unknown'
    message = result.get('message') or ''
    code = result.get('result')
    parts = [f'LDAP bind failed: {description}']
    if code is not None:
        parts.append(f'(code {code})')
    if message:
        parts.append(str(message).strip())
    return ' '.join(parts)


def connect_from_options(options) -> Tuple[ldap3.Connection, ldapdomaindump.domainDumper]:
    """Create a bound LDAP connection and domain dumper from argparse/namespace options."""
    domain, username, password = parse_credentials(getattr(options, 'target', '') or '')
    if not domain:
        raise LdapConnectionError('Domain name should be specified')
    if getattr(options, 'anon', False):
        username = ''
        password = ''

    hashes = getattr(options, 'hashes', None)
    aes_key = getattr(options, 'aesKey', None)
    no_pass = getattr(options, 'no_pass', False)
    do_kerberos = bool(getattr(options, 'k', False) or aes_key)
    dc_host = getattr(options, 'dc_host', None)
    has_cert = bool(getattr(options, 'pfx', None) or getattr(options, 'cert', None))
    cert_auth = (getattr(options, 'cert_auth', None) or 'auto').lower()
    if cert_auth not in ('auto', 'pkinit', 'external'):
        raise LdapConnectionError('-cert-auth must be auto, pkinit or external')

    client_cert = client_key = None
    if has_cert and cert_auth != 'external':
        cert_obj = _x509_from_options(options)
        cert_user, cert_domain = username_from_x509(cert_obj) if cert_obj else (None, None)
        if not username and cert_user:
            username = cert_user
            log.debug('Username %s taken from certificate', username)
        if not domain and cert_domain:
            domain = cert_domain
        if cert_auth == 'pkinit' and not dc_host:
            raise LdapConnectionError('PKINIT requires -dc-host')
        if dc_host and username:
            try:
                ccache_path = pkinit_ccache_from_options(options, domain, username, dc_host)
                os.environ['KRB5CCNAME'] = ccache_path
                do_kerberos = True
                no_pass = True
                log.info(f'PKINIT TGT acquired for {domain}\\{username}, binding with Kerberos')
            except LdapConnectionError as exc:
                if cert_auth == 'pkinit':
                    raise
                log.info(f'PKINIT failed ({exc}). Falling back to SASL EXTERNAL.')
        elif cert_auth == 'pkinit':
            raise LdapConnectionError('PKINIT needs a username (target or UPN in the certificate) and -dc-host')

    if has_cert and not do_kerberos:
        client_cert, client_key = _client_cert_from_options(options)

    use_ldaps = bool(getattr(options, 'use_ldaps', False) or client_cert)

    if not password and username and hashes is None and not no_pass and aes_key is None and not has_cert:
        if sys.stdin.isatty():
            password = getpass()
        else:
            raise LdapConnectionError('Password is required (or pass -hashes / -k -no-pass / -pfx)')
    if not password and no_pass and hashes is None and not do_kerberos and aes_key is None and not has_cert:
        # Dummy secret used by ntlmrelayx SOCKS / proxychains LDAP clients.
        password = 'relay'
        log.debug('No password with -no-pass: using dummy password for SOCKS/relay binds')

    if aes_key is not None:
        do_kerberos = True
    if do_kerberos and not dc_host:
        raise LdapConnectionError('Kerberos auth requires DNS name of the target DC. Use -dc-host.')

    lmhash, nthash = parse_hashes(hashes)
    target = domain if getattr(options, 'dc_ip', None) is None else options.dc_ip

    log.debug('Connecting to %s as %s\\%s', target, domain, username)
    client = perform_ldap_connection(
        target, domain, username, password, do_kerberos, use_ldaps, hashes,
        lmhash, nthash, aes_key, dc_host,
        client_cert=client_cert, client_key=client_key,
        gc=bool(getattr(options, 'gc', False)),
    )

    result = getattr(client, 'result', None) or {}
    if result.get('result', 1) != 0:
        raise LdapConnectionError(_format_bind_error(result))

    log.debug('Connection established')
    domain_dump_config = ldapdomaindump.domainDumpConfig()
    domain_dump_config.basepath = getattr(options, 'lootdir', '.') or '.'
    domain_dumper = ldapdomaindump.domainDumper(client.server, client, domain_dump_config)
    return client, domain_dumper


def _signing_required(result) -> bool:
    if not result:
        return False
    code = result.get('result')
    description = str(result.get('description') or '').lower()
    message = str(result.get('message') or '').lower()
    if code in (8, 13, 48):
        return True
    return any(token in description or token in message for token in (
        'strongerauthrequired', 'confidentialityrequired', 'ldap signing', 'channel binding',
    ))


def _connection_features() -> dict:
    """What this ldap3 build can do beyond stock 2.9.1."""
    params = inspect.signature(ldap3.Connection.__init__).parameters
    return {
        'channel_binding': 'channel_binding' in params,
        'session_security': 'session_security' in params,
    }


def _channel_binding_value():
    return getattr(ldap3, 'TLS_CHANNEL_BINDING', True)


def _session_security_value():
    for name in ('ENCRYPT', 'SIGNATURE'):
        value = getattr(ldap3, name, None)
        if value is not None:
            return value
    return 'ENCRYPT'


def _ntlm_connection_kwargs(user, password, server_ssl: bool, start_tls: bool = False) -> dict:
    """NTLM Connection kwargs; enable signing/EPA only when this ldap3 supports them."""
    kwargs = {
        'user': user,
        'password': password,
        'authentication': ldap3.NTLM,
    }
    features = _connection_features()
    tls = bool(server_ssl or start_tls)
    if features['channel_binding'] and tls:
        kwargs['channel_binding'] = _channel_binding_value()
    if features['session_security'] and not tls:
        kwargs['session_security'] = _session_security_value()
    return kwargs


def _ldap_ports(ldaps: bool, gc: bool) -> Tuple[int, int]:
    """Return (plain_port, tls_port) for DC LDAP or Global Catalog."""
    if gc:
        return 3268, 3269
    return 389, 636


def perform_ldap_connection(target: str, domain: str, username: str, password: str,
                            do_kerberos: bool, ldaps: Optional[bool], hashes: Optional[str],
                            lmhash: Optional[str], nthash: Optional[str],
                            aes_key: Optional[str], kdc_host: Optional[str],
                            client_cert: Optional[str] = None,
                            client_key: Optional[str] = None,
                            gc: bool = False) -> ldap3.Connection:
    user_domain = fr'{domain}\{username}'
    features = _connection_features()
    log.debug(
        'ldap3 features: channel_binding=%s session_security=%s',
        features['channel_binding'], features['session_security'],
    )
    if client_cert:
        ldaps = True
    plain_port, tls_port = _ldap_ports(bool(ldaps), gc)
    if gc:
        log.debug('Using Global Catalog ports %s/%s', plain_port, tls_port)
    client_args = (
        aes_key, do_kerberos, domain, hashes, kdc_host, lmhash, nthash,
        password,
    )
    if not ldaps:
        server = ldap3.Server(target, get_info=ldap3.ALL, port=plain_port, use_ssl=False)
        try:
            return get_ldap_client(
                *client_args, server, user_domain, username,
                client_cert=client_cert,
            )
        except LdapConnectionError as exc:
            if do_kerberos or not _looks_like_signing_error(exc):
                raise
            log.info(f'DC rejected plaintext LDAP ({exc}). Trying StartTLS, then LDAPS.')
            try:
                return _try_starttls(
                    target, client_args, user_domain, username, client_cert, client_key,
                    port=plain_port,
                )
            except (LDAPSocketOpenError, LdapConnectionError) as starttls_exc:
                if not _looks_like_starttls_fallback(starttls_exc):
                    raise
                log.info(f'StartTLS did not satisfy the DC ({starttls_exc}). Retrying over LDAPS.')

    last_error = None
    for name, version in _tls_versions():
        tls = _make_tls(version, client_cert, client_key)
        server = ldap3.Server(target, get_info=ldap3.ALL, port=tls_port, use_ssl=True, tls=tls)
        try:
            log.debug('Trying LDAPS with %s', name)
            return get_ldap_client(
                *client_args, server, user_domain, username,
                client_cert=client_cert,
            )
        except LDAPSocketOpenError as exc:
            last_error = exc
            log.debug('LDAPS %s failed', name, exc_info=True)
    raise LdapConnectionError(f'Failed to open LDAPS connection: {last_error}')


def _try_starttls(target, client_args, user_domain, username, client_cert, client_key, port=389):
    """Bind after StartTLS. Used when plaintext LDAP is rejected."""
    last_error = None
    for name, version in _tls_versions():
        tls = _make_tls(version, client_cert, client_key)
        server = ldap3.Server(target, get_info=ldap3.ALL, port=port, use_ssl=False, tls=tls)
        try:
            log.debug('Trying StartTLS with %s', name)
            return get_ldap_client(
                *client_args, server, user_domain, username,
                client_cert=client_cert, start_tls=True,
            )
        except LDAPSocketOpenError as exc:
            last_error = exc
            log.debug('StartTLS %s failed', name, exc_info=True)
        except LdapConnectionError as exc:
            text = str(exc).lower()
            if 'starttls' in text or 'start tls' in text:
                last_error = exc
                log.debug('StartTLS %s failed', name, exc_info=True)
                continue
            raise
    raise LdapConnectionError(f'Failed to start TLS: {last_error}')


def _start_tls(connection):
    """Open the socket if needed and issue StartTLS."""
    if connection.closed:
        connection.open()
    if not connection.start_tls():
        raise LdapConnectionError('StartTLS failed')


def _looks_like_signing_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(token in text for token in (
        'strongerauthrequired', 'confidentialityrequired', 'ldap signing',
        'channel binding', 'code 8', 'code 13', 'code 48',
    ))


def _looks_like_starttls_fallback(exc: Exception) -> bool:
    """True when StartTLS failed in a way that still warrants an LDAPS retry."""
    if isinstance(exc, LDAPSocketOpenError):
        return True
    text = str(exc).lower()
    if 'start tls' in text or 'starttls' in text:
        return True
    return _looks_like_signing_error(exc)


def get_ldap_client(aes_key, do_kerberos, domain, hashes, kdc_host, lmhash,
                    nthash, password, server, user_domain, username,
                    client_cert=None, start_tls=False):
    if client_cert:
        connection = ldap3.Connection(
            server, authentication=ldap3.SASL, sasl_mechanism=ldap3.EXTERNAL,
        )
        if start_tls:
            _start_tls(connection)
        bind_result = connection.bind()
        if not bind_result:
            raise LdapConnectionError(
                f'{_format_bind_error(connection.result)} (SASL EXTERNAL client-certificate bind)'
            )
        return connection

    if do_kerberos:
        connection = ldap3.Connection(server)
        connection.open()
        if start_tls:
            _start_tls(connection)
        login_ldap3_kerberos(
            connection, username, password, domain, lmhash, nthash, aes_key, kdc_host
        )
        return connection

    if not username and hashes is None:
        connection = ldap3.Connection(server)
        if start_tls:
            _start_tls(connection)
        bind_result = connection.bind()
        if not bind_result:
            message = f'{_format_bind_error(connection.result)} (anonymous bind)'
            if _signing_required(connection.result):
                message += _signing_followup(bool(server.ssl or start_tls), connection.result)
            raise LdapConnectionError(message)
        log.info('Anonymous bind succeeded')
        return connection

    if hashes is not None:
        bind_password = hashes
        auth_label = 'hash'
    else:
        bind_password = password
        auth_label = 'password'

    connection = ldap3.Connection(
        server,
        **_ntlm_connection_kwargs(
            user_domain, bind_password, bool(server.ssl), start_tls=start_tls,
        ),
    )
    if start_tls:
        _start_tls(connection)
    bind_result = connection.bind()
    if not bind_result:
        message = f'{_format_bind_error(connection.result)} (user {user_domain}, {auth_label} auth)'
        if _signing_required(connection.result):
            message += _signing_followup(bool(server.ssl or start_tls), connection.result)
        raise LdapConnectionError(message)
    return connection


def _signing_followup(over_tls: bool, result) -> str:
    """Extra hint when the DC wants signing or channel binding."""
    if not over_tls:
        return '. DC likely requires LDAP signing or channel binding; retrying StartTLS/LDAPS if possible'
    if _connection_features()['channel_binding']:
        return '. DC still rejected the TLS bind (signing/EPA)'
    text = f'{result}'.lower()
    if 'channel binding' in text or 'epa' in text:
        return (
            '. DC requires channel binding (EPA). This ldap3 build cannot send '
            'channel binding tokens; pip install "ldap_shell[epa]"'
        )
    return '. DC likely requires LDAP signing or channel binding over TLS'


def login_ldap3_kerberos(connection: ldap3.Connection, user: str, password: str,
                         domain: str = '', lmhash: str = '', nthash: str = '', aes_key: str = '',
                         kdc_host: Optional[str] = None):
    TGT = None
    TGS = None
    log.debug('Logging in via Kerberos')
    if (lmhash is not None and lmhash != '') or (nthash is not None and nthash != ''):
        if len(lmhash) % 2:
            lmhash = '0' + lmhash
        if len(nthash) % 2:
            nthash = '0' + nthash
        try:
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    try:
        ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
    except Exception:
        log.debug('No ccache present', exc_info=True)
    else:
        if len(domain) == 0:
            domain = ccache.principal.realm['data'].decode('utf-8')
            log.debug('Domain "%s" retrieved from CCache', domain)

        log.debug('Using Kerberos cache %s', os.getenv('KRB5CCNAME'))
        principal = f'ldap/{kdc_host.upper()}@{domain.upper()}'

        creds = ccache.getCredential(principal)
        if creds is None:
            principal = f'krbtgt/{domain.upper()}@{domain.upper()}'
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                log.debug('Using TGT from cache')
            else:
                log.debug('No valid credentials found in cache')
        else:
            TGS = creds.toTGS(principal)
            log.debug('Using TGS from cache')

        if user == '' and creds is not None:
            user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
        elif user == '' and len(ccache.principal.components) > 0:
            user = ccache.principal.components[0]['data'].decode('utf-8')
        log.debug('Username "%s" retrieved from CCache', user)

    user_name = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    if TGT is None:
        if TGS is None:
            tgt, cipher, old_session_key, session_key = getKerberosTGT(
                user_name, password, domain, lmhash, nthash, aes_key, kdc_host
            )
    else:
        tgt = TGT['KDC_REP']
        cipher = TGT['cipher']
        session_key = TGT['sessionKey']

    if TGS is None:
        server_name = Principal(f'ldap/{kdc_host}', type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, old_session_key, session_key = getKerberosTGS(
            server_name, domain, kdc_host, tgt, cipher, session_key
        )
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        session_key = TGS['sessionKey']

    blob = SPNEGO_NegTokenInit()
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    ap_req = AP_REQ()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    ap_req['ap-options'] = constants.encodeFlags([])
    seq_set(ap_req, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', user_name.components_to_asn1)
    now = _utc_now()
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)
    encrypted_encoded_authenticator = cipher.encrypt(session_key, 11, encoded_authenticator, None)

    ap_req['authenticator'] = noValue
    ap_req['authenticator']['etype'] = cipher.enctype
    ap_req['authenticator']['cipher'] = encrypted_encoded_authenticator
    blob['MechToken'] = encoder.encode(ap_req)

    request = ldap3.operation.bind.bind_operation(
        connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO', blob.getData()
    )

    if connection.closed:
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise LdapConnectionError(f'Kerberos LDAP bind failed: {response}')

    connection.bound = True
    connection.refresh_server_info()
    connection.user = connection.extend.standard.who_am_i()
    return True
