"""LDAP connection helpers shared by the interactive shell, inline CLI and MCP."""
import datetime
import inspect
import logging
import os
import ssl
import sys
from binascii import unhexlify
from getpass import getpass
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


class LdapConnectionError(Exception):
    """Raised when an LDAP bind or socket connection fails."""


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def _tls_versions():
    versions = []
    for name in ('PROTOCOL_TLSv1_2', 'PROTOCOL_TLSv1_1', 'PROTOCOL_TLSv1'):
        version = getattr(ssl, name, None)
        if version is not None:
            versions.append((name, version))
    return versions


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

    hashes = getattr(options, 'hashes', None)
    aes_key = getattr(options, 'aesKey', None)
    no_pass = getattr(options, 'no_pass', False)
    do_kerberos = bool(getattr(options, 'k', False) or aes_key)
    dc_host = getattr(options, 'dc_host', None)
    use_ldaps = bool(getattr(options, 'use_ldaps', False))

    if not password and username and hashes is None and not no_pass and aes_key is None:
        if sys.stdin.isatty():
            password = getpass()
        else:
            raise LdapConnectionError('Password is required (or pass -hashes / -k -no-pass)')

    if aes_key is not None:
        do_kerberos = True
    if do_kerberos and not dc_host:
        raise LdapConnectionError('Kerberos auth requires DNS name of the target DC. Use -dc-host.')

    lmhash, nthash = parse_hashes(hashes)
    target = domain if getattr(options, 'dc_ip', None) is None else options.dc_ip

    log.debug('Connecting to %s as %s\\%s', target, domain, username)
    client = perform_ldap_connection(
        target, domain, username, password, do_kerberos, use_ldaps, hashes,
        lmhash, nthash, aes_key, dc_host
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


def _ntlm_connection_kwargs(user, password, server_ssl: bool) -> dict:
    kwargs = {
        'user': user,
        'password': password,
        'authentication': ldap3.NTLM,
    }
    params = inspect.signature(ldap3.Connection.__init__).parameters
    if server_ssl and 'channel_binding' in params:
        kwargs['channel_binding'] = True
    return kwargs


def perform_ldap_connection(target: str, domain: str, username: str, password: str,
                            do_kerberos: bool, ldaps: Optional[bool], hashes: Optional[str],
                            lmhash: Optional[str], nthash: Optional[str],
                            aes_key: Optional[str], kdc_host: Optional[str]) -> ldap3.Connection:
    user_domain = fr'{domain}\{username}'
    if not ldaps:
        server = ldap3.Server(target, get_info=ldap3.ALL, use_ssl=False)
        try:
            return get_ldap_client(
                aes_key, do_kerberos, domain, hashes, kdc_host, lmhash, nthash,
                password, server, user_domain, username
            )
        except LdapConnectionError as exc:
            if do_kerberos or not _looks_like_signing_error(exc):
                raise
            log.info('DC rejected plaintext LDAP (%s). Retrying over LDAPS.', exc)

    last_error = None
    for name, version in _tls_versions():
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=version, ciphers='ALL:@SECLEVEL=0')
        server = ldap3.Server(target, get_info=ldap3.ALL, port=636, use_ssl=True, tls=tls)
        try:
            log.debug('Trying LDAPS with %s', name)
            return get_ldap_client(
                aes_key, do_kerberos, domain, hashes, kdc_host, lmhash, nthash,
                password, server, user_domain, username
            )
        except LDAPSocketOpenError as exc:
            last_error = exc
            log.debug('LDAPS %s failed', name, exc_info=True)
    raise LdapConnectionError(f'Failed to open LDAPS connection: {last_error}')


def _looks_like_signing_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(token in text for token in (
        'strongerauthrequired', 'confidentialityrequired', 'ldap signing',
        'channel binding', 'code 8', 'code 13', 'code 48',
    ))


def get_ldap_client(aes_key, do_kerberos, domain, hashes, kdc_host, lmhash,
                    nthash, password, server, user_domain, username):
    if do_kerberos:
        connection = ldap3.Connection(server)
        connection.open()
        login_ldap3_kerberos(
            connection, username, password, domain, lmhash, nthash, aes_key, kdc_host
        )
        return connection

    if hashes is not None:
        bind_password = hashes
        auth_label = 'hash'
    else:
        bind_password = password
        auth_label = 'password'

    connection = ldap3.Connection(
        server, **_ntlm_connection_kwargs(user_domain, bind_password, bool(server.ssl))
    )
    bind_result = connection.bind()
    if not bind_result:
        message = f'{_format_bind_error(connection.result)} (user {user_domain}, {auth_label} auth)'
        if _signing_required(connection.result):
            message += '. DC likely requires LDAP signing or channel binding; retrying LDAPS if possible'
        raise LdapConnectionError(message)
    return connection


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
