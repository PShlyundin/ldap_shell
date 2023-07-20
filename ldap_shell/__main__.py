"""
Main file.
"""
import argparse
import datetime
import logging
import os
import pathlib
import ssl
import sys
from binascii import unhexlify
from getpass import getpass
from typing import Optional

import ldap3
import ldapdomaindump
from ldap3.core.exceptions import LDAPSocketOpenError
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type.univ import noValue

from ldap_shell.impacket_ldap_shell import LdapShell
from ldap_shell.krb5 import constants
from ldap_shell.krb5.asn1 import TGS_REP, AP_REQ, seq_set, Authenticator
from ldap_shell.krb5.ccache import CCache
from ldap_shell.krb5.kerberos_v5 import getKerberosTGT, getKerberosTGS
from ldap_shell.krb5.types import Principal, Ticket, KerberosTime
from ldap_shell.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap_shell.utils import init_logging, parse_credentials

log = logging.getLogger('ldap-shell')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=True,
                                     description='LDAP shell utility')
    parser.add_argument('target', action='store', help='domain/username[:password]')
    parser.add_argument(
        '-dc-ip', action='store', metavar='IP',
        help='IP address of the domain controller. '
             'If omitted the domain part (FQDN) specified in '
             'the target parameter will be used'
    )
    parser.add_argument(
        '-dc-host', action='store', metavar='hostname',
        help='hostname of the domain controller'
    )
    parser.add_argument(
        '-use-ldaps', action='store_true', help='Use LDAPS for create user/computer and change passwords'
    )
    parser.add_argument('-no-pass', action='store_true',
                        help='don\'t ask for password (useful for -k)')
    parser.add_argument(
        '-k', action='store_true',
        help='use Kerberos authentication. Grabs credentials from ccache file '
             '(KRB5CCNAME) based on target parameters. If valid credentials '
             'cannot be found, it will use the ones specified in the command '
             'line'
    )
    parser.add_argument('-aesKey', action='store', metavar='hex key',
                        help='AES key to use for Kerberos Authentication '
                             '(128 or 256 bits)')
    parser.add_argument('-hashes', action='store', metavar='LMHASH:BTHASH',
                        help='NTLM hashes, format is LMHASH:BTHASH')
    parser.add_argument('-debug', action='store_true', help='print debug output')
    parser.add_argument('-log-path', action='store', metavar='path', type=pathlib.Path,
                        help='save logs to specified path')
    parser.add_argument('-l', '--lootdir', action='store', type=pathlib.Path, metavar='LOOTDIR', default='.',
                        help='loot directory in which gathered loot such as domain dumps will be stored '
                             '(default: current directory)')
    return parser.parse_args()


def main() -> None:
    init_logging(False)
    options = parse_args()
    log_debug = options.debug
    log_path = options.log_path
    if log_debug or log_path is not None:
        init_logging(log_debug, log_path)

    start_shell(options)


class StdioShell:
    stdin = sys.stdin
    stdout = sys.stdout


def start_shell(options: argparse.Namespace):
    domain, username, password = parse_credentials(options.target)
    use_ldaps = False
    if len(domain) == 0:
        log.critical('Domain name should be specified')
        sys.exit(1)

    if len(password) == 0 and len(username) != 0 and options.hashes is None \
            and not options.no_pass and options.aesKey is None:
        password = getpass()

    if options.aesKey is not None:
        options.k = True

    if options.k and options.dc_host is None:
        log.critical('Kerberos auth requires DNS name of the target DC. Use -dc-host.')
        sys.exit(1)
    if options.use_ldaps:
        use_ldaps = True

    lmhash = None
    nthash = None
    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')

    target = domain if options.dc_ip is None else options.dc_ip

    log.debug('Starting shell for %s w/ user %s', target, username)
    client = perform_ldap_connection(
        target, domain, username, password, options.k, use_ldaps, options.hashes,
        lmhash, nthash, options.aesKey, options.dc_host
    )

    if 'result' in client.result and client.result['result'] == 0:
        log.debug('Connection established')
    else:
        log.critical('Unknown error. Rerun with -debug to diagnose the issue.')
        sys.exit(1)

    domain_dump_config = ldapdomaindump.domainDumpConfig()
    domain_dump_config.basepath = options.lootdir
    domain_dumper = ldapdomaindump.domainDumper(client.server, client, domain_dump_config)

    shell = LdapShell(
        sys.stdin, sys.stdout, domain_dumper, client
    )
    log.info('Starting interactive shell')
    shell.cmdloop()  # Blocks forever
    log.info('Bye!')


def perform_ldap_connection(target: str, domain: str, username: str, password: str,
                            do_kerberos: bool, ldaps: Optional[bool], hashes: Optional[str],
                            lmhash: Optional[str], nthash: Optional[str],
                            aes_key: Optional[str], kdc_host: Optional[str]) -> ldap3.Connection:
    log.debug('Performing LDAP connection...')
    if ldaps:
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers='ALL:@SECLEVEL=0')
        server = ldap3.Server(target, get_info=ldap3.ALL, port=636, use_ssl=True, tls=tls)
        user_domain = fr'{domain}\{username}'

        try:
            connection = get_ldap_client(aes_key, do_kerberos, domain, hashes, kdc_host, lmhash, nthash, password, server,
                                         user_domain, username)
        except LDAPSocketOpenError:
            log.debug('Failed to connect via TLSv1.2, trying TLSv1')
            log.debug('Details:', exc_info=True)
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2, ciphers='ALL:@SECLEVEL=0')
            server = ldap3.Server(target, get_info=ldap3.ALL, port=636, use_ssl=True, tls=tls)
            connection = get_ldap_client(aes_key, do_kerberos, domain, hashes, kdc_host, lmhash, nthash, password, server,
                                         user_domain, username)
        return connection
    else:
        server = ldap3.Server(target, get_info=ldap3.ALL, use_ssl=False)
        user_domain = fr'{domain}\{username}'
        connection = get_ldap_client(aes_key, do_kerberos, domain, hashes, kdc_host, lmhash, nthash, password, server,
                                         user_domain, username)
        return connection


def get_ldap_client(aes_key, do_kerberos, domain, hashes, kdc_host, lmhash,
                    nthash, password, server, user_domain, username):
    if do_kerberos:
        connection = ldap3.Connection(server)
        bind_result = connection.bind()
        if not bind_result:
            log.debug(f'Failed to perform LDAP bind to {server} w/ user {user_domain} and the provided password.')
            log.debug('Details:')
            log.debug(connection.result)
        login_ldap3_kerberos(
            connection, username, password, domain, lmhash, nthash, aes_key, kdc_host
        )
    elif hashes is not None:
        connection = ldap3.Connection(server, user=user_domain, password=hashes,
                                      authentication=ldap3.NTLM)
        bind_result = connection.bind()
        if not bind_result:
            log.debug(f'Failed to perform LDAP bind to {server} w/ user {user_domain} and the provided hash.')
            log.debug('Details:')
            log.debug(connection.result)
    else:
        connection = ldap3.Connection(server, user=user_domain, password=password,
                                      authentication=ldap3.NTLM)
        bind_result = connection.bind()
        if not bind_result:
            log.debug(f'Failed to perform LDAP bind with user {user_domain} and the provided password.')
            log.debug('Details:')
            log.debug(connection.result)

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
        try:  # just in case they were converted already
            lmhash = unhexlify(lmhash)
            nthash = unhexlify(nthash)
        except TypeError:
            pass

    # noinspection PyBroadException
    try:
        ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
    except Exception:
        log.warning('No ccache present', exc_info=True)
    else:
        if len(domain) == 0:
            domain = ccache.principal.realm['data'].decode('utf-8')
            log.debug('Domain "%s" retrieved from CCache', domain)

        logging.debug('Using Kerberos cache %s', os.getenv('KRB5CCNAME'))
        principal = f'ldap/{kdc_host.upper()}@{domain.upper()}'  # TODO: is this right?

        creds = ccache.getCredential(principal)
        if creds is None:
            # Let's try for the TGT and go from there
            principal = f'krbtgt/{domain.upper()}@{domain.upper()}'
            creds = ccache.getCredential(principal)
            if creds is not None:
                TGT = creds.toTGT()
                logging.debug('Using TGT from cache')
            else:
                logging.debug('No valid credentials found in cache')
        else:
            TGS = creds.toTGS(principal)
            logging.debug('Using TGS from cache')

        if user == '' and creds is not None:
            user = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')
        elif user == '' and len(ccache.principal.components) > 0:
            user = ccache.principal.components[0]['data'].decode('utf-8')
        logging.debug('Username "%s" retrieved from CCache', user)

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
        # noinspection PyUnboundLocalVariable
        tgs, cipher, old_session_key, session_key = getKerberosTGS(server_name, domain, kdc_host, tgt, cipher,
                                                                   session_key)
    else:
        tgs = TGS['KDC_REP']
        cipher = TGS['cipher']
        session_key = TGS['sessionKey']

    blob = SPNEGO_NegTokenInit()

    # Kerberos
    blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

    # Let's extract the ticket from the TGS
    tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    ticket = Ticket()
    ticket.from_asn1(tgs['ticket'])

    # Now let's build the AP_REQ
    ap_req = AP_REQ()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = []
    ap_req['ap-options'] = constants.encodeFlags(opts)
    seq_set(ap_req, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = domain
    seq_set(authenticator, 'cname', user_name.components_to_asn1)
    now = datetime.datetime.utcnow()

    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encoded_authenticator = encoder.encode(authenticator)

    # Key Usage 11
    # AP-REQ Authenticator (includes application authenticator
    # subkey), encrypted with the application session key
    # (Section 5.5.1)
    encrypted_encoded_authenticator = cipher.encrypt(session_key, 11, encoded_authenticator, None)

    ap_req['authenticator'] = noValue
    ap_req['authenticator']['etype'] = cipher.enctype
    ap_req['authenticator']['cipher'] = encrypted_encoded_authenticator

    blob['MechToken'] = encoder.encode(ap_req)

    # FIXME: Why?
    # noinspection PyUnresolvedReferences
    request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO',
                                                  blob.getData())

    # Done with the Kerberos saga, now let's get into LDAP
    if connection.closed:  # try to open connection if closed
        connection.open(read_server_info=False)

    connection.sasl_in_progress = True
    response = connection.post_send_single_response(connection.send('bindRequest', request, None))
    connection.sasl_in_progress = False
    if response[0]['result'] != 0:
        raise Exception(f'Failed to bind: {response}')

    connection.bound = True
    connection.refresh_server_info()
    connection.user = connection.extend.standard.who_am_i()

    return True


if __name__ == '__main__':
    main()
