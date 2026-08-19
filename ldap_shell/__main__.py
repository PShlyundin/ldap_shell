"""
CLI entrypoint: interactive LDAP shell.
"""
import argparse
import logging
import pathlib
import sys

from ldap_shell.utils import init_logging

log = logging.getLogger('ldap-shell')


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=True, description='LDAP shell utility')
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
        '-use-ldaps', action='store_true',
        help='Use LDAPS (port 636) for the whole session'
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
                        help='NTLM hashes, format is LMHASH:NTHASH or :NTHASH')
    parser.add_argument('-debug', action='store_true', help='print debug output')
    parser.add_argument('-log-path', action='store', metavar='path', type=pathlib.Path,
                        help='save logs to specified path')
    parser.add_argument('-l', '--lootdir', action='store', type=pathlib.Path, metavar='LOOTDIR', default='.',
                        help='loot directory in which gathered loot such as domain dumps will be stored '
                             '(default: current directory)')
    return parser.parse_args(argv)


def main(argv=None) -> None:
    init_logging(False)
    options = parse_args(argv)
    if options.debug or options.log_path is not None:
        init_logging(options.debug, options.log_path)

    from ldap_shell.session import LdapConnectionError, connect_from_options
    from ldap_shell.prompt import Prompt

    try:
        client, domain_dumper = connect_from_options(options)
    except LdapConnectionError as exc:
        log.critical('%s', exc)
        sys.exit(1)

    log.info('Starting interactive shell')
    Prompt(domain_dumper, client).cmdloop()
    log.info('Bye!')


if __name__ == '__main__':
    main()
