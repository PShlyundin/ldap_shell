"""
CLI entrypoint: interactive shell, inline one-shot commands, or MCP server.
"""
import argparse
import json
import logging
import pathlib
import shlex
import sys

from ldap_shell.utils import init_logging

log = logging.getLogger('ldap-shell')


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        add_help=True,
        description=(
            'LDAP shell for Active Directory enumeration and ACL abuse. '
            'Run without a command for an interactive prompt, or pass a command inline.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'examples:\n'
            '  ldap_shell domain.local/user:pass\n'
            '  ldap_shell domain.local/user:pass whoami\n'
            '  ldap_shell domain.local/user:pass search "(sAMAccountName=admin)"\n'
            '  ldap_shell domain.local/user:pass -c "get_acl admin" -c whoami\n'
            '  ldap_shell domain.local/user:pass --mcp\n'
        ),
    )
    parser.add_argument(
        'target',
        nargs='?',
        default=None,
        help='domain/username[:password]',
    )
    parser.add_argument(
        'inline_command',
        nargs='?',
        default=None,
        help='command to run once, then exit',
    )
    parser.add_argument(
        'inline_args',
        nargs='*',
        default=[],
        help='arguments for the inline command',
    )
    parser.add_argument(
        '-c', '--command',
        action='append',
        dest='commands',
        default=[],
        metavar='CMD',
        help='inline command (repeatable). Does not start the interactive prompt',
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='print inline/MCP command results as JSON',
    )
    parser.add_argument(
        '--mcp',
        action='store_true',
        help='start an MCP stdio server on this connection instead of a prompt',
    )
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
    parser.add_argument(
        '-non-interactive',
        action='store_true',
        help='read commands from stdin and exit (no prompt)',
    )
    parser.add_argument('-log-path', action='store', metavar='path', type=pathlib.Path,
                        help='save logs to specified path')
    parser.add_argument('-l', '--lootdir', action='store', type=pathlib.Path, metavar='LOOTDIR', default='.',
                        help='loot directory in which gathered loot such as domain dumps will be stored '
                             '(default: current directory)')
    return parser.parse_args(argv)


def collect_inline_commands(options: argparse.Namespace) -> list:
    commands = list(options.commands or [])
    if options.inline_command:
        parts = [options.inline_command, *(options.inline_args or [])]
        commands.append(' '.join(shlex.quote(part) for part in parts))
    if options.non_interactive and not commands and not sys.stdin.isatty():
        commands.extend(
            line.strip() for line in sys.stdin
            if line.strip() and not line.lstrip().startswith('#')
        )
    return commands


def run_inline(client, domain_dumper, commands, as_json=False) -> int:
    from ldap_shell.runner import CommandRunner

    runner = CommandRunner(domain_dumper, client)
    results = runner.execute_many(commands, capture=as_json)
    exit_code = 0
    payload = []
    for result in results:
        if as_json:
            payload.append({
                'ok': result.ok,
                'command': result.command,
                'output': result.output,
                'error': result.error,
            })
        if not result.ok:
            exit_code = 1
    if as_json:
        print(json.dumps(payload if len(payload) != 1 else payload[0], indent=2, ensure_ascii=False))
    return exit_code


def main(argv=None) -> None:
    init_logging(False)
    options = parse_args(argv)
    if options.debug or options.log_path is not None:
        init_logging(options.debug, options.log_path)

    if options.mcp and not options.target:
        from ldap_shell.mcp_server import main as mcp_main
        mcp_main(options)
        return

    if not options.target:
        parse_args(['-h'])
        sys.exit(2)

    from ldap_shell.session import LdapConnectionError, connect_from_options

    try:
        client, domain_dumper = connect_from_options(options)
    except LdapConnectionError as exc:
        log.critical('%s', exc)
        sys.exit(1)

    inline_commands = collect_inline_commands(options)
    if options.mcp:
        from ldap_shell.mcp_server import serve
        serve(client, domain_dumper, as_json=options.json)
        return

    if inline_commands:
        sys.exit(run_inline(client, domain_dumper, inline_commands, as_json=options.json))

    from ldap_shell.prompt import Prompt
    log.info('Starting interactive shell')
    Prompt(domain_dumper, client).cmdloop()
    log.info('Bye!')


if __name__ == '__main__':
    main()
