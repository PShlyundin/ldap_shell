"""MCP stdio server exposing ldap_shell modules as tools."""
from __future__ import annotations

import argparse
import json
import logging
import os
from types import SimpleNamespace
from typing import Optional

from ldap_shell.runner import CommandRunner
from ldap_shell.session import LdapConnectionError, connect_from_options
from ldap_shell.utils import current_sam

log = logging.getLogger('ldap-shell.mcp')


class ShellState:
    def __init__(self):
        self.client = None
        self.domain_dumper = None
        self.runner: Optional[CommandRunner] = None

    def attach(self, client, domain_dumper):
        self.client = client
        self.domain_dumper = domain_dumper
        self.runner = CommandRunner(domain_dumper, client)

    @property
    def connected(self) -> bool:
        return self.runner is not None


STATE = ShellState()


def options_from_env(base=None):
    opts = base or SimpleNamespace()
    opts.target = getattr(opts, 'target', None) or os.environ.get('LDAP_SHELL_TARGET')
    opts.dc_ip = getattr(opts, 'dc_ip', None) or os.environ.get('LDAP_SHELL_DC_IP')
    opts.dc_host = getattr(opts, 'dc_host', None) or os.environ.get('LDAP_SHELL_DC_HOST')
    opts.hashes = getattr(opts, 'hashes', None) or os.environ.get('LDAP_SHELL_HASHES')
    opts.aesKey = getattr(opts, 'aesKey', None) or os.environ.get('LDAP_SHELL_AESKEY')
    opts.use_ldaps = bool(getattr(opts, 'use_ldaps', False) or os.environ.get('LDAP_SHELL_USE_LDAPS'))
    opts.k = bool(getattr(opts, 'k', False) or os.environ.get('LDAP_SHELL_KRB5'))
    opts.no_pass = bool(getattr(opts, 'no_pass', False) or os.environ.get('LDAP_SHELL_NO_PASS'))
    opts.pfx = getattr(opts, 'pfx', None) or os.environ.get('LDAP_SHELL_PFX')
    opts.pfx_pass = getattr(opts, 'pfx_pass', None) or os.environ.get('LDAP_SHELL_PFX_PASS')
    opts.cert = getattr(opts, 'cert', None) or os.environ.get('LDAP_SHELL_CERT')
    opts.key = getattr(opts, 'key', None) or os.environ.get('LDAP_SHELL_KEY')
    opts.lootdir = getattr(opts, 'lootdir', None) or os.environ.get('LDAP_SHELL_LOOTDIR') or '.'
    return opts


def _require_runner() -> CommandRunner:
    if not STATE.connected:
        raise RuntimeError(
            'Not connected. Call connect() first or start with '
            '`ldap_shell DOMAIN/user:pass --mcp` / LDAP_SHELL_TARGET.'
        )
    return STATE.runner


def serve(client=None, domain_dumper=None, as_json=False):
    """Start the MCP stdio server. Optional pre-bound connection."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise SystemExit(
            'MCP extra is not installed. Install with: pip install "ldap_shell[mcp]"'
        ) from exc

    if client is not None and domain_dumper is not None:
        STATE.attach(client, domain_dumper)

    mcp = FastMCP('ldap_shell')

    @mcp.tool()
    def connect(
        target: str,
        dc_ip: str = '',
        dc_host: str = '',
        hashes: str = '',
        use_ldaps: bool = False,
        kerberos: bool = False,
        pfx: str = '',
        pfx_pass: str = '',
        cert: str = '',
        key: str = '',
    ) -> str:
        """Bind to a domain controller. target is domain/username[:password]."""
        opts = SimpleNamespace(
            target=target,
            dc_ip=dc_ip or None,
            dc_host=dc_host or None,
            hashes=hashes or None,
            use_ldaps=use_ldaps,
            k=kerberos,
            no_pass=kerberos and not hashes,
            aesKey=None,
            pfx=pfx or None,
            pfx_pass=pfx_pass or None,
            cert=cert or None,
            key=key or None,
            lootdir='.',
        )
        try:
            bound_client, dumper = connect_from_options(opts)
        except LdapConnectionError as exc:
            return json.dumps({'ok': False, 'error': str(exc)})
        STATE.attach(bound_client, dumper)
        return json.dumps({'ok': True, 'user': current_sam(bound_client)})

    @mcp.tool()
    def status() -> str:
        """Show whether an LDAP session is bound and as whom."""
        if not STATE.connected:
            return json.dumps({'ok': False, 'connected': False})
        return json.dumps({
            'ok': True,
            'connected': True,
            'user': current_sam(STATE.client),
            'host': getattr(STATE.client.server, 'host', None),
        })

    @mcp.tool()
    def list_commands() -> str:
        """List ldap_shell modules, their arguments and help text."""
        runner = _require_runner()
        return json.dumps(runner.list_commands(), indent=2)

    @mcp.tool()
    def run(command: str) -> str:
        """Run one ldap_shell command, e.g. `get_acl admin` or `search (sAMAccountName=john)`."""
        runner = _require_runner()
        result = runner.execute(command, capture=True)
        return json.dumps({
            'ok': result.ok,
            'command': result.command,
            'output': result.output,
            'error': result.error,
        }, ensure_ascii=False)

    log.info('Starting ldap_shell MCP server')
    mcp.run(transport='stdio')


def main(options=None):
    """Entry point for `ldap_shell-mcp` and `ldap_shell --mcp` without a pre-bound client."""
    if options is None:
        parser = argparse.ArgumentParser(description='ldap_shell MCP server')
        parser.add_argument('target', nargs='?', help='domain/username[:password]')
        parser.add_argument('-dc-ip', dest='dc_ip')
        parser.add_argument('-dc-host', dest='dc_host')
        parser.add_argument('-hashes', dest='hashes')
        parser.add_argument('-use-ldaps', action='store_true', dest='use_ldaps')
        parser.add_argument('-pfx', dest='pfx')
        parser.add_argument('-pfx-pass', dest='pfx_pass')
        parser.add_argument('-cert', dest='cert')
        parser.add_argument('-key', dest='key')
        parser.add_argument('-k', action='store_true')
        parser.add_argument('-no-pass', action='store_true')
        parser.add_argument('-aesKey', dest='aesKey')
        parser.add_argument('--debug', action='store_true')
        options = parser.parse_args()

    options = options_from_env(options)
    client = domain_dumper = None
    if getattr(options, 'target', None):
        try:
            client, domain_dumper = connect_from_options(options)
        except LdapConnectionError as exc:
            raise SystemExit(f'Failed to connect: {exc}') from exc
    serve(client, domain_dumper)
