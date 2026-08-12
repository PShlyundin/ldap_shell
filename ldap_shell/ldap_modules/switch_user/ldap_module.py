import logging
import re
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType, arg_field
from ldap_shell.utils.security_utils import SecurityUtils
from ldap_shell.utils import current_domain, current_sam


class LdapShellModule(BaseLdapModule):
    """Module for switching current user"""

    help_text = "Switch current user to another"
    examples_text = """
    Example 1: Switch to user with password specified in command line
    `switch_user username password`

    Example 2: Switch to user with interactive password prompt
    `switch_user username`

    Example 3: Switch to user using NTLM hash
    `switch_user username :1a59bd44fe5bec39c44c8cd3524dee`
    `switch_user username aad3b435b51404eeaad3b435b51404ee:1a59bd44fe5bec39c44c8cd3524dee`

    Example 4: Switch to computer account
    `switch_user srv1$ password`

    Example 5: Switch with a PFX (PKINIT / EXTERNAL, same rules as -pfx)
    `switch_user john ./john.pfx`
    `switch_user john ./john.pfx pfx-secret`
    `switch_user john ./cert.pem ./key.pem`
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        username: str = arg_field(
            description="Username to switch to",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )
        password: Optional[str] = arg_field(
            None,
            description="Password, NTLM hash, .pfx path or .pem cert",
            arg_type=ArgumentType.STRING
        )
        extra: Optional[str] = arg_field(
            None,
            description="PFX password, or PEM private key if password is a cert",
            arg_type=ArgumentType.STRING
        )

    def __init__(self, args_dict: dict,
                 domain_dumper: domainDumper,
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _switch_with_cert(self, username, secret, extra) -> bool:
        from pathlib import Path
        from types import SimpleNamespace

        from ldap_shell.session import LdapConnectionError, adopt_ldap_connection, connect_from_options

        suffix = Path(secret).suffix.lower()
        domain = current_domain(self.client)
        host = getattr(self.client.server, 'host', None)
        port = getattr(self.client.server, 'port', None)
        is_ip = bool(host and all(part.isdigit() for part in host.split('.')))
        opts = SimpleNamespace(
            target=f'{domain}/{username}',
            dc_ip=host if is_ip else None,
            dc_host=None if is_ip else host,
            hashes=None,
            aesKey=None,
            no_pass=True,
            k=False,
            use_ldaps=bool(self.client.server.ssl or self.client.tls_started),
            pfx=secret if suffix == '.pfx' else None,
            pfx_pass=extra if suffix == '.pfx' else None,
            cert=secret if suffix in ('.pem', '.crt') else None,
            key=extra if suffix in ('.pem', '.crt') else None,
            cert_auth='auto',
            gc=port in (3268, 3269),
            lootdir='.',
        )
        try:
            new_client, _dumper = connect_from_options(opts)
        except LdapConnectionError as exc:
            self.log.error(f'Certificate bind failed: {exc}')
            return False
        adopt_ldap_connection(self.client, new_client)
        self.domain_dumper.connection = self.client
        self.domain_dumper.server = self.client.server
        return True

    def __call__(self):
        import getpass
        from pathlib import Path

        username = self.args.username
        password = self.args.password
        extra = self.args.extra
        old_user = current_sam(self.client)

        if password and Path(password).suffix.lower() in ('.pfx', '.pem', '.crt'):
            if self._switch_with_cert(username, password, extra):
                self.log.info(f'Success! User {old_user} was changed to {username}')
                return f'{username}# '
            return False

        if not password:
            import sys
            if not sys.stdin.isatty():
                self.log.error('Password required (or pass a .pfx/.pem path)')
                return False
            password = getpass.getpass()

        domain = current_domain(self.client)
        old_password = self.client.password
        old_auth = self.client.authentication

        lmhash = 'aad3b435b51404eeaad3b435b51404ee'
        nthash = None
        if re.match(r'^:[0-9a-f]{32}$', password, re.I) or re.match(r'^[0-9a-f]{32}:[0-9a-f]{32}$', password, re.I) or re.match(r'^[0-9a-f]{32}$', password, re.I):
            self.log.debug('Attempting to use hash')
            if re.match(r'^[0-9a-f]{32}$', password, re.I):
                nthash = password
            else:
                nthash = password.split(':')[1]
        else:
            nthash = SecurityUtils.calculate_ntlm(password)

        if self.client.rebind(user=f'{domain}\\{username}', password=f'{lmhash}:{nthash}', authentication='NTLM'):
            self.log.info(f'Success! User {old_user} was changed to {username}')
            return f'{username}# '

        self.log.error('Failed to switch user. Check password.')
        if old_user and old_password is not None:
            try:
                self.client.rebind(user=f'{domain}\\{old_user}', password=old_password, authentication=old_auth)
            except Exception as exc:
                self.log.error(f'Failed to restore previous session: {exc}')
        return False
