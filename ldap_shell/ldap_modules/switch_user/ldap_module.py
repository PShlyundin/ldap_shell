import logging
import re
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
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
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        username: str = Field(
            description="Username to switch to",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )
        password: Optional[str] = Field(
            None,
            description="User's password or NTLM hash (optional)",
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

    def __call__(self):
        import getpass

        username = self.args.username
        password = self.args.password
        if not password:
            password = getpass.getpass()

        domain = current_domain(self.client)
        old_user = current_sam(self.client)
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
            self.log.info('Success! User %s was changed to %s', old_user, username)
            return f'{username}# '

        self.log.error('Failed to switch user. Check password.')
        if old_user and old_password is not None:
            try:
                self.client.rebind(user=f'{domain}\\{old_user}', password=old_password, authentication=old_auth)
            except Exception as exc:
                self.log.error('Failed to restore previous session: %s', exc)
        return False
