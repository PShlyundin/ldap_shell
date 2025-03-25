import logging
import re
import copy
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.security_utils import SecurityUtils

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

        lmhash = None
        nthash = None
        domain = self.client.user.split('\\')[0]
        old_user = self.client.user.split('\\')[1]
        old_client = copy.copy(self.client)

        # Check if hash was provided instead of password
        if re.match('^:[0-9a-f]{32}$', password) or re.match('^[0-9a-f]{32}:[0-9a-f]{32}$', password) or re.match('^[0-9a-f]{32}$', password):
            self.log.debug('Attempting to use hash')
            lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            if re.match('^[0-9a-f]{32}$', password):
                nthash = password
            else:
                nthash = password.split(":")[1]
        
        if nthash:
            if self.client.rebind(user=domain+'\\'+username, password=lmhash+':'+nthash, authentication='NTLM'):
                self.log.info(f'Success! User {old_user} was changed to {username}')
                return f'\n{username}# '
            else:
                self.log.error('Failed to switch user. Check password.')
                self.client = old_client
                return False
        else:
            lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            nthash = SecurityUtils.calculate_ntlm(password)
            if self.client.rebind(user=domain+'\\'+username, password=lmhash+':'+nthash, authentication='NTLM'):
                self.log.info(f'Success! User {old_user} was changed to {username}')
                return f'\n{username}# '
            else:
                self.log.error('Failed to switch user. Check password.')
                self.client = old_client
                return False
