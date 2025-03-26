import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
import re
from ldap3.utils.conv import escape_filter_chars
import ldap3

class LdapShellModule(BaseLdapModule):
    """Module for enabling user accounts in Active Directory"""
    
    help_text = "Enable a user account in the domain"
    examples_text = """
    Example: Enable user account
    `enable_account john.doe`
    ```
    [INFO] Found user DN: CN=john.doe,CN=Users,DC=domain,DC=local
    [INFO] Original userAccountControl: 514
    [INFO] User john.doe enabled successfully!
    ```
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        username: str = Field(
            description="Username to enable",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
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
        UF_ACCOUNT_DISABLE = 2  # Flag for disabling account

        try:
            # Search for user
            search_filter = f'(sAMAccountName={escape_filter_chars(self.args.username)})'
            if not self.client.search(self.domain_dumper.root, search_filter, 
                                    attributes=['objectSid', 'userAccountControl']):
                self.log.error(f"User {self.args.username} not found in domain")
                return

            if not self.client.entries:
                self.log.error(f"User {self.args.username} not found in domain")
                return

            user_dn = self.client.entries[0].entry_dn
            user_account_control = self.client.entries[0]['userAccountControl'].value
            
            self.log.info(f"Found user DN: {user_dn}")
            self.log.info(f"Original userAccountControl: {user_account_control}")

            # Remove account disable flag
            new_user_account_control = user_account_control & ~UF_ACCOUNT_DISABLE
            
            # Update userAccountControl attribute
            result = self.client.modify(user_dn, 
                                      {'userAccountControl': (ldap3.MODIFY_REPLACE, [new_user_account_control])})

            if result:
                self.log.info(f'User {self.args.username} enabled successfully!')
            else:
                error_msg = self.client.result
                self.log.error(f'Failed to enable user: {error_msg}')

        except Exception as e:
            self.log.error(f'Error enabling user: {str(e)}')
            if 'insufficient access rights' in str(e).lower():
                self.log.info('Try relaying with LDAPS (--use-ldaps) or use elevated credentials')

