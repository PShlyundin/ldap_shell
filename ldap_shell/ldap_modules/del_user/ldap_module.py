import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
import re
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for deleting user accounts from Active Directory"""
    
    help_text = "Delete a user account from the domain"
    examples_text = """
    Example: Delete user
    `del_user john.doe`
    ```
    [INFO] User john.doe deleted successfully!
    ```
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        username: str = Field(
            description="Username to delete",
            arg_type=ArgumentType.USER
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
        try:
            # Search for user
            search_filter = f'(sAMAccountName={escape_filter_chars(self.args.username)})'
            if not self.client.search(self.domain_dumper.root, search_filter, attributes=['distinguishedName']):
                self.log.error(f"User {self.args.username} not found in domain")
                return

            if not self.client.entries:
                self.log.error(f"User {self.args.username} not found in domain")
                return

            user_dn = self.client.entries[0].entry_dn
            self.log.info(f"Found user DN: {user_dn}")

            # Delete user
            result = self.client.delete(user_dn)

            if result:
                self.log.info(f'User {self.args.username} deleted successfully!')
            else:
                error_msg = self.client.result
                self.log.error(f'Failed to delete user: {error_msg}')

        except Exception as e:
            self.log.error(f'Error deleting user: {str(e)}')
            if 'insufficient access rights' in str(e).lower():
                self.log.info('Try relaying with LDAPS (--use-ldaps) or use elevated credentials')

