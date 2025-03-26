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
    """Module for deleting computer accounts from Active Directory"""
    
    help_text = "Delete a computer account from the domain"
    examples_text = """
    Example: Delete computer
    `del_computer SRV01$`
    ```
    [INFO] Computer SRV01$ deleted successfully!
    ```
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        computer_name: str = Field(
            description="Computer account name (must end with $)",
            arg_type=ArgumentType.COMPUTER
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
        # Validate computer name format
        if not self.args.computer_name.endswith('$'):
            self.args.computer_name = self.args.computer_name + '$'

        try:
            # Search for computer
            search_filter = f'(sAMAccountName={escape_filter_chars(self.args.computer_name)})'
            if not self.client.search(self.domain_dumper.root, search_filter, attributes=['distinguishedName']):
                self.log.error(f"Computer {self.args.computer_name} not found in domain")
                return

            if not self.client.entries:
                self.log.error(f"Computer {self.args.computer_name} not found in domain")
                return

            computer_dn = self.client.entries[0].entry_dn
            self.log.info(f"Found computer DN: {computer_dn}")

            # Delete computer
            result = self.client.delete(computer_dn)

            if result:
                self.log.info(f'Computer {self.args.computer_name} deleted successfully!')
            else:
                error_msg = self.client.result
                self.log.error(f'Failed to delete computer: {error_msg}')

        except Exception as e:
            self.log.error(f'Error deleting computer: {str(e)}')
            if 'insufficient access rights' in str(e).lower():
                self.log.info('Try relaying with LDAPS (--use-ldaps) or use elevated credentials')

