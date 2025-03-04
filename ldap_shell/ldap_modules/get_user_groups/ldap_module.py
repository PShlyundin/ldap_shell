import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for retrieves all groups recursively this user is a member of"""

    help_text = "Retrieves all groups recursively this user is a member of"
    examples_text = """
    Get groups for user 'testuser'
    `get_user_groups testuser`
    ```
    [INFO] Group: Domain Users
    ```
    Get groups for group "Remote Management Users"
    `get_user_groups "Remote Management Users"`
    ```
    [INFO] Found 5 groups
    [INFO] Group: Administrators
    [INFO] Group: Schema Admins
    [INFO] Group: Domain Admins
    [INFO] Group: Denied RODC Password Replication Group
    [INFO] Group: group1
    ```
    Get groups for computer 'srv01'
    `get_user_groups srv01$`
    ```
    [INFO] Group: Domain Computers
    ```
    """
    module_type = "Get Info"
    class ModuleArgs(BaseModel):
        user: Optional[str] = Field(
            ...,  # This argument is required
            description="Target AD user",
            arg_type=[ArgumentType.USER, ArgumentType.GROUP, ArgumentType.COMPUTER]  # Changed to list of types
        )

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')
        self.LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'

    def __call__(self):
        self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(self.args.user)})', 
                          attributes=['distinguishedName'])

        if len(self.client.entries) != 1:
            self.log.error(f'User not found in LDAP: {self.args.user}')
            return

        user_dn = self.client.entries[0].entry_dn

        self.client.search(self.domain_dumper.root,
                          f'(member:{self.LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(user_dn)})',
                          attributes=['distinguishedName', 'sAMAccountName', 'name'])

        if self.client.result['result'] == 0:
            if len(self.client.entries) == 0:
                if self.args.user.endswith('$'):
                    self.log.info('Group: Domain Computers')
                else:
                    self.log.info('Group: Domain Users')
            else:
                self.log.info(f'Found {len(self.client.entries)} groups {self.args.user}')
                for entry in self.client.entries:
                    self.log.info(f'Group: {entry.sAMAccountName}')
        else:
            self.log.error('Error searching for user groups')
