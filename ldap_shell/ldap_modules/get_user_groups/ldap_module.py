import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional, List
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ModuleArgument, ArgumentType
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for retrieves all groups this user is a member of"""
    
    class ModuleArgs(BaseModel):
        """Model for describing module arguments.
        
        Field() to configure each argument with:
           - default value (None for optional args)
           - description - explains the argument's purpose
           - arg_type - one of ArgumentType enum values:
             * USER - for AD user objects
             * COMPUTER - for AD computers  
             * DIRECTORY - for filesystem paths
             * STRING - for text input
             more types in ../base_module.py
             
        Example:
            class ModuleArgs(BaseModel):
                user: str = Field(
                    description="Target AD user",
                    arg_type=ArgumentType.USER
                )
                group: Optional[str] = Field(
                    None, # This argument is not required
                    description="Optional AD group", 
                    arg_type=ArgumentType.GROUP
                )
        """

        user: Optional[str] = Field(
            ..., # This argument is not required
            description="Target AD user",
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
            self.log.info(f'Found {len(self.client.entries)} groups for user {self.args.user}')
            for entry in self.client.entries:
                self.log.info(f'Group: {entry.sAMAccountName}')
        else:
            self.log.error('Error searching for user groups')
