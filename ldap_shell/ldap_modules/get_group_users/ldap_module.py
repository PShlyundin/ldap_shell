import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils

class LdapShellModule(BaseLdapModule):
    """Module for retrieves all users in a group"""
    
    help_text = "Get all users in a group"
    examples_text = """
    Example 1
    `get_group_users group`
    ```
    [INFO] sccm_admin - SCCM Servers Admin 
    [INFO] sqldeveloper - SQL Developer
    [INFO] sqlplus - SQL*Plus
    [INFO] j.doe - John Doe
    ```
    """
    module_type = "Get Info" # Get Info, Abuse ACL, Misc and Other.
    LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'
    class ModuleArgs(BaseModel):
        group: Optional[str] = Field(
            ...,  # This argument is required
            description="Group name",
            arg_type=ArgumentType.GROUP
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
        group_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.group)
        if not group_dn:
            raise Exception(f'Group not found in LDAP: {self.args.group}')

        self.client.search(self.domain_dumper.root,
                    f'(memberof:{self.LDAP_MATCHING_RULE_IN_CHAIN}:={group_dn})',
                    attributes=['sAMAccountName', 'name'])
        for entry in self.client.entries:
            self.log.info(f'{entry["sAMAccountName"].value} - {entry["name"].value}')
