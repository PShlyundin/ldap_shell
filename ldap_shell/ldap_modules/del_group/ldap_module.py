import logging
from ldap3 import Connection, SUBTREE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType

class LdapShellModule(BaseLdapModule):
    """Module for deleting groups from Active Directory"""

    help_text = "Delete group from Active Directory"
    examples_text = """
    Delete a group by name
    `del_group "Test Group"`
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        group_name: str = Field(
            description="Name of the group to delete",
            arg_type=[ArgumentType.GROUP]
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
        # Search for group by name
        self.client.search(
            self.domain_dumper.root,
            f'(&(objectClass=group)(sAMAccountName={self.args.group_name}))',
            SUBTREE,
            attributes=['distinguishedName']
        )
        
        if len(self.client.entries) == 0:
            self.log.error(f"Group {self.args.group_name} not found")
            return

        group_dn = self.client.entries[0].distinguishedName.value

        # Delete the group
        if self.client.delete(group_dn):
            self.log.info(f"Group {self.args.group_name} deleted successfully")
        else:
            self.log.error(f"Failed to delete group {self.args.group_name}: {self.client.result}")