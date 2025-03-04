import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType

class LdapShellModule(BaseLdapModule):
    """Module for retrieves all users in a group"""
    
    help_text = "Get all users in a group"
    examples_text = """
    Example 1
    `get_group_users group`
    Example 2
    `get_group_users group`
    """
    module_type = "Get Info" # Get Info, Abuse ACL, Misc and Other.

    class ModuleArgs(BaseModel):
        group: Optional[str] = Field(
            None,  # This argument is not required
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
        self.log.info(f"Template module called with args: {self.args}")
        # Get current user DN
        user_dn = self.client.extend.standard.who_am_i()
        if user_dn:
            self.log.info(f"Current user DN: {user_dn}")
        else:
            self.log.error("Failed to get current user DN")

