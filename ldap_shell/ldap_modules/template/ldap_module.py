import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType

class LdapShellModule(BaseLdapModule):
    """Module for retrieves all groups this user is a member of"""
    
    help_text = "Template module"
    examples_text = """
    Example 1
    `template`
    ```
    [INFO] Template module any output
    ```
    Example 2
    `template argument1 argument2`
    ```
    [INFO] Template module any output
    ```
    """
    module_type = "Get Info" # Get Info, Abuse ACL, Misc and Other.

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
                    ..., # This argument is required
                    description="Target AD user",
                    arg_type=ArgumentType.USER
                )
                group: Optional[str] = Field(
                    None, # This argument is not required
                    description="Optional AD group", 
                    arg_type=ArgumentType.GROUP
                )
        """

        example_arg: Optional[str] = Field(
            None,  # This argument is not required
            description="Example argument",
            arg_type=[ArgumentType.STRING, ArgumentType.USER, ArgumentType.GROUP, ArgumentType.COMPUTER]  # Changed to list of types
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
