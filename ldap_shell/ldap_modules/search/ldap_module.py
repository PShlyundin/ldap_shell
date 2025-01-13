import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional, List
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ModuleArgument, ArgumentType

class LdapShellModule(BaseLdapModule):
    """Module for dumping information from AD"""
    
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

        output_dir: Optional[str] = Field(
            None, # This argument is not required
            description="Directory to save dump files",
            arg_type=ArgumentType.DIRECTORY
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
        self.log.info('Starting dump operation...')
        
        if self.args.output_dir:
            self.domain_dumper.config.basepath = self.args.output_dir
        
        self.domain_dumper.domainDump()
        self.log.info(f'Domain info dumped into {self.args.output_dir}')
