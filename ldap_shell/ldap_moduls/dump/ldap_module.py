import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional, List
from ldap_shell.ldap_moduls.base_module import BaseLdapModule, ModuleArgument, ArgumentType

class DumpModuleArgs(BaseModel):
    """Model for describing module arguments"""
    output_dir: str = Field(..., description="Directory to save dump files")
    
    class Config:
        extra = "forbid"  # Disallow additional fields

class LdapShellModule(BaseLdapModule):
    """Module for dumping information from AD"""
    
    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = DumpModuleArgs(**args_dict)  # Automatic validation
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    @classmethod
    def get_arguments(cls) -> List[ModuleArgument]:
        return [
            ModuleArgument(
                name="output_dir",
                arg_type=ArgumentType.DIRECTORY,
                required=True,
                description="Directory to save dump files"
            )
        ]

    def __call__(self):
        self.log.info('Starting dump operation...')
        
        self.domain_dumper.config.basepath = self.args.output_dir
        
        self.domain_dumper.domainDump()
        self.log.info(f'Domain info dumped into {self.args.output_dir}')
