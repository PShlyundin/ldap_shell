import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional, List
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ModuleArgument, ArgumentType

class LdapShellModule(BaseLdapModule):
    """Module for dumping information from AD. This command will perform the same action as running the ldapdomaindump tool"""
    
    help_text = "Dumps the domain"
    examples_text = """
    Dump domain information to current directory
    `dump`
    Dump domain information to /tmp/
    `dump /tmp/`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
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
