import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper

class LdapShellModule:
    def __init__(self, line: str,  
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log: None|logging.Logger=None):
        self.line = line
        self.log = log or logging.getLogger('ldap-shell.shell')
        self.domain_dumper = domain_dumper
        self.client = client

    def parse_args(self, line: str) -> str:
        # TODO: big logic parse args
        ...

    def __call__(self):
        params = self.parse_args(self.line)
        self.log.info('Dumping domain info...')
        self.domain_dumper.domainDump()
        self.log.info(f'Domain info dumped into lootdir {self.domain_dumper.config.basepath.resolve()}')
