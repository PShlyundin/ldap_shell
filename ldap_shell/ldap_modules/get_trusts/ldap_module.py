import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel
from ldap_shell.ldap_modules.base_module import BaseLdapModule

DIRECTIONS = {0: 'DISABLED', 1: 'INBOUND', 2: 'OUTBOUND', 3: 'BIDIRECTIONAL'}
TYPES = {1: 'WINDOWS_NON_AD', 2: 'WINDOWS_AD', 3: 'MIT'}


class LdapShellModule(BaseLdapModule):
    """List domain trusts"""

    help_text = "List AD trusts and their direction"
    examples_text = """
    `get_trusts`
    ```
    [INFO] child.domain.local  BIDIRECTIONAL  WINDOWS_AD
    ```
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        pass

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=trustedDomain)',
            attributes=['name', 'trustPartner', 'trustDirection', 'trustType', 'trustAttributes', 'flatName'],
            paged_size=200
        )
        if not self.client.entries:
            self.log.info('No trusts found')
            return
        for entry in self.client.entries:
            partner = entry['trustPartner'].value or entry['name'].value
            direction = DIRECTIONS.get(int(entry['trustDirection'].value or 0), entry['trustDirection'].value)
            trust_type = TYPES.get(int(entry['trustType'].value or 0), entry['trustType'].value)
            self.log.info('%s  %s  %s', partner, direction, trust_type)
