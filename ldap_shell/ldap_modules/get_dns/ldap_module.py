import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils


class LdapShellModule(BaseLdapModule):
    """Dump AD-integrated DNS records"""

    help_text = "List AD-integrated DNS nodes (DomainDnsZones)"
    examples_text = """
    `get_dns`
    `get_dns dc01`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        name: Optional[str] = Field(
            None,
            description="Optional DNS node name filter",
            arg_type=ArgumentType.STRING
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        zone_base = f'DC=DomainDnsZones,{self.domain_dumper.root}'
        search_filter = '(objectClass=dnsNode)'
        if self.args.name:
            search_filter = f'(&(objectClass=dnsNode)(dc={LdapUtils.escape_filter(self.args.name)}))'
        if not self.client.search(
            zone_base,
            search_filter,
            attributes=['dc', 'dnsRecord', 'name'],
            paged_size=500
        ):
            self.log.error('DNS search failed: %s', self.client.result)
            return
        if not self.client.entries:
            self.log.info('No DNS nodes found under %s', zone_base)
            return
        for entry in self.client.entries:
            name = entry['dc'].value or entry['name'].value or entry.entry_dn
            records = entry['dnsRecord'].values if 'dnsRecord' in entry else []
            self.log.info('%s  records=%s', name, len(records))
