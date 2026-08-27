import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType, arg_field
from ldap_shell.ldap_modules.set_dns.ldap_module import describe_dns_record
from ldap_shell.utils.ldap_utils import LdapUtils


class LdapShellModule(BaseLdapModule):
    """Dump AD-integrated DNS records"""

    help_text = "List AD-integrated DNS nodes and decode A/CNAME records"
    examples_text = """
    `get_dns`
    `get_dns dc01`
    Inline: `ldap_shell domain.local/user:pass get_dns wpad`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        name: Optional[str] = arg_field(
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
        search_filter = '(objectClass=dnsNode)'
        if self.args.name:
            search_filter = f'(&(objectClass=dnsNode)(dc={LdapUtils.escape_filter(self.args.name)}))'
        bases = [
            f'DC=DomainDnsZones,{self.domain_dumper.root}',
            f'DC=ForestDnsZones,{self.domain_dumper.root}',
        ]
        found = False
        for zone_base in bases:
            if not self.client.search(
                zone_base,
                search_filter,
                attributes=['dc', 'dnsRecord', 'name'],
                paged_size=500,
            ):
                continue
            if not self.client.entries:
                continue
            found = True
            for entry in self.client.entries:
                name = entry['dc'].value or entry['name'].value or entry.entry_dn
                raw_records = []
                if 'dnsRecord' in entry:
                    raw_records = entry['dnsRecord'].raw_values or entry['dnsRecord'].values
                parsed = [describe_dns_record(item) for item in raw_records]
                if parsed:
                    self.log.info(f'{name}  {", ".join(parsed)}')
                else:
                    self.log.info(f'{name}  records=0')
        if not found:
            self.log.info('No DNS nodes found under DomainDnsZones/ForestDnsZones')
