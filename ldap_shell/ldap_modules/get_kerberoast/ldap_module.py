import logging
from typing import Optional

from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils

ACCOUNTDISABLE = 2


class LdapShellModule(BaseLdapModule):
    """Find user accounts with an SPN (Kerberoastable)."""

    help_text = "Find users with a servicePrincipalName (Kerberoastable)"
    examples_text = """
    `get_kerberoast`
    `get_kerberoast sql.svc`
    Inline: `ldap_shell domain.local/user:pass get_kerberoast`
    MCP: `run` with command `get_kerberoast`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: Optional[str] = arg_field(
            None,
            description="Optional sAMAccountName to check",
            arg_type=ArgumentType.USER,
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
        self.log.info(f'Found {len(self.client.entries)} Kerberoastable user(s):')
        for entry in self.client.entries:
            spns = entry['servicePrincipalName'].values if 'servicePrincipalName' in entry else []
            self.log.info(f'  {entry["sAMAccountName"].value}  {", ".join(spns)}')
