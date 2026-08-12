import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR

UAS_UNCONSTRAINED = 0x80000
UAS_PROTOCOL = 0x1000000


class LdapShellModule(BaseLdapModule):
    """List unconstrained, constrained and resource-based constrained delegation"""

    help_text = "Show unconstrained, constrained and RBCD delegation"
    examples_text = """
    `get_delegation`
    `get_delegation DC01$`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            None,
            description="Optional sAMAccountName to filter",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        search_filter = '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'
        if self.args.target:
            search_filter = f'(&{LdapUtils.sam_filter(self.args.target)}{search_filter})'

        self.client.search(
            self.domain_dumper.root,
            search_filter,
            attributes=['sAMAccountName', 'userAccountControl', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity'],
            paged_size=500
        )
        if not self.client.entries:
            self.log.info('No delegation entries found')
            return

        for entry in self.client.entries:
            name = entry['sAMAccountName'].value
            uac = int(entry['userAccountControl'].value or 0)
            if uac & UAS_UNCONSTRAINED:
                self.log.info('[UNCONSTRAINED] %s', name)
            if uac & UAS_PROTOCOL:
                self.log.info('[PROTOCOL] %s', name)
            allowed = entry['msDS-AllowedToDelegateTo'].values if 'msDS-AllowedToDelegateTo' in entry else []
            if allowed:
                self.log.info('[CONSTRAINED] %s -> %s', name, ', '.join(allowed))
            raw = entry['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values if 'msDS-AllowedToActOnBehalfOfOtherIdentity' in entry else []
            if raw:
                try:
                    sd = SR_SECURITY_DESCRIPTOR(data=raw[0])
                    trustees = []
                    for ace in sd['Dacl'].aces:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        trustees.append(LdapUtils.sid_to_user(self.client, self.domain_dumper, sid) or sid)
                    self.log.info('[RBCD] %s <- %s', name, ', '.join(trustees) or 'empty')
                except Exception as exc:
                    self.log.info('[RBCD] %s (unparsed: %s)', name, exc)
