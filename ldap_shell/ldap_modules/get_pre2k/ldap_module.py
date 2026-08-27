import logging
from typing import Optional

from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils

WORKSTATION_TRUST = 4096


class LdapShellModule(BaseLdapModule):
    """Find computer accounts that likely still have the default pre-Win2k password."""

    help_text = "Find unused computer accounts (pre2k: password often equals the short name)"
    examples_text = """
    `get_pre2k`
    `get_pre2k WS01$`
    Inline: `ldap_shell domain.local/user:pass get_pre2k`
    Password to try: sAMAccountName without the trailing $.
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: Optional[str] = arg_field(
            None,
            description="Optional computer sAMAccountName",
            arg_type=ArgumentType.COMPUTER,
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        search_filter = (
            f'(&(objectClass=computer)'
            f'(userAccountControl:1.2.840.113556.1.4.803:={WORKSTATION_TRUST})'
            f'(|(logonCount=0)(!(lastLogon=*))(lastLogon=0)))'
        )
        if self.args.target:
            search_filter = f'(&{search_filter}{LdapUtils.sam_filter(self.args.target)})'
        self.client.search(
            self.domain_dumper.root,
            search_filter,
            attributes=['sAMAccountName', 'logonCount', 'lastLogon', 'whenCreated'],
            paged_size=500,
        )
        if not self.client.entries:
            self.log.info('No unused/pre2k computer accounts found')
            return
        self.log.info(f'Found {len(self.client.entries)} unused computer account(s):')
        for entry in self.client.entries:
            sam = entry['sAMAccountName'].value or ''
            guess = sam[:-1] if sam.endswith('$') else sam
            created = entry['whenCreated'].value if 'whenCreated' in entry else '-'
            self.log.info(f'  {sam}  created={created}  try password {guess!r}')
