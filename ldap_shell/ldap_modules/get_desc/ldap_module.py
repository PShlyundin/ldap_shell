import logging
from typing import Optional

from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils


class LdapShellModule(BaseLdapModule):
    """List user descriptions (often contain leftover passwords)."""

    help_text = "Dump non-empty user description attributes"
    examples_text = """
    `get_desc`
    `get_desc pass`
    Inline: `ldap_shell domain.local/user:pass get_desc`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        needle: Optional[str] = arg_field(
            None,
            description="Optional substring filter (case-insensitive)",
            arg_type=ArgumentType.STRING,
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        search_filter = '(&(objectCategory=person)(objectClass=user)(description=*))'
        if self.args.needle:
            search_filter = (
                f'(&(objectCategory=person)(objectClass=user)'
                f'(description=*{LdapUtils.escape_filter(self.args.needle)}*))'
            )
        self.client.search(
            self.domain_dumper.root,
            search_filter,
            attributes=['sAMAccountName', 'description'],
            paged_size=500,
        )
        if not self.client.entries:
            self.log.info('No user descriptions found')
            return
        needle = (self.args.needle or '').lower()
        shown = 0
        for entry in self.client.entries:
            desc = entry['description'].value if 'description' in entry else ''
            if desc is None:
                continue
            text = str(desc)
            if needle and needle not in text.lower():
                continue
            self.log.info(f'  {entry["sAMAccountName"].value}  {text}')
            shown += 1
        if not shown:
            self.log.info('No user descriptions matched')
        else:
            self.log.info(f'Found {shown} description(s)')
