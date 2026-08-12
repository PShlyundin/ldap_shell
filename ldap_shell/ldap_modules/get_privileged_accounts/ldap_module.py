import logging
from typing import Optional

from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule
from ldap_shell.utils.ldap_utils import LdapUtils

PRIVILEGED_GROUPS = (
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
    'DnsAdmins',
    'Group Policy Creator Owners',
)
IN_CHAIN = '1.2.840.113556.1.4.1941'


class LdapShellModule(BaseLdapModule):
    """List members of built-in privileged AD groups"""

    help_text = "List Domain Admins and other built-in privileged groups"
    examples_text = """
    `get_privileged_accounts`
    `get_privileged_accounts "Backup Operators"`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        group: Optional[str] = Field(
            None,
            description="One privileged group, or all if omitted",
            arg_type=ArgumentType.GROUP
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _dump_group(self, name: str):
        group_dn = LdapUtils.get_dn(self.client, self.domain_dumper, name)
        if not group_dn:
            self.log.info(f'=== {name} === not found')
            return
        self.client.search(
            self.domain_dumper.root,
            f'(memberof:{IN_CHAIN}:={LdapUtils.escape_filter(group_dn)})',
            attributes=['sAMAccountName', 'objectClass', 'userAccountControl'],
            paged_size=500
        )
        self.log.info(f'=== {name} === {len(self.client.entries)} member(s)')
        for entry in self.client.entries:
            classes = entry['objectClass'].values if 'objectClass' in entry else []
            kind = 'computer' if 'computer' in classes else 'group' if 'group' in classes else 'user'
            disabled = ''
            try:
                if int(entry['userAccountControl'].value or 0) & 2:
                    disabled = ' [disabled]'
            except Exception:
                pass
            self.log.info(f'  [{kind}] {entry["sAMAccountName"].value}{disabled}')

    def __call__(self):
        names = [self.args.group] if self.args.group else list(PRIVILEGED_GROUPS)
        for name in names:
            self._dump_group(name)
