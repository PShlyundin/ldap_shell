import logging
from typing import Optional

from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule
from ldap_shell.utils.ldap_utils import LdapUtils

DONT_REQUIRE_PREAUTH = 0x400000


class LdapShellModule(BaseLdapModule):
    """Find users with DONT_REQUIRE_PREAUTH set (AS-REP roastable)"""

    help_text = "Find users vulnerable to AS-REP roasting"
    examples_text = """
    `get_asreproast`
    `get_asreproast john.doe`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            None,
            description="Optional sAMAccountName to check",
            arg_type=ArgumentType.USER
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        search_filter = (
            f'(&(objectCategory=person)(objectClass=user)'
            f'(userAccountControl:1.2.840.113556.1.4.803:={DONT_REQUIRE_PREAUTH}))'
        )
        if self.args.target:
            search_filter = f'(&{search_filter}{LdapUtils.sam_filter(self.args.target)})'

        self.client.search(
            self.domain_dumper.root,
            search_filter,
            attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl', 'pwdLastSet'],
            paged_size=500
        )
        if not self.client.entries:
            self.log.info('No AS-REP roastable users found')
            return
        self.log.info('Found %s AS-REP roastable user(s):', len(self.client.entries))
        for entry in self.client.entries:
            self.log.info('  %s  %s', entry['sAMAccountName'].value, entry.entry_dn)
