import logging
from ldap3 import Connection, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils

ACTIONS = {
    'add': MODIFY_ADD,
    'replace': MODIFY_REPLACE,
    'del': MODIFY_DELETE,
    'delete': MODIFY_DELETE,
}


class LdapShellModule(BaseLdapModule):
    """Add, replace or delete an arbitrary LDAP attribute"""

    help_text = "Modify an arbitrary attribute on a target object"
    examples_text = """
    `set_attr john description replace "compromised"`
    `set_attr john info add "note"`
    `set_attr john info del "note"`
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target sAMAccountName or DN",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER, ArgumentType.GROUP, ArgumentType.DN]
        )
        attribute: str = Field(
            description="Attribute name",
            arg_type=ArgumentType.STRING
        )
        action: str = Field(
            description="add / replace / del",
            arg_type=ArgumentType.ACTION
        )
        value: Optional[str] = Field(
            None,
            description="Attribute value (optional for delete-all)",
            arg_type=ArgumentType.STRING
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        action = (self.args.action or '').lower()
        if action not in ACTIONS:
            self.log.error('Invalid action %s. Use add/replace/del', self.args.action)
            return
        target_dn = LdapUtils.resolve_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error('Target not found: %s', self.args.target)
            return
        values = [self.args.value] if self.args.value is not None else []
        if action in ('add', 'replace') and not values:
            self.log.error('Value is required for %s', action)
            return
        ok = self.client.modify(target_dn, {self.args.attribute: [(ACTIONS[action], values)]})
        if ok:
            self.log.info('%s %s on %s', action, self.args.attribute, target_dn)
        else:
            self.log.error('Modify failed: %s', self.client.result)
