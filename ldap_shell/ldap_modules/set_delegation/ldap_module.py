import logging

from ldap3 import MODIFY_REPLACE, Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils


class LdapShellModule(BaseLdapModule):
    """List, add or delete constrained delegation SPNs (msDS-AllowedToDelegateTo)."""

    help_text = "Manage constrained delegation SPNs on a user or computer"
    examples_text = """
    `set_delegation WEB01$ list`
    `set_delegation WEB01$ add cifs/dc.domain.local`
    `set_delegation WEB01$ del cifs/dc.domain.local`
    Inline: `ldap_shell domain.local/user:pass set_delegation WEB01$ add cifs/dc.domain.local`
    Protocol transition is a UAC flag: `uac_modify WEB01$ add TRUSTED_TO_AUTH_FOR_DELEGATION`
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = arg_field(
            description="Target user or computer",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER],
        )
        action: str = arg_field(
            description="Action: list, add or del",
            arg_type=ArgumentType.ACTION,
        )
        spn: str = arg_field(
            None,
            description="SPN to add or delete",
            arg_type=ArgumentType.STRING,
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        target_dn = LdapUtils.resolve_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error(f'Target not found: {self.args.target}')
            return

        if not self.client.search(target_dn, '(objectClass=*)', attributes=['msDS-AllowedToDelegateTo']):
            self.log.error(f'Failed to read msDS-AllowedToDelegateTo: {self.client.result}')
            return

        current = []
        if self.client.entries and 'msDS-AllowedToDelegateTo' in self.client.entries[0]:
            current = list(self.client.entries[0]['msDS-AllowedToDelegateTo'].values)

        action = (self.args.action or '').lower()
        if action == 'list':
            if not current:
                self.log.info(f'No constrained delegation SPNs on {self.args.target}')
                return
            self.log.info(f'Constrained delegation SPNs for {self.args.target}:')
            for spn in current:
                self.log.info(f'  {spn}')
            return

        if not self.args.spn:
            self.log.error('SPN is required for add/del')
            return

        if action == 'add':
            if self.args.spn in current:
                self.log.warning(f'SPN {self.args.spn} already present')
                return
            new_values = current + [self.args.spn]
        elif action == 'del':
            if self.args.spn not in current:
                self.log.warning(f'SPN {self.args.spn} is not present')
                return
            new_values = [item for item in current if item != self.args.spn]
        else:
            self.log.error('Invalid action. Use list/add/del')
            return

        if not self.client.modify(target_dn, {'msDS-AllowedToDelegateTo': [(MODIFY_REPLACE, new_values)]}):
            self.log.error(f'Failed to update msDS-AllowedToDelegateTo: {self.client.result}')
            return
        self.log.info(f'{action} {self.args.spn} on {self.args.target}')
