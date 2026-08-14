import logging
from ldap3 import Connection
from ldap3.protocol.microsoft import security_descriptor_control
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR


class LdapShellModule(BaseLdapModule):
    """Read and pretty-print the DACL of a target object"""

    help_text = "Show DACL entries for a user, computer, group or DN"
    examples_text = """
    `get_acl admin`
    ```
    [INFO] owner: S-1-5-21-...-512 (Domain Admins)
    [INFO] ALLOW john GenericAll
    [INFO] ALLOW Domain Admins GenericAll
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target object (sAMAccountName or DN)",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER, ArgumentType.GROUP, ArgumentType.DN]
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

        self.client.search(
            self.domain_dumper.root,
            LdapUtils.dn_filter(target_dn),
            attributes=['nTSecurityDescriptor', 'sAMAccountName'],
            controls=security_descriptor_control(sdflags=0x07)
        )
        if not self.client.entries:
            self.log.error(f'Failed to read security descriptor of {target_dn}')
            return

        raw = self.client.entries[0]['nTSecurityDescriptor'].raw_values
        if not raw:
            self.log.error('Empty security descriptor')
            return

        sd = SR_SECURITY_DESCRIPTOR(data=raw[0])
        owner = sd['OwnerSid'].formatCanonical() if sd['OwnerSid'] else None
        owner_name = LdapUtils.sid_to_user(self.client, self.domain_dumper, owner) if owner else None
        self.log.info(f'target: {target_dn}')
        owner_label = f'{owner} ({owner_name})' if owner_name else owner
        self.log.info(f'owner: {owner_label}')

        if not sd['Dacl'] or not getattr(sd['Dacl'], 'aces', None):
            self.log.info('No DACL entries')
            return

        for ace in sd['Dacl'].aces:
            try:
                sid = ace['Ace']['Sid'].formatCanonical()
            except Exception:
                continue
            trustee = LdapUtils.sid_to_user(self.client, self.domain_dumper, sid) or sid
            ace_type = ace.get('TypeName', 'ACE')
            allow = 'ALLOW' if 'ALLOWED' in str(ace_type).upper() else 'DENY'
            rights = ','.join(AceUtils.ace_rights(ace))
            object_type = ''
            try:
                object_type = AceUtils.object_type_name(ace['Ace']['ObjectType'])
            except Exception:
                pass
            extra = f' object={object_type}' if object_type else ''
            self.log.info(f'{allow} {trustee} {rights}{extra}')
