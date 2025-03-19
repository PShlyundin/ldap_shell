import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
import ldap3
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR

class LdapShellModule(BaseLdapModule):
    """Module for clearing RBCD permissions for a target computer"""
    
    help_text = "Clear RBCD permissions for a target computer"
    examples_text = """
    Example: clear RBCD permissions from pentest$ to DC01
    `clear_rbcd DC01$ pentest$`
    ```
    [INFO] RBCD permissions cleared successfully! pentest$ can no longer impersonate users on DC01$
    ```
 
    Example: clear all RBCD permissions to DC01$
    `clear_rbcd DC01$`
    ```
    [INFO] RBCD permissions cleared successfully!
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target computer account",
            arg_type=ArgumentType.COMPUTER
        )
        grantee: Optional[str] = Field(
            None,
            description="SAM account name of the target computer",
            arg_type=[ArgumentType.RBCD]
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
        target_sid = None
        # Get target information
        target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error(f'Target computer not found: {self.args.target}')
            return
        
        # Get target SID
        if self.args.grantee:
            target_sid = LdapUtils.get_sid(self.client, self.domain_dumper, self.args.grantee)

        # Get current security descriptor
        try:
            entry = self.client.search(
                target_dn,
                f'(sAMAccountName={self.args.target})',
                attributes=['msDS-AllowedToActOnBehalfOfOtherIdentity']
            )
            if not entry or len(self.client.entries) != 1:
                self.log.error('Failed to retrieve target AllowedToActOnBehalfOfOtherIdentity attribute')
                return
            
            sd_data = self.client.entries[0]['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values
            if target_sid:
                sd = SR_SECURITY_DESCRIPTOR(data=sd_data[0])
                for ace in sd['Dacl'].aces:
                    if ace['Ace']['Sid'].formatCanonical() == target_sid:
                        #Delete ACE
                        sd['Dacl'].aces.remove(ace)

                self.client.modify(target_dn, {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, [sd.getData()]]})

                if self.client.result['result'] == 0:
                    self.log.info(f'RBCD permissions cleared successfully! {self.args.grantee} can no longer impersonate users on {self.args.target}')
                else:
                    self.log.error(f'Failed to modify RBCD permissions: {self.client.result["description"]}')
            else:
                sd = LdapUtils.create_empty_sd()

                self.client.modify(target_dn,
                           {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, [sd.getData()]]})
                self.log.info(f'RBCD permissions cleared successfully!')

        except Exception as e:
            self.log.error(f'Error processing security descriptor: {str(e)}')
            return

