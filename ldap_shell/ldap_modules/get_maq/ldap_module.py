import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from ldap_shell.utils.ldap_utils import LdapUtils

class LdapShellModule(BaseLdapModule):
    """Retrieves Machine Account Quota and related information"""
    
    help_text = "Get Machine Account Quota and allowed users"
    examples_text = """
    The ms-DS-MachineAccountQuota attribute is stored on the domain object and not on users.
    To find out how many machine accounts a user can create, you need to subtract the number
    of machine accounts created by the user from the total number of machine accounts allowed.
    When a user creates a machine account, the SID of the user who created the machine account is written to the ms-DS-CreatorSID attribute.
    
    Get global Machine Account Quota
    `get_maq`
    ```
    [INFO] Global domain policy ms-DS-MachineAccountQuota=10
    ```
    Get Machine Account Quota for specific user
    `get_maq john.doe`
    ```
    [INFO] User john.doe have MachineAccountQuota=9
    ```
    """
    module_type = "Get Info" # Get Info, Abuse ACL, Misc and Other.

    class ModuleArgs(BaseModel):
        user: Optional[str] = Field(
            None,
            description="Check if specific user can create machine accounts",
            arg_type=ArgumentType.USER
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
        self.client.search(self.domain_dumper.root, '(objectClass=*)', attributes=['ms-DS-MachineAccountQuota'],
                controls=security_descriptor_control(sdflags=0x04))
        maq = self.client.entries[0].entry_attributes_as_dict['ms-DS-MachineAccountQuota'][0]
        if maq < 1:
            self.log.error(f"Global domain policy ms-DS-MachineAccountQuota={maq}")
            return
        if self.args.user:
            user_sid = LdapUtils.get_sid(self.client, self.domain_dumper, self.args.user)
            self.client.search(self.domain_dumper.root, f'(&(objectClass=computer)(mS-DS-CreatorSID={user_sid}))', attributes=['ms-ds-creatorsid'])
            user_machins = len(self.client.entries)
            self.log.info(f'User {self.args.user} have MachineAccountQuota={maq - user_machins}')
        else:
            self.log.info(f'Global domain policy ms-DS-MachineAccountQuota={maq}')
