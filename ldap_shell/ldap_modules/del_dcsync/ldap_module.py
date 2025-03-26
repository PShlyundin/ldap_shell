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
from ldap_shell.utils.ldap_utils import LdapUtils
class LdapShellModule(BaseLdapModule):
    """Module to remove DS-Replication privileges from target"""
    
    help_text = "Remove DCSync rights from user/computer by deleting ACEs in domain DACL"
    examples_text = """
    Remove DCSync privileges from target user
    `del_dcsync CN=John Doe,CN=Users,DC=contoso,DC=com`
    ```
    [INFO] DCSync rights removed from John Doe
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            description="Target DN of user/computer to revoke rights",
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

        if not sd_data:
            self.log.error('Failed to retrieve domain security descriptor')
            return

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])
        dcsync_guids = {
            LdapUtils.string_to_bin('1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'),
            LdapUtils.string_to_bin('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'),
            LdapUtils.string_to_bin('89e95b76-444d-4c62-991a-0facbeda640c')
        }

        if len(sd_data) < 1:
            raise Exception(f'Check if target have write access to the domain object')
        else:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

        new_aces = []
        for ace in sd['Dacl'].aces:
            if ace['Ace']['Sid'].formatCanonical() == user_sid:
                try:
                    # Convert binary ObjectType to string
                    object_type = ace['Ace']['ObjectType']
                    if object_type in dcsync_guids:  # <-- direct binary data comparison
                        continue
                except AttributeError:
                    pass
            new_aces.append(ace)

        # Apply changes
        sd['Dacl'].aces = new_aces
        self.client.modify(
            target_dn,
            {'nTSecurityDescriptor': [MODIFY_REPLACE, [sd.getData()]]},
            controls=security_descriptor_control(sdflags=0x04)
        )

        if self.client.result['result'] == 0:
            user_name = LdapUtils.get_name_from_dn(user_dn)
            self.log.info(f'DCSync rights removed from {user_name}')
        else:
            self.process_error_response()

