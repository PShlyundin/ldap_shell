import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.security_utils import SecurityUtils

class LdapShellModule(BaseLdapModule):
    """Module for changing a user's password"""
    
    help_text = "Attempt to change a given user's password. Requires LDAPS."
    examples_text = """
    Example: change password for john.doe
    `change_password john.doe "NewPassword123!"`
    ```
    [INFO] Successfully changed password for "john.doe"
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        user: str = Field(
            description="Target AD user",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )
        password: Optional[str] = Field(
            default=None,
            description="New password (optional - random if not specified)",
            arg_type=ArgumentType.STRING
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
        # Automatically start StartTLS if no secure connection exists
        if not self.client.tls_started and not self.client.server.ssl:
            self.log.info('Detected insecure connection, attempting to start StartTLS...')
            try:
                if not self.client.start_tls():
                    self.log.error("StartTLS failed")
                    return
                self.log.info('StartTLS successfully activated!')
            except Exception as e:
                self.log.error(f'Error starting StartTLS: {str(e)}')
                return

        user_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.user)
        if not user_dn:
            self.log.error(f'User not found: {self.args.user}')
            return

        # Generate password if not specified
        password = self.args.password or SecurityUtils.generate_password()

        try:
            # Use special method to change password
            self.client.extend.microsoft.modify_password(user_dn, password)
            
            if self.client.result['result'] == 0:
                self.log.info('Password changed successfully for "%s"! New password: "%s"', 
                            self.args.user, password)
            else:
                self.log.error('Password change failed: %s', self.client.result['description'])
                
        except Exception as e:
            self.log.error(f'Failed to change password: {str(e)}')
