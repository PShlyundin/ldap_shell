import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.security_utils import SecurityUtils
import re
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for adding new user accounts to Active Directory"""
    
    help_text = "Add a new user account to the domain"
    examples_text = """
    Example: Add user with random password
    `add_user john.doe`
    ```
    [INFO] Starting TLS connection...
    [INFO] TLS established successfully
    [INFO] User john.doe added successfully to CN=john.doe,CN=Users,DC=domain,DC=local! Password: "xK9mP2$vL5nR8@q"
    ```
    Example: Add user with specific password
    `add_user john.doe "P@ssw0rd123!"`
    ```
    [INFO] User john.doe added successfully to CN=john.doe,CN=Users,DC=domain,DC=local! Password: "P@ssw0rd123!"
    ```
    Example: Add user to specific OU
    `add_user john.doe "P@ssw0rd123!" "OU=testUsers,DC=domain,DC=local"`
    ```
    [INFO] User john.doe added successfully to CN=john.doe,OU=testUsers,DC=domain,DC=local! Password: "P@ssw0rd123!"
    ```
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        username: str = Field(
            description="Username for the new account",
            arg_type=ArgumentType.STRING
        )
        password: Optional[str] = Field(
            None,
            description="Optional password (random if not specified)",
            arg_type=ArgumentType.STRING
        )
        target_dn: Optional[str] = Field(
            None,
            description="Target DN to add the user to",
            arg_type=ArgumentType.DN
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
        # Check secure connection
        if not self.client.tls_started and not self.client.server.ssl:
            self.log.info('Starting TLS connection...')
            if not self.client.start_tls():
                self.log.error("TLS setup failed")
                return
            self.log.info('TLS established successfully')

        try:
            # Check if user exists
            search_filter = f'(sAMAccountName={escape_filter_chars(self.args.username)})'
            if self.client.search(self.domain_dumper.root, search_filter, attributes=['distinguishedName']):
                if self.client.entries:
                    self.log.error(f'Failed add user: user {self.args.username} already exists!')
                    return

            # Generate password if not provided
            password = self.args.password or SecurityUtils.generate_password(15)
            
            # Prepare user attributes
            new_user_dn = f'CN={self.args.username},{self.args.target_dn or f"CN=Users,{self.domain_dumper.root}"}'
            ucd = {
                'objectCategory': f'CN=Person,CN=Schema,CN=Configuration,{self.domain_dumper.root}',
                'distinguishedName': new_user_dn,
                'cn': self.args.username,
                'sn': self.args.username,
                'givenName': self.args.username,
                'displayName': self.args.username,
                'name': self.args.username,
                'userAccountControl': 512,
                'accountExpires': '0',
                'sAMAccountName': self.args.username,
                'unicodePwd': f'"{password}"'.encode('utf-16-le')
            }

            # Create user object
            result = self.client.add(
                new_user_dn,
                ['top', 'person', 'organizationalPerson', 'user'],
                ucd
            )

            if result:
                self.log.info(f'User {self.args.username} added successfully to {new_user_dn}! Password: "{password}"')
            else:
                error_msg = self.client.result
                self.log.error(f'Failed to add user: {error_msg}')

        except Exception as e:
            self.log.error(f'Error adding user: {str(e)}')
            if 'insufficient access rights' in str(e).lower():
                self.log.info('Try relaying with LDAPS (--use-ldaps) or use elevated credentials')

