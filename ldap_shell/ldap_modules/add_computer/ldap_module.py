import logging
from ldap3 import Connection, MODIFY_REPLACE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.security_utils import SecurityUtils
import re
import ldap3
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for adding new computer accounts to Active Directory"""
    
    help_text = "Add a new computer account to the domain"
    examples_text = """
    Example: Add computer with random password
    `add_computer SRV01$`
    ```
    [INFO] Starting TLS connection...
    [INFO] TLS established successfully
    [INFO] Computer SRV01$ added successfully to CN=SRV01,CN=Computers,DC=domain,DC=local! Password: "6nJHsGxnVX5MfPK"

    ```
    Example: Add computer with specific password
    `add_computer SRV01$ "P@ssw0rd123!"`
    ```
    [INFO] Computer SRV01$ added successfully to CN=SRV01,CN=Computers,DC=domain,DC=local! Password: "P@ssw0rd123!"
    ```
    Example: Add computer to specific OU
    `add_computer SRV01$ "P@ssw0rd123!" "OU=testComputers,DC=domain,DC=local"`
    ```
    [INFO] Computer SRV01$ added successfully to CN=SRV01,OU=testComputers,DC=domain,DC=local! Password: "P@ssw0rd123!"
    ```
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        computer_name: str = Field(
            description="Computer account name (must end with $)",
            arg_type=ArgumentType.STRING
        )
        password: Optional[str] = Field(
            None,
            description="Optional password (random if not specified)",
            arg_type=ArgumentType.STRING
        )
        target_dn: Optional[str] = Field(
            None,
            description="Target DN to add the computer to",
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
        # Validate computer name format
        if not self.args.computer_name.endswith('$'):
            self.args.computer_name = self.args.computer_name + '$'

        # Check secure connection
        if not self.client.tls_started and not self.client.server.ssl:
            self.log.info('Starting TLS connection...')
            if not self.client.start_tls():
                self.log.error("TLS setup failed")
                return
            self.log.info('TLS established successfully')

        # Generate password if not provided
        password = self.args.password or SecurityUtils.generate_password(15)
        computer_hostname = self.args.computer_name[:-1]
        
        try:
            # Проверка существования объекта
            search_filter = f'(sAMAccountName={escape_filter_chars(self.args.computer_name)})'
            if self.client.search(self.domain_dumper.root, search_filter, attributes=['distinguishedName']):
                existing_dns = [entry.entry_dn for entry in self.client.entries]
                if existing_dns:
                    self.log.error(f"Computer already exists in locations: {', '.join(existing_dns)}")
                    return

            computer_dn = f"CN={computer_hostname},{self.args.target_dn or f'CN=Computers,{self.domain_dumper.root}'}"

            # Prepare computer attributes
            domain = LdapUtils.get_domain_name(self.domain_dumper.root)
            spns = [
                f'HOST/{computer_hostname}',
                f'HOST/{computer_hostname}.{domain}',
                f'RestrictedKrbHost/{computer_hostname}',
                f'RestrictedKrbHost/{computer_hostname}.{domain}',
            ]
            # Create computer object
            result = self.client.add(
                computer_dn,
                ['top', 'person', 'organizationalPerson', 'user', 'computer'],
                {
                    'sAMAccountName': self.args.computer_name,
                    'userAccountControl': 4096,
                    'unicodePwd': f'"{password}"'.encode('utf-16-le'),
                    'servicePrincipalName': spns,
                    'objectCategory': f'CN=Computer,CN=Schema,CN=Configuration,{self.domain_dumper.root}',
                    'dnsHostName': f'{computer_hostname}.{domain}',
                    'name': computer_hostname,
                    'cn': computer_hostname,
                    'displayName': computer_hostname
                }
            )

            if result:
                self.log.info(f'Computer {self.args.computer_name} added successfully to {computer_dn}! Password: "{password}"')
            else:
                error_msg = self.client.result
                self.log.error(f'Failed to add computer: {error_msg}')

        except Exception as e:
            self.log.error(f'Error adding computer: {str(e)}')
            if 'insufficient access rights' in str(e).lower():
                self.log.info('Try relaying with LDAPS (--use-ldaps) or use elevated credentials')

