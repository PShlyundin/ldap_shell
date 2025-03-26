import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
import ldap3

class LdapShellModule(BaseLdapModule):
    """Module for establishing TLS connection with LDAP server"""
    
    help_text = "Start TLS connection with LDAP server"
    examples_text = """
    TLS over LDAP is required for operations that require an encrypted channel, such as adding a user or computer.
    Example: Start TLS connection
    `start_tls`
    ```
    [INFO] Sending StartTLS command...
    [INFO] StartTLS established successfully!
    ```
    """
    module_type = "Connection"

    class ModuleArgs(BaseModel):
        pass  # No arguments needed for this module

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        try:
            # Проверяем, не установлено ли уже TLS соединение
            if not self.client.tls_started and not self.client.server.ssl:
                self.log.info('Sending StartTLS command...')
                if not self.client.start_tls():
                    self.log.error("StartTLS failed")
                    return
                self.log.info('StartTLS established successfully!')
            else:
                self.log.info('TLS connection is already established')
                
        except Exception as e:
            self.log.error(f'Error establishing TLS connection: {str(e)}')
