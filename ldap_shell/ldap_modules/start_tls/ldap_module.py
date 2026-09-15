import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel
from ldap_shell.ldap_modules.base_module import BaseLdapModule
from ldap_shell.session import ensure_tls


class LdapShellModule(BaseLdapModule):
    """Module for establishing TLS connection with LDAP server"""

    help_text = "Start TLS connection with LDAP server"
    examples_text = """
    TLS over LDAP is required for operations that need an encrypted channel
    (password change, Shadow Credentials / get_ntlm, add user/computer).
    If StartTLS is rejected by the DC, the session automatically switches to LDAPS.

    Example:
    `start_tls`
    ```
    [INFO] Sending StartTLS command...
    [INFO] StartTLS failed (...); falling back to LDAPS
    [INFO] Switched session to LDAPS
    ```
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        pass

    def __init__(self, args_dict: dict,
                 domain_dumper: domainDumper,
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        if getattr(self.client, 'tls_started', False) or getattr(self.client.server, 'ssl', False):
            self.log.info('TLS connection is already established')
            return
        if not ensure_tls(self.client, self.domain_dumper, self.log):
            return False
