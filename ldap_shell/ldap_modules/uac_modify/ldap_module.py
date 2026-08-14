import logging
from ldap3 import Connection, MODIFY_REPLACE
from ldapdomaindump import domainDumper
from pydantic import BaseModel
from typing import Optional, Union
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap3.utils.conv import escape_filter_chars

class LdapShellModule(BaseLdapModule):
    """Module for modifying UserAccountControl flags on user/computer accounts"""
    
    help_text = "Modify UserAccountControl flags on user or computer accounts"
    examples_text = """
    List current UAC flags for a user:
    `uac_modify john.doe list`
    ```
    [INFO] Current UserAccountControl flags for john.doe:
    [INFO] Value: 512 (0x200)
    [INFO] Active flags: NORMAL_ACCOUNT
    ```
    
    Add ACCOUNT_DISABLE flag (disable account):
    `uac_modify john.doe add ACCOUNT_DISABLE`
    or
    `uac_modify john.doe add 2`
    or
    `uac_modify john.doe add 0x2`
    ```
    [INFO] Added flag ACCOUNT_DISABLE (2) to user john.doe
    [INFO] New UserAccountControl value: 514 (0x202)
    ```
    
    Remove ACCOUNT_DISABLE flag (enable account):
    `uac_modify john.doe del ACCOUNT_DISABLE`
    ```
    [INFO] Removed flag ACCOUNT_DISABLE (2) from user john.doe
    [INFO] New UserAccountControl value: 512 (0x200)
    ```
    
    Add multiple flags at once:
    `uac_modify john.doe add DONT_REQUIRE_PREAUTH,PASSWD_NOTREQD`
    ```
    [INFO] Added flags DONT_REQUIRE_PREAUTH (4194304), PASSWD_NOTREQD (32) to user john.doe
    [INFO] New UserAccountControl value: 4194336 (0x400020)
    ```
    """
    module_type = "Misc"

    # UserAccountControl flags mapping
    UAC_FLAGS = {
        'SCRIPT': 0x0001,
        'ACCOUNT_DISABLE': 0x0002,
        'HOMEDIR_REQUIRED': 0x0008,
        'LOCKOUT': 0x0010,
        'PASSWD_NOTREQD': 0x0020,
        'PASSWD_CANT_CHANGE': 0x0040,
        'ENCRYPTED_TEXT_PWD_ALLOWED': 0x0080,
        'TEMP_DUPLICATE_ACCOUNT': 0x0100,
        'NORMAL_ACCOUNT': 0x0200,
        'INTERDOMAIN_TRUST_ACCOUNT': 0x0800,
        'WORKSTATION_TRUST_ACCOUNT': 0x1000,
        'SERVER_TRUST_ACCOUNT': 0x2000,
        'DONT_EXPIRE_PASSWORD': 0x10000,
        'MNS_LOGON_ACCOUNT': 0x20000,
        'SMARTCARD_REQUIRED': 0x40000,
        'TRUSTED_FOR_DELEGATION': 0x80000,
        'NOT_DELEGATED': 0x100000,
        'USE_DES_KEY_ONLY': 0x200000,
        'DONT_REQUIRE_PREAUTH': 0x400000,
        'PASSWORD_EXPIRED': 0x800000,
        'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x1000000,
        'PARTIAL_SECRETS_ACCOUNT': 0x04000000,
    }

    class ModuleArgs(BaseModel):
        samaccountname: str = arg_field(
            description="sAMAccountName of the target user/computer",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )
        action: str = arg_field(
            description="Action to perform: add, del, or list",
            arg_type=ArgumentType.ACTION
        )
        flags: Optional[str] = arg_field(
            default=None,
            description="UAC flags to modify (comma-separated for multiple flags). "
                       "Can be flag names, decimal values, or hex values (0x prefix)",
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

    def parse_flags(self, flags_str: str) -> list:
        """Parse flags string into list of integer values"""
        if not flags_str:
            return []
        
        flags = []
        for flag in flags_str.split(','):
            flag = flag.strip().upper()
            
            # Check if it's a named flag
            if flag in self.UAC_FLAGS:
                flags.append(self.UAC_FLAGS[flag])
            # Check if it's a hex value
            elif flag.startswith('0X'):
                try:
                    flags.append(int(flag, 16))
                except ValueError:
                    self.log.error(f"Invalid hex value: {flag}")
                    return []
            # Check if it's a decimal value
            else:
                try:
                    flags.append(int(flag))
                except ValueError:
                    self.log.error(f"Invalid flag value: {flag}")
                    return []
        
        return flags

    def get_flag_names(self, value: int) -> list:
        """Get list of flag names for a given UAC value"""
        active_flags = []
        for name, flag_value in self.UAC_FLAGS.items():
            if value & flag_value:
                active_flags.append(name)
        return active_flags

    def list_flags(self, target_dn: str, samaccountname: str):
        """List current UAC flags for the target"""
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
            active_flags = self.get_flag_names(current_uac)
            
            self.log.info(f"Current UserAccountControl flags for {samaccountname}:")
            self.log.info(f"Value: {current_uac} (0x{current_uac:x})")
            if active_flags:
                self.log.info(f"Active flags: {', '.join(active_flags)}")
            else:
                self.log.info("No active flags")

        except Exception as e:
            self.log.error(f'Error listing flags: {str(e)}')

    def modify_flags(self, target_dn: str, samaccountname: str, action: str, flags: list):
        """Modify UAC flags for the target"""
        try:
            # Get current userAccountControl
            entry = self.client.search(
                target_dn,
                '(objectClass=*)',
                attributes=['userAccountControl']
            )
            if not entry or len(self.client.entries) != 1:
                self.log.error('Failed to get userAccountControl attribute')
                return

            current_uac = self.client.entries[0]['userAccountControl'].value
            self.log.debug(f'Current userAccountControl: {current_uac} (0x{current_uac:x})')

            # Apply modifications
            new_uac = current_uac
            modified_flags = []
            
            for flag_value in flags:
                if action == 'add':
                    new_uac |= flag_value
                    # Find flag name for logging
                    flag_name = None
                    for name, value in self.UAC_FLAGS.items():
                        if value == flag_value:
                            flag_name = name
                            break
                    if not flag_name:
                        flag_name = f"0x{flag_value:x}"
                    modified_flags.append(f"{flag_name} ({flag_value})")
                elif action == 'del':
                    new_uac &= ~flag_value
                    # Find flag name for logging
                    flag_name = None
                    for name, value in self.UAC_FLAGS.items():
                        if value == flag_value:
                            flag_name = name
                            break
                    if not flag_name:
                        flag_name = f"0x{flag_value:x}"
                    modified_flags.append(f"{flag_name} ({flag_value})")

            self.log.debug(f'New userAccountControl: {new_uac} (0x{new_uac:x})')

            # Apply changes
            res = self.client.modify(
                target_dn,
                {'userAccountControl': [(MODIFY_REPLACE, [new_uac])]}
            )

            if res:
                action_text = "Added" if action == 'add' else "Removed"
                self.log.info(f'{action_text} flags {", ".join(modified_flags)} to/from user {samaccountname}')
                self.log.info(f'New UserAccountControl value: {new_uac} (0x{new_uac:x})')
            else:
                self.log.error(f'Failed to modify userAccountControl: {self.client.result["description"]}')

        except Exception as e:
            self.log.error(f'Error modifying userAccountControl: {str(e)}')

    def __call__(self):
        # Get target DN
        target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.samaccountname)
        if not target_dn:
            self.log.error(f'Target account not found: {self.args.samaccountname}')
            return

        # Validate action
        if self.args.action not in ['add', 'del', 'list']:
            self.log.error('Action must be one of: add, del, list')
            return

        # Handle list action
        if self.args.action == 'list':
            self.list_flags(target_dn, self.args.samaccountname)
            return

        # Validate flags for add/del actions
        if not self.args.flags:
            self.log.error('Flags parameter is required for add/del actions')
            return

        # Parse flags
        flags = self.parse_flags(self.args.flags)
        if not flags:
            self.log.error('No valid flags provided')
            return

        # Modify flags
        self.modify_flags(target_dn, self.args.samaccountname, self.args.action, flags)
