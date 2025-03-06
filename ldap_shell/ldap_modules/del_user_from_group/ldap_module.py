import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
import ldap3
from ldap_shell.utils.ldap_utils import LdapUtils

class LdapShellModule(BaseLdapModule):
    """Module for deleting a user from a group"""
    
    help_text = "Delete a user from a group"
    examples_text = """
    Example: delete john.doe from Domain Admins group
    `del_user_from_group john.doe "Domain Admins"`
    ```
    [INFO] Successfully deleted "john.doe" from "Domain Admins"
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        user: str = Field(
            description="Target AD user",
            arg_type=[ArgumentType.USER, ArgumentType.GROUP]
        )
        group: str = Field(
            description="Target AD group",
            arg_type=ArgumentType.GROUP
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
        user_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.user)
        if not user_dn:
            self.log.error(f'User not found: {self.args.user}')
            return

        group_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.group)
        if not group_dn:
            self.log.error(f'Group not found: {self.args.group}')
            return

        try:
            res = self.client.modify(
                group_dn, 
                {'member': [(ldap3.MODIFY_DELETE, [user_dn])]}
            )
        except Exception as e:
            self.log.error(f'Failed to delete user: {str(e)}')
            return

        if res:
            self.log.info('Successfully deleted "%s" from "%s"', self.args.user, self.args.group)
            current_user = self.client.extend.standard.who_am_i().split(',')[0][3:]
            if current_user.lower() == self.args.user.lower():
                self.log.warning('You modified your own group membership. Re-login may be required.')
        else:
            self.log.error('Failed to delete user: %s', self.client.result['description'])
