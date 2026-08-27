import logging
from ldap3 import Connection, MODIFY_DELETE, MODIFY_REPLACE
from ldapdomaindump import domainDumper
from pydantic import BaseModel
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils

SHOW_DELETED = ('1.2.840.113556.1.4.417', True, None)


class LdapShellModule(BaseLdapModule):
    """Restore a deleted AD object from the recycle bin"""

    help_text = "Restore a deleted user/computer/group from the AD recycle bin"
    examples_text = """
    `restore john.doe`
    `restore john.doe "OU=Users,DC=domain,DC=local"`
    """
    module_type = "Misc"

    class ModuleArgs(BaseModel):
        target: str = arg_field(
            description="sAMAccountName or CN of the deleted object",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER, ArgumentType.GROUP, ArgumentType.STRING]
        )
        target_dn: Optional[str] = arg_field(
            None,
            description="Optional new parent DN. Defaults to lastKnownParent",
            arg_type=ArgumentType.DN
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        escaped = LdapUtils.escape_filter(self.args.target)
        search_filter = f'(&(isDeleted=TRUE)(|(sAMAccountName={escaped})(cn={escaped})(name={escaped})))'
        self.client.search(
            self.domain_dumper.root,
            search_filter,
            attributes=['distinguishedName', 'lastKnownParent', 'sAMAccountName', 'cn'],
            controls=[SHOW_DELETED]
        )
        if not self.client.entries:
            self.log.error(f'Deleted object not found: {self.args.target}')
            return
        entry = self.client.entries[0]
        deleted_dn = entry.entry_dn
        parent = self.args.target_dn or entry['lastKnownParent'].value
        if not parent:
            self.log.error('No lastKnownParent and no target_dn provided')
            return
        name = entry['cn'].value or entry['sAMAccountName'].value or self.args.target
        new_dn = f'CN={name},{parent}'
        ok = self.client.modify(deleted_dn, {
            'isDeleted': [(MODIFY_DELETE, [])],
            'distinguishedName': [(MODIFY_REPLACE, [new_dn])],
        })
        if ok:
            self.log.info(f'Restored {deleted_dn} -> {new_dn}')
        else:
            self.log.error(f'Restore failed: {self.client.result}')
