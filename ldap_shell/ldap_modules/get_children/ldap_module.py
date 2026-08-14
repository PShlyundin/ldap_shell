import logging
from ldap3 import Connection, LEVEL
from ldapdomaindump import domainDumper
from pydantic import BaseModel
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils


class LdapShellModule(BaseLdapModule):
    """List immediate children of an object or OU"""

    help_text = "List child objects of a DN or container"
    examples_text = """
    `get_children "OU=Servers,DC=domain,DC=local"`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: Optional[str] = arg_field(
            None,
            description="Parent DN or sAMAccountName (default: domain root)",
            arg_type=[ArgumentType.DN, ArgumentType.OU]
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        base = self.domain_dumper.root
        if self.args.target:
            base = LdapUtils.resolve_dn(self.client, self.domain_dumper, self.args.target) or self.args.target
        self.client.search(
            base,
            '(objectClass=*)',
            search_scope=LEVEL,
            attributes=['sAMAccountName', 'objectClass', 'distinguishedName'],
            paged_size=500
        )
        if not self.client.entries:
            self.log.info(f'No children under {base}')
            return
        for entry in self.client.entries:
            classes = entry['objectClass'].values if 'objectClass' in entry else []
            kind = classes[-1] if classes else 'object'
            name = entry['sAMAccountName'].value if 'sAMAccountName' in entry else entry.entry_dn
            self.log.info(f'[{kind}] {name}')
