import logging
from ldap3 import Connection, SUBTREE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from colorama import init, Fore, Style
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils

init()

# Interesting writable attributes -> (attack, ldap_shell command hint)
INTERESTING_ATTRS = {
    'msds-keycredentiallink': ('Shadow Credentials', 'get_ntlm {name}'),
    'msds-allowedtoactonbehalfofotheridentity': ('RBCD', 'set_rbcd {name} <grantee>'),
    'serviceprincipalname': ('Targeted Kerberoast', 'set_spn {name} add <SPN>'),
    'scriptpath': ('Logon script', 'set_attribute {name} scriptPath <path>'),
    'member': ('Add member', 'add_user_to_group <you> {name}'),
    'useraccountcontrol': ('UAC abuse (e.g. AS-REP roast)', 'uac_modify {name} add DONT_REQUIRE_PREAUTH'),
}


class LdapShellModule(BaseLdapModule):
    """Module for listing objects and attributes writable by the current user (effective rights)"""

    help_text = "List what the CURRENT account can write, using server-computed effective rights (allowedAttributesEffective / sDRightsEffective / allowedChildClassesEffective)."
    examples_text = """
    # get_writable

    Asks the DC which attributes/objects YOU can actually write, using the
    constructed effective-rights attributes. This already accounts for group
    nesting, inheritance and deny ACEs - no client-side DACL parsing needed.

    List everything the current user can write across the domain:
    `get_writable`
    ```
    [INFO] Objects writable by corp\\user:
     CN=m.petrov,CN=Users,DC=corp,DC=local
        write attrs : scriptPath, servicePrincipalName
        (owner/dacl): -
        => Targeted Kerberoast : set_spn m.petrov add <SPN>
    ```

    Effective rights for a single object:
    `get_writable m.petrov`

    Restrict object class scanned (user/computer/group), default is all three:
    `get_writable computer`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            None,
            description="A single object (name/DN) OR an objectClass keyword (user/computer/group). Empty = scan user+computer+group.",
            arg_type=[ArgumentType.STRING, ArgumentType.USER,
                      ArgumentType.COMPUTER, ArgumentType.GROUP]
        )

    ATTRS = ['distinguishedName', 'allowedAttributesEffective',
             'allowedChildClassesEffective', 'sDRightsEffective']

    def __init__(self, args_dict: dict,
                 domain_dumper: domainDumper,
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _sd_rights(self, value):
        try:
            v = int(value)
        except (TypeError, ValueError):
            return []
        out = []
        if v & 0x03:
            out.append('OWNER')
        if v & 0x04:
            out.append('DACL')
        if v & 0x08:
            out.append('SACL')
        return out

    def _emit(self, entry):
        """Return True if the entry has any effective write right, and print it."""
        def val(attr):
            try:
                return entry[attr].value
            except Exception:
                return None

        write_attrs = val('allowedAttributesEffective') or []
        if isinstance(write_attrs, (str, bytes)):
            write_attrs = [write_attrs]
        write_attrs = [a.decode() if isinstance(a, bytes) else str(a) for a in write_attrs]

        child = val('allowedChildClassesEffective') or []
        if isinstance(child, (str, bytes)):
            child = [child]
        child = [c.decode() if isinstance(c, bytes) else str(c) for c in child]

        sd_rights = self._sd_rights(val('sDRightsEffective'))

        if not (write_attrs or child or sd_rights):
            return False

        dn = entry['distinguishedName'].value
        name = LdapUtils.get_name_from_dn(dn)
        print(f" {Fore.WHITE}{Style.BRIGHT}{dn}{Style.RESET_ALL}")
        if write_attrs:
            print(f"    write attrs : {', '.join(write_attrs)}")
        if sd_rights:
            print(f"    {Fore.RED}{Style.BRIGHT}write SD    : {', '.join(sd_rights)}{Style.RESET_ALL}"
                  f"  => set_owner {name} / dacl_modify {name} <you> add GenericAll")
        if child:
            print(f"    create child: {', '.join(child)}")

        # attack hints for interesting attributes
        for a in write_attrs:
            hint = INTERESTING_ATTRS.get(a.lower())
            if hint:
                attack, cmd = hint
                print(f"    => {Fore.YELLOW}{attack}{Style.RESET_ALL} : "
                      f"{Fore.GREEN}{cmd.replace('{name}', name)}{Style.RESET_ALL}")
        print()
        return True

    def __call__(self):
        # Determine scope
        single_dn = None
        ldap_filter = "(|(objectClass=user)(objectClass=computer)(objectClass=group))"
        if self.args.target:
            t = self.args.target.lower()
            if t in ('user', 'computer', 'group', 'ou'):
                ldap_filter = ("(objectClass=organizationalUnit)" if t == 'ou'
                               else f"(objectClass={t})")
            else:
                # a specific object
                if self.args.target.lower().startswith(('cn=', 'ou=', 'dc=')):
                    single_dn = self.args.target
                else:
                    single_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.target)
                if not single_dn:
                    self.log.error(f'Object not found: {self.args.target}')
                    return

        self.log.info(f"Effective write rights for {self.client.user}:")
        print()

        try:
            if single_dn:
                self.client.search(single_dn, '(objectClass=*)',
                                   search_scope=SUBTREE, attributes=self.ATTRS)
            else:
                self.client.search(self.domain_dumper.root, ldap_filter,
                                   search_scope=SUBTREE, attributes=self.ATTRS,
                                   paged_size=1000)
        except Exception as e:
            self.log.error(f'Search failed: {e}')
            return

        count = 0
        for entry in self.client.entries:
            if self._emit(entry):
                count += 1

        if count == 0:
            self.log.info('No writable objects/attributes found for the current account.')
        else:
            self.log.info(f'{count} object(s) with effective write rights.')
