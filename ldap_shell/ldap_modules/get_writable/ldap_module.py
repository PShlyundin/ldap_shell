import logging
from ldap3 import Connection, SUBTREE
from ldap3.protocol.microsoft import security_descriptor_control
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils import current_sam
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR

INTERESTING = {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'WriteProperty', 'ExtendedRight'}


class LdapShellModule(BaseLdapModule):
    """Find objects whose DACL grants interesting write rights to the current user"""

    help_text = "Find objects writable by the current user (or a trustee)"
    examples_text = """
    `get_writable`
    `get_writable john`
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        trustee: Optional[str] = Field(
            None,
            description="Trustee to check (default: current user)",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER, ArgumentType.GROUP]
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        trustee = self.args.trustee or current_sam(self.client)
        sid = LdapUtils.get_sid(self.client, self.domain_dumper, trustee)
        if not sid:
            self.log.error(f'Trustee not found: {trustee}')
            return
        self.log.info(f'Searching interesting ACEs for {trustee} ({sid})')

        found = 0
        generator = self.client.extend.standard.paged_search(
            search_base=self.domain_dumper.root,
            search_filter='(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit))',
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'distinguishedName', 'nTSecurityDescriptor', 'objectClass'],
            controls=security_descriptor_control(sdflags=0x07),
            paged_size=300,
            generator=True
        )
        for entry in generator:
            if entry.get('type') != 'searchResEntry':
                continue
            raw = (entry.get('raw_attributes') or {}).get('nTSecurityDescriptor') or []
            if not raw:
                continue
            try:
                sd = SR_SECURITY_DESCRIPTOR(data=raw[0])
            except Exception:
                continue
            hits = []
            owner = ''
            try:
                owner = sd['OwnerSid'].formatCanonical() if sd['OwnerSid'] else ''
            except Exception:
                pass
            if owner == sid:
                hits.append('Owner')
            aces = getattr(sd.get('Dacl'), 'aces', None) if sd['Dacl'] else None
            if aces:
                for ace in aces:
                    try:
                        ace_sid = ace['Ace']['Sid'].formatCanonical()
                    except Exception:
                        continue
                    if ace_sid != sid:
                        continue
                    rights = [name for name in AceUtils.ace_rights(ace) if name in INTERESTING]
                    if rights:
                        object_type = ''
                        try:
                            object_type = AceUtils.object_type_name(ace['Ace']['ObjectType'])
                        except Exception:
                            pass
                        label = '+'.join(rights)
                        if object_type:
                            label += f'({object_type})'
                        hits.append(label)
            if not hits:
                continue
            attrs = entry.get('attributes') or {}
            name = attrs.get('sAMAccountName') or attrs.get('distinguishedName') or entry.get('dn')
            self.log.info(f'{name}  {", ".join(hits)}')
            found += 1
        if not found:
            self.log.info(f'No interesting writable objects found for {trustee}')
        else:
            self.log.info(f'Found {found} writable object(s)')
