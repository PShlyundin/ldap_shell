import logging
from typing import Optional, Set

from ldap3 import SUBTREE, Connection
from ldap3.protocol.microsoft import security_descriptor_control
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils import current_sam
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ldaptypes import LDAP_SID, SR_SECURITY_DESCRIPTOR

INTERESTING = {'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'WriteProperty', 'ExtendedRight'}
WELL_KNOWN = {'S-1-1-0', 'S-1-5-11'}
SEARCH_FILTER = (
    '(|(objectClass=user)(objectClass=computer)(objectClass=group)'
    '(objectClass=organizationalUnit)(objectClass=domain)'
    '(objectClass=groupPolicyContainer)(objectClass=container))'
)


def _sid_from_raw(raw) -> str:
    """Parse a binary SID to canonical form."""
    sid = LDAP_SID(data=raw)
    return sid.formatCanonical()


class LdapShellModule(BaseLdapModule):
    """Find objects whose DACL grants interesting write rights, with a next-command hint."""

    help_text = "Find writable objects and the shell command that abuses the ACE"
    examples_text = """
    `get_writable`
    `get_writable john`
    Inline: `ldap_shell domain.local/user:pass get_writable`
    MCP: `run` with command `get_writable`
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        trustee: Optional[str] = arg_field(
            None,
            description="Trustee to check (default: current user)",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER, ArgumentType.GROUP],
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _trustee_sids(self, trustee: str, sid: str) -> Set[str]:
        sids = {sid} | set(WELL_KNOWN)
        dn = LdapUtils.get_dn(self.client, self.domain_dumper, trustee)
        if not dn:
            return sids
        if not self.client.search(dn, '(objectClass=*)', attributes=['tokenGroups']):
            return sids
        raw_list = []
        if self.client.response:
            raw_list = self.client.response[0].get('raw_attributes', {}).get('tokenGroups') or []
        if not raw_list and self.client.entries and 'tokenGroups' in self.client.entries[0]:
            raw_list = self.client.entries[0]['tokenGroups'].raw_values
        for raw in raw_list:
            try:
                sids.add(_sid_from_raw(raw))
            except Exception:
                continue
        return sids

    def __call__(self):
        trustee = self.args.trustee or current_sam(self.client)
        sid = LdapUtils.get_sid(self.client, self.domain_dumper, trustee)
        if not sid:
            self.log.error(f'Trustee not found: {trustee}')
            return
        sids = self._trustee_sids(trustee, sid)
        self.log.info(f'Searching interesting ACEs for {trustee} ({sid}, {len(sids)} SIDs)')

        found = 0
        generator = self.client.extend.standard.paged_search(
            search_base=self.domain_dumper.root,
            search_filter=SEARCH_FILTER,
            search_scope=SUBTREE,
            attributes=['sAMAccountName', 'distinguishedName', 'displayName', 'nTSecurityDescriptor', 'objectClass'],
            controls=security_descriptor_control(sdflags=0x07),
            paged_size=300,
            generator=True,
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
            if owner in sids:
                hits.append(('Owner', ''))
            aces = getattr(sd.get('Dacl'), 'aces', None) if sd['Dacl'] else None
            if aces:
                for ace in aces:
                    try:
                        ace_sid = ace['Ace']['Sid'].formatCanonical()
                    except Exception:
                        continue
                    if ace_sid not in sids:
                        continue
                    rights = [name for name in AceUtils.ace_rights(ace) if name in INTERESTING]
                    if not rights:
                        continue
                    object_type = ''
                    try:
                        object_type = AceUtils.object_type_name(ace['Ace']['ObjectType'])
                    except Exception:
                        pass
                    hits.append(('+'.join(rights), object_type))
            if not hits:
                continue
            attrs = entry.get('attributes') or {}
            name = attrs.get('sAMAccountName') or attrs.get('displayName') or attrs.get('distinguishedName') or entry.get('dn')
            for rights, object_type in hits:
                label = rights
                if object_type:
                    label += f'({object_type})'
                hint = AceUtils.suggest_abuse(str(name), rights.split('+'), object_type)
                if hint:
                    self.log.info(f'{name}  {label}  → {hint}')
                else:
                    self.log.info(f'{name}  {label}')
            found += 1
        if not found:
            self.log.info(f'No interesting writable objects found for {trustee}')
        else:
            self.log.info(f'Found {found} writable object(s)')
