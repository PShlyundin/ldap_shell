from typing import Optional
import re
from struct import pack, unpack
import logging
from ldap3 import SUBTREE
from ldap3.utils.conv import escape_filter_chars
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR, LDAP_SID, ACL
from ldap3.protocol.microsoft import security_descriptor_control

log = logging.getLogger('ldap-shell.utils')
_SID_NAME_CACHE = {}


class LdapUtils:
    @staticmethod
    def escape_filter(value: Optional[str]) -> str:
        """Escape a value for use inside an LDAP filter."""
        if value is None:
            return ''
        return escape_filter_chars(str(value))

    @staticmethod
    def sam_filter(name: str) -> str:
        """Build a sAMAccountName equality filter."""
        return f'(sAMAccountName={LdapUtils.escape_filter(name)})'

    @staticmethod
    def dn_filter(dn: str) -> str:
        """Build a distinguishedName equality filter."""
        return f'(distinguishedName={LdapUtils.escape_filter(dn)})'

    @staticmethod
    def looks_like_dn(value: str) -> bool:
        """Return True if value looks like a distinguished name."""
        if not value:
            return False
        return bool(re.search(r'(^|,)\s*[A-Za-z][A-Za-z0-9-]*\s*=', value))

    @staticmethod
    def resolve_dn(client, domain_dumper, name_or_dn: str) -> Optional[str]:
        """Resolve either a DN or a sAMAccountName to a DN."""
        if not name_or_dn:
            return None
        if LdapUtils.looks_like_dn(name_or_dn) and LdapUtils.check_dn(client, domain_dumper, name_or_dn):
            return name_or_dn
        return LdapUtils.get_dn(client, domain_dumper, name_or_dn)

    @staticmethod
    def get_dn(client, domain_dumper, name: str) -> Optional[str]:
        """Get DN with automatic computer account retry"""
        result = LdapUtils._search_with_retry(
            client,
            domain_dumper,
            name,
            attributes=['distinguishedName']
        )
        return result.entry_dn if result else None

    @staticmethod
    def get_attribute(client, domain_dumper, name: str, attribute: str) -> Optional[str]:
        """Get attribute with computer account auto-retry"""
        result = LdapUtils._search_with_retry(
            client,
            domain_dumper,
            name,
            attributes=[attribute]
        )
        return result[attribute].value if result else None

    @staticmethod
    def get_sid(client, domain_dumper, name: str) -> Optional[str]:
        """Get SID with computer account auto-retry"""
        result = LdapUtils._search_with_retry(
            client,
            domain_dumper,
            name,
            attributes=['objectSid']
        )
        return result['objectSid'].value if result else None

    @staticmethod
    def sid_to_user(client, domain_dumper, sid: str) -> str:
        """Convert SID to samAccountName. Results are cached for the process."""
        if not sid:
            return None
        cached = _SID_NAME_CACHE.get(sid)
        if cached is not None:
            return cached or None
        client.search(
            domain_dumper.root,
            f'(objectSid={LdapUtils.escape_filter(sid)})',
            attributes=['sAMAccountName']
        )
        name = client.entries[0]['sAMAccountName'].value if client.entries else ''
        _SID_NAME_CACHE[sid] = name
        return name or None

    @staticmethod
    def check_dn(client, domain_dumper, dn: str) -> bool:
        """Check if DN is valid"""
        client.search(
            domain_dumper.root,
            LdapUtils.dn_filter(dn),
            attributes=['objectClass']
        )
        return len(client.entries) > 0

    @staticmethod
    def get_domain_name(dn: str) -> str:
        """Get domain name from DN"""
        return re.sub(',DC=', '.', dn[dn.find('DC='):], flags=re.I)[3:]

    @staticmethod
    def get_info_by_dn(client, domain_dumper, dn: str) -> Optional[tuple]:
        """Get info by DN"""
        client.search(
            domain_dumper.root,
            LdapUtils.dn_filter(dn),
            attributes=['nTSecurityDescriptor', 'objectSid'],
            controls=security_descriptor_control(sdflags=0x04)
        )
        if len(client.entries) > 0:
            return client.entries[0]['nTSecurityDescriptor'].raw_values, client.entries[0]['objectSid'].value
        return None

    @staticmethod
    def get_name_from_dn(dn: str) -> Optional[str]:
        """Get name from DN"""
        return dn.split(',')[0].split('=')[1]

    @staticmethod
    def _search_with_retry(client, domain_dumper, name: str, attributes: list):
        client.search(
            domain_dumper.root,
            LdapUtils.sam_filter(name),
            attributes=attributes
        )
        if client.entries:
            return client.entries[0]

        if not name.endswith('$'):
            retry_name = f'{name}$'
            client.search(
                domain_dumper.root,
                LdapUtils.sam_filter(retry_name),
                attributes=attributes
            )
            if client.entries:
                log.debug('Auto-corrected computer account name: %s -> %s', name, retry_name)
                return client.entries[0]

        return None

    @staticmethod
    def paged_search(client, search_base, search_filter, attributes, paged_size=500):
        """Yield raw paged LDAP search entries."""
        generator = client.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=attributes,
            paged_size=paged_size,
            generator=True
        )
        for entry in generator:
            if entry.get('type') == 'searchResEntry':
                yield entry

    @staticmethod
    def bin_to_string(uuid):
        uuid1, uuid2, uuid3 = unpack('<LHH', uuid[:8])
        uuid4, uuid5, uuid6 = unpack('>HHL', uuid[8:16])
        return '%08X-%04X-%04X-%04X-%04X%08X' % (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6)

    @staticmethod
    def string_to_bin(uuid):
        matches = re.match(
            r"([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})",
            uuid)
        if not matches:
            raise ValueError(f'Invalid UUID: {uuid}')
        (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = [int(x, 16) for x in matches.groups()]
        uuid = pack('<LHH', uuid1, uuid2, uuid3)
        uuid += pack('>HHL', uuid4, uuid5, uuid6)
        return uuid

    @staticmethod
    def create_empty_sd():
        sd = SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 32772
        sd['OwnerSid'] = LDAP_SID()
        sd['OwnerSid'].fromCanonical('S-1-5-32-544')
        sd['GroupSid'] = b''
        sd['Sacl'] = b''
        acl = ACL()
        acl['AclRevision'] = 4
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = []
        sd['Dacl'] = acl
        return sd
