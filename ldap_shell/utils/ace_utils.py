import ldap_shell.utils.ldaptypes as ldaptypes
from ldap_shell.utils.ldap_utils import LdapUtils

RIGHT_NAMES = (
    ('GenericAll', 0x000F01FF),
    ('GenericWrite', 0x00020028),
    ('WriteDacl', 0x00040000),
    ('WriteOwner', 0x00080000),
    ('WriteProperty', 0x00000020),
    ('ExtendedRight', 0x00000100),
    ('Delete', 0x00010000),
    ('ReadControl', 0x00020000),
)

OBJECT_GUIDS = {
    '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
    '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79': 'msDS-AllowedToActOnBehalfOfOtherIdentity',
    '5b47d60f-6090-40b2-9f37-2a4de88f3063': 'msDS-KeyCredentialLink',
    'bf9679c0-0de6-11d0-a285-00aa003049e2': 'Member',
    'f3a64788-5306-11d1-a9c5-0000f80367c1': 'Service-Principal-Name',
    '00fbf30c-91fe-11d1-aebc-0000f80367c1': 'altSecurityIdentities',
    'bf967a68-0de6-11d0-a285-00aa003049e2': 'userAccountControl',
    'bf967a0e-0de6-11d0-a285-00aa003049e2': 'pwdLastSet',
    'bf967a6a-0de6-11d0-a285-00aa003049e2': 'userParameters',
    'bf967acd-0de6-11d0-a285-00aa003049e2': 'sIDHistory',
    'bf967950-0de6-11d0-a285-00aa003049e2': 'description',
    '72e39547-7b18-11d1-adef-00c04fd8d5cd': 'dNSHostName',
    'e0fa1e8c-9b45-11d0-afdd-00c04fd930c9': 'dnsRecord',
    '800d94ad-9ab4-11d0-affe-0000f80367c1': 'msDS-AllowedToDelegateTo',
    'bf967a07-0de6-11d0-a285-00aa003049e2': 'scriptPath',
    'f30e3bbe-9ff0-11d1-b603-0000f80367c1': 'gPLink',
}

_HINTS = {
    'msDS-KeyCredentialLink': 'set_keycred {name} add',
    'msDS-AllowedToActOnBehalfOfOtherIdentity': 'set_rbcd {name} <grantee>',
    'Member': 'add_user_to_group <user> {name}',
    'Service-Principal-Name': 'set_spn {name} add <spn>',
    'User-Force-Change-Password': 'change_password {name}',
    'DS-Replication-Get-Changes': 'set_dcsync <trustee>',
    'DS-Replication-Get-Changes-All': 'set_dcsync <trustee>',
    'DS-Replication-Get-Changes-In-Filtered-Set': 'set_dcsync <trustee>',
    'altSecurityIdentities': 'set_attr {name} altSecurityIdentities add <value>',
    'msDS-AllowedToDelegateTo': 'set_delegation {name} add <spn>',
    'sIDHistory': 'add_sid_history {name} <sid>',
    'userAccountControl': 'uac_modify {name} add <flag>',
    'dnsRecord': 'set_dns {name} add A <ip>',
    'dNSHostName': 'set_attr {name} dNSHostName replace <fqdn>',
    'description': 'set_attr {name} description replace <text>',
    'gPLink': 'set_attr {name} gPLink replace <gpo>',
    'pwdLastSet': 'set_attr {name} pwdLastSet replace 0',
}


class AceUtils:
    @staticmethod
    def create_allow_ace(sid):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551  # Full control
        
        # Handle both string SID and binary format
        if isinstance(sid, str):
            acedata['Sid'] = ldaptypes.LDAP_SID()
            acedata['Sid'].fromCanonical(sid)
        else:
            acedata['Sid'] = sid
            
        nace['Ace'] = acedata
        return nace
    
    @staticmethod
    def create_empty_sd():
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 32772
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        # BUILTIN\Administrators
        sd['OwnerSid'].fromCanonical('S-1-5-32-544')
        sd['GroupSid'] = b''
        sd['Sacl'] = b''
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 4
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = []
        sd['Dacl'] = acl
        return sd

    @staticmethod
    def createACE(sid, object_type=None, access_mask=983551): # 983551 Full control
        nace = ldaptypes.ACE()
        nace['AceFlags'] = 0x00

        if object_type is None:
            acedata = ldaptypes.ACCESS_ALLOWED_ACE()
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        else:
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
            acedata['ObjectType'] = LdapUtils.string_to_bin(object_type)
            acedata['InheritedObjectType'] = b''
            acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT

        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = access_mask

        if type(sid) is str:
            acedata['Sid'] = ldaptypes.LDAP_SID()
            acedata['Sid'].fromCanonical(sid)
        else:
            acedata['Sid'] = sid

        nace['Ace'] = acedata
        return nace

    @staticmethod
    def describe_mask(mask_value: int):
        names = [name for name, bit in RIGHT_NAMES if mask_value & bit == bit or mask_value == bit]
        return names or [f'0x{int(mask_value):X}']

    @staticmethod
    def object_type_name(raw) -> str:
        if not raw:
            return ''
        try:
            guid = LdapUtils.bin_to_string(raw).lower()
        except Exception:
            return ''
        return OBJECT_GUIDS.get(guid, guid)

    @staticmethod
    def ace_rights(ace) -> list:
        try:
            mask = ace['Ace']['Mask']['Mask']
        except Exception:
            return []
        return AceUtils.describe_mask(int(mask))

    @staticmethod
    def suggest_abuse(name: str, rights, object_type: str = '') -> str:
        """Best-effort next shell command for a writable ACE."""
        if object_type and object_type in _HINTS:
            return _HINTS[object_type].format(name=name)
        joined = set(rights or [])
        if 'Owner' in joined or 'WriteOwner' in joined:
            return f'set_owner {name}'
        if 'WriteDacl' in joined:
            return f'dacl_modify {name} <grantee> add GenericAll'
        if 'GenericAll' in joined or 'GenericWrite' in joined:
            return f'set_attr {name} <attr> replace <value>'
        if 'WriteProperty' in joined:
            return f'set_attr {name} <attr> replace <value>'
        if 'ExtendedRight' in joined:
            return f'change_password {name}'
        return ''