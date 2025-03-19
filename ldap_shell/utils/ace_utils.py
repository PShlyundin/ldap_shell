import ldap_shell.utils.ldaptypes as ldaptypes
from ldap_shell.utils.ldap_utils import LdapUtils

class AceUtils:
    @staticmethod
    def create_allow_ace(sid):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551  # Full control
        
        # Обрабатываем как строковый SID, так и бинарный формат
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