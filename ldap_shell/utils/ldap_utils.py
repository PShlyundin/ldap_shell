from typing import Optional
import re
from struct import pack, unpack
import logging

class LdapUtils:
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
    def _search_with_retry(client, domain_dumper, name: str, attributes: list):
        # Первоначальный поиск
        client.search(
            domain_dumper.root,
            f'(sAMAccountName={name})',
            attributes=attributes
        )
        if client.entries:
            return client.entries[0]
        
        # Если не найдено, пробуем добавить $ для компьютерных аккаунтов
        if not name.endswith('$'):
            retry_name = f'{name}$'
            client.search(
                domain_dumper.root,
                f'(sAMAccountName={retry_name})',
                attributes=attributes
            )
            if client.entries:
                logging.debug(f'Auto-corrected computer account name: {name} -> {retry_name}')
                return client.entries[0]
        
        return None

    @staticmethod
    def bin_to_string(uuid):
        uuid1, uuid2, uuid3 = unpack('<LHH', uuid[:8])
        uuid4, uuid5, uuid6 = unpack('>HHL', uuid[8:16])
        return '%08X-%04X-%04X-%04X-%04X%08X' % (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6)

    @staticmethod
    def string_to_bin(uuid):
        # If a UUID in the 00000000-0000-0000-0000-000000000000 format, parse it as Variant 2 UUID
        # The first three components of the UUID are little-endian, and the last two are big-endian
        matches = re.match(
            r"([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})",
            uuid)
        (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = [int(x, 16) for x in matches.groups()]
        uuid = pack('<LHH', uuid1, uuid2, uuid3)
        uuid += pack('>HHL', uuid4, uuid5, uuid6)
        return uuid