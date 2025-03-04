from typing import Optional

class LdapUtils:
    @staticmethod
    def get_dn(client, domain_dumper, name: str) -> Optional[str]:
        """Get DN by user/group name"""
        client.search(
            domain_dumper.root,
            f'(sAMAccountName={name})',
            attributes=['distinguishedName']
        )
        if client.entries:
            return client.entries[0].entry_dn
        return None

