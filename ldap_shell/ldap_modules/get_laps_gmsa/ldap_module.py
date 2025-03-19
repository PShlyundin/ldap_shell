import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from Cryptodome.Hash import MD4
import binascii
from ldap_shell.utils.security_utils import MSDS_MANAGEDPASSWORD_BLOB
from impacket.dpapi_ng import EncryptedPasswordBlob, KeyIdentifier, compute_kek, create_sd, decrypt_plaintext, unwrap_cek
from impacket.dcerpc.v5 import transport, epm, gkdi
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc5652
import json
import re

class LdapShellModule(BaseLdapModule):
    """Module for retrieving LAPS and GMSA passwords"""
    
    help_text = "Retrieves LAPS and GMSA passwords associated with a given account (sAMAccountName) or for all. Supported LAPS 2.0"
    examples_text = """
    Get all LAPS and GMSA passwords
    `get_laps_gmsa`
    ```
    [INFO] [LAPS v2] SRV1$: 2ph97sJVNl8PB1
    [INFO] [LAPS v1] SRV2$: 1BP8lNVJs79hp2
    [INFO] No GMSA accounts found
    ```
    Get LAPS and GMSA passwords for machine account wks1$
    `get_laps_gmsa wks1$`
    ```
    [INFO] [LAPS v2] wks1$: 2ph97sJVNl8PB1
    ```
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: Optional[str] = Field(
            None,
            description="Computer account name (SAMAccountName)",
            arg_type=ArgumentType.COMPUTER
        )
    
    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __decrypt_laps_v2(self, encrypted_data):
        """Decrypt LAPS v2 password using Impacket implementation"""
        try:
            # Extract domain components
            domain, _, user = self.client.user.partition('\\')
            
            encrypted_blob = EncryptedPasswordBlob(encrypted_data)
            parsed_cms, remaining = decoder.decode(encrypted_blob['Blob'], asn1Spec=rfc5652.ContentInfo())
            enveloped_data = parsed_cms['content']
            
            # Extract key identifier
            parsed_enveloped, _ = decoder.decode(enveloped_data, asn1Spec=rfc5652.EnvelopedData())
            kek_info = parsed_enveloped['recipientInfos'][0]['kekri']
            kek_identifier = kek_info['kekid'] 
            key_params = KeyIdentifier(bytes(kek_identifier['keyIdentifier']))
            tmp,_ = decoder.decode(kek_identifier['other']['keyAttr'])
            sid = tmp['field-1'][0][0][1].asOctets().decode("utf-8") 
                        
            # Create Security Descriptor
            target_sd = create_sd(sid)
            
            # Setup RPC connection
            string_binding = epm.hept_map(self.client.server.host, gkdi.MSRPC_UUID_GKDI, protocol = 'ncacn_ip_tcp')
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            # Check password format for hash
            if ':' in self.client.password and re.match(r'[a-f0-9]{32}', self.client.password.lower().split(':')[1]):
                password_parts = self.client.password.split(':')
                if len(password_parts) == 2:
                    # If hash detected, use it for authentication
                    rpc_transport.set_credentials(
                        user,
                        '',  # Empty password
                        domain,
                        lmhash='aad3b435b51404eeaad3b435b51404ee',
                        nthash=password_parts[1]
                    )
            else:
                # If not hash, use regular password authentication
                rpc_transport.set_credentials(
                    user, 
                    self.client.password,
                    domain
                )
            
            dce = rpc_transport.get_dce_rpc()
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()
            dce.bind(gkdi.MSRPC_UUID_GKDI)
            
            # Get group key with correct parameters
            resp = gkdi.GkdiGetKey(
                dce,
                target_sd=target_sd,
                l0=key_params['L0Index'],
                l1=key_params['L1Index'],
                l2=key_params['L2Index'],
                root_key_id=key_params['RootKeyId']
            )
            
            gke = gkdi.GroupKeyEnvelope(b''.join(resp['pbbOut']))
            kek = compute_kek(gke, key_params)
            
            # Remove caching and related logic
            enc_content_parameter = bytes(parsed_enveloped['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters'])
            iv, _ = decoder.decode(enc_content_parameter)
            iv = bytes(iv[0])
            
            cek = unwrap_cek(kek, bytes(kek_info['encryptedKey']))
            return decrypt_plaintext(cek, iv, remaining)
            
        except Exception as e:
            self.log.error(f"Error decrypting LAPS v2: {str(e)}")
            return None

    def __check_laps_attributes(self):
        """Check available LAPS attributes in domain"""
        self.laps_attributes = []
        schema = self.client.server.schema
        
        # Check for attributes in schema
        if 'ms-mcs-admpwd' in schema.attribute_types:
            self.laps_attributes.append('ms-Mcs-AdmPwd')  # Case sensitive for LDAP
            
        if 'mslaps-encryptedpassword' in schema.attribute_types:
            self.laps_attributes.append('msLAPS-EncryptedPassword')
            
        return bool(self.laps_attributes)

    def __call__(self):
        # Determine available LAPS attributes
        if not self.__check_laps_attributes():
            self.log.error("LAPS is not configured in domain")
            return

        # Form search filter
        search_filter = '(objectClass=computer)'
        if self.args.target:
            search_filter = f'(&(objectClass=computer)(sAMAccountName={self.args.target}))'
        else:
            # Dynamically create filter based on available attributes
            attr_filters = []
            if 'ms-Mcs-AdmPwd' in self.laps_attributes:
                attr_filters.append('(ms-Mcs-AdmPwd=*)')
            if 'msLAPS-EncryptedPassword' in self.laps_attributes:
                attr_filters.append('(msLAPS-EncryptedPassword=*)')
            
            if not attr_filters:
                self.log.error("No available LAPS attributes for search")
                return
                
            search_filter = f'(&(objectClass=computer)(|{"".join(attr_filters)}))'

        # Execute search
        self.client.search(
            self.domain_dumper.root,
            search_filter,
            attributes=['sAMAccountName'] + self.laps_attributes
        )

        for entry in self.client.entries:
            hostname = entry['sAMAccountName'].value
            password = None
            
            # Process LAPS v1
            if 'ms-Mcs-AdmPwd' in entry:
                laps_v1 = entry['ms-Mcs-AdmPwd'].value
                if laps_v1:
                    self.log.info(f'[LAPS v1] {hostname}: {laps_v1}')
                    continue

            # Process LAPS v2
            if 'msLAPS-EncryptedPassword' in entry:
                laps_v2 = entry['msLAPS-EncryptedPassword'].value
                if laps_v2:
                    decrypted = self.__decrypt_laps_v2(laps_v2)
                    if decrypted:
                        password = json.loads(decrypted[:-18].decode('utf-16le'))['p']
                        self.log.info(f'[LAPS v2] {hostname}: {password}')
        
        # Process GMSA
        self.client.search(
            self.domain_dumper.root,
            '(objectClass=msDS-GroupManagedServiceAccount)',
            attributes=['sAMAccountName', 'msDS-ManagedPassword', 'msDS-GroupMSAMembership']
        )
        
        if not self.client.entries:
            self.log.info('No GMSA accounts found')
            return
            
        for entry in self.client.entries:
            if 'msDS-ManagedPassword' in entry:
                blob = MSDS_MANAGEDPASSWORD_BLOB(entry['msDS-ManagedPassword'].raw_values[0])
                ntlm_hash = MD4.new()
                ntlm_hash.update(blob['CurrentPassword'][:-2])
                passwd = binascii.hexlify(ntlm_hash.digest()).decode()
                self.log.info(f'[GMSA] {entry["sAMAccountName"].value}:::aad3b435b51404eeaad3b435b51404ee:{passwd}')

