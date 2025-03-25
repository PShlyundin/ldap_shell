import datetime
import logging
import random
import socket
import struct
from binascii import unhexlify, hexlify
from typing import Optional

from Cryptodome.Cipher import DES
from Cryptodome.Hash import MD4
from pyasn1.codec.der import encoder, decoder
from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import noValue

import ldap_shell.utils.nt_errors as nt_errors
from ldap_shell.krb5 import constants
from ldap_shell.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, seq_set, seq_set_iter, KERB_ERROR_DATA, KRB_ERROR, \
    AS_REP, METHOD_DATA, ETYPE_INFO2, ETYPE_INFO, PA_ENC_TS_ENC, EncryptedData, EncASRepPart, TGS_REP, AP_REQ, \
    Authenticator, TGS_REQ, EncTGSRepPart
from ldap_shell.krb5.crypto import _enctype_table, Key, InvalidChecksum
from ldap_shell.krb5.types import Principal, KerberosTime, Ticket
from ldap_shell.utils import b

log = logging.getLogger('ldap-shell.kerberos')

try:
    rand = random.SystemRandom()
except NotImplementedError:
    rand = random
    log.warning('Failed to initialize system random, using from stdlib')
    log.debug('Details:', exc_info=True)


class SessionError(Exception):
    """
    This is the exception every client should catch regardless of the underlying
    SMB version used. We'll take care of that. NETBIOS exceptions are NOT included,
    since all SMB versions share the same NETBIOS instances.
    """

    def __init__(self, error=0, packet=None):
        Exception.__init__(self)
        self.error = error
        self.packet = packet

    def getErrorCode(self):
        return self.error

    def getErrorPacket(self):
        return self.packet

    def getErrorString(self):
        return nt_errors.ERROR_MESSAGES[self.error]

    def __str__(self):
        if self.error in nt_errors.ERROR_MESSAGES:
            return f'SMB SessionError: {nt_errors.ERROR_MESSAGES[self.error]} (0x{self.error:x})'
        else:
            return f'SMB SessionError: 0x{self.error:x}'


class KerberosError(SessionError):
    """
    This is the exception every client should catch regardless of the underlying
    SMB version used. We'll take care of that. NETBIOS exceptions are NOT included,
    since all SMB versions share the same NETBIOS instances.
    """

    def __init__(self, error=0, packet=None):
        SessionError.__init__(self)
        self.error = error
        self.packet = packet
        if packet is not None:
            self.error = self.packet['error-code']

    def getErrorCode(self):
        return self.error

    def getErrorPacket(self):
        return self.packet

    def getErrorString(self):
        return constants.ERROR_MESSAGES[self.error]

    def __str__(self):
        retString = f'Kerberos SessionError: {constants.ERROR_MESSAGES[self.error]}({self.error})'
        try:
            # Let's try to get the NT ERROR, if not, we quit and give the general one
            if self.error == constants.ErrorCodes.KRB_ERR_GENERIC.value:
                eData = decoder.decode(self.packet['e-data'], asn1Spec=KERB_ERROR_DATA())[0]
                nt_error = struct.unpack('<L', eData['data-value'].asOctets()[:4])[0]
                retString += f'\nNT ERROR: {nt_errors.ERROR_MESSAGES[nt_error]}({nt_error})'
        except:
            pass

        return retString


class SessionKeyDecryptionError(Exception):
    """
    Exception risen when we fail to decrypt a session key within an AS-REP
    message.
    It provides context information such as full AS-REP message but also the
    cipher, key and cipherText used when the error occurred.
    """

    def __init__(self, message, asRep, cipher, key, cipherText):
        self.message = message
        self.asRep = asRep
        self.cipher = cipher
        self.key = key
        self.cipherText = cipherText

    def __str__(self):
        return "SessionKeyDecryptionError: %s" % self.message


def __expand_DES_key(key):
    # Expand the key from a 7-byte password key into a 8-byte DES key
    if not isinstance(key, bytes):
        key = bytes(key)
    key = bytearray(key[:7]).ljust(7, b'\x00')
    s = bytearray()
    s.append(((key[0] >> 1) & 0x7f) << 1)
    s.append(((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1)
    s.append(((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1)
    s.append(((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1)
    s.append(((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1)
    s.append(((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1)
    s.append(((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1)
    s.append((key[6] & 0x7f) << 1)
    return bytes(s)


def __DES_block(key, msg):
    cipher = DES.new(__expand_DES_key(key), DES.MODE_ECB)
    return cipher.encrypt(msg)


KNOWN_DES_INPUT = b"KGS!@#$%"


def compute_lmhash(password):
    # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
    password = password.upper()
    lmhash = __DES_block(b(password[:7]), KNOWN_DES_INPUT)
    lmhash += __DES_block(b(password[7:14]), KNOWN_DES_INPUT)
    return lmhash


def compute_nthash(password):
    # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
    try:
        password = str(password).encode('utf_16le')
    except UnicodeDecodeError:
        import sys
        password = password.decode(sys.getfilesystemencoding()).encode('utf_16le')

    hash = MD4.new()
    hash.update(password)
    return hash.digest()


def sendReceive(data, host, kdcHost):
    if kdcHost is None:
        targetHost = host
    else:
        targetHost = kdcHost

    messageLen = struct.pack('!i', len(data))

    log.debug('Trying to connect to KDC at %s' % targetHost)
    try:
        af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, 88, 0, socket.SOCK_STREAM)[0]
        s = socket.socket(af, socktype, proto)
        s.connect(sa)
    except socket.error as e:
        raise socket.error("Connection error (%s:%s)" % (targetHost, 88), e)

    s.sendall(messageLen + data)

    recvDataLen = struct.unpack('!i', s.recv(4))[0]

    r = s.recv(recvDataLen)
    while len(r) < recvDataLen:
        r += s.recv(recvDataLen - len(r))

    try:
        krbError = KerberosError(packet=decoder.decode(r, asn1Spec=KRB_ERROR())[0])
    except:
        return r

    if krbError.getErrorCode() != constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
        raise krbError

    return r


def getKerberosTGT(clientName, password, domain, lmhash, nthash,
                   aesKey: Optional[str] = '', kdcHost=None, requestPAC=True):
    # Convert to binary form, just in case we're receiving strings
    if isinstance(lmhash, str):
        try:
            lmhash = unhexlify(lmhash)
        except TypeError:
            pass
    if isinstance(nthash, str):
        try:
            nthash = unhexlify(nthash)
        except TypeError:
            pass
    if isinstance(aesKey, str):
        try:
            aesKey = unhexlify(aesKey)
        except TypeError:
            pass

    asReq = AS_REQ()

    domain = domain.upper()
    serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

    pacRequest = KERB_PA_PAC_REQUEST()
    pacRequest['include-pac'] = requestPAC
    encodedPacRequest = encoder.encode(pacRequest)

    asReq['pvno'] = 5
    asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

    asReq['padata'] = noValue
    asReq['padata'][0] = noValue
    asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    asReq['padata'][0]['padata-value'] = encodedPacRequest

    reqBody = seq_set(asReq, 'req-body')

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.proxiable.value)
    reqBody['kdc-options'] = constants.encodeFlags(opts)

    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    seq_set(reqBody, 'cname', clientName.components_to_asn1)

    if domain == '':
        raise Exception('Empty Domain not allowed in Kerberos')

    reqBody['realm'] = domain

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['rtime'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] = rand.getrandbits(31)

    # Yes.. this shouldn't happen but it's inherited from the past
    if aesKey is None:
        aesKey = b''

    if nthash == b'':
        # This is still confusing. I thought KDC_ERR_ETYPE_NOSUPP was enough,
        # but I found some systems that accepts all ciphers, and trigger an error
        # when requesting subsequent TGS :(. More research needed.
        # So, in order to support more than one cypher, I'm setting aes first
        # since most of the systems would accept it. If we're lucky and
        # KDC_ERR_ETYPE_NOSUPP is returned, we will later try rc4.
        if aesKey != b'':
            if len(aesKey) == 32:
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),)
            else:
                supportedCiphers = (int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
        else:
            supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),)
    else:
        # We have hashes to try, only way is to request RC4 only
        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

    seq_set_iter(reqBody, 'etype', supportedCiphers)

    message = encoder.encode(asReq)

    try:
        r = sendReceive(message, domain, kdcHost)
    except KerberosError as e:
        if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
            if supportedCiphers[0] in (constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value,
                                       constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value) and aesKey == b'':
                supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, kdcHost)
            else:
                raise
        else:
            raise

            # This should be the PREAUTH_FAILED packet or the actual TGT if the target principal has the
    # 'Do not require Kerberos preauthentication' set
    preAuth = True
    try:
        asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
    except:
        # Most of the times we shouldn't be here, is this a TGT?
        asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        # Yes
        preAuth = False

    encryptionTypesData = dict()
    salt = ''
    if preAuth is False:
        # In theory, we should have the right credentials for the etype specified before.
        methods = asRep['padata']
        encryptionTypesData[supportedCiphers[0]] = salt  # handle RC4 fallback, we don't need any salt
        tgt = r
    else:
        methods = decoder.decode(asRep['e-data'], asn1Spec=METHOD_DATA())[0]

    for method in methods:
        if method['padata-type'] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
            etypes2 = decoder.decode(method['padata-value'], asn1Spec=ETYPE_INFO2())[0]
            for etype2 in etypes2:
                try:
                    if etype2['salt'] is None or etype2['salt'].hasValue() is False:
                        salt = ''
                    else:
                        salt = etype2['salt'].prettyPrint()
                except PyAsn1Error:
                    salt = ''

                encryptionTypesData[etype2['etype']] = b(salt)
        elif method['padata-type'] == constants.PreAuthenticationDataTypes.PA_ETYPE_INFO.value:
            etypes = decoder.decode(method['padata-value'], asn1Spec=ETYPE_INFO())[0]
            for etype in etypes:
                try:
                    if etype['salt'] is None or etype['salt'].hasValue() is False:
                        salt = ''
                    else:
                        salt = etype['salt'].prettyPrint()
                except PyAsn1Error:
                    salt = ''

                encryptionTypesData[etype['etype']] = b(salt)

    enctype = supportedCiphers[0]

    cipher = _enctype_table[enctype]

    # Pass the hash/aes key :P
    if nthash != b'' and (isinstance(nthash, bytes) and nthash != b''):
        key = Key(cipher.enctype, nthash)
    elif aesKey != b'':
        key = Key(cipher.enctype, aesKey)
    else:
        key = cipher.string_to_key(password, encryptionTypesData[enctype], None)

    tgt = None
    if preAuth is True:
        if enctype in encryptionTypesData is False:
            raise Exception('No Encryption Data Available!')

        # Let's build the timestamp
        timeStamp = PA_ENC_TS_ENC()

        now = datetime.datetime.utcnow()
        timeStamp['patimestamp'] = KerberosTime.to_asn1(now)
        timeStamp['pausec'] = now.microsecond

        # Encrypt the shyte
        encodedTimeStamp = encoder.encode(timeStamp)

        # Key Usage 1
        # AS-REQ PA-ENC-TIMESTAMP padata timestamp, encrypted with the
        # client key (Section 5.2.7.2)
        encriptedTimeStamp = cipher.encrypt(key, 1, encodedTimeStamp, None)

        encryptedData = EncryptedData()
        encryptedData['etype'] = cipher.enctype
        encryptedData['cipher'] = encriptedTimeStamp
        encodedEncryptedData = encoder.encode(encryptedData)

        # Now prepare the new AS_REQ again with the PADATA
        # ToDo: cannot we reuse the previous one?
        asReq = AS_REQ()

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
        asReq['padata'][0]['padata-value'] = encodedEncryptedData

        asReq['padata'][1] = noValue
        asReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][1]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        reqBody['realm'] = domain

        now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = rand.getrandbits(31)

        seq_set_iter(reqBody, 'etype', ((int(cipher.enctype),)))

        try:
            tgt = sendReceive(encoder.encode(asReq), domain, kdcHost)
        except Exception as e:
            if str(e).find('KDC_ERR_ETYPE_NOSUPP') >= 0:
                if lmhash == b'' and nthash == b'' and (aesKey == b'' or aesKey is None):
                    lmhash = compute_lmhash(password)
                    nthash = compute_nthash(password)
                    return getKerberosTGT(clientName, password, domain, lmhash, nthash, aesKey, kdcHost, requestPAC)
            raise

        asRep = decoder.decode(tgt, asn1Spec=AS_REP())[0]

    # So, we have the TGT, now extract the new session key and finish
    cipherText = asRep['enc-part']['cipher']

    if preAuth is False:
        # Let's output the TGT enc-part/cipher in John format, in case somebody wants to use it.
        log.debug('$krb5asrep$%d$%s@%s:%s$%s' % (
            asRep['enc-part']['etype'], clientName, domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]),
            hexlify(asRep['enc-part']['cipher'].asOctets()[16:])))
    # Key Usage 3
    # AS-REP encrypted part (includes TGS session key or
    # application session key), encrypted with the client key
    # (Section 5.4.2)
    try:
        plainText = cipher.decrypt(key, 3, cipherText)
    except InvalidChecksum as e:
        # probably bad password if preauth is disabled
        if preAuth is False:
            error_msg = "failed to decrypt session key: %s" % str(e)
            raise SessionKeyDecryptionError(error_msg, asRep, cipher, key, cipherText)
        raise
    encASRepPart = decoder.decode(plainText, asn1Spec=EncASRepPart())[0]

    # Get the session key and the ticket
    cipher = _enctype_table[encASRepPart['key']['keytype']]
    sessionKey = Key(cipher.enctype, encASRepPart['key']['keyvalue'].asOctets())

    # ToDo: Check Nonces!

    return tgt, cipher, key, sessionKey


def getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey):
    # Decode the TGT
    try:
        decodedTGT = decoder.decode(tgt, asn1Spec=AS_REP())[0]
    except:
        decodedTGT = decoder.decode(tgt, asn1Spec=TGS_REP())[0]

    domain = domain.upper()
    # Extract the ticket from the TGT
    ticket = Ticket()
    ticket.from_asn1(decodedTGT['ticket'])

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)

    opts = list()
    apReq['ap-options'] = constants.encodeFlags(opts)
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = decodedTGT['crealm'].asOctets()

    clientName = Principal()
    clientName.from_asn1(decodedTGT, 'crealm', 'cname')

    seq_set(authenticator, 'cname', clientName.components_to_asn1)

    now = datetime.datetime.utcnow()
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)

    # Key Usage 7
    # TGS-REQ PA-TGS-REQ padata AP-REQ Authenticator (includes
    # TGS authenticator subkey), encrypted with the TGS session
    # key (Section 5.5.1)
    encryptedEncodedAuthenticator = cipher.encrypt(sessionKey, 7, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    encodedApReq = encoder.encode(apReq)

    tgsReq = TGS_REQ()

    tgsReq['pvno'] = 5
    tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgsReq['padata'] = noValue
    tgsReq['padata'][0] = noValue
    tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgsReq['padata'][0]['padata-value'] = encodedApReq

    reqBody = seq_set(tgsReq, 'req-body')

    opts = list()
    opts.append(constants.KDCOptions.forwardable.value)
    opts.append(constants.KDCOptions.renewable.value)
    opts.append(constants.KDCOptions.renewable_ok.value)
    opts.append(constants.KDCOptions.canonicalize.value)

    reqBody['kdc-options'] = constants.encodeFlags(opts)
    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    reqBody['realm'] = domain

    now = datetime.datetime.utcnow() + datetime.timedelta(days=1)

    reqBody['till'] = KerberosTime.to_asn1(now)
    reqBody['nonce'] = rand.getrandbits(31)
    seq_set_iter(reqBody, 'etype',
                 (
                     int(constants.EncryptionTypes.rc4_hmac.value),
                     int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
                     int(constants.EncryptionTypes.des_cbc_md5.value),
                     int(cipher.enctype)
                 )
                 )

    message = encoder.encode(tgsReq)

    r = sendReceive(message, domain, kdcHost)

    # Get the session key

    tgs = decoder.decode(r, asn1Spec=TGS_REP())[0]

    cipherText = tgs['enc-part']['cipher']

    # Key Usage 8
    # TGS-REP encrypted part (includes application session
    # key), encrypted with the TGS session key (Section 5.4.2)
    plainText = cipher.decrypt(sessionKey, 8, cipherText)

    encTGSRepPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]

    newSessionKey = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'].asOctets())
    # Creating new cipher based on received keytype
    cipher = _enctype_table[encTGSRepPart['key']['keytype']]

    # Check we've got what we asked for
    res = decoder.decode(r, asn1Spec=TGS_REP())[0]
    spn = Principal()
    spn.from_asn1(res['ticket'], 'realm', 'sname')

    if spn.components[0] == serverName.components[0]:
        # Yes.. bye bye
        return r, cipher, sessionKey, newSessionKey
    else:
        # Let's extract the Ticket, change the domain and keep asking
        domain = spn.components[1]
        return getKerberosTGS(serverName, domain, kdcHost, r, cipher, newSessionKey)
