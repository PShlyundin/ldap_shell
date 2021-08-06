from pyasn1.type import univ, namedtype, tag, constraint, char, useful

from ldap_shell.krb5 import constants


def _sequence_component(name, tag_value, type, **subkwargs):
    return namedtype.NamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))


def _vno_component(tag_value, name="pvno"):
    return _sequence_component(
        name, tag_value, univ.Integer(),
        subtypeSpec=constraint.ValueRangeConstraint(5, 5))


def _msg_type_component(tag_value, values):
    c = constraint.ConstraintsUnion(
        *(constraint.SingleValueConstraint(int(v)) for v in values))
    return _sequence_component('msg-type', tag_value, univ.Integer(),
                               subtypeSpec=c)


def _sequence_optional_component(name, tag_value, type, **subkwargs):
    return namedtype.OptionalNamedType(name, type.subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            tag_value),
        **subkwargs))


def _application_tag(tag_value):
    return univ.Sequence.tagSet.tagExplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed,
                int(tag_value)))


def seq_set(seq, name, builder=None, *args, **kwargs):
    component = seq.setComponentByName(name).getComponentByName(name)
    if builder is not None:
        seq.setComponentByName(name, builder(component, *args, **kwargs))
    else:
        seq.setComponentByName(name)
    return seq.getComponentByName(name)


def seq_set_iter(seq, name, iterable):
    component = seq.setComponentByName(name).getComponentByName(name)
    for pos, v in enumerate(iterable):
        component.setComponentByPosition(pos, v)


class Int32(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        -2147483648, 2147483647)


class PA_DATA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('padata-type', 1, Int32()),
        _sequence_component('padata-value', 2, univ.OctetString())
    )


class KerberosString(char.GeneralString):
    # TO DO marc: I'm not sure how to express this constraint in the API.
    # For now, we will be liberal in what we accept.
    # subtypeSpec = constraint.PermittedAlphabetConstraint(char.IA5String())
    pass


class Realm(KerberosString):
    pass


class PrincipalName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("name-type", 0, Int32()),
        _sequence_component("name-string", 1,
                            univ.SequenceOf(componentType=KerberosString()))
    )


class UInt32(univ.Integer):
    # subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
    #     0, 4294967295)
    pass


class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("etype", 0, Int32()),
        _sequence_optional_component("kvno", 1, UInt32()),
        _sequence_component("cipher", 2, univ.OctetString())
    )


class Ticket(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.Ticket.value)
    componentType = namedtype.NamedTypes(
        _vno_component(name="tkt-vno", tag_value=0),
        _sequence_component("realm", 1, Realm()),
        _sequence_component("sname", 2, PrincipalName()),
        _sequence_component("enc-part", 3, EncryptedData())
    )


class KDC_REP(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.AS_REP.value,
                                constants.ApplicationTagNumbers.TGS_REP.value)),
        _sequence_optional_component('padata', 2,
                                     univ.SequenceOf(componentType=PA_DATA())),
        _sequence_component('crealm', 3, Realm()),
        _sequence_component('cname', 4, PrincipalName()),
        _sequence_component('ticket', 5, Ticket()),
        _sequence_component('enc-part', 6, EncryptedData())
    )


class AS_REP(KDC_REP):
    tagSet = _application_tag(constants.ApplicationTagNumbers.AS_REP.value)


class TGS_REP(KDC_REP):
    tagSet = _application_tag(constants.ApplicationTagNumbers.TGS_REP.value)


class EncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('keytype', 0, Int32()),
        _sequence_component('keyvalue', 1, univ.OctetString()))


class KerberosTime(useful.GeneralizedTime):
    pass


class LastReq(univ.SequenceOf):
    componentType = univ.Sequence(componentType=namedtype.NamedTypes(
        _sequence_component('lr-type', 0, Int32()),
        _sequence_component('lr-value', 1, KerberosTime())
    ))


class KerberosFlags(univ.BitString):
    # TO DO marc: it doesn't look like there's any way to specify the
    # SIZE (32.. MAX) parameter to the encoder.  However, we can
    # arrange at a higher layer to pass in >= 32 bits to the encoder.
    pass


class TicketFlags(KerberosFlags):
    pass


class HostAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("addr-type", 0, Int32()),
        _sequence_component("address", 1, univ.OctetString())
    )


class HostAddresses(univ.SequenceOf):
    componentType = HostAddress()


class METHOD_DATA(univ.SequenceOf):
    componentType = PA_DATA()


class EncKDCRepPart(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('key', 0, EncryptionKey()),
        _sequence_component('last-req', 1, LastReq()),
        _sequence_component('nonce', 2, UInt32()),
        _sequence_optional_component('key-expiration', 3, KerberosTime()),
        _sequence_component('flags', 4, TicketFlags()),
        _sequence_component('authtime', 5, KerberosTime()),
        _sequence_optional_component('starttime', 6, KerberosTime()),
        _sequence_component('endtime', 7, KerberosTime()),
        _sequence_optional_component('renew-till', 8, KerberosTime()),
        _sequence_component('srealm', 9, Realm()),
        _sequence_component('sname', 10, PrincipalName()),
        _sequence_optional_component('caddr', 11, HostAddresses()),
        _sequence_optional_component('encrypted_pa_data', 12, METHOD_DATA())
    )


class EncASRepPart(EncKDCRepPart):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncASRepPart.value)


class EncTGSRepPart(EncKDCRepPart):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncTGSRepPart.value)


class KRB_CRED(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_CRED.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_CRED.value,)),
        _sequence_optional_component('tickets', 2,
                                     univ.SequenceOf(componentType=Ticket())),
        _sequence_component('enc-part', 3, EncryptedData()),
    )


class KrbCredInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('key', 0, EncryptionKey()),
        _sequence_optional_component('prealm', 1, Realm()),
        _sequence_optional_component('pname', 2, PrincipalName()),
        _sequence_optional_component('flags', 3, TicketFlags()),
        _sequence_optional_component('authtime', 4, KerberosTime()),
        _sequence_optional_component('starttime', 5, KerberosTime()),
        _sequence_optional_component('endtime', 6, KerberosTime()),
        _sequence_optional_component('renew-till', 7, KerberosTime()),
        _sequence_optional_component('srealm', 8, Realm()),
        _sequence_optional_component('sname', 9, PrincipalName()),
        _sequence_optional_component('caddr', 10, HostAddresses()),
    )


class Microseconds(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 999999)


class EncKrbCredPart(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.EncKrbCredPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component('ticket-info', 0, univ.SequenceOf(componentType=KrbCredInfo())),
        _sequence_optional_component('nonce', 1, UInt32()),
        _sequence_optional_component('timestamp', 2, KerberosTime()),
        _sequence_optional_component('usec', 3, Microseconds()),
        _sequence_optional_component('s-address', 4, HostAddress()),
        _sequence_optional_component('r-address', 5, HostAddress()),
    )


class KDCOptions(KerberosFlags):
    pass


class KDC_REQ_BODY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('kdc-options', 0, KDCOptions()),
        _sequence_optional_component('cname', 1, PrincipalName()),
        _sequence_component('realm', 2, Realm()),
        _sequence_optional_component('sname', 3, PrincipalName()),
        _sequence_optional_component('from', 4, KerberosTime()),
        _sequence_component('till', 5, KerberosTime()),
        _sequence_optional_component('rtime', 6, KerberosTime()),
        _sequence_component('nonce', 7, UInt32()),
        _sequence_component('etype', 8,
                            univ.SequenceOf(componentType=Int32())),
        _sequence_optional_component('addresses', 9, HostAddresses()),
        _sequence_optional_component('enc-authorization-data', 10,
                                     EncryptedData()),
        _sequence_optional_component('additional-tickets', 11,
                                     univ.SequenceOf(componentType=Ticket()))
    )


class KDC_REQ(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _vno_component(1),
        _msg_type_component(2, (constants.ApplicationTagNumbers.AS_REQ.value,
                                constants.ApplicationTagNumbers.TGS_REQ.value)),
        _sequence_optional_component('padata', 3,
                                     univ.SequenceOf(componentType=PA_DATA())),
        _sequence_component('req-body', 4, KDC_REQ_BODY())
    )


class AS_REQ(KDC_REQ):
    tagSet = _application_tag(constants.ApplicationTagNumbers.AS_REQ.value)


class KERB_PA_PAC_REQUEST(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('include-pac',
                            univ.Boolean().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    )


class KERB_ERROR_DATA(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('data-type', 1, Int32()),
        _sequence_component('data-value', 2, univ.OctetString()))


class KRB_ERROR(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.KRB_ERROR.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.KRB_ERROR.value,)),
        _sequence_optional_component('ctime', 2, KerberosTime()),
        _sequence_optional_component('cusec', 3, Microseconds()),
        _sequence_component('stime', 4, KerberosTime()),
        _sequence_component('susec', 5, Microseconds()),
        _sequence_component('error-code', 6, Int32()),
        _sequence_optional_component('crealm', 7, Realm()),
        _sequence_optional_component('cname', 8, PrincipalName()),
        _sequence_component('realm', 9, Realm()),
        _sequence_component('sname', 10, PrincipalName()),
        _sequence_optional_component('e-text', 11, KerberosString()),
        _sequence_optional_component('e-data', 12, univ.OctetString())
    )


class ETYPE_INFO_ENTRY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('etype', 0, Int32()),
        _sequence_optional_component('salt', 1, univ.OctetString()))


class ETYPE_INFO(univ.SequenceOf):
    componentType = ETYPE_INFO_ENTRY()


class ETYPE_INFO2_ENTRY(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('etype', 0, Int32()),
        _sequence_optional_component('salt', 1, KerberosString()),
        _sequence_optional_component('s2kparams', 2, univ.OctetString()))


class ETYPE_INFO2(univ.SequenceOf):
    componentType = ETYPE_INFO2_ENTRY()


class PA_ENC_TS_ENC(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('patimestamp', 0, KerberosTime()),
        _sequence_optional_component('pausec', 1, Microseconds()))


class APOptions(KerberosFlags):
    pass


class AP_REQ(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.AP_REQ.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (constants.ApplicationTagNumbers.AP_REQ.value,)),
        _sequence_component('ap-options', 2, APOptions()),
        _sequence_component('ticket', 3, Ticket()),
        _sequence_component('authenticator', 4, EncryptedData())
    )


class Checksum(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component('cksumtype', 0, Int32()),
        _sequence_component('checksum', 1, univ.OctetString()))


class AuthorizationData(univ.SequenceOf):
    componentType = univ.Sequence(componentType=namedtype.NamedTypes(
        _sequence_component('ad-type', 0, Int32()),
        _sequence_component('ad-data', 1, univ.OctetString())
    ))


class Authenticator(univ.Sequence):
    tagSet = _application_tag(constants.ApplicationTagNumbers.Authenticator.value)
    componentType = namedtype.NamedTypes(
        _vno_component(name='authenticator-vno', tag_value=0),
        _sequence_component('crealm', 1, Realm()),
        _sequence_component('cname', 2, PrincipalName()),
        _sequence_optional_component('cksum', 3, Checksum()),
        _sequence_component('cusec', 4, Microseconds()),
        _sequence_component('ctime', 5, KerberosTime()),
        _sequence_optional_component('subkey', 6, EncryptionKey()),
        _sequence_optional_component('seq-number', 7, UInt32()),
        _sequence_optional_component('authorization-data', 8,
                                     AuthorizationData())
    )


class TGS_REQ(KDC_REQ):
    tagSet = _application_tag(constants.ApplicationTagNumbers.TGS_REQ.value)
