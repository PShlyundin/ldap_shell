import re
from pathlib import Path

from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.module_loader import ModuleLoader

ROOT = Path(__file__).resolve().parents[1]


def test_version_is_3():
    setup = (ROOT / 'setup.py').read_text()
    pyproject = (ROOT / 'pyproject.toml').read_text()
    assert "version='3.0.0'" in setup
    assert 'version = "3.0.0"' in pyproject


def test_module_loader_includes_new_commands():
    names = ModuleLoader.list_modules()
    for required in (
        'whoami', 'get_acl', 'get_writable', 'get_delegation', 'get_trusts',
        'restore', 'set_attr', 'get_asreproast', 'get_privileged_accounts',
        'add_sid_history', 'get_kerberoast', 'set_delegation', 'set_keycred',
        'set_dns', 'set_badsuccessor', 'get_pre2k', 'get_desc',
    ):
        assert required in names


def test_describe_mask_generic_all():
    names = AceUtils.describe_mask(0x000F01FF)
    assert 'GenericAll' in names


def test_roast_hashcat_formats():
    from ldap_shell.utils.roast_utils import format_asrep, format_tgs

    cipher = bytes(range(32))
    asrep = format_asrep('alice', 'lab.local', 23, cipher)
    assert asrep.startswith('$krb5asrep$23$alice@LAB.LOCAL:')
    tgs = format_tgs('sql', 'lab.local', 'MSSQLSvc/db.lab.local', 23, cipher)
    assert tgs.startswith('$krb5tgs$23$*sql$LAB.LOCAL$MSSQLSvc/db.lab.local*')


def test_empty_sd_roundtrip_bytes():
    blob = AceUtils.create_empty_sd().getData()
    assert isinstance(blob, (bytes, bytearray))
    assert len(blob) > 8
    restored = AceUtils.create_empty_sd()
    restored.fromString(blob)
    assert restored['OwnerSid'].formatCanonical() == 'S-1-5-32-544'


def test_create_ace_inherit_flag():
    ace = AceUtils.create_allow_ace('S-1-5-21-1-2-3-4', inherit=True)
    assert ace['AceFlags'] == 0x03
    plain = AceUtils.createACE('S-1-5-21-1-2-3-4')
    assert plain['AceFlags'] == 0x00


def test_suggest_abuse_maps_keycred_and_owner():
    assert AceUtils.suggest_abuse('john', ['WriteProperty'], 'msDS-KeyCredentialLink') == 'set_keycred john add'
    assert AceUtils.suggest_abuse('admin', ['WriteOwner']) == 'set_owner admin'
    assert AceUtils.suggest_abuse('OU', ['WriteDacl']).startswith('dacl_modify')
    assert AceUtils.object_type_name(
        LdapUtils.string_to_bin('5b47d60f-6090-40b2-9f37-2a4de88f3063')
    ) == 'msDS-KeyCredentialLink'


def test_arg_field_does_not_emit_pydantic_extra_kwarg_warning():
    import warnings

    from pydantic import BaseModel
    from pydantic.warnings import PydanticDeprecatedSince20

    from ldap_shell.ldap_modules.base_module import ArgumentType, arg_field

    with warnings.catch_warnings():
        warnings.simplefilter('error', PydanticDeprecatedSince20)

        class Sample(BaseModel):
            user: str = arg_field(description='u', arg_type=ArgumentType.USER)

    assert Sample.model_fields['user'].json_schema_extra['arg_type'] is ArgumentType.USER


def test_dns_a_record_roundtrip():
    from ldap_shell.ldap_modules.set_dns.ldap_module import pack_dns_a, unpack_dns_type

    blob = pack_dns_a('10.0.0.5', ttl=180, serial=7)
    assert unpack_dns_type(blob) == 1
    assert blob[-4:] == bytes((10, 0, 0, 5))
    try:
        pack_dns_a('not-an-ip')
    except ValueError:
        return
    raise AssertionError('expected ValueError')


def test_dns_cname_record_roundtrip():
    from ldap_shell.ldap_modules.set_dns.ldap_module import (
        describe_dns_record,
        encode_dns_count_name,
        pack_dns_a,
        pack_dns_cname,
        unpack_dns_type,
    )

    blob = pack_dns_cname('server.domain.local')
    assert unpack_dns_type(blob) == 5
    encoded = encode_dns_count_name('server.domain.local')
    assert encoded[1] == 3
    assert b'server' in encoded
    assert encoded.endswith(b'\x00')
    assert describe_dns_record(blob) == 'CNAME server.domain.local'
    assert describe_dns_record(pack_dns_a('10.0.0.5')) == 'A 10.0.0.5'
    try:
        encode_dns_count_name('')
    except ValueError:
        return
    raise AssertionError('expected ValueError')


def test_badsuccessor_module_surface():
    source = (ROOT / 'ldap_shell/ldap_modules/set_badsuccessor/ldap_module.py').read_text()
    assert 'msDS-ManagedAccountPrecededByLink' in source
    assert 'msDS-DelegatedMSAState' in source
    assert 'msDS-DelegatedManagedServiceAccount' in source
    assert 'msDS-ManagedPassword' in source
    assert 'getKerberosTGT' in source
    module = ModuleLoader.load_module('set_badsuccessor')
    assert [arg.name for arg in module.get_arguments()] == ['action', 'victim', 'container', 'name']


def test_parse_managed_password_blob():
    import struct

    from Cryptodome.Hash import MD4

    from ldap_shell.ldap_modules.set_badsuccessor.ldap_module import parse_managed_password

    password = 'TestPass1!'
    raw = password.encode('utf-16-le') + b'\x00\x00'
    query = b'\x00' * 8
    unchanged = b'\x00' * 8
    cur_off = 16
    query_off = cur_off + len(raw)
    unch_off = query_off + len(query)
    total = unch_off + len(unchanged)
    blob = struct.pack('<HHLHHHH', 1, 0, total, cur_off, 0, query_off, unch_off)
    blob += raw + query + unchanged
    got_password, nthash = parse_managed_password(blob)
    assert got_password == password
    assert nthash == MD4.new(password.encode('utf-16-le')).hexdigest()


def test_kerberoast_and_delegation_args():
    roast = ModuleLoader.load_module('get_kerberoast')
    names = [arg.name for arg in roast.get_arguments()]
    assert names == ['target', 'output']
    assert roast.get_arguments()[0].required is False

    deleg = ModuleLoader.load_module('set_delegation')
    assert [arg.name for arg in deleg.get_arguments()] == ['target', 'action', 'spn']
    source = (ROOT / 'ldap_shell/ldap_modules/get_kerberoast/ldap_module.py').read_text()
    assert 'servicePrincipalName=*' in source
    assert 'objectCategory=person' in source


def test_modules_call_arg_field_not_field_arg_type():
    for path in (ROOT / 'ldap_shell/ldap_modules').glob('*/ldap_module.py'):
        text = path.read_text()
        if 'arg_type=' not in text:
            continue
        assert 'arg_field(' in text
        assert re.search(r'\bField\s*\(', text) is None
