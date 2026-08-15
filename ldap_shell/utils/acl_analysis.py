"""Shared helpers for DACL analysis (get_acl / get_writable).

Turns raw nTSecurityDescriptor ACEs into human-readable findings and, most
importantly, maps abusable rights to concrete attacks and to the ldap_shell
command that performs them.
"""
import ldap_shell.utils.ldaptypes as ldaptypes
from ldap_shell.utils.ldap_utils import LdapUtils


# --- Access mask bits (MS-DTYP / ADTS) ------------------------------------- #
ACCESS_MASK_BITS = [
    (0x80000000, 'GenericRead'),
    (0x40000000, 'GenericWrite'),
    (0x20000000, 'GenericExecute'),
    (0x10000000, 'GenericAll'),
    (0x00080000, 'WriteOwner'),
    (0x00040000, 'WriteDacl'),
    (0x00020000, 'ReadControl'),
    (0x00010000, 'Delete'),
    (0x00000100, 'AllExtendedRights'),
    (0x00000080, 'ListObject'),
    (0x00000040, 'DeleteTree'),
    (0x00000020, 'WriteProperties'),
    (0x00000010, 'ReadProperties'),
    (0x00000008, 'Self'),
    (0x00000004, 'ListChildObjects'),
    (0x00000002, 'DeleteChild'),
    (0x00000001, 'CreateChild'),
]

SIMPLE_PERMISSIONS = [
    (0xf01ff, 'FullControl'),
    (0x301bf, 'Modify'),
    (0x200a9, 'ReadAndExecute'),
    (0x2019f, 'ReadAndWrite'),
    (0x20094, 'Read'),
    (0x200bc, 'Write'),
]

# Severity levels used for coloring / sorting
CRIT, HIGH, MED, LOW = 'CRIT', 'HIGH', 'MED', 'LOW'
SEVERITY_ORDER = {CRIT: 0, HIGH: 1, MED: 2, LOW: 3}

# --- Extended rights (CONTROL_ACCESS ACEs) --------------------------------- #
# guid (lowercase) -> (friendly name, attack label, severity, command template)
EXTENDED_RIGHTS = {
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': ('DS-Replication-Get-Changes', 'DCSync (part) - use secretsdump as this principal', HIGH, None),
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': ('DS-Replication-Get-Changes-All', 'DCSync - use secretsdump as this principal', CRIT, None),
    '89e95b76-444d-4c62-991a-0facbeda640c': ('DS-Replication-Get-Changes-In-Filtered-Set', 'DCSync (part)', HIGH, None),
    '00299570-246d-11d0-a768-00aa006e0529': ('User-Force-Change-Password', 'Force password reset', HIGH, 'change_password {target} <NewPass>'),
    'ab721a53-1e2f-11d0-9819-00aa0040529b': ('User-Change-Password', None, LOW, None),
    '45ec5156-db7e-47bb-b53f-dbeb2d03c40f': ('Reanimate-Tombstones', 'Reanimate tombstones', MED, None),
    'ba33815a-4f93-4c76-87f3-57574bff8109': ('Migrate-SID-History', 'SID History injection', HIGH, None),
}

# --- Abusable attributes (WriteProperty object ACEs), keyed by schemaIDGUID - #
# guid (lowercase) -> (friendly name, attack label, severity, command template)
ABUSABLE_ATTRS = {
    'bf9679a8-0de6-11d0-a285-00aa003049e2': ('scriptPath', 'Logon script -> code exec at victim logon', HIGH, 'set_attribute {target} scriptPath <\\\\host\\share\\x.cmd>'),
    'bf967a05-0de6-11d0-a285-00aa003049e2': ('profilePath', 'Profile path hijack (UNC coerce)', MED, 'set_attribute {target} profilePath <\\\\host\\share>'),
    'f3a64788-5306-11d1-a9c5-0000f80367c1': ('servicePrincipalName', 'Targeted Kerberoast', HIGH, 'set_spn {target} add <SPN>'),
    'bf9679c0-0de6-11d0-a285-00aa003049e2': ('member', 'Add member to group', HIGH, 'add_user_to_group <you> {target}'),
    'bf967a68-0de6-11d0-a285-00aa003049e2': ('userAccountControl', 'UAC abuse (AS-REP roast / disable / delegation)', HIGH, 'uac_modify {target} add DONT_REQUIRE_PREAUTH'),
    '5b47d60f-6090-40b2-9f37-2a4de88f3063': ('msDS-KeyCredentialLink', 'Shadow Credentials', HIGH, 'get_ntlm {target}'),
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79': ('msDS-AllowedToActOnBehalfOfOtherIdentity', 'RBCD', HIGH, 'set_rbcd {target} <grantee>'),
    '800d94d7-b7a1-42a1-b14d-7cae1423d07f': ('msDS-AllowedToDelegateTo', 'Constrained delegation abuse', HIGH, None),
    'f30e3bbe-9ff0-11d1-b603-0000f80367c1': ('gPLink', 'GPO link abuse (OU-linked)', HIGH, None),
    'bf9679e1-0de6-11d0-a285-00aa003049e2': ('unicodePwd', 'Set password (needs LDAPS)', HIGH, 'change_password {target} <NewPass>'),
    '888eedd6-ce04-df40-b462-b8a50e41ba38': ('msDS-GroupMSAMembership', 'Read gMSA password', HIGH, 'get_laps_gmsa {target}'),
}

# --- Well-known / privileged trustees (hidden unless show_all) ------------- #
WELL_KNOWN_SIDS = {
    'S-1-1-0': 'Everyone',
    'S-1-3-0': 'Creator Owner',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'SELF',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-18': 'SYSTEM',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-554': 'Pre-Windows 2000 Compatible Access',
    'S-1-5-32-560': 'Windows Authorization Access Group',
    'S-1-5-32-561': 'Terminal Server License Servers',
}
# Trustees considered "already privileged" or default service groups whose
# default ACEs are noise -> not interesting as an attack path
PRIVILEGED_SIDS = {'S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0', 'S-1-5-10',
                   'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551',
                   'S-1-5-32-554', 'S-1-5-32-560', 'S-1-5-32-561', 'S-1-5-32-568',
                   'S-1-5-32-569'}
# Domain RIDs of default privileged / default service groups (Cert Publishers 517,
# RAS and IAS Servers 553)
# Broad/default trustees: real, targeted delegations are rarely granted to
# these, so *generic* (non-specifically-abusable) findings for them are noise
# and hidden by default. Known high-value rights (GenericAll, DCSync, RBCD,
# scriptPath, ...) are still shown even for these trustees.
BROAD_SIDS = {'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545'}  # Everyone, Authenticated Users, Users

# Domain RIDs of default privileged groups
# 512 Domain Admins, 516 Domain Controllers, 518 Schema Admins, 519 Enterprise Admins,
# 520 Group Policy Creator Owners, 521 RODCs, 498 Enterprise RODCs,
# 526 Key Admins, 527 Enterprise Key Admins (default ms-DS-KeyCredentialLink writers)
PRIVILEGED_RIDS = {512, 516, 518, 519, 520, 521, 498, 526, 527, 517, 553}


def parse_perms(mask):
    """Decode an access mask into a list of permission names."""
    perms = []
    m = mask
    for value, name in SIMPLE_PERMISSIONS:
        if (m & value) == value:
            perms.append(name)
            m &= ~value
    for value, name in ACCESS_MASK_BITS:
        if m & value:
            perms.append(name)
    return perms


def is_privileged_sid(sid):
    if sid in PRIVILEGED_SIDS:
        return True
    try:
        rid = int(sid.rsplit('-', 1)[1])
        return rid in PRIVILEGED_RIDS
    except (ValueError, IndexError):
        return False


def analyze_ace(ace, guid_resolver=None):
    """Analyze a single ACE. Returns a dict describing it, or None if the ACE
    type is not access-allowed/denied.

    guid_resolver(guid) -> friendly attribute/class name (from schema), optional.
    """
    tname = ace['TypeName']
    allowed = tname in ('ACCESS_ALLOWED_ACE', 'ACCESS_ALLOWED_OBJECT_ACE',
                        'ACCESS_ALLOWED_CALLBACK_ACE', 'ACCESS_ALLOWED_CALLBACK_OBJECT_ACE')
    denied = tname in ('ACCESS_DENIED_ACE', 'ACCESS_DENIED_OBJECT_ACE',
                       'ACCESS_DENIED_CALLBACK_ACE', 'ACCESS_DENIED_CALLBACK_OBJECT_ACE')
    if not (allowed or denied):
        return None

    a = ace['Ace']
    mask = a['Mask']['Mask']
    sid = a['Sid'].formatCanonical()
    inherited = ace.hasFlag(ldaptypes.ACE.INHERITED_ACE)

    object_type = None
    if tname.endswith('OBJECT_ACE') and a['ObjectType']:
        object_type = LdapUtils.bin_to_string(a['ObjectType']).lower()

    finding = {
        'allow': allowed,
        'sid': sid,
        'mask': mask,
        'perms': parse_perms(mask),
        'inherited': inherited,
        'object_type': object_type,
        'attacks': [],          # list of (label, severity, cmd_template)
        'right_name': None,     # friendly name for object ACEs
        'severity': LOW,
        'generic': False,       # True for non-specifically-abusable findings
    }

    # --- object-specific ACE (extended right or property write) --- #
    if object_type:
        if object_type in EXTENDED_RIGHTS:
            name, attack, sev, cmd = EXTENDED_RIGHTS[object_type]
            finding['right_name'] = name
            if attack and (mask & 0x100):  # CONTROL_ACCESS
                finding['attacks'].append((attack, sev, cmd))
        elif object_type in ABUSABLE_ATTRS:
            name, attack, sev, cmd = ABUSABLE_ATTRS[object_type]
            finding['right_name'] = name
            # WriteProperty / validated-write / GenericAll over this attribute
            if attack and (mask & (0x20 | 0x08 | 0x10000000)):
                finding['attacks'].append((attack, sev, cmd))
        else:
            # Unknown GUID: resolve against the schema and still surface any
            # write / validated-write / extended-right as a generic finding so
            # nothing abusable is silently hidden (matches get_writable).
            name = guid_resolver(object_type) if guid_resolver else None
            label = name or object_type
            finding['right_name'] = label
            # Generic findings are marked so the default view can hide them for
            # broad/default trustees. Unknown extended rights (Send-As, Send-To,
            # Receive-As, ...) are almost never the abuse primitive, so they are
            # not flagged as attacks at all - only the known ones in
            # EXTENDED_RIGHTS are.
            if mask & 0x20:          # WriteProperty on some attribute/property-set
                cmd = f'set_attribute {{target}} {name} <value>' if name else None
                finding['attacks'].append((f'WriteProperty: {label}', MED, cmd))
                finding['generic'] = True
            elif mask & 0x08:        # validated write
                finding['attacks'].append((f'Validated write: {label}', MED, None))
                finding['generic'] = True
    else:
        # --- generic (whole-object) ACE: decode by mask bits --- #
        # Real DACLs express GenericAll either as the generic bit (0x10000000)
        # or, more commonly, as the expanded FullControl mask (0xf01ff).
        if (mask & 0x10000000) or ((mask & 0xf01ff) == 0xf01ff):
            finding['attacks'].append(('Full control (GenericAll)', CRIT, 'set_owner {target}'))
        else:
            if mask & 0x00040000:  # WriteDacl
                finding['attacks'].append(('WriteDACL -> grant self GenericAll', CRIT,
                                           'dacl_modify {target} <you> add GenericAll'))
            if mask & 0x00080000:  # WriteOwner
                finding['attacks'].append(('WriteOwner -> take ownership', CRIT, 'set_owner {target}'))
            if (mask & 0x40000000) or (mask & 0x20):  # GenericWrite or WriteProperty(all)
                finding['attacks'].append(('GenericWrite -> RBCD / Shadow Creds / Kerberoast', HIGH,
                                           'set_rbcd {target} <grantee>'))
            if mask & 0x00000100:  # AllExtendedRights
                finding['attacks'].append(('AllExtendedRights -> DCSync / ForceChangePassword', HIGH,
                                           'change_password {target} <NewPass>'))

    if denied:
        # A deny ACE is not an attack path; keep it visible but not actionable
        finding['attacks'] = []

    if finding['attacks']:
        finding['severity'] = min((s for _, s, _ in finding['attacks']),
                                  key=lambda s: SEVERITY_ORDER[s])
    return finding
