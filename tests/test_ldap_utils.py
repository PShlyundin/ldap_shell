from ldap3.utils.conv import escape_filter_chars

from ldap_shell.utils.ldap_utils import LdapUtils


def test_escape_filter_escapes_specials():
    raw = 'admin)(|(objectClass=*)'
    escaped = LdapUtils.escape_filter(raw)
    assert escaped == escape_filter_chars(raw)
    assert ')' not in escaped or '\\29' in escaped


def test_sam_and_dn_filters_are_wrapped():
    assert LdapUtils.sam_filter('john') == '(sAMAccountName=john)'
    assert LdapUtils.sam_filter('a*b').startswith('(sAMAccountName=')
    assert '*' not in LdapUtils.sam_filter('a*b')
    assert LdapUtils.dn_filter('CN=x,DC=lab').startswith('(distinguishedName=')


def test_looks_like_dn():
    assert LdapUtils.looks_like_dn('CN=john,CN=Users,DC=lab,DC=local')
    assert LdapUtils.looks_like_dn('OU=Servers,DC=lab,DC=local')
    assert not LdapUtils.looks_like_dn('john.doe')
    assert not LdapUtils.looks_like_dn('DC01$')
    assert not LdapUtils.looks_like_dn('')


def test_get_name_from_dn():
    assert LdapUtils.get_name_from_dn('CN=john.doe,CN=Users,DC=lab,DC=local') == 'john.doe'
