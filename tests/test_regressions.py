from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_set_genericall_resolves_target_not_grantee():
    source = (ROOT / 'ldap_shell/ldap_modules/set_genericall/ldap_module.py').read_text()
    assert 'target_dn = LdapUtils.resolve_dn(self.client, self.domain_dumper, self.args.target)' in source
    assert 'get_dn(self.client, self.domain_dumper, self.args.grantee)' in source


def test_clear_rbcd_uses_ldap3_modify_tuples():
    source = (ROOT / 'ldap_shell/ldap_modules/clear_rbcd/ldap_module.py').read_text()
    assert '[(ldap3.MODIFY_REPLACE, [sd.getData()])]' in source
    assert "['msDS-AllowedToActOnBehalfOfOtherIdentity']: [ldap3.MODIFY_REPLACE" not in source
