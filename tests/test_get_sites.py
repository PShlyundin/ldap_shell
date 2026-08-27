import io
from contextlib import redirect_stdout
from types import SimpleNamespace

from ldap_shell.ldap_modules.get_sites.ldap_module import (
    LdapShellModule,
    site_from_server_dn,
    site_from_site_object,
    split_dn,
)

ROOT = 'DC=lab,DC=local'
SITES = f'CN=Sites,CN=Configuration,{ROOT}'


class _Attr:
    def __init__(self, value):
        self.value = value


class _Entry:
    """Minimal stand-in for an ldap3 Entry."""

    def __init__(self, dn, **attrs):
        self.entry_dn = dn
        self._attrs = attrs

    def __contains__(self, key):
        return key in self._attrs

    def __getitem__(self, key):
        return _Attr(self._attrs[key])


class _Client:
    """Returns canned entries depending on the search base and filter."""

    def __init__(self, responses):
        self.responses = responses
        self.entries = []
        self.searches = []

    def search(self, base, ldap_filter, attributes=None, paged_size=None):
        self.searches.append((base, ldap_filter))
        self.entries = self.responses.get((base, ldap_filter), [])
        return True


def _module(client, site=None):
    args = {'site': site} if site else {}
    return LdapShellModule(args, SimpleNamespace(root=ROOT), client, log=_Log())


class _Log:
    def __init__(self):
        self.info_lines = []
        self.error_lines = []

    def info(self, msg):
        self.info_lines.append(str(msg))

    def error(self, msg):
        self.error_lines.append(str(msg))

    def debug(self, msg):
        pass


def _client_with_two_sites():
    return _Client({
        (SITES, '(objectClass=site)'): [
            _Entry(f'CN=HQ,{SITES}', cn='HQ', location='Moscow'),
            _Entry(f'CN=Branch,{SITES}', cn='Branch'),
            _Entry(f'CN=Empty,{SITES}', cn='Empty'),
        ],
        (SITES, '(objectClass=server)'): [
            _Entry(f'CN=DC02,CN=Servers,CN=HQ,{SITES}', cn='DC02', dNSHostName='dc02.lab.local'),
            _Entry(f'CN=DC01,CN=Servers,CN=HQ,{SITES}', cn='DC01', dNSHostName='dc01.lab.local'),
            _Entry(f'CN=DC03,CN=Servers,CN=Branch,{SITES}', cn='DC03'),
        ],
        (f'CN=Subnets,{SITES}', '(objectClass=subnet)'): [
            _Entry('CN=10.0.1.0/24', cn='10.0.1.0/24', siteObject=f'CN=Branch,{SITES}'),
            _Entry('CN=10.0.0.0/24', cn='10.0.0.0/24', siteObject=f'CN=HQ,{SITES}',
                   location='Moscow', description='office'),
            _Entry('CN=192.168.9.0/24', cn='192.168.9.0/24'),
        ],
    })


def _run(module):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        module()
    return buffer.getvalue()


def test_split_dn_respects_escaped_comma():
    assert split_dn('CN=a\\,b,CN=c') == ['CN=a\\,b', 'CN=c']


def test_site_extracted_from_server_dn():
    assert site_from_server_dn(f'CN=DC01,CN=Servers,CN=Branch,{SITES}') == 'Branch'
    assert site_from_server_dn('CN=DC01,CN=Computers,DC=lab,DC=local') is None


def test_site_extracted_from_site_object():
    assert site_from_site_object(f'CN=Branch,{SITES}') == 'Branch'
    assert site_from_site_object('') is None


def test_groups_dcs_and_subnets_under_their_site():
    module = _module(_client_with_two_sites())
    out = _run(module)
    assert 'SITE: Branch' in out and 'SITE: HQ' in out
    hq = out.split('SITE: HQ')[1]
    assert 'DC01' in hq and 'DC02' in hq and '10.0.0.0/24' in hq
    assert 'DC03' not in hq.split('SITE:')[0]
    assert '[Moscow] - office' in out


def test_site_without_dcs_or_subnets_is_still_listed():
    out = _run(_module(_client_with_two_sites()))
    empty = out.split('SITE: Empty')[1]
    assert 'Domain Controllers: none' in empty
    assert 'IP Subnets: none' in empty


def test_subnet_without_siteobject_reported_separately():
    module = _module(_client_with_two_sites())
    out = _run(module)
    assert 'Subnets not linked to any site (1)' in out
    assert '192.168.9.0/24' in out.split('Subnets not linked')[1]
    assert 'unlinked subnet(s)' in module.log.info_lines[-1]


def test_summary_counts():
    module = _module(_client_with_two_sites())
    _run(module)
    assert '3 site(s), 3 DC(s), 2 subnet(s)' in module.log.info_lines[-1]


def test_filter_by_single_site():
    module = _module(_client_with_two_sites(), site='branch')
    out = _run(module)
    assert 'SITE: Branch' in out
    assert 'SITE: HQ' not in out
    assert 'Subnets not linked' not in out
    assert '1 site(s), 1 DC(s), 1 subnet(s)' in module.log.info_lines[-1]


def test_unknown_site_is_an_error():
    module = _module(_client_with_two_sites(), site='nope')
    _run(module)
    assert module.log.error_lines and 'Site not found' in module.log.error_lines[0]


def test_no_sites_at_all():
    module = _module(_Client({}))
    _run(module)
    assert 'No sites found' in module.log.info_lines[-1]


def test_search_failure_does_not_raise():
    class _Broken(_Client):
        def search(self, *a, **kw):
            raise RuntimeError('boom')

    module = _module(_Broken({}))
    _run(module)
    assert 'No sites found' in module.log.info_lines[-1]
