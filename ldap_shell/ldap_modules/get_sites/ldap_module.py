import logging
import re
from collections import defaultdict
from typing import Optional

from colorama import Fore, Style, init
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field

init()


def split_dn(dn: str) -> list:
    """Split a DN on unescaped commas."""
    return re.split(r'(?<!\\),', dn or '')


def site_from_server_dn(dn: str) -> Optional[str]:
    """CN=DC01,CN=Servers,CN=Branch,CN=Sites,... -> Branch"""
    parts = split_dn(dn)
    for i, part in enumerate(parts):
        if part.strip().lower() == 'cn=servers' and i + 1 < len(parts):
            return parts[i + 1].strip()[3:]
    return None


def site_from_site_object(dn: str) -> Optional[str]:
    """CN=Branch,CN=Sites,CN=Configuration,... -> Branch"""
    if not dn:
        return None
    head = split_dn(dn)[0].strip()
    return head[3:] if head.lower().startswith('cn=') else None


class LdapShellModule(BaseLdapModule):
    """Map AD sites to their domain controllers and IP subnets"""

    help_text = "Show AD sites with their domain controllers and IP subnets"
    examples_text = """
    List every site in the forest:
    `get_sites`
    ```
    [INFO] Configuration: CN=Configuration,DC=domain,DC=local
     SITE: Default-First-Site-Name
        Domain Controllers (1):
          |- DC01                (dc01.domain.local)
        IP Subnets (2):
          |- 10.0.0.0/24         [HQ] - office
          `- 10.0.1.0/24
    [INFO] 3 site(s), 4 DC(s), 7 subnet(s)
    ```

    Only one site:
    `get_sites Branch-Office`

    Inline: `ldap_shell domain.local/user:pass get_sites`
    MCP: `run` with command `get_sites`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        site: Optional[str] = arg_field(
            None,
            description="Show only this site (default: all sites)",
            arg_type=ArgumentType.STRING,
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _search(self, base: str, ldap_filter: str, attributes: list) -> list:
        """Search that survives a missing container instead of raising."""
        try:
            self.client.search(base, ldap_filter, attributes=attributes, paged_size=500)
        except Exception as exc:
            self.log.debug(f'Search under {base} failed: {exc}')
            return []
        return list(self.client.entries)

    def _sites(self, sites_dn: str) -> dict:
        sites = {}
        for entry in self._search(sites_dn, '(objectClass=site)', ['cn', 'description', 'location']):
            name = str(entry['cn'].value)
            sites[name] = {
                'description': str(entry['description'].value) if 'description' in entry and entry['description'].value else '',
                'location': str(entry['location'].value) if 'location' in entry and entry['location'].value else '',
            }
        return sites

    def _servers(self, sites_dn: str) -> dict:
        servers = defaultdict(list)
        entries = self._search(
            sites_dn, '(objectClass=server)', ['cn', 'dNSHostName', 'distinguishedName']
        )
        for entry in entries:
            site = site_from_server_dn(str(entry.entry_dn))
            if not site:
                continue
            servers[site].append({
                'name': str(entry['cn'].value),
                'dns': str(entry['dNSHostName'].value) if 'dNSHostName' in entry and entry['dNSHostName'].value else '',
            })
        for items in servers.values():
            items.sort(key=lambda item: item['name'].lower())
        return servers

    def _subnets(self, sites_dn: str) -> tuple:
        subnets = defaultdict(list)
        orphans = []
        entries = self._search(
            f'CN=Subnets,{sites_dn}', '(objectClass=subnet)',
            ['cn', 'siteObject', 'location', 'description'],
        )
        for entry in entries:
            info = {
                'subnet': str(entry['cn'].value),
                'location': str(entry['location'].value) if 'location' in entry and entry['location'].value else '',
                'description': str(entry['description'].value) if 'description' in entry and entry['description'].value else '',
            }
            site_dn = str(entry['siteObject'].value) if 'siteObject' in entry and entry['siteObject'].value else ''
            site = site_from_site_object(site_dn)
            if site:
                subnets[site].append(info)
            else:
                orphans.append(info)
        for items in subnets.values():
            items.sort(key=lambda item: item['subnet'])
        orphans.sort(key=lambda item: item['subnet'])
        return subnets, orphans

    @staticmethod
    def _suffix(info: dict) -> str:
        location = f" [{info['location']}]" if info.get('location') else ''
        description = f" - {info['description']}" if info.get('description') else ''
        return f'{location}{description}'

    @staticmethod
    def _column(text: str, width: int, tail: str, color: str = '') -> str:
        """Pad text to width only when something follows, so lines never trail spaces."""
        body = f'{text:<{width}}' if tail else text
        return f'{color}{body}{Style.RESET_ALL if color else ""}{tail}'

    def _print_branch(self, items: list, render) -> None:
        for i, item in enumerate(items):
            prefix = '`-' if i == len(items) - 1 else '|-'
            print(f'      {prefix} {render(item)}')

    def __call__(self):
        config_dn = f'CN=Configuration,{self.domain_dumper.root}'
        sites_dn = f'CN=Sites,{config_dn}'
        self.log.info(f'Configuration: {config_dn}')

        sites = self._sites(sites_dn)
        servers = self._servers(sites_dn)
        subnets, orphan_subnets = self._subnets(sites_dn)

        names = set(sites) | set(servers) | set(subnets)
        if self.args.site:
            wanted = self.args.site.lower()
            names = {name for name in names if name.lower() == wanted}
            if not names:
                self.log.error(f'Site not found: {self.args.site}')
                return
        if not names:
            self.log.info('No sites found')
            return

        for name in sorted(names, key=str.lower):
            meta = sites.get(name, {})
            print(f' {Fore.WHITE}{Style.BRIGHT}SITE: {name}{Style.RESET_ALL}{self._suffix(meta)}')

            site_dcs = servers.get(name, [])
            if site_dcs:
                print(f'    {Fore.CYAN}Domain Controllers ({len(site_dcs)}):{Style.RESET_ALL}')
                self._print_branch(
                    site_dcs,
                    lambda dc: self._column(dc['name'], 24, f" ({dc['dns']})" if dc['dns'] else ''),
                )
            else:
                print(f'    {Fore.YELLOW}Domain Controllers: none{Style.RESET_ALL}')

            site_subnets = subnets.get(name, [])
            if site_subnets:
                print(f'    {Fore.CYAN}IP Subnets ({len(site_subnets)}):{Style.RESET_ALL}')
                self._print_branch(
                    site_subnets,
                    lambda net: self._column(net['subnet'], 20, self._suffix(net), Fore.GREEN),
                )
            else:
                print(f'    {Fore.YELLOW}IP Subnets: none{Style.RESET_ALL}')
            print()

        if orphan_subnets and not self.args.site:
            print(f' {Fore.WHITE}{Style.BRIGHT}Subnets not linked to any site ({len(orphan_subnets)}):{Style.RESET_ALL}')
            self._print_branch(
                orphan_subnets,
                lambda net: self._column(net['subnet'], 20, self._suffix(net), Fore.GREEN),
            )
            print()

        total_dcs = sum(len(servers.get(name, [])) for name in names)
        total_subnets = sum(len(subnets.get(name, [])) for name in names)
        summary = f'{len(names)} site(s), {total_dcs} DC(s), {total_subnets} subnet(s)'
        if orphan_subnets and not self.args.site:
            summary += f', {len(orphan_subnets)} unlinked subnet(s)'
        self.log.info(summary)
