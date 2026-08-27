import logging

from ldap3 import BASE, Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel

from ldap_shell.ldap_modules.base_module import BaseLdapModule

DOMAIN_ATTRS = [
    'minPwdLength', 'pwdHistoryLength', 'pwdProperties',
    'minPwdAge', 'maxPwdAge', 'lockoutThreshold',
    'lockoutDuration', 'lockoutObservationWindow',
]
PSO_ATTRS = [
    'cn', 'msDS-PasswordSettingsPrecedence',
    'msDS-MinimumPasswordLength', 'msDS-PasswordHistoryLength',
    'msDS-PasswordComplexityEnabled', 'msDS-PasswordReversibleEncryptionEnabled',
    'msDS-MinimumPasswordAge', 'msDS-MaximumPasswordAge',
    'msDS-LockoutThreshold', 'msDS-LockoutDuration',
    'msDS-LockoutObservationWindow', 'msDS-PSOAppliesTo',
]
COMPLEX = 1


def filetime_span(value) -> str:
    """Render an AD FILETIME interval (100-ns ticks, usually negative)."""
    if value is None:
        return '-'
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return str(value)
    if ticks == 0 or ticks == -0x8000000000000000:
        return 'never'
    seconds = abs(ticks) / 10_000_000
    if seconds >= 86400:
        return f'{seconds / 86400:.1f}d'
    if seconds >= 3600:
        return f'{seconds / 3600:.1f}h'
    return f'{seconds / 60:.1f}m'


class LdapShellModule(BaseLdapModule):
    """Show domain password policy, FGPP, and SASL mechanisms."""

    help_text = "Domain / FGPP password policy and DC SASL mechs"
    examples_text = """
    `get_policy`
    Inline: `ldap_shell domain.local/user:pass get_policy`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        pass

    def __init__(self, args_dict: dict, domain_dumper: domainDumper, client: Connection, log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def __call__(self):
        info = getattr(self.client.server, 'info', None)
        other = getattr(info, 'other', None) or {}
        sasl = other.get('supportedSASLMechanisms') or []
        if sasl:
            self.log.info(f'SASL: {", ".join(sasl)}')
        if not self.client.search(self.domain_dumper.root, '(objectClass=domain)', search_scope=BASE, attributes=DOMAIN_ATTRS):
            self.log.error(f'Failed to read domain policy: {self.client.result}')
        elif self.client.entries:
            entry = self.client.entries[0]
            props = int(entry['pwdProperties'].value or 0) if 'pwdProperties' in entry else 0
            self.log.info(
                f'domain policy: minLen={entry["minPwdLength"].value if "minPwdLength" in entry else "-"} '
                f'history={entry["pwdHistoryLength"].value if "pwdHistoryLength" in entry else "-"} '
                f'complex={"yes" if props & COMPLEX else "no"} '
                f'minAge={filetime_span(entry["minPwdAge"].value if "minPwdAge" in entry else None)} '
                f'maxAge={filetime_span(entry["maxPwdAge"].value if "maxPwdAge" in entry else None)} '
                f'lockout={entry["lockoutThreshold"].value if "lockoutThreshold" in entry else "-"}/'
                f'{filetime_span(entry["lockoutDuration"].value if "lockoutDuration" in entry else None)}'
            )

        pso_base = f'CN=Password Settings Container,CN=System,{self.domain_dumper.root}'
        if not self.client.search(pso_base, '(objectClass=msDS-PasswordSettings)', attributes=PSO_ATTRS):
            return
        if not self.client.entries:
            self.log.info('No fine-grained password policies')
            return
        self.log.info(f'FGPP: {len(self.client.entries)} PSO(s)')
        for entry in self.client.entries:
            applies = entry['msDS-PSOAppliesTo'].values if 'msDS-PSOAppliesTo' in entry else []
            self.log.info(
                f'  {entry["cn"].value}  prec={entry["msDS-PasswordSettingsPrecedence"].value} '
                f'minLen={entry["msDS-MinimumPasswordLength"].value} '
                f'complex={entry["msDS-PasswordComplexityEnabled"].value} '
                f'maxAge={filetime_span(entry["msDS-MaximumPasswordAge"].value if "msDS-MaximumPasswordAge" in entry else None)} '
                f'applies={len(applies)}'
            )
