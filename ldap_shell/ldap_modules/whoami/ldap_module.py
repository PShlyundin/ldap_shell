import logging
from ldap3 import Connection
from ldapdomaindump import domainDumper
from pydantic import BaseModel
from ldap_shell.ldap_modules.base_module import BaseLdapModule
from ldap_shell.utils import current_sam
from ldap_shell.utils.ldap_utils import LdapUtils

UAC_FLAGS = {
    0x0002: 'ACCOUNTDISABLE',
    0x0010: 'LOCKOUT',
    0x0020: 'PASSWD_NOTREQD',
    0x10000: 'DONT_EXPIRE_PASSWORD',
    0x40000: 'SMARTCARD_REQUIRED',
    0x80000: 'TRUSTED_FOR_DELEGATION',
    0x100000: 'NOT_DELEGATED',
    0x400000: 'DONT_REQUIRE_PREAUTH',
    0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
}


class LdapShellModule(BaseLdapModule):
    """Show the current LDAP identity, groups and useful flags"""

    help_text = "Show current bind identity, groups and account flags"
    examples_text = """
    `whoami`
    ```
    [INFO] bind: DOMAIN\\admin
    [INFO] dn: CN=admin,CN=Users,DC=domain,DC=local
    [INFO] groups: Domain Admins, Enterprise Admins
    ```
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
        sam = current_sam(self.client)
        who = None
        try:
            who = self.client.extend.standard.who_am_i()
        except Exception:
            pass
        self.log.info('bind: %s', self.client.user)
        if who:
            self.log.info('whoami: %s', who)
        self.log.info('host: %s ssl=%s start_tls=%s', self.client.server.host, bool(self.client.server.ssl), bool(self.client.tls_started))

        dn = LdapUtils.get_dn(self.client, self.domain_dumper, sam)
        if not dn:
            return
        self.client.search(
            self.domain_dumper.root,
            LdapUtils.dn_filter(dn),
            attributes=['sAMAccountName', 'objectSid', 'memberOf', 'userAccountControl', 'servicePrincipalName', 'adminCount']
        )
        if not self.client.entries:
            return
        entry = self.client.entries[0]
        self.log.info('dn: %s', dn)
        self.log.info('sid: %s', entry['objectSid'].value)
        uac = int(entry['userAccountControl'].value or 0)
        flags = [name for bit, name in UAC_FLAGS.items() if uac & bit]
        self.log.info('uac: %s (%s)', uac, ', '.join(flags) or 'none')
        if entry['adminCount'].value:
            self.log.info('adminCount: %s', entry['adminCount'].value)
        groups = entry['memberOf'].values if 'memberOf' in entry else []
        if groups:
            pretty = [LdapUtils.get_name_from_dn(g) for g in groups]
            self.log.info('groups: %s', ', '.join(pretty))
        spns = entry['servicePrincipalName'].values if 'servicePrincipalName' in entry else []
        if spns:
            self.log.info('spn: %s', ', '.join(spns))
