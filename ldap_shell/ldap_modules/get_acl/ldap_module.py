import logging
from ldap3 import Connection
import ldap3
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from colorama import init, Fore, Style
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap_shell.utils import acl_analysis as acl

init()

SEV_COLOR = {
    acl.CRIT: Fore.RED + Style.BRIGHT,
    acl.HIGH: Fore.YELLOW + Style.BRIGHT,
    acl.MED: Fore.CYAN,
    acl.LOW: Style.DIM,
}


class LdapShellModule(BaseLdapModule):
    """Module for analyzing the DACL of an AD object and highlighting abusable rights"""

    help_text = "Read and analyze an object's DACL: resolve trustees, decode rights, flag abusable ACEs and suggest the ldap_shell command to abuse them."
    examples_text = """
    # get_acl

    Reads the target's nTSecurityDescriptor, resolves every trustee (SID -> name),
    decodes the access mask and object-type GUID, and - the useful part - tags
    each abusable ACE with the concrete attack and the ldap_shell command to run.

    By default only *interesting* ACEs are shown: abusable rights held by
    non-privileged principals. Read-only ACEs and default admin trustees
    (Domain Admins, SYSTEM, ...) are hidden as noise.

    Analyze a user's DACL:
    `get_acl m.petrov`
    ```
    [INFO] DACL of CN=m.petrov,CN=Users,DC=corp,DC=local  (owner: Domain Admins)
    [INFO] 2 abusable ACE(s) of 41 (use `get_acl m.petrov all` for the full DACL)

     [CRIT] ALLOW  corp\\helpdesk (S-1-5-...-1109)
            rights : ForceChangePassword
            attack : Force password reset
            run    : change_password m.petrov <NewPass>
    ```

    Show the FULL DACL (including read-only / privileged trustees):
    `get_acl m.petrov all`

    Show only ACEs where a specific principal is the trustee:
    `get_acl "CN=Domain Admins,CN=Users,DC=corp,DC=local" j.doe`
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target object whose DACL to analyze (sAMAccountName or DN)",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER,
                      ArgumentType.GROUP, ArgumentType.DN]
        )
        filter: Optional[str] = Field(
            None,
            description="'all' to show the full DACL, or a principal (name/SID) to filter by trustee",
            arg_type=[ArgumentType.STRING, ArgumentType.USER,
                      ArgumentType.COMPUTER, ArgumentType.GROUP]
        )

    def __init__(self, args_dict: dict,
                 domain_dumper: domainDumper,
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')
        self._sid_cache = {}

    def _resolve_sid(self, sid):
        if sid in acl.WELL_KNOWN_SIDS:
            return acl.WELL_KNOWN_SIDS[sid]
        if sid in self._sid_cache:
            return self._sid_cache[sid]
        name = LdapUtils.sid_to_user(self.client, self.domain_dumper, sid)
        self._sid_cache[sid] = name or sid
        return self._sid_cache[sid]

    def _read_sd(self, target_dn):
        # sdflags 0x07 = OWNER + GROUP + DACL
        self.client.search(
            self.domain_dumper.root,
            f'(distinguishedName={target_dn})',
            attributes=['nTSecurityDescriptor'],
            controls=ldap3.protocol.microsoft.security_descriptor_control(sdflags=0x07)
        )
        if not self.client.entries:
            return None
        raw = self.client.entries[0]['nTSecurityDescriptor'].raw_values
        if not raw:
            return None
        return SR_SECURITY_DESCRIPTOR(data=raw[0])

    def _print_finding(self, f, target_name):
        color = SEV_COLOR.get(f['severity'], '')
        verb = 'ALLOW' if f['allow'] else 'DENY '
        trustee = self._resolve_sid(f['sid'])
        tags = []
        if f['inherited']:
            tags.append('inherited')
        if not f['allow']:
            tags.append('DENY')
        tag_str = ('  [' + ', '.join(tags) + ']') if tags else ''

        print(f"{color} [{f['severity']}]{Style.RESET_ALL} {verb} "
              f"{Fore.WHITE}{Style.BRIGHT}{trustee}{Style.RESET_ALL} ({f['sid']}){tag_str}")

        # rights line
        rights = f['right_name'] or ', '.join(f['perms']) or f"0x{f['mask']:x}"
        print(f"        rights : {rights}")

        # attacks + suggested commands
        for label, sev, cmd in f['attacks']:
            ac = SEV_COLOR.get(sev, '')
            print(f"        attack : {ac}{label}{Style.RESET_ALL}")
            if cmd:
                cmd = cmd.replace('{target}', target_name)
                print(f"        run    : {Fore.GREEN}{cmd}{Style.RESET_ALL}")
        print()

    def __call__(self):
        # Resolve target DN
        target = self.args.target
        if target.lower().startswith(('cn=', 'ou=', 'dc=')):
            target_dn = target if LdapUtils.check_dn(self.client, self.domain_dumper, target) else None
        else:
            target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, target)
        if not target_dn:
            self.log.error(f'Target object not found: {target}')
            return
        target_name = LdapUtils.get_name_from_dn(target_dn)

        # Options: 'all' or a trustee filter
        show_all = False
        principal_sid = None
        if self.args.filter:
            if self.args.filter.lower() == 'all':
                show_all = True
            else:
                principal_sid = (self.args.filter if self.args.filter.upper().startswith('S-1-')
                                 else LdapUtils.get_sid(self.client, self.domain_dumper, self.args.filter))
                if not principal_sid:
                    self.log.error(f'Principal not found: {self.args.filter}')
                    return

        sd = self._read_sd(target_dn)
        if sd is None:
            self.log.error('Could not read nTSecurityDescriptor (need read access to it)')
            return

        owner_sid = sd['OwnerSid'].formatCanonical()
        owner_name = self._resolve_sid(owner_sid)

        aces = sd['Dacl'].aces if sd['Dacl'] else []
        total = len(aces)

        findings = []
        for ace in aces:
            f = acl.analyze_ace(ace)
            if f is None:
                continue
            if principal_sid and f['sid'] != principal_sid:
                continue
            if not show_all and not principal_sid:
                # noise filter: keep only abusable ACEs by non-privileged trustees
                if not f['attacks']:
                    continue
                if acl.is_privileged_sid(f['sid']):
                    continue
            findings.append(f)

        # Sort by severity (crit first), inherited last within same severity
        findings.sort(key=lambda x: (acl.SEVERITY_ORDER[x['severity']], x['inherited']))

        self.log.info(f"DACL of {target_dn}  (owner: {owner_name})")
        if show_all or principal_sid:
            scope = 'all ACEs' if show_all else f"ACEs for {self.args.filter}"
            self.log.info(f"{len(findings)} of {total} {scope}")
        else:
            self.log.info(f"{len(findings)} abusable ACE(s) of {total} "
                          f"(use `get_acl {target} all` for the full DACL)")
        print()

        if not findings:
            self.log.info('No matching ACEs.' if (show_all or principal_sid)
                          else 'No abusable ACEs found for non-privileged principals.')
            return

        for f in findings:
            self._print_finding(f, target_name)
