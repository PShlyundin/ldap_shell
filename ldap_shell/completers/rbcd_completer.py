from prompt_toolkit.completion import WordCompleter, Completion
from prompt_toolkit.document import Document
from .base import BaseArgumentCompleter
from ldap_shell.utils.ldaptypes import SR_SECURITY_DESCRIPTOR
from ldap_shell.utils.ace_utils import AceUtils
from ldap_shell.utils.ldap_utils import LdapUtils

class RBCDCompleter(BaseArgumentCompleter):
    def __init__(self, ldap_connection, domain_dumper):
        self.client = ldap_connection
        self.domain_dumper = domain_dumper

    def get_completions(self, document, complete_event, current_word):
        if not isinstance(document, Document):
            return
        
        text = document.text_before_cursor

        target = text.split()[-2]
        if text.endswith(' '):
            word_before_cursor = ''
            target = text.split()[-1]
        else:
            word_before_cursor = text.split()[-1]
        entry = self.client.search(
            self.domain_dumper.root,
            f'(sAMAccountName={target})',
            attributes=['msDS-AllowedToActOnBehalfOfOtherIdentity']
        )
        if not entry or len(self.client.entries) != 1:
            return
            
        sd_data = self.client.entries[0]['msDS-AllowedToActOnBehalfOfOtherIdentity'].raw_values
        users_list = []

        if sd_data:
            sd = SR_SECURITY_DESCRIPTOR(data=sd_data[0])
            for ace in sd['Dacl'].aces:
                sid = ace['Ace']['Sid'].formatCanonical()
                users_list.append(LdapUtils.sid_to_user(self.client, self.domain_dumper, sid))
        else:
            return

        for user in users_list:
            if word_before_cursor.lower() in user.lower():
                yield Completion(
                    user,
                    start_position=-len(word_before_cursor),
                    display=user
                )
