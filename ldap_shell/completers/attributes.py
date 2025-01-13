from prompt_toolkit.completion import FuzzyWordCompleter, Completion
from prompt_toolkit.document import Document
from .base import BaseArgumentCompleter

class AttributesCompleter(BaseArgumentCompleter):
    """Completer for LDAP attributes"""
    
    COMMON_LDAP_ATTRIBUTES = [
		'objectSid', 'objectGUID', 'objectClass', 'cn', 'sn', 'givenName', 'displayName',
		'name', 'sAMAccountName', 'sAMAccountType', 'userPrincipalName', 'userAccountControl',
		'accountExpires', 'adminCount', 'badPasswordTime', 'badPwdCount', 'codePage',
		'countryCode', 'description', 'distinguishedName', 'groupType', 'homeDirectory',
		'homeDrive', 'lastLogoff', 'lastLogon', 'lastLogonTimestamp', 'logonCount',
		'mail', 'memberOf', 'primaryGroupID', 'profilePath', 'pwdLastSet',
		'scriptPath', 'servicePrincipalName', 'trustDirection', 'trustType',
		'whenChanged', 'whenCreated', 'objectCategory', 'dSCorePropagationData',
		'instanceType', 'uSNChanged', 'uSNCreated'
	]
    
    def get_completions(self, document: Document, complete_event, current_word: str) -> list[Completion]:
        # Разбиваем текущий ввод на части по запятой
        if ',' in current_word:
            prefix = ','.join(current_word.split(',')[:-1]) + ','
            current_word = current_word.split(',')[-1].strip()
        else:
            prefix = ''
            
        # Создаем словарь с описаниями атрибутов
        meta_dict = {attr: "LDAP attribute" for attr in self.COMMON_LDAP_ATTRIBUTES}
        
        # Используем FuzzyWordCompleter для атрибутов
        completer = FuzzyWordCompleter(
            words=self.COMMON_LDAP_ATTRIBUTES,
            meta_dict=meta_dict
        )
        
        completions = []
        for completion in completer.get_completions(Document(current_word.lower()), complete_event):
            new_text = prefix + completion.text
            completions.append(Completion(
                new_text,
                start_position=-len(current_word) - len(prefix),
                display=completion.display,
                display_meta=completion.display_meta
            ))
        
        return completions 