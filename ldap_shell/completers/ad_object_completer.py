from prompt_toolkit.completion import WordCompleter, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import HTML
from .base import BaseArgumentCompleter
from typing import Union
from abc import abstractmethod

class ADObjectCompleter(BaseArgumentCompleter):
    """Completer for AD objects (users, computers, groups, OUs)"""
    highlight_color = None  # Базовый цвет, переопределяется в наследниках
    
    def __init__(self, ldap_connection, domain_dumper):
        self.ldap = ldap_connection
        self.domain_dumper = domain_dumper
        self.bottom_toolbar = HTML('<style bg="ansired"> Loading AD objects... </style>')
        self._cached_objects = None
        #super().__init__([], ignore_case=True)

    def get_completions(self, document: Document, complete_event, current_word=None):
        if not isinstance(document, Document):
            return
        
        text = document.text_before_cursor
        in_quotes = (text.count('"') % 2) == 1 or (text.count("'") % 2) == 1
        
        if not self._cached_objects:
            self._cached_objects = self._get_ad_objects()
        
        word_before_cursor = text.split()[-1] if text.split() else ''
        
        for obj in self._cached_objects:
            if ' ' in obj and not in_quotes:
                obj = f'"{obj}"'
                
            if word_before_cursor.lower() in obj.lower():
                display = self._highlight_match(obj, word_before_cursor)
                if self.highlight_color:
                    display = f"<style bg='{self.highlight_color}'>{display}</style>"
                yield Completion(
                    obj,
                    start_position=-len(word_before_cursor),
                    display=HTML(display)
                )

    def _highlight_match(self, text: str, substr: str) -> str:
        """Highlights the matching part of the text"""
        if not substr:
            return text
            
        index = text.lower().find(substr.lower())
        if index >= 0:
            before = text[:index]
            match = text[index:index + len(substr)]
            after = text[index + len(substr):]
            return f"{before}<b><style fg='black'>{match}</style></b>{after}"
        return text

    def _get_ad_objects(self):
        objects = set()
        #ldap_filter = '(|'\
        #             '(objectClass=user)'\
        #             '(objectClass=computer)'\
        #             '(objectClass=group)'\
        #             '(objectClass=organizationalUnit))'
        ldap_filter = self.get_ldap_filter()
        
        try:
            self.ldap.search(
                self.domain_dumper.root,
                ldap_filter,
                attributes=['sAMAccountName', 'name']
            )
            
            for entry in self.ldap.entries:
                if hasattr(entry, 'sAMAccountName'):
                    objects.add(str(entry.sAMAccountName))
                elif hasattr(entry, 'name'):
                    objects.add(str(entry.name))
            
        except Exception as e:
            self.log.error(f"Error fetching AD objects: {str(e)}")
            
        self.bottom_toolbar = ''
        return objects 
   
    @abstractmethod
    def get_ldap_filter(self):
        """Each inheritor must define its own LDAP filter"""
        pass

class UserCompleter(ADObjectCompleter):
    highlight_color = "ansibrightgreen"  # Яркий зеленый фон для пользователей
    
    def get_ldap_filter(self):
        return "(&(objectCategory=person)(objectClass=user))"

class ComputerCompleter(ADObjectCompleter):
    highlight_color = "ansibrightred"  # Яркий красный фон для компьютеров
    
    def get_ldap_filter(self):
        return "(objectClass=computer)"

class GroupCompleter(ADObjectCompleter):
    highlight_color = "ansibrightyellow"  # Яркий желтый фон для групп
    
    def get_ldap_filter(self):
        return "(objectClass=group)"

class OUCompleter(ADObjectCompleter):
    highlight_color = "ansibrightmagenta"  # Яркий фиолетовый фон для OU
    
    def get_ldap_filter(self):
        return "(objectClass=organizationalUnit)"