from prompt_toolkit.completion import WordCompleter, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import HTML
from .base import BaseArgumentCompleter
from typing import Union
from abc import abstractmethod

class ADObjectCompleter(BaseArgumentCompleter):
    """Completer for AD objects (users, computers, groups, OUs)"""
    highlight_color = None  # Базовый цвет, переопределяется в наследниках
    attributes = ['sAMAccountName', 'name']  # Базовый набор атрибутов
    
    def __init__(self, ldap_connection, domain_dumper):
        self.ldap = ldap_connection
        self.domain_dumper = domain_dumper
        self._cached_objects = None

    def get_completions(self, document: Document, complete_event, current_word=None):
        if not isinstance(document, Document):
            return
        
        text = document.text_before_cursor
        in_quotes = (text.count('"') % 2) == 1 or (text.count("'") % 2) == 1
        
        if not self._cached_objects:
            self._cached_objects = self._get_ad_objects()
        
        if text.endswith(' '):
            word_before_cursor = ''
        else:
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
        ldap_filter = self.get_ldap_filter()
        
        try:
            self.ldap.search(
                self.domain_dumper.root,
                ldap_filter,
                attributes=self.attributes
            )
            
            for entry in self.ldap.entries:
                # Для каждого типа объекта свой приоритет атрибутов
                if hasattr(entry, self.primary_attribute):
                    objects.add(str(getattr(entry, self.primary_attribute)))
                elif hasattr(entry, self.fallback_attribute):
                    objects.add(str(getattr(entry, self.fallback_attribute)))
            
        except Exception as e:
            print(f"Error fetching AD objects: {str(e)}")
            
        return objects 
   
    @abstractmethod
    def get_ldap_filter(self):
        """Each inheritor must define its own LDAP filter"""
        pass

class UserCompleter(ADObjectCompleter):
    highlight_color = "ansibrightgreen"  # Яркий зеленый фон для пользователей
    primary_attribute = 'sAMAccountName'
    fallback_attribute = 'name'
    
    def get_ldap_filter(self):
        return "(&(objectCategory=person)(objectClass=user))"

class ComputerCompleter(ADObjectCompleter):
    highlight_color = "ansibrightred"  # Яркий красный фон для компьютеров
    primary_attribute = 'sAMAccountName'
    fallback_attribute = 'name'
    
    def get_ldap_filter(self):
        return "(objectClass=computer)"

class GroupCompleter(ADObjectCompleter):
    highlight_color = "ansibrightyellow"  # Яркий желтый фон для групп
    primary_attribute = 'sAMAccountName'
    fallback_attribute = 'name'
    
    def get_ldap_filter(self):
        return "(objectClass=group)"

class OUCompleter(ADObjectCompleter):
    highlight_color = "ansibrightmagenta"  # Яркий фиолетовый фон для OU
    primary_attribute = 'name'
    fallback_attribute = 'distinguishedName'
    attributes = ['name', 'distinguishedName']  # Переопределяем атрибуты для OU
    
    def get_ldap_filter(self):
        return "(objectClass=organizationalUnit)"