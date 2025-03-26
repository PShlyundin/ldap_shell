from prompt_toolkit.completion import WordCompleter, Completion
from prompt_toolkit.document import Document
from .base import BaseArgumentCompleter
from prompt_toolkit.formatted_text import HTML
from ldap3 import SUBTREE
from ldap_shell.completers.base import ADObjectCacheManager

class DNCompleter(BaseArgumentCompleter):
    """Completer for DN"""
    def __init__(self, ldap_connection, domain_dumper):
        self.ldap = ldap_connection
        self.domain_dumper = domain_dumper
        self.cache_manager = ADObjectCacheManager()

    def get_completions(self, document: Document, complete_event, current_word=None):
        if not isinstance(document, Document):
            return

        text = document.text_before_cursor.replace('"', '')
        
        # Получаем кеш из менеджера
        cached_objects = self.cache_manager.get_cache(self.__class__.__name__)
        if cached_objects is None:
            cached_objects = self._get_ad_objects()
            self.cache_manager.set_cache(self.__class__.__name__, cached_objects)
        
        if text.endswith(' '):
            word_before_cursor = ''
        else:
            word_before_cursor = text.split()[-1] if text.split() else ''

        for obj in cached_objects:
            # Проверяем как identifier, так и DN
            if (word_before_cursor.lower() in obj['identifier'].lower() or
                word_before_cursor.lower() in obj['dn'].lower()):
                
                display = self._highlight_match(obj['identifier'], word_before_cursor)
                if obj['color']:
                    display = f"<style bg='{obj['color']}'>{display}</style>"
                yield Completion(
                    text = f"\"{obj['dn']}\"",
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
        objects = []
        COLOR_MAPPING = {
            'user': 'ansibrightgreen',
            'computer': 'ansibrightred',
            'group': 'ansibrightyellow',
            'ou': '#FF00FF',
            'domain_root': 'ansiblue',
            'gpo': 'ansibrightblue'
        }

        # Используем встроенный метод для пейджинации
        search_generator = self.ldap.extend.standard.paged_search(
            search_base=self.domain_dumper.root,
            search_filter='(objectClass=*)',
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'objectClass', 'sAMAccountName', 'ou', 'displayName', 'cn'],
            paged_size=500,
            generator=True
        )

        for entry in search_generator:
            if entry['type'] != 'searchResEntry':
                continue
            
            dn = entry['dn']
            obj_classes = entry['attributes'].get('objectClass', [])
            
            # Определяем тип
            if 'user' in obj_classes:
                obj_type = 'User'
                identifier = entry['attributes'].get('sAMAccountName', [''])
                highlight_color = COLOR_MAPPING['user']
            elif 'computer' in obj_classes:
                obj_type = 'Computer'
                identifier = entry['attributes'].get('sAMAccountName', [''])
                highlight_color = COLOR_MAPPING['computer']
            elif 'group' in obj_classes:
                obj_type = 'Group'
                identifier = entry['attributes'].get('sAMAccountName', [''])
                highlight_color = COLOR_MAPPING['group']
            elif 'organizationalUnit' in obj_classes:
                obj_type = 'OU'
                identifier = dn.split(',')[0].split('=')[1]
                highlight_color = COLOR_MAPPING['ou']
            elif 'domainDNS' in obj_classes and dn.count(',') == 1:
                obj_type = 'Domain Root'
                identifier = dn.split('=')[1].split(',')[0]
                highlight_color = COLOR_MAPPING['domain_root']
            elif 'groupPolicyContainer' in obj_classes:
                obj_type = 'GPO'
                # Получаем displayName или cn, учитывая возможное отсутствие атрибутов
                display_name = entry['attributes'].get('displayName', [None])
                cn_value = entry['attributes'].get('cn', [None])
                identifier = display_name or cn_value or dn.split(',')[0].split('=')[1]
                highlight_color = COLOR_MAPPING['gpo']
            else:
                continue

            obj_info = {
                "identifier": identifier,
                "type": obj_type,
                "dn": dn,
                "color": highlight_color
            }
            objects.append(obj_info)

        return objects
