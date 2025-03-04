from prompt_toolkit.completion import Completion
from prompt_toolkit.document import Document
from .base import BaseArgumentCompleter
from ldap_shell.utils.module_loader import ModuleLoader
from difflib import SequenceMatcher

class CommandCompleter(BaseArgumentCompleter):
    """Completer for LDAP commands with fuzzy matching"""

    def get_completions(self, document: Document, complete_event, current_word: str) -> list[Completion]:
        list_modules = ModuleLoader.list_modules()
        completions = []
        
        # Преобразуем текущее слово в нижний регистр для сравнения
        current_word_lower = current_word.lower()
        
        # Создаем список кортежей (модуль, коэффициент схожести)
        matches = []
        for module in list_modules:
            # Проверяем вхождение без учета регистра
            module_lower = module.lower()
            
            # Вычисляем коэффициент схожести
            ratio = SequenceMatcher(None, current_word_lower, module_lower).ratio()
            
            # Если текущее слово является подстрокой модуля или наоборот,
            # или коэффициент схожести больше 0.5
            if (current_word_lower in module_lower or 
                module_lower in current_word_lower or 
                ratio > 0.5):
                matches.append((module, ratio))
        
        # Сортируем по коэффициенту схожести
        matches.sort(key=lambda x: x[1], reverse=True)
        
        # Создаем completion для каждого совпадения
        for module, ratio in matches:
            completions.append(
                Completion(
                    module, 
                    start_position=-len(current_word),
                    display_meta=f'Module: {module} (match: {ratio:.2f})'
                )
            )
            
        return completions
        