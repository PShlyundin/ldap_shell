from abc import ABC, abstractmethod
from prompt_toolkit.completion import Completion
from prompt_toolkit.document import Document
from typing import Dict, Optional
import threading
from ldap_shell.utils import history

class BaseArgumentCompleter(ABC):
    """Base class for argument completers"""
    
    @abstractmethod
    def get_completions(self, document: Document, complete_event, current_word: str) -> list[Completion]:
        """Return list of completions for current word"""
        pass

class ADObjectCacheManager:
    """Singleton менеджер кеша для AD объектов"""
    _instance = None
    _lock = threading.Lock()
    _caches: Dict[str, Dict] = {}
    _last_history_position = 0
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def _should_refresh_cache(self) -> bool:
        """Проверяет, нужно ли обновить кеш на основе новых команд в истории"""
        try:
            # Получаем все команды из истории
            history_commands = list(history.get_strings())
            current_position = len(history_commands)
            
            # Если позиция изменилась, проверяем новые команды
            if current_position > self._last_history_position:
                # Проверяем только новые команды
                new_commands = history_commands[self._last_history_position:]
                self._last_history_position = current_position
                
                # Проверяем, есть ли среди новых команд add_ или del_
                return any(
                    any(cmd in command for cmd in ['add_', 'del_'])
                    for command in new_commands
                )
                
            return False
        except Exception:
            return False
    
    def get_cache(self, completer_type: str) -> Optional[set]:
        """Получить кеш для определенного типа комплитера"""
        cache_data = self._caches.get(completer_type)
        if cache_data is None:
            return None
            
        # Проверяем, нужно ли обновить кеш
        if self._should_refresh_cache():
            return None
            
        return cache_data['objects']
    
    def set_cache(self, completer_type: str, objects: set):
        """Установить кеш для определенного типа комплитера"""
        self._caches[completer_type] = {
            'objects': objects
        }
    
    def clear_cache(self, completer_type: Optional[str] = None):
        """Очистить кеш для определенного типа комплитера или все кеши"""
        if completer_type:
            self._caches.pop(completer_type, None)
        else:
            self._caches.clear()