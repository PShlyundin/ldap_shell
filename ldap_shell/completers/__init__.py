from itertools import chain
from typing import Union, List, Type
from .base import BaseArgumentCompleter
from .ad_object_completer import ADObjectCompleter, UserCompleter, ComputerCompleter, GroupCompleter, OUCompleter
from ..ldap_modules.base_module import ArgumentType
from .directory import DirectoryCompleter
from .attributes import AttributesCompleter
from collections import defaultdict

COMPLETERS = {
        ArgumentType.DIRECTORY: DirectoryCompleter,
        ArgumentType.USER: UserCompleter,
        ArgumentType.COMPUTER: ComputerCompleter,
        ArgumentType.GROUP: GroupCompleter,
        ArgumentType.OU: OUCompleter,
        ArgumentType.ATTRIBUTES: AttributesCompleter,
    }

class CompleterFactory:
    @staticmethod
    def create_completer(
        arg_type: Union[List[str], str], 
        client=None, 
        domain_dumper=None
    ) -> BaseArgumentCompleter:
        """
        Creates a completer or multiple completers based on argument type(s)
        Returns a MultiCompleter if multiple types are provided
        """
        # Преобразуем одиночный тип в список для единообразной обработки
        arg_types = [arg_type] if not isinstance(arg_type, list) else arg_type
        
        completers = []
        for arg_type in arg_types:
            completer_class = COMPLETERS.get(arg_type)
            if completer_class:
                if issubclass(completer_class, ADObjectCompleter):
                    completers.append(completer_class(client, domain_dumper))
                else:
                    completers.append(completer_class())
                    
        if not completers:
            return None
            
        # Если только один комплитер, возвращаем его
        if len(completers) == 1:
            return completers[0]
            
        # Если несколько комплитеров, оборачиваем их в MultiCompleter
        return MultiCompleter(completers)


class MultiCompleter(BaseArgumentCompleter):
    """Completer that combines results from multiple completers"""
    
    def __init__(self, completers: List[BaseArgumentCompleter]):
        self.completers = completers
        self.max_total_suggestions = 10
        
    def get_completions(self, document, complete_event, current_word: str):
        # Получаем все возможные дополнения от каждого комплитера
        all_completions = defaultdict(list)
        for completer in self.completers:
            completions = list(completer.get_completions(document, complete_event, current_word))
            if completions:  # Добавляем только если есть результаты
                all_completions[completer] = completions
                
        if not all_completions:
            return
            
        # Вычисляем, сколько подсказок брать от каждого комплитера
        num_completers = len(all_completions)
        base_per_completer = max(1, self.max_total_suggestions // num_completers)
        remaining = self.max_total_suggestions - (base_per_completer * num_completers)
        
        # Распределяем подсказки
        for completer, completions in all_completions.items():
            # Если это последний комплитер, отдаем ему оставшиеся слоты
            if remaining > 0 and completer == list(all_completions.keys())[-1]:
                num_suggestions = base_per_completer + remaining
            else:
                num_suggestions = base_per_completer
                
            # Выдаем подсказки для текущего комплитера
            for completion in completions[:num_suggestions]:
                yield completion