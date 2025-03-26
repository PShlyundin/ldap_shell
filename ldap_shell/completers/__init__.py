from itertools import chain
from typing import Union, List, Type
from .base import BaseArgumentCompleter
from .ad_object_completer import ADObjectCompleter, UserCompleter, ComputerCompleter, GroupCompleter, OUCompleter
from ..ldap_modules.base_module import ArgumentType
from .directory import DirectoryCompleter
from .attributes import AttributesCompleter
from .command import CommandCompleter
from collections import defaultdict
from .rbcd_completer import RBCDCompleter
from .dn_completer import DNCompleter
from .add_del_completer import AddDelCompleter
from .mask_completer import MaskCompleter
from .boolean_completer import BooleanCompleter
from .action_completer import ActionCompleter

COMPLETERS = {
        ArgumentType.DIRECTORY: DirectoryCompleter,
        ArgumentType.USER: UserCompleter,
        ArgumentType.COMPUTER: ComputerCompleter,
        ArgumentType.GROUP: GroupCompleter,
        ArgumentType.OU: OUCompleter,
        ArgumentType.ATTRIBUTES: AttributesCompleter,
        ArgumentType.COMMAND: CommandCompleter,
        ArgumentType.RBCD: RBCDCompleter,
        ArgumentType.DN: DNCompleter,
        ArgumentType.ADD_DEL: AddDelCompleter,
        ArgumentType.MASK: MaskCompleter,
        ArgumentType.BOOLEAN: BooleanCompleter,
        ArgumentType.ACTION: ActionCompleter
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
        # Convert single type to list for uniform processing
        arg_types = [arg_type] if not isinstance(arg_type, list) else arg_type
        
        completers = []
        for arg_type in arg_types:
            completer_class = COMPLETERS.get(arg_type)
            if completer_class:
                if issubclass(completer_class, ADObjectCompleter) or issubclass(completer_class, RBCDCompleter) or issubclass(completer_class, DNCompleter):
                    completers.append(completer_class(client, domain_dumper))
                else:
                    completers.append(completer_class())
        if not completers:
            return None
        
        return MultiCompleter(completers)


class MultiCompleter(BaseArgumentCompleter):
    """Completer that combines results from multiple completers"""
    
    def __init__(self, completers: List[BaseArgumentCompleter]):
        self.completers = completers
        self.max_total_suggestions = 20
        
    def get_completions(self, document, complete_event, current_word: str):
        # Get all possible completions from each completer
        all_completions = defaultdict(list)
        for completer in self.completers:
            completions = list(completer.get_completions(document, complete_event, current_word))
            if completions:  # Add only if there are results
                all_completions[completer] = completions
        if not all_completions:
            return None
            
        # Calculate how many suggestions to take from each completer
        num_completers = len(all_completions)
        base_per_completer = max(1, self.max_total_suggestions // num_completers)
        remaining = self.max_total_suggestions - (base_per_completer * num_completers)
        # Distribute suggestions
        for completer, completions in all_completions.items():
            # If this is the last completer, give it the remaining slots
            if remaining > 0 and completer == list(all_completions.keys())[-1]:
                num_suggestions = base_per_completer + remaining
            else:
                num_suggestions = base_per_completer
                
            # Yield suggestions for current completer
            for completion in completions[:num_suggestions]:
                yield completion