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
        
        # Convert current word to lowercase for comparison
        current_word_lower = current_word.lower()
        
        # Create list of tuples (module, similarity ratio)
        matches = []
        for module in list_modules:
            # Check inclusion case-insensitive
            module_lower = module.lower()
            
            # Calculate similarity ratio
            ratio = SequenceMatcher(None, current_word_lower, module_lower).ratio()
            
            # If current word is substring of module or vice versa,
            # or similarity ratio is greater than 0.5
            if (current_word_lower in module_lower or 
                module_lower in current_word_lower or 
                ratio > 0.5):
                matches.append((module, ratio))
        
        # Sort by similarity ratio
        matches.sort(key=lambda x: x[1], reverse=True)
        
        # Create completion for each match
        for module, ratio in matches:
            completions.append(
                Completion(
                    module, 
                    start_position=-len(current_word),
                    display_meta=f'{ModuleLoader.load_module(module).__doc__}'
                )
            )
            
        return completions