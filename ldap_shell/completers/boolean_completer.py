from prompt_toolkit.completion import Completion
from prompt_toolkit.document import Document
from .base import BaseArgumentCompleter

class BooleanCompleter(BaseArgumentCompleter):
    """Completer for boolean actions"""
    
    def get_completions(self, document: Document, complete_event, current_word: str) -> list[Completion]:
        completions = []
        
        options = ['true', 'false']
        
        for option in options:
            if option.startswith(current_word.lower()):
                completions.append(Completion(
                    option,
                    start_position=-len(current_word),
                    display=option,
                    display_meta="Action"
                ))
                
        return completions