from pathlib import Path
from prompt_toolkit.completion import Completion
from prompt_toolkit.document import Document
from .base import BaseArgumentCompleter
import os

class DirectoryCompleter(BaseArgumentCompleter):
    """Completer for directory paths"""
    
    def get_completions(self, document: Document, complete_event, current_word: str) -> list[Completion]:
        completions = []
        
        try:
            # Get path for autocompletion
            if not current_word or current_word == '/':
                directory = Path.cwd()
                current_word = ''
            elif os.path.isabs(current_word):
                directory = Path(current_word).parent if not current_word.endswith('/') else Path(current_word)
            else:
                directory = (Path.cwd() / current_word).parent if not current_word.endswith('/') else Path.cwd() / current_word
                
            for item in directory.iterdir():
                if item.is_dir():
                    display_name = item.name + '/'
                    completion = str(item.relative_to(Path.cwd())) + '/' if not os.path.isabs(current_word) else str(item.absolute()) + '/'
                    
                    if completion.startswith(current_word):
                        completions.append(Completion(
                            completion,
                            start_position=-len(current_word),
                            display=display_name,
                            display_meta="Directory"
                        ))
                        
        except (PermissionError, FileNotFoundError):
            pass
            
        return completions 