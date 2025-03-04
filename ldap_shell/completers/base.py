from abc import ABC, abstractmethod
from prompt_toolkit.completion import Completion
from prompt_toolkit.document import Document

class BaseArgumentCompleter(ABC):
    """Base class for argument completers"""
    
    @abstractmethod
    def get_completions(self, document: Document, complete_event, current_word: str) -> list[Completion]:
        """Return list of completions for current word"""
        pass