from prompt_toolkit.completion import Completion
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.completion import Completer
from prompt_toolkit.key_binding import KeyBindings
from typing import Optional
import logging
import shlex

from ldap_shell.completers import CompleterFactory
from ldap_shell.utils.module_loader import ModuleLoader
from ldap_shell.utils import history
from ldap_shell.runner import CommandRunner
from ldap_shell.utils import current_sam


class ModuleCompleter(Completer):
    def __init__(self, modules, domain_dumper, client):
        self.modules = modules
        self.domain_dumper = domain_dumper
        self.client = client

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        try:
            words = shlex.split(text)
        except ValueError:
            words = shlex.split(text + '"')
        if text.endswith(' '):
            words.append('')

        if len(words) <= 1 and not text.endswith(' '):
            word = words[0] if words else ''
            for module_name in self.modules:
                if module_name.startswith(word):
                    yield Completion(
                        module_name,
                        start_position=-len(word),
                        display_meta=self.modules[module_name].__doc__
                    )
            return

        module_name = words[0]
        if module_name not in self.modules:
            return

        module_class = self.modules[module_name]
        arguments = module_class.get_arguments()
        current_arg_index = max(len(words) - 2, 0)
        if current_arg_index + 1 > len(arguments):
            return

        current_arg = arguments[current_arg_index]
        completer = CompleterFactory.create_completer(
            current_arg.arg_type,
            self.client,
            self.domain_dumper
        )
        if completer:
            current_word = document.get_word_before_cursor()
            yield from completer.get_completions(document, complete_event, current_word)


class ModuleSuggester(AutoSuggest):
    """Suggests hints from history and module arguments"""

    def __init__(self, modules, history):
        self.modules = modules
        self.history = history

    def get_suggestion(self, buffer, document) -> Optional[Suggestion]:
        text = document.text_before_cursor
        history_suggestion = self._get_history_suggestion(text)
        if history_suggestion:
            return history_suggestion
        return self._get_module_suggestion(text)

    def _get_history_suggestion(self, text: str) -> Optional[Suggestion]:
        if not text.strip():
            return None
        base_command = text.split()[0]
        last_full_command = None
        for entry in reversed(list(self.history.get_strings())):
            if entry.startswith(base_command + ' '):
                last_full_command = entry
                break
        if not last_full_command:
            return None
        if last_full_command.startswith(text):
            return Suggestion(last_full_command[len(text):])
        return None

    def _get_module_suggestion(self, text: str) -> Optional[Suggestion]:
        words = text.split()
        if len(words) == 0 or words[0] not in self.modules:
            return None
        module = self.modules[words[0]]
        args = module.get_arguments()
        current_arg_index = len(words) - 1
        if current_arg_index >= len(args):
            return None
        current_arg = args[current_arg_index]
        suggestion = f"{current_arg.name} " if current_arg.required else f"[{current_arg.name}] "
        return Suggestion(suggestion)


class Prompt:
    def __init__(self, domain_dumper, client, noninteractive=False):
        self.domain_dumper = domain_dumper
        self.client = client
        self.history = history
        self.noninteractive = noninteractive
        self.runner = CommandRunner(domain_dumper, client)
        self.modules = self.runner.modules
        self.prompt = f'{current_sam(self.client)}# '

        self.completer = ModuleCompleter(self.modules, domain_dumper=self.domain_dumper, client=self.client)
        self.suggester = ModuleSuggester(self.modules, self.history)
        self.kb = KeyBindings()

        @self.kb.add('enter')
        def _(event):
            b = event.current_buffer
            if b.complete_state and b.complete_state.current_completion:
                completion = b.complete_state.current_completion
                available_commands = ModuleLoader.list_modules()
                if completion.text in available_commands and ' ' not in b.document.text_before_cursor:
                    b.delete(len(b.document.text_after_cursor))
                    b.delete_before_cursor(len(b.document.text_before_cursor))
                    b.insert_text(completion.text + ' ')
                else:
                    text = b.document.text
                    cursor_position = b.document.cursor_position
                    text_before_cursor = text[:cursor_position]
                    if text_before_cursor.count('"') % 2 == 1:
                        quoted_words = shlex.split(text_before_cursor + '"')
                    else:
                        quoted_words = shlex.split(text_before_cursor)
                    last_word = quoted_words[-1]
                    if ',' in last_word and 'DC=' not in last_word:
                        del_word = last_word.split(',')[-1]
                    elif ' ' in last_word or '"' in last_word or 'DC=' in last_word:
                        del_word = f'"{last_word}"'
                    else:
                        del_word = last_word
                    last_separator = len(text_before_cursor) - len(del_word)
                    if last_separator >= 0:
                        chars_to_delete = cursor_position - last_separator
                        if chars_to_delete > 0:
                            b.delete_before_cursor(chars_to_delete)
                    else:
                        b.delete_before_cursor(len(text_before_cursor))
                    b.insert_text(completion.text)
                b.complete_state = None
                return
            event.current_buffer.validate_and_handle()

        @self.kb.add('tab')
        def _(event):
            b = event.current_buffer
            if b.complete_state:
                b.complete_next()
            else:
                b.start_completion(select_first=False)

    def parseline(self, line):
        return self.runner.parseline(line)

    def is_valid_line(self, line):
        cmd, arg, line = self.parseline(line)
        return bool(line and cmd)

    def _parse_arg_string(self, module_name: str, arg_string: str) -> dict:
        return self.runner.parse_args(module_name, arg_string)

    def parse_module_args(self, module_name: str, arg_string: str) -> dict:
        return self.runner.parse_args(module_name, arg_string)

    def execute_module(self, module_name: str, args_dict: dict):
        module = self.modules[module_name](
            args_dict,
            self.domain_dumper,
            self.client,
            logging.getLogger('ldap-shell')
        )
        return module()

    def check_args_exist(self, module_name: str, args_dict: dict):
        return not self.runner.missing_args(module_name, args_dict)

    def onecmd(self, line):
        result = self.runner.execute(line, capture=False)
        if result.prompt:
            self.prompt = result.prompt
        return result.prompt

    def cmdloop(self):
        self.session = PromptSession(
            self.prompt,
            completer=None if self.noninteractive else self.completer,
            complete_style=CompleteStyle.MULTI_COLUMN,
            history=self.history,
            auto_suggest=None if self.noninteractive else self.suggester,
            key_bindings=None if self.noninteractive else self.kb,
            complete_while_typing=not self.noninteractive
        )
        while True:
            try:
                line = self.session.prompt(self.prompt)
                if line.strip() == 'exit':
                    break
                prompt = self.onecmd(line)
                if prompt:
                    self.prompt = prompt
            except (KeyboardInterrupt, EOFError):
                break
