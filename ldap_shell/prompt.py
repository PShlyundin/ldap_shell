from prompt_toolkit.completion import FuzzyWordCompleter, Completion
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory, AutoSuggest, Suggestion
from prompt_toolkit.history import FileHistory
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.formatted_text import HTML
import string
from ldap_shell.helper import Helper
import os
import importlib
import logging
from pydantic import ValidationError
from prompt_toolkit.completion import Completer
from pathlib import Path
from ldap_shell.ldap_modules.base_module import ArgumentType
from prompt_toolkit.document import Document
from prompt_toolkit.auto_suggest import ConditionalAutoSuggest
from prompt_toolkit.key_binding import KeyBindings
from ldap_shell.completers import CompleterFactory
import shlex

class ShellCompleter(FuzzyWordCompleter):
	def __init__(self, list_commands, meta):
		self.list_commands = list_commands
		self.meta = meta

	def get_completions(self, document, complete_event):
		word = document.text_before_cursor
		if not " " in word:
			for command in self.list_commands:
				if command.startswith(word):
					display = HTML("%s<b></b> ") % (command)
					yield Completion(
						command,
						start_position=-len(word),
						display=display,
						display_meta=self.meta.get(command),
					)

class ModuleCompleter(Completer):
	def __init__(self, modules, domain_dumper, client):
		self.modules = modules
		self.domain_dumper = domain_dumper
		self.client = client
		
	def get_completions(self, document, complete_event):
		text = document.text_before_cursor
		words = text.split()
		
		# If this is the first word - suggest modules
		if len(words) <= 1:
			word = words[0] if words else ''
			for module_name in self.modules:
				if module_name.startswith(word):
					yield Completion(
						module_name,
						start_position=-len(word),
						display_meta=self.modules[module_name].LdapShellModule.__doc__
					)
			return

		# Get current module and argument
		module_name = words[0]
		if not any(module_name.startswith(m) for m in self.modules):
			return
			
		module_class = self.modules[module_name].LdapShellModule
		arguments = module_class.get_arguments()
		
		# Determine which argument needs suggestions
		current_arg_index = len(words) - 2
		if current_arg_index >= len(arguments):
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
			

class ModuleAutoSuggest(AutoSuggest):
	def __init__(self, modules):
		self.modules = modules

	def get_suggestion(self, buffer, document: Document):
		text = document.text
		words = text.split()

		if not words:
			return None

		module_name = words[0]
		if module_name not in self.modules:
			return None

		module_class = self.modules[module_name].LdapShellModule
		arguments = module_class.get_arguments()
		
		# Determine current argument
		current_arg_index = len(words) - 1
		if current_arg_index >= len(arguments):
			return None

		current_arg = arguments[current_arg_index]
		
		# If current argument is a directory
		if current_arg.arg_type == ArgumentType.DIRECTORY:
			current_word = words[-1] if len(words) > 1 else ''
			
			# If user has already started typing path, don't suggest
			if current_word:
				return None
				
			# Suggest current directory
			cwd = str(Path.cwd()) + '/'
			# If last character is space, add suggestion
			if text.endswith(' '):
				return Suggestion(cwd)
			
		return None

class MultiAutoSuggest(AutoSuggest):
	def __init__(self, suggesters):
		self.suggesters = suggesters

	def get_suggestion(self, buffer, document):
		for suggester in self.suggesters:
			suggestion = suggester.get_suggestion(buffer, document)
			if suggestion:
				return suggestion
		return None

class Prompt:
	def __init__(self, domain_dumper, client):
		self.domain_dumper = domain_dumper
		self.client = client
		self.prompt = '# '
		self.history = FileHistory(os.path.expanduser('~/.ldap_shell_history'))
		self.helper = Helper()
		self.meta = self.helper.get_meta()
		self.identchars = string.ascii_letters + string.digits + '_'

		self.modules = {}
		self.load_modules()

		self.completer = ModuleCompleter(self.modules, domain_dumper=self.domain_dumper, client=self.client)

		# Create key bindings
		self.kb = KeyBindings()
		
		@self.kb.add('enter')
		def _(event):
			"""Handle Enter press"""
			b = event.current_buffer

			# Если есть активное состояние автодополнения
			if b.complete_state and b.complete_state.current_completion:
				completion = b.complete_state.current_completion

				# Получаем список команд
				available_commands = self.list_modules()

				# Если completion - это команда
				if completion.text in available_commands:
					# Удаляем весь текст
					b.delete(len(b.document.text_after_cursor))  # сначала после курсора
					b.delete_before_cursor(len(b.document.text_before_cursor))  # затем до курсора
					# Вставляем команду
					b.insert_text(completion.text + ' ')
				else:
					# Для аргументов: находим последний пробел или запятую перед курсором
					text = b.document.text
					cursor_position = b.document.cursor_position
					text_before_cursor = text[:cursor_position]

					# Находим позицию последнего разделителя (пробел или запятая)
					if text_before_cursor.find('"') %2 == 1:
						quoted_words = shlex.split(text_before_cursor+'"')
					else:
						quoted_words = shlex.split(text_before_cursor)

					last_word = quoted_words[-1]

					if ',' in last_word:
						del_word = last_word.split(',')[-1]
					elif ' ' in last_word:
						del_word = f'"{last_word}"'
					else:
						del_word = last_word

					last_separator = len(text_before_cursor) - len(del_word)

					if last_separator >= 0:
						# Удаляем текст от последнего разделителя до курсора
						chars_to_delete = cursor_position - (last_separator)
						if chars_to_delete > 0:
							b.delete_before_cursor(chars_to_delete)
					else:
						# Если разделитель не найден, удаляем весь текст до курсора
						b.delete_before_cursor(len(text_before_cursor))

					b.insert_text(completion.text)
				
				# Очищаем состояние автодополнения
				b.complete_state = None
				return

			# Если нет активного автодополнения - выполняем команду
			event.current_buffer.validate_and_handle()	

		@self.kb.add('tab')
		def _(event):
			"""Handle Tab press"""
			b = event.current_buffer
			
			if b.complete_state:
				b.complete_next()
			else:
				if b.suggestion and b.suggestion.text:
					b.insert_text(b.suggestion.text)
				else:
					b.start_completion(select_first=False)

	@staticmethod
	def list_modules() -> list[str]:
		module_path = os.path.join(os.path.dirname(__file__), 'ldap_modules')
		modules = os.listdir(module_path)
		modules_list = []
		for module in modules:
			if os.path.isdir(os.path.join(module_path, module)) and not '__' in module and module != 'template':
				modules_list.append(module)
		return modules_list

	def load_modules(self):
		"""Load all modules from ldap_modules directory"""
		self.modules = {}
		modules_list = self.list_modules()
		for module_name in modules_list:
			module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
			self.modules[module_name] = module

	def parseline(self, line):
		line = line.strip()
		if not line:
			return None, None, line
		elif line[0] == '?':
			line = 'help ' + line[1:]
		i, n = 0, len(line)
		while i < n and line[i] in self.identchars: i = i+1
		cmd, arg = line[:i], line[i:].strip()
		return cmd, arg, line

	def is_valid_line(self, line):
		cmd, arg, line = self.parseline(line)
		if not line:
			return False
		if cmd is None:
			return False
		self.lastcmd = line
		if line == 'EOF' :
			self.lastcmd = ''
		if cmd == '':
			return False
		return True

	def _parse_arg_string(self, module_name: str, arg_string: str) -> dict:
		args_dict = {}
		
		# Используем shlex для корректного разбора строки с учетом кавычек
		try:
			args = shlex.split(arg_string)
		except ValueError as e:
			# Если есть незакрытые кавычки, пытаемся обработать как есть
			print(f"Warning: {e}")
			args = arg_string.strip().split()
		
		for i, value in enumerate(args):
			if i >= len(self.modules[module_name].LdapShellModule.get_arguments()):
				break
			arg_name = self.modules[module_name].LdapShellModule.get_arguments()[i].name
			args_dict[arg_name] = value
		return args_dict

	def parse_module_args(self, module_name: str, arg_string: str) -> dict:
		if module_name not in self.modules:
			raise ValueError(f"Module {module_name} not found")
			
		args_dict = self._parse_arg_string(module_name, arg_string)
		return args_dict

	def execute_module(self, module_name: str, args_dict: dict):
		"""Execute module with given arguments"""
		#try:	
		module = self.modules[module_name].LdapShellModule(
				args_dict,
				self.domain_dumper,
				self.client,
				logging.getLogger('ldap-shell.shell')
			)
		return module()
		#except ValidationError as e:
		#	error_messages = []
		#	for error in e.errors():
		#		field = error["loc"][0]
		#		message = error["msg"]
		#		error_messages.append(f"{field}: {message}")
		#	raise ValueError("\n".join(error_messages))

	def onecmd(self, line):
		cmd, arg_string, _ = self.parseline(line)
		if self.is_valid_line(line) is False:
			print(f'*** Unknown syntax: {line}')
			return

		if cmd in self.modules:
			try:
				args_dict = self.parse_module_args(cmd, arg_string)
				return self.execute_module(cmd, args_dict)
			except ValueError as e:
				print(f"Error: {e}")
				import traceback
				print("Traceback:")
				print(traceback.format_exc())
		else:
			print(f'Module {cmd} not found')

	def cmdloop(self):
		if self.noninteractive:
			self.session = PromptSession(self.prompt,)
		else:
			self.session = PromptSession(
				self.prompt,
				completer=self.completer,
				complete_style=CompleteStyle.MULTI_COLUMN,
				history=self.history,
				auto_suggest=ConditionalAutoSuggest(
					MultiAutoSuggest([
						ModuleAutoSuggest(self.modules),
						AutoSuggestFromHistory(),
					]), True
				),
				key_bindings=self.kb,
				complete_while_typing=True
			)
		while True:
			try:
				line = self.session.prompt(self.prompt)
				if line.strip() == 'exit':
					break
				self.onecmd(line)
			except KeyboardInterrupt:
				break  
