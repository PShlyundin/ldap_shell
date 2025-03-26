from prompt_toolkit.completion import Completion
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.history import FileHistory
from prompt_toolkit.shortcuts import CompleteStyle
import string
from ldap_shell.helper import Helper
import os
import logging
from prompt_toolkit.completion import Completer
from ldap_shell.ldap_modules.base_module import ArgumentType
from prompt_toolkit.key_binding import KeyBindings
from ldap_shell.completers import CompleterFactory
from ldap_shell.utils.module_loader import ModuleLoader
from ldap_shell.utils import history
import shlex

class ModuleCompleter(Completer):
	def __init__(self, modules, domain_dumper, client):
		self.modules = modules
		self.domain_dumper = domain_dumper
		self.client = client
		
	def get_completions(self, document, complete_event):
		text = document.text_before_cursor
		try:
			words = shlex.split(text)
		except:
			words = shlex.split(text+'"')
		if text.endswith(' '):
			words.append('')
		
		# If this is the first word - suggest modules
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
		# Get current module and argument
		module_name = words[0]
		if not any(module_name.startswith(m) for m in self.modules):
			return
			
		module_class = self.modules[module_name]
		arguments = module_class.get_arguments()
		
		# Determine which argument needs suggestions
		current_arg_index = max(len(words) - 2, 0)

		if current_arg_index+1 > len(arguments):
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
		self.history = history  # Should be prompt_toolkit.history.History
		
	def get_suggestion(self, buffer, document) -> Suggestion | None:
		text = document.text_before_cursor
		
		# 1. Check history
		history_suggestion = self._get_history_suggestion(text)
		if history_suggestion:
			return history_suggestion
			
		# 2. Suggest module arguments
		return self._get_module_suggestion(text)
	
	def _get_history_suggestion(self, text: str) -> Suggestion | None:
		"""Find last used argument for current command"""
		if not text.strip():
			return None

		# Get base command (first word)
		base_command = text.split()[0]
		
		# Search history for last full command with this base name
		last_full_command = None
		for entry in reversed(list(self.history.get_strings())):
			if entry.startswith(base_command + ' '):
				last_full_command = entry
				break
		
		if not last_full_command:
			return None
		
		# Compare current input with history entry
		if last_full_command.startswith(text):
			remaining_part = last_full_command[len(text):]
			return Suggestion(remaining_part)
		
		return None
	
	def _get_module_suggestion(self, text: str) -> Suggestion | None:
		"""Standard module argument suggestion"""
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
	def __init__(self, domain_dumper, client):
		self.domain_dumper = domain_dumper
		self.client = client
		self.prompt = '# '
		self.history = history
		self.helper = Helper()
		self.meta = self.helper.get_meta()
		self.identchars = string.ascii_letters + string.digits + '_'

		self.modules = ModuleLoader.load_modules()

		self.completer = ModuleCompleter(self.modules, domain_dumper=self.domain_dumper, client=self.client)
		self.suggester = ModuleSuggester(self.modules, self.history)

		# Create key bindings
		self.kb = KeyBindings()
		
		@self.kb.add('enter')
		def _(event):
			"""Handle Enter press"""
			b = event.current_buffer

			# If there is active autocompletion state
			if b.complete_state and b.complete_state.current_completion:
				completion = b.complete_state.current_completion

				# Get list of commands
				available_commands = ModuleLoader.list_modules()

				# If completion is a command
				if completion.text in available_commands and not ' ' in b.document.text_before_cursor:
					# Delete all text
					b.delete(len(b.document.text_after_cursor))  # first after cursor
					b.delete_before_cursor(len(b.document.text_before_cursor))  # then before cursor
					# Insert command
					b.insert_text(completion.text + ' ')
				else:
					# For arguments: find last space or comma before cursor
					text = b.document.text
					cursor_position = b.document.cursor_position
					text_before_cursor = text[:cursor_position]

					# Find position of last separator (space or comma)
					if text_before_cursor.count('"') % 2 == 1:
						quoted_words = shlex.split(text_before_cursor+'"')
					else:
						quoted_words = shlex.split(text_before_cursor)
					
					last_word = quoted_words[-1]
					if ',' in last_word and not 'DC=' in last_word:
						del_word = last_word.split(',')[-1]
					elif ' ' in last_word or '"' in last_word:
						del_word = f'"{last_word}"'
					elif 'DC=' in last_word:
						del_word = f'"{last_word}"'
					else:
						del_word = last_word
					last_separator = len(text_before_cursor) - len(del_word)

					if last_separator >= 0:
						# Delete text from last separator to cursor
						chars_to_delete = cursor_position - (last_separator)
						if chars_to_delete > 0:
							b.delete_before_cursor(chars_to_delete)
					else:
						# If no separator found, delete all text before cursor
						b.delete_before_cursor(len(text_before_cursor))

					b.insert_text(completion.text)
				
				# Clear autocompletion state
				b.complete_state = None
				return

			# If no active autocompletion - execute command
			event.current_buffer.validate_and_handle()	

		@self.kb.add('tab')
		def _(event):
			"""Handle Tab press"""
			b = event.current_buffer
			
			if b.complete_state:
				b.complete_next()
			else:
				b.start_completion(select_first=False)

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
		
		# Use shlex for proper string parsing with quotes
		try:
			args = shlex.split(arg_string)
		except ValueError as e:
			# If there are unclosed quotes, try to process as is
			print(f"Warning: {e}")
			args = arg_string.strip().split()
		
		for i, value in enumerate(args):
			if i >= len(self.modules[module_name].get_arguments()):
				break
			arg_name = self.modules[module_name].get_arguments()[i].name
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
		module = self.modules[module_name](
				args_dict,
				self.domain_dumper,
				self.client,
				logging.getLogger('ldap-shell')
			)
		return module()

	def check_args_exist(self, module_name: str, args_dict: dict):
		module = self.modules[module_name]
		arguments = module.get_arguments()
		for arg in arguments:
			if arg.name not in args_dict and arg.required:
				return False
		return True

	def onecmd(self, line):
		cmd, arg_string, _ = self.parseline(line)
		if self.is_valid_line(line) is False:
			return

		if cmd in self.modules:
			try:
				args_dict = self.parse_module_args(cmd, arg_string)
				if not self.check_args_exist(cmd, args_dict):
					print(f'*** Missing required arguments for {cmd}. Use `help {cmd}` to see available arguments.')
					return
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
				auto_suggest=self.suggester, #AutoSuggestFromHistory(),
				key_bindings=self.kb,
				complete_while_typing=True
			)
		while True:
			try:
				line = self.session.prompt(self.prompt)
				if line.strip() == 'exit':
					break
				prompt = self.onecmd(line)
				if prompt:
					self.prompt = prompt
			except KeyboardInterrupt:
				break  
