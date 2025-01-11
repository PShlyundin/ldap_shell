from prompt_toolkit.completion import FuzzyWordCompleter, Completion
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.formatted_text import HTML
import string
from ldap_shell.helper import Helper
import os
import importlib

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

class Prompt:
	def __init__(self):
		self.prompt = '# '
		self.history = InMemoryHistory()
		self.helper = Helper()
		self.meta = self.helper.get_meta()
		for e in self.helper.get_args():
			self.history.append_string(e)
		self.completer = ShellCompleter(['_'.join(e.split('_')[1:]) for e in dir(self) if 'do_' in e and e!='do_EOF'], self.meta)
		self.identchars = string.ascii_letters + string.digits + '_'

		self.modules = {}
		self.load_modules()

	def load_modules(self):
		module_path = os.path.join(os.path.dirname(__file__), 'ldap_moduls')
		for module_name in os.listdir(module_path):
			if os.path.isdir(os.path.join(module_path, module_name)) and module_name != '__pycache__':
				module = importlib.import_module(f'ldap_shell.ldap_moduls.{module_name}.ldap_module')
				self.modules[module_name] = module
		print(f'Loaded modules: {self.modules}')

	def default(self, line):
		self.stdout.write('*** Unknown syntax: %s\n'%line)

	def parseline(self, line):
		line = line.strip()
		if not line:
			return None, None, line
		elif line[0] == '?':
			line = 'help ' + line[1:]
		elif line[0] == '!':
			if hasattr(self, 'do_shell'):
				line = 'shell ' + line[1:]
			else:
				return None, None, line
		i, n = 0, len(line)
		while i < n and line[i] in self.identchars: i = i+1
		cmd, arg = line[:i], line[i:].strip()
		return cmd, arg, line

	def onecmd_(self, line):
		cmd, arg, line = self.parseline(line)
		if not line:
			return self.emptyline()
		if cmd is None:
			return self.default(line)
		self.lastcmd = line
		if line == 'EOF' :
			self.lastcmd = ''
		if cmd == '':
			return self.default(line)
		else:
			try:
				func = getattr(self, 'do_' + cmd)
			except AttributeError:
				return self.default(line)
			return func(arg)

	def onecmd(self, line):
		cmd, arg, line = self.parseline(line)
		print(f'cmd: {cmd}, arg: {arg}, line: {line}')
		if cmd in self.modules:
			module = self.modules[cmd]
			return module.LdapShellModule(arg)()
		else:
			print(f'Module {cmd} not found')

	def cmdloop(self):
		if self.noninteractive:
			self.session = PromptSession(self.prompt,)
		else:
			self.session = PromptSession(self.prompt, completer=self.completer, complete_style=CompleteStyle.MULTI_COLUMN, history=self.history,
				auto_suggest=AutoSuggestFromHistory(),)
		while True:
			try:
				line = self.session.prompt(self.prompt)
				if line.strip() == 'exit':
					break
				self.onecmd(line)
			except KeyboardInterrupt:
				break  
			
