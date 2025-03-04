import os
import importlib

class ModuleLoader:
	@staticmethod
	def list_modules() -> list[str]:
		module_path = os.path.join(os.path.dirname(__file__), '../ldap_modules')
		modules = os.listdir(module_path)
		modules_list = []
		for module in modules:
			if os.path.isdir(os.path.join(module_path, module)) and not '__' in module and module != 'template':
				modules_list.append(module)
		return modules_list
	
	@staticmethod
	def load_modules():
		"""Load all modules from ldap_modules directory"""
		modules = {}
		modules_list = ModuleLoader.list_modules()
		for module_name in modules_list:
			module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
			modules[module_name] = module.LdapShellModule
		return modules
	
	@staticmethod
	def load_module(module_name: str):
		module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
		return module.LdapShellModule

	def get_module_help(module_name: str):
		module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
		help_text = module.help_text
		del module
		return help_text
	
	def get_module_examples(module_name: str):
		module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
		examples_text = module.examples_text
		del module
		return examples_text
	