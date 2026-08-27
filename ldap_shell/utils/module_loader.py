import importlib
import os


class ModuleLoader:
    @staticmethod
    def list_modules() -> list:
        module_path = os.path.join(os.path.dirname(__file__), '../ldap_modules')
        modules_list = []
        for module in os.listdir(module_path):
            full = os.path.join(module_path, module)
            if os.path.isdir(full) and not module.startswith('__') and module != 'template':
                modules_list.append(module)
        return sorted(modules_list)

    @staticmethod
    def load_modules():
        """Load all modules from ldap_modules directory"""
        modules = {}
        for module_name in ModuleLoader.list_modules():
            module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
            modules[module_name] = module.LdapShellModule
        return modules

    @staticmethod
    def load_module(module_name: str):
        module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
        return module.LdapShellModule

    @staticmethod
    def get_module_help(module_name: str):
        module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
        return module.help_text

    @staticmethod
    def get_module_examples(module_name: str):
        module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
        return module.examples_text
