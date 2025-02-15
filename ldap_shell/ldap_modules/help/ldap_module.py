import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.prompt import Prompt
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
import importlib
from colorama import init, Fore, Back, Style
import textwrap
# Инициализируем colorama для кроссплатформенной поддержки
init()

class LdapShellModule(BaseLdapModule):
    """Module for show help"""

    help_text = "Show help"
    examples_text = """
    Show help for a specific command
    `help get_user_groups`
    Show help for all commands
    `help`
    """
    module_type = "Other"

    class ModuleArgs(BaseModel):
        command: Optional[str] = Field(
            None,  # This argument is required
            description="Command to execute",
            arg_type=[ArgumentType.STRING]  # Changed to list of types
        )
    
    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def print_markdown(self, text: str) -> str:
        lines = text.split('\n')
        result = []
        in_code_block = False
        
        for line in lines:
            # Заголовки
            if line.strip().startswith('# '):
                result.append(f"{Fore.CYAN}{line.strip().strip('# ')}{Style.RESET_ALL}")
            elif line.strip().startswith('## '):
                result.append(f"{Fore.BLUE}{line.strip().strip('## ')}{Style.RESET_ALL}")
            elif line.strip().startswith('### '):
                result.append(f"{Fore.GREEN}{line.strip().strip('### ')}{Style.RESET_ALL}")
            # Блоки кода
            elif line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue
            elif in_code_block:
                result.append(f"{Back.BLACK}{Fore.WHITE}{line}{Style.RESET_ALL}")
            # Инлайн код
            else:
                while '`' in line:
                    start = line.find('`')
                    end = line.find('`', start + 1)
                    if end == -1:
                        break
                    code = line[start+1:end]
                    line = line[:start] + f"{Fore.YELLOW}{code}{Style.RESET_ALL}" + line[end+1:]
                result.append(line)
        
        print('\n'.join(result))

    def __call__(self):
        modules = Prompt.list_modules()
        helper_modules = {}
        for module_name in modules:
            module = importlib.import_module(f'ldap_shell.ldap_modules.{module_name}.ldap_module')
            helper_modules[module_name] = {}
            if hasattr(module.LdapShellModule, 'help_text'):
                helper_modules[module_name]['help'] = module.LdapShellModule.help_text
            if hasattr(module.LdapShellModule, 'module_type'):
                helper_modules[module_name]['type'] = module.LdapShellModule.module_type
            arguments = module.LdapShellModule.ModuleArgs.schema()
            helper_modules[module_name]['args'] = []
            for arg in arguments['properties']:
                if 'default' in arguments['properties'][arg]:
                    helper_modules[module_name]['args'].append(f"[{arg}]")
                else:
                    helper_modules[module_name]['args'].append(f"{arg}")

        # Группируем модули по главам
        chapters = {}
        for module_name in helper_modules:
            if helper_modules[module_name].get('type'):
                chapter = helper_modules[module_name]['type']
            else:
                chapter = 'Other'
            if chapter not in chapters:
                chapters[chapter] = []
            help_text = helper_modules[module_name]['help']
            args = helper_modules[module_name]['args']
            chapters[chapter].append(f"    {module_name} {(' '.join(args))} - {help_text}")

        if self.args.command:
            if self.args.command in Prompt.list_modules():
                module = importlib.import_module(f'ldap_shell.ldap_modules.{self.args.command}.ldap_module')
                module_class = module.LdapShellModule
                
                # Собираем информацию о модуле
                header = module_class.__doc__ or "No description available"
                help_text = module_class.help_text
                examples = module_class.examples_text
                args_schema = module_class.ModuleArgs.model_json_schema()
                # Формируем текст
                help_md = f"""
`{self.args.command} {' '.join(helper_modules[self.args.command]['args'])}`

# Command: {self.args.command} 
    {header}

# Description
    {help_text}

# Arguments
"""
                # Добавляем информацию об аргументах
                for arg_name, arg_info in args_schema.get('properties', {}).items():
                    required = arg_name in args_schema.get('required', [])
                    arg_types = module_class.ModuleArgs.model_fields[arg_name].json_schema_extra['arg_type']
                    if isinstance(arg_types, list):
                        arg_type = '|'.join([arg_type.name for arg_type in arg_types])
                    else:
                        arg_type = arg_types.name
                    description = arg_info.get('description', 'No description')
                    name = arg_name
                    
                    help_md += f"""    ### {name}
        - Description: {description}
        - Type: `{arg_type}`
"""
                help_md += f"\n# Examples"
                # Добавляем примеры использования
                if examples:
                    help_md += f"\n{textwrap.dedent(examples.lstrip('\n'))}"
                # Выводим 
                self.print_markdown(help_md)

            else:
                self.log.error(f"Command {self.args.command} not found")
                return
        
        else:
            # Выводим в нужном формате
            for chapter, commands in chapters.items():
                print(f"\n{chapter}")
                for command in sorted(commands):
                    print(command)
            print('exit - exit from shell')
