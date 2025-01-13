from .attributes import AttributesCompleter
from .directory import DirectoryCompleter
from ldap_shell.ldap_modules.base_module import ArgumentType

# Маппинг типов аргументов на их комплитеры
COMPLETERS = {
    ArgumentType.ATTRIBUTES: AttributesCompleter(),
    ArgumentType.DIRECTORY: DirectoryCompleter(),
} 