from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from ldap3 import Connection
from ldapdomaindump import domainDumper

class ArgumentType(str, Enum):
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    OU = "OU"
    DIRECTORY = "directory"
    STRING = "string"
    INTEGER = "integer"

class ModuleArgument:
    def __init__(self, name: str, arg_type: ArgumentType, description: str):
        self.name = name
        self.arg_type = arg_type
        self.description = description

class BaseLdapModule:
    """Base class for all LDAP modules"""
    
    @classmethod
    def get_module_info(cls):
        """Returns module information based on ModuleArgs class"""
        return {
            "name": cls.__name__,
            "description": cls.__doc__ or "",
            "arguments": cls.get_arguments()
        }

    @classmethod
    def get_arguments(cls) -> List[ModuleArgument]:
        """Returns module arguments from ModuleArgs class"""
        arguments = []
        for name, field in cls.ModuleArgs.model_fields.items():
            arg_type = field.json_schema_extra.get('arg_type', ArgumentType.STRING) if field.json_schema_extra else ArgumentType.STRING
            description = field.description or ""
            arguments.append(ModuleArgument(name, arg_type, description))
        return arguments