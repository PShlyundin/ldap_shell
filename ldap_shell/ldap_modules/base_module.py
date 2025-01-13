from enum import Enum
from typing import Dict, List, Optional, Annotated
from pydantic import BaseModel, Field, BeforeValidator
from ldap3 import Connection
from ldapdomaindump import domainDumper

def parse_attributes(value) -> List[str]:
    """Convert input to list of attributes.
    Supports single attribute or comma-separated list."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [attr.strip() for attr in value.split(',')] if ',' in value else [value]
    return []

# Custom types for module arguments
AttributesList = Annotated[List[str], BeforeValidator(parse_attributes)]

class ArgumentType(str, Enum):
    """Types of arguments that can be used in modules"""
    STRING = 'string'
    USER = 'user'
    GROUP = 'group'
    OU = 'ou'
    COMPUTER = 'computer'
    DIRECTORY = 'directory'
    ATTRIBUTES = 'attributes'  # New type for LDAP attributes

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