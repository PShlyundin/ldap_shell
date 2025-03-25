from enum import Enum, auto
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

class ArgumentType(Enum):
    USER = 'user'
    COMPUTER = 'computer'
    GROUP = 'group'
    OU = 'ou'
    DIRECTORY = 'directory'
    STRING = 'string'
    AD_OBJECT = 'ad_object'
    ATTRIBUTES = 'attributes'
    COMMAND = 'command'
    RBCD = 'rbcd'
    ADD_DEL = 'add_del'
    DN = 'dn'
    MASK = 'mask'
    BOOLEAN = 'boolean'

class ModuleArgument:
    def __init__(self, name: str, arg_type: ArgumentType, description: str, required: bool):
        self.name = name
        self.arg_type = arg_type
        self.description = description
        self.required = required
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
    def get_args_required(cls) -> List[str]:
        """Returns a list of required arguments"""
        required_args = []
        for name, field in cls.ModuleArgs.model_fields.items():
            if field.is_required():
                required_args.append(f'{name}')
            else:
                required_args.append(f'[{name}]')
        return required_args

    @classmethod
    def get_arguments(cls) -> List[ModuleArgument]:
        """Returns module arguments from ModuleArgs class"""
        arguments = []
        for name, field in cls.ModuleArgs.model_fields.items():
            arg_type = field.json_schema_extra.get('arg_type', ArgumentType.STRING) if field.json_schema_extra else ArgumentType.STRING
            required = field.is_required()
            description = field.description or ""
            arguments.append(ModuleArgument(name, arg_type, description, required))
        return arguments