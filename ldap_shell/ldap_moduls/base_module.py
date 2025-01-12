from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator
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

class ADObject(BaseModel):
    """Base model for Active Directory objects"""
    distinguished_name: str
    object_type: ArgumentType
    sid: str

class ModuleArgument(BaseModel):
    """Model for describing module argument"""
    name: str
    arg_type: ArgumentType
    required: bool = True
    description: str = ""
    default: Optional[str] = None

class ModuleConfig(BaseModel):
    """Base module configuration"""
    name: str
    description: str
    examples: List[str]
    arguments: List[ModuleArgument]

class BaseLdapModule:
    """Base class for all LDAP modules"""
    
    @classmethod
    def get_module_info(cls) -> ModuleConfig:
        return ModuleConfig(
            name=cls.__name__,
            description=cls.__doc__ or "",
            examples=cls.get_examples(),
            arguments=cls.get_arguments()
        )

    @classmethod
    def get_arguments(cls) -> List[ModuleArgument]:
        """Must be overridden in each module"""
        raise NotImplementedError
    
    @classmethod
    def get_examples(cls) -> List[str]:
        """Must be overridden in each module"""
        raise NotImplementedError