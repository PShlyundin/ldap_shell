import logging
from ldap3 import Connection    
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional, List
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ModuleArgument, ArgumentType, AttributesList
from datetime import datetime, timedelta
import re

class LdapShellModule(BaseLdapModule):
    """Module for searching AD objects"""

    help_text = "Search AD objects"
    examples_text = """
    ## Search user with all attributes:
    `search "(sAMAccountName=john.doe)"`
    ``` 
        objectClass          : top
                            person
                            organizationalPerson
                            user
        pwdLastSet           : 2024-07-22 18:09:40+0000
        ...
        objectSid            : S-1-5-21-170099002-3324421148-3202989712-2994
        whenCreated          : 2024-07-22 18:09:40+0000
        distinguishedName    : CN=john.doe,CN=Users,DC=roasting,DC=lab
        sAMAccountName       : john.doe
        ...
        sn                   : john.doe
    ```
    ## Search user with specific attributes:
    `search "(sAMAccountName=john.doe)" sAMAccountName,objectSid,name`
    ``` 
        objectSid     : S-1-5-21-170099002-3324421148-3202989712-2994
        name          : john.doe
        sAMAccountName: john.doe
    ```
    """
    module_type = "Get Info"

    class ModuleArgs(BaseModel):
        ldap_filter: str = Field(
            ..., # This argument is required
            description="LDAP filter",
            arg_type=ArgumentType.STRING
        )
        attributes: Optional[AttributesList] = Field(
            None, # This argument is not required
            description="Attributes to retrieve (single or comma-separated)",
            arg_type=ArgumentType.ATTRIBUTES
        )
    
    def __init__(self, args_dict: dict, 
                 domain_dumper: domainDumper, 
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict) 
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    def convert_windows_timestamp(self, timestamp):
        """Convert Windows timestamp to human readable format"""
        try:
            # Convert string to number
            timestamp = int(timestamp)
            if timestamp < 116444736000000000:
                return timestamp
            windows_epoch = datetime(1601, 1, 1)
            delta = timedelta(microseconds=timestamp // 10)  # divide by 10 to convert to microseconds
            return (windows_epoch + delta).strftime('%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return timestamp

    def format_value(self, value):
        """Format single value with proper formatting"""
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S%z')
        elif isinstance(value, bytes):
            try:
                return value.decode('utf-8')
            except UnicodeDecodeError:
                return value.hex()
        elif isinstance(value, list):
            return [self.format_value(v) for v in value]
        return str(value)

    def format_entry(self, entry):
        """Format LDAP entry with proper output formatting"""
        formatted_entry = {}
        
        for key, values in entry.entry_attributes_as_dict.items():
            # Convert each value
            formatted_values = []
            for value in values:
                formatted_value = self.format_value(value)
                formatted_values.append(formatted_value)
                
            # If value is single - no need for list
            if len(formatted_values) == 1:
                formatted_entry[key] = formatted_values[0]
            else:
                formatted_entry[key] = formatted_values
            
        return formatted_entry

    def __call__(self):
        self.log.info('Starting search operation...')
        
        attributes = self.args.attributes
        search_query = self.args.ldap_filter

        self.log.debug('search_query={}'.format(search_query))
        self.log.debug('attributes={}'.format(attributes))
        
        if not attributes:
            attributes = ['*']
        try:
            self.client.search(self.domain_dumper.root, search_query, attributes=attributes)
        except Exception as e:
            self.log.error(f"Error searching: {e}")
            return
        
        if len(self.client.entries) == 0:
            self.log.info('No results found')
            return
            
        for entry in self.client.entries:
            # Format each entry before displaying
            formatted_entry = self.format_entry(entry)
            
            # Print in the desired format
            print("\n")  # Empty line between entries
            max_key_length = max(len(key) for key in formatted_entry.keys())
            
            for key, value in formatted_entry.items():
                if isinstance(value, list):
                    # Проверяем, не пустой ли список
                    if not value:
                        print(f"{key.ljust(max_key_length)}: ")
                    else:
                        # Многострочный вывод для списков
                        print(f"{key.ljust(max_key_length)}: {value[0]}")
                        for v in value[1:]:
                            print(f"{' ' * max_key_length}  {v}")
                else:
                    # Single line output for single values
                    print(f"{key.ljust(max_key_length)}: {value}")
