import logging
import re
import base64
from ldap3 import Connection, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldapdomaindump import domainDumper
from pydantic import BaseModel, Field
from typing import Optional
from ldap_shell.ldap_modules.base_module import BaseLdapModule, ArgumentType
from ldap_shell.utils.ldap_utils import LdapUtils


class LdapShellModule(BaseLdapModule):
    """Module for writing any attribute on an AD object with automatic type detection from the schema"""

    help_text = "Write, append, delete or clear any attribute on an AD object. The value type (string/int/bool/binary) is auto-detected from the AD schema."
    examples_text = """
    # set_attribute

    Generic LDAP write primitive. Unlike the specialised modules, this one can
    modify *any* attribute. You never specify the type by hand: the module reads
    the attribute's syntax from the AD schema (already loaded by ldap3) and coerces
    your input automatically.

    ## How the type is resolved

    The category is taken from the schema, not from what you typed:
    - Integer / LargeInteger  -> value parsed as a number (supports 0x.., and the
      keywords `never`/`max`/`infinity` -> 0x7FFFFFFFFFFFFFFF, handy for accountExpires)
    - Boolean                 -> `true/1/yes/on` vs `false/0/no/off`, sent as LDAP TRUE/FALSE
    - GeneralizedTime         -> sent verbatim (e.g. 20250101000000.0Z)
    - Octet String / SID / NT-Security-Descriptor -> treated as binary (see below)
    - everything else         -> sent as a UTF-8 string

    Whether a comma means "several values" or is a literal character is also decided
    by the schema (`isSingleValued`): multi-valued attributes split on `,`,
    single-valued ones keep the comma.

    ## Binary value auto-detection (only for binary attributes)

    For binary attributes the *encoding of your input* is auto-detected, in order:
      1. `@/path/to/file`  -> read raw bytes from a file (blobs, certs, SDs)
      2. hex               -> `0x0102ff` or a plain even-length hex string
      3. base64            -> a valid base64 string
      4. otherwise         -> the raw text encoded as UTF-8

    You can force the interpretation with an inline prefix (this is part of the
    value, not a CLI flag), which also works to override a wrong/missing schema:
      `hex:0102ff`   `b64:AQID`   `str:literal text`   `@/tmp/blob.bin`

    ## Examples

    Set a logon script (Logon-Script / scriptPath), string attribute:
    `set_attribute john.doe scriptPath evil.bat`
    ```
    [INFO] scriptPath on john.doe: '' -> 'evil.bat' (string, REPLACE)
    [INFO] Attribute scriptPath updated successfully
    ```

    Value with spaces - use quotes. NOTE: the shell parser (shlex) eats
    backslashes inside double quotes, so for UNC paths use SINGLE quotes
    (kept literally) or double every backslash:
    `set_attribute john.doe profilePath '\\\\dc01\\profiles\\john'`   (single quotes: literal)
    Single-valued attrs (scriptPath, profilePath, ...) ignore `add` and are
    always replaced - use the default action, not `add`.

    Numeric attribute - detected as Integer, parsed as a number:
    `set_attribute HOST01$ msDS-SupportedEncryptionTypes 24`
    ```
    [INFO] msDS-SupportedEncryptionTypes on HOST01$: '0' -> '24' (int, REPLACE)
    ```

    LargeInteger + keyword:
    `set_attribute john.doe accountExpires never`

    Boolean attribute:
    `set_attribute "CN=Foo,CN=Users,DC=corp,DC=local" showInAdvancedViewOnly true`

    Multi-valued attribute (schema says multi -> comma splits into two values):
    `set_attribute HOST01$ servicePrincipalName "HOST/h,HOST/h.corp.local"`

    Append a single value without touching the others (MODIFY_ADD):
    `set_attribute HOST01$ servicePrincipalName cifs/evil.corp.local add`

    Delete one specific value (MODIFY_DELETE):
    `set_attribute HOST01$ servicePrincipalName cifs/evil.corp.local del`

    Binary attribute - hex / base64 / file are auto-detected:
    `set_attribute HOST01$ msDS-AllowedToActOnBehalfOfOtherIdentity 0x01000480...`
    `set_attribute victim  msDS-KeyCredentialLink @/tmp/keycred.blob`

    Clear the whole attribute (omit the value):
    `set_attribute john.doe scriptPath`
    ```
    [INFO] Cleared scriptPath on john.doe
    ```
    """
    module_type = "Abuse ACL"

    # Subschema SYNTAX OIDs (as parsed by ldap3 from the AD aggregate schema)
    _INT_SYNTAXES = {
        '1.3.6.1.4.1.1466.115.121.1.27',   # Integer / Enumeration
        '1.2.840.113556.1.4.906',          # LargeInteger (Interval, Int64)
    }
    _BOOL_SYNTAXES = {
        '1.3.6.1.4.1.1466.115.121.1.7',    # Boolean
    }
    _TIME_SYNTAXES = {
        '1.3.6.1.4.1.1466.115.121.1.24',   # GeneralizedTime
        '1.3.6.1.4.1.1466.115.121.1.53',   # UTCTime
    }
    _BINARY_SYNTAXES = {
        '1.3.6.1.4.1.1466.115.121.1.40',   # Octet String (also SID)
        '1.2.840.113556.1.4.907',          # NT Security Descriptor
        '1.2.840.113556.1.4.903',          # Object(DN-Binary)
    }

    class ModuleArgs(BaseModel):
        target: str = Field(
            description="Target object (sAMAccountName or DN)",
            arg_type=[ArgumentType.USER, ArgumentType.COMPUTER,
                      ArgumentType.GROUP, ArgumentType.DN]
        )
        attribute: str = Field(
            description="LDAP attribute name to modify (e.g. scriptPath, profilePath)",
            arg_type=ArgumentType.ATTRIBUTES
        )
        value: Optional[str] = Field(
            None,
            description="Value(s). Comma-separated for multi-valued attrs. Omit to clear the attribute. "
                        "Binary auto-detected; force with hex:/b64:/str:/@file prefixes.",
            arg_type=ArgumentType.STRING
        )
        action: Optional[str] = Field(
            "replace",
            description="replace (default) | add | del",
            arg_type=ArgumentType.ADD_DEL
        )

    def __init__(self, args_dict: dict,
                 domain_dumper: domainDumper,
                 client: Connection,
                 log=None):
        self.args = self.ModuleArgs(**args_dict)
        self.domain_dumper = domain_dumper
        self.client = client
        self.log = log or logging.getLogger('ldap-shell.shell')

    # ------------------------------------------------------------------ #
    # Type resolution (layer 1): category comes from the schema, not the value
    # ------------------------------------------------------------------ #
    def _resolve_type(self, attr):
        """Return (category, single_valued) from the schema loaded by ldap3."""
        schema = getattr(self.client.server, 'schema', None)
        at = schema.attribute_types.get(attr) if schema and schema.attribute_types else None
        if not at:
            self.log.warning(f"Attribute '{attr}' not found in schema, treating as string")
            return 'string', True

        syntax = at.syntax
        single = bool(at.single_value)
        if syntax in self._INT_SYNTAXES:
            return 'int', single
        if syntax in self._BOOL_SYNTAXES:
            return 'bool', single
        if syntax in self._TIME_SYNTAXES:
            return 'time', single
        if syntax in self._BINARY_SYNTAXES:
            return 'binary', single
        return 'string', single

    # ------------------------------------------------------------------ #
    # Value coercion (layer 2): turn the typed string into the right python type
    # ------------------------------------------------------------------ #
    def _coerce_value(self, category, raw):
        # Inline explicit overrides (part of the value, not a CLI flag).
        # Also serve as an escape hatch when the schema is missing/wrong.
        if raw.startswith('@'):
            with open(raw[1:], 'rb') as f:
                return f.read()
        low4 = raw[:4].lower()
        if low4 == 'hex:':
            return self._hex_to_bytes(raw[4:])
        if low4 == 'b64:':
            return base64.b64decode(raw[4:], validate=True)
        if low4 == 'str:':
            return raw[4:]

        if category == 'int':
            token = raw.strip().lower()
            if token in ('never', 'max', 'infinity'):
                return 0x7FFFFFFFFFFFFFFF
            return int(raw, 0)  # supports decimal and 0x-hex
        if category == 'bool':
            # ldap3 to_raw(True) would send b'True' (wrong), so emit the literal
            return 'TRUE' if raw.strip().lower() in ('true', '1', 'yes', 'y', 'on') else 'FALSE'
        if category == 'time':
            return raw
        if category == 'binary':
            return self._auto_binary(raw)
        return raw  # string

    def _auto_binary(self, raw):
        # 1) hex (0x-prefixed or plain even-length hex)
        candidate = raw[2:] if raw[:2].lower() == '0x' else raw
        if len(candidate) % 2 == 0 and candidate and re.fullmatch(r'[0-9a-fA-F]+', candidate):
            return bytes.fromhex(candidate)
        # 2) base64
        try:
            return base64.b64decode(raw, validate=True)
        except Exception:
            pass
        # 3) raw text
        return raw.encode()

    @staticmethod
    def _hex_to_bytes(s):
        s = s.strip()
        if s[:2].lower() == '0x':
            s = s[2:]
        return bytes.fromhex(s.replace(' ', ''))

    @staticmethod
    def _display(values):
        """Human-friendly representation for logging."""
        out = []
        for v in values:
            if isinstance(v, bytes):
                out.append('0x' + v.hex() if len(v) <= 32 else f'<{len(v)} bytes>')
            else:
                out.append(str(v))
        if not out:
            return "''"
        return ', '.join(f"'{v}'" for v in out)

    def _get_current(self, target_dn, attr):
        try:
            if not self.client.search(target_dn, '(objectClass=*)', attributes=[attr]):
                return []
            if not self.client.entries or attr not in self.client.entries[0]:
                return []
            return list(self.client.entries[0][attr].values)
        except Exception:
            return []

    # ------------------------------------------------------------------ #
    def __call__(self):
        attr = self.args.attribute

        # Resolve target DN (accept raw DN or sAMAccountName)
        target = self.args.target
        if target.lower().startswith(('cn=', 'ou=', 'dc=')):
            target_dn = target if LdapUtils.check_dn(self.client, self.domain_dumper, target) else None
        else:
            target_dn = LdapUtils.get_dn(self.client, self.domain_dumper, target)
        if not target_dn:
            self.log.error(f'Target object not found: {target}')
            return

        action = (self.args.action or 'replace').lower()
        if action not in ('replace', 'add', 'del', 'delete'):
            self.log.error("action must be one of: replace, add, del")
            return

        category, single = self._resolve_type(attr)

        # Split raw values according to the schema's single/multi flag
        if self.args.value is None:
            raw_values = []
        elif single:
            raw_values = [self.args.value]
        else:
            raw_values = [v.strip() for v in self.args.value.split(',') if v.strip()]

        # Coerce each value to the resolved type
        try:
            coerced = [self._coerce_value(category, v) for v in raw_values]
        except FileNotFoundError as e:
            self.log.error(f'File not found: {e.filename}')
            return
        except Exception as e:
            self.log.error(f'Failed to parse value as {category}: {e}')
            return

        # Map action -> ldap3 operation
        if action == 'replace':
            op = MODIFY_REPLACE
        elif action == 'add':
            if not coerced:
                self.log.error("action 'add' requires a value")
                return
            # 'add' on a single-valued attribute that already holds a value
            # fails server-side with attributeOrValueExists. For single-valued
            # attrs 'add' is semantically a replace, so fall back to it.
            if single:
                self.log.warning(f"{attr} is single-valued; 'add' would fail "
                                 f"(attributeOrValueExists) - using REPLACE instead")
                op = MODIFY_REPLACE
                action = 'replace'  # keep success reporting consistent
            else:
                op = MODIFY_ADD
        else:  # del / delete
            op = MODIFY_DELETE

        current = self._get_current(target_dn, attr)

        try:
            res = self.client.modify(target_dn, {attr: [(op, coerced)]})
        except Exception as e:
            self.log.error(f'Error modifying {attr}: {e}')
            if 'insufficient access rights' in str(e).lower():
                self.log.info('You likely lack write access to this attribute. '
                              'Try LDAPS / elevated creds, or gain write via an ACL abuse first.')
            return

        if not res:
            desc = self.client.result.get('description')
            msg = self.client.result.get('message', '')
            self.log.error(f'Failed to modify {attr}: {desc} {msg}')
            if desc == 'insufficientAccessRights':
                self.log.info('You likely lack write access to this attribute. '
                              'Try LDAPS / elevated creds, or gain write via an ACL abuse first.')
            return

        # Success reporting
        if action == 'replace' and not coerced:
            self.log.info(f'Cleared {attr} on {target}')
        elif action == 'del' or action == 'delete':
            what = self._display(coerced) if coerced else 'ALL values'
            self.log.info(f'Removed {what} from {attr} on {target}')
        elif action == 'add':
            self.log.info(f'Appended {self._display(coerced)} to {attr} on {target}')
        else:  # replace with values
            self.log.info(f'{attr} on {target}: {self._display(current)} -> '
                          f'{self._display(coerced)} ({category}, REPLACE)')
        self.log.info(f'Attribute {attr} updated successfully')
