"""Shared command runner for the interactive prompt, inline CLI and MCP."""
from __future__ import annotations

import io
import logging
import shlex
import string
import traceback
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ldap_shell.utils.module_loader import ModuleLoader

log = logging.getLogger('ldap-shell')


@dataclass
class CommandResult:
    ok: bool
    command: str
    output: str = ''
    error: Optional[str] = None
    prompt: Optional[str] = None
    data: Any = None


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: List[str] = []
        self.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))

    def emit(self, record):
        self.records.append(self.format(record))


class CommandRunner:
    """Parse and execute ldap_shell module commands without a TTY."""

    def __init__(self, domain_dumper, client):
        self.domain_dumper = domain_dumper
        self.client = client
        self.modules = ModuleLoader.load_modules()
        self.identchars = string.ascii_letters + string.digits + '_'

    def list_commands(self) -> List[Dict[str, Any]]:
        commands = []
        for name in sorted(self.modules):
            module = self.modules[name]
            commands.append({
                'name': name,
                'help': getattr(module, 'help_text', '') or (module.__doc__ or '').strip(),
                'type': getattr(module, 'module_type', 'Other'),
                'arguments': [
                    {
                        'name': arg.name,
                        'required': arg.required,
                        'description': arg.description,
                        'type': (
                            [item.value for item in arg.arg_type]
                            if isinstance(arg.arg_type, list)
                            else getattr(arg.arg_type, 'value', str(arg.arg_type))
                        ),
                    }
                    for arg in module.get_arguments()
                ],
            })
        return commands

    def parseline(self, line: str):
        line = (line or '').strip()
        if not line:
            return None, None, line
        if line[0] == '?':
            line = 'help ' + line[1:]
        i, n = 0, len(line)
        while i < n and line[i] in self.identchars:
            i += 1
        return line[:i], line[i:].strip(), line

    def parse_args(self, module_name: str, arg_string: str) -> dict:
        if module_name not in self.modules:
            raise ValueError(f'Module {module_name} not found')
        try:
            values = shlex.split(arg_string)
        except ValueError as exc:
            log.warning(f'Argument parse warning: {exc}')
            values = arg_string.strip().split()

        args_dict = {}
        arguments = self.modules[module_name].get_arguments()
        for i, value in enumerate(values):
            if i >= len(arguments):
                break
            args_dict[arguments[i].name] = value
        return args_dict

    def missing_args(self, module_name: str, args_dict: dict) -> List[str]:
        missing = []
        for arg in self.modules[module_name].get_arguments():
            if arg.required and arg.name not in args_dict:
                missing.append(arg.name)
        return missing

    def execute(self, line: str, capture: bool = False) -> CommandResult:
        cmd, arg_string, raw = self.parseline(line)
        if not raw or not cmd:
            return CommandResult(ok=True, command=line or '', output='')

        if cmd == 'exit':
            return CommandResult(ok=True, command=cmd, output='', data={'exit': True})

        if cmd not in self.modules:
            error = f'Module {cmd} not found'
            if not capture:
                print(error)
            return CommandResult(ok=False, command=raw, error=error)

        try:
            args_dict = self.parse_args(cmd, arg_string)
        except ValueError as exc:
            error = str(exc)
            if not capture:
                print(f'Error: {error}')
            return CommandResult(ok=False, command=raw, error=error)

        missing = self.missing_args(cmd, args_dict)
        if missing:
            error = (
                f'Missing required arguments for {cmd}: {", ".join(missing)}. '
                f'Use `help {cmd}` to see available arguments.'
            )
            if not capture:
                print(f'*** {error}')
            return CommandResult(ok=False, command=raw, error=error)

        stdout = io.StringIO()
        log_handler = _ListHandler()
        logger = logging.getLogger('ldap-shell')
        if capture:
            logger.addHandler(log_handler)

        try:
            module = self.modules[cmd](
                args_dict,
                self.domain_dumper,
                self.client,
                logger,
            )
            if capture:
                with redirect_stdout(stdout), redirect_stderr(stdout):
                    returned = module()
            else:
                returned = module()
        except Exception as exc:
            error = f'{exc}\n{traceback.format_exc()}'
            if not capture:
                print(f'Error: {exc}')
                print(traceback.format_exc())
            return CommandResult(ok=False, command=raw, error=str(exc), output=error)
        finally:
            if capture:
                logger.removeHandler(log_handler)

        if returned is False:
            output = '\n'.join(log_handler.records + [stdout.getvalue()]).strip()
            return CommandResult(ok=False, command=raw, output=output, error='Command failed')

        prompt = returned if isinstance(returned, str) else None
        output = '\n'.join(part for part in (*log_handler.records, stdout.getvalue()) if part).strip()
        return CommandResult(ok=True, command=raw, output=output, prompt=prompt, data=returned)

    def execute_many(self, lines: List[str], capture: bool = False) -> List[CommandResult]:
        results = []
        for line in lines:
            text = line.strip()
            if not text or text.startswith('#'):
                continue
            result = self.execute(text, capture=capture)
            results.append(result)
            if not result.ok:
                break
            if isinstance(result.data, dict) and result.data.get('exit'):
                break
        return results
