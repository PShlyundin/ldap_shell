import logging

class LdapShellModule:
    def __init__(self, line: str, log: None|logging.Logger=None):
        self._line = line
        self._log = log or logging.getLogger('ldap-shell.shell')

    @classmethod
    def parse_args(cls, line: str) -> str:
        # TODO: big logic parse args
        return line+'123'

    def __call__(self):
        params = self.parse_args(self._line)
        self._log.info('Hello, world!{}'.format(params))
    
    #def do_hello(self, line):
    #    m = HelloModule(
    #        param=HelloModule.parse_args(line), 
    #        log=self._log
    #    )
    #    m()