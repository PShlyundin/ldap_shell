import logging

class HelloModule:
    def __init__(self, param: str, log: None|logging.Logger=None):
        self._param = param
        self._log = log or logging.getLogger('ldap-shell.shell')

    @classmethod
    def parse_args(cls, line: str) -> str:
        return line

    def __call__(self):
        self._log.info('Hello, world!{}'.format(self._param))
    
def do_hello(obj, line):
    m = HelloModule(
        param=HelloModule.parse_args(line), 
        log=obj._log
    )
    m()
