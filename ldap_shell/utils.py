import logging

import logging.config
import os
import re
from datetime import datetime
from typing import Optional, Tuple

log = logging.getLogger('ldap-shell.utils')

# Compat
PY3 = True


def init_logging(debug: bool, logs_dir_path: Optional[str] = None) -> None:
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'console_basic': {
                'format': '%(asctime)s <%(filename)s:%(lineno)d> [%(levelname)s] '
                          '%(name)s: %(message)s',
                'datefmt': '%H:%M:%S',
            },
            'file_text': {
                'format': '%(asctime)s (+%(relativeCreated)d) [%(levelname)s] P%(process)d T%(thread)d'
                          ' <%(pathname)s:%(lineno)d, %(funcName)s at %(module)s> \'%(name)s\': %(message)s',
            },
        },
        'handlers': {
            'console': {
                'level': 'DEBUG' if debug else 'INFO',
                'class': 'logging.StreamHandler',
                'stream': 'ext://sys.stdout',
                'formatter': 'console_basic',
            },
        },
        'loggers': {
            '': {
                'level': 'DEBUG',
                'handlers': ['console', ],
            },
            'ldap-shell': {
                'level': 'DEBUG',
                'handlers': ['console', ],
                'propagate': False,
            },
        },
    }
    log_file_path = None
    if logs_dir_path is not None:
        date_str = datetime.now().strftime('%Y-%m-%d_%H-%M-%S.%f')
        filename = f'ldap-shell_{date_str}.log'
        log_file_path = os.path.join(logs_dir_path, filename)
        config['handlers']['file'] = {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': log_file_path,
            'mode': 'wt',
            'encoding': 'utf-8',
            'formatter': 'file_text',
        }

        for logger in config['loggers'].values():
            # noinspection PyUnresolvedReferences
            logger['handlers'].append('file')

    logging.config.dictConfig(config)
    log.debug('Logging (re)initialised, debug=%s, log_file=%s', debug, log_file_path)


credential_regex = re.compile(r'(?:(?:([^/:]*)/)?([^:]*)(?::(.*))?)?')


def parse_credentials(credentials: str) -> Tuple[str, str, str]:
    """Helper function to parse credentials information. The expected format is:

    <DOMAIN></USERNAME><:PASSWORD>

    :param credentials: credentials to parse
    :type credentials: string

    :return: tuple of domain, username and password
    :rtype: (string, string, string)
    """
    domain, username, password = credential_regex.match(credentials).groups('')
    return domain, username, password


def b(s):
    """Impacket PY2/3 compat wrapper"""
    return s.encode("latin-1")
