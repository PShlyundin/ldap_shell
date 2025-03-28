"""
Installation script.
"""
from setuptools import find_packages, setup

with open('README.md', mode='r', encoding='utf-8') as f:
    readme = f.read()

setup(
    name='ldap_shell',
    version='2.0.0',
    description='LDAP shell utility from Impacket',
    long_description=readme,
    author='Riocool',
    author_email='Riocool33@gmail.com',
    url='https://github.com/PShlyundin/ldap_shell',
    install_requires=[
        'ldap3',
        'ldapdomaindump',
        'pyasn1',
        'pycryptodomex',
        'dsinternals',
        'minikerberos',
        'winsspi',
        'impacket',
        'pyOpenSSL',
        'pycryptodome',
        'prompt_toolkit',
        'pydantic',
        'oscrypto @ git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8',
        'colorama',
    ],
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'ldap_shell': [
            'ldap_modules/*/ldap_module.py',
            'ldap_modules/*/*',  # Include all files in module subfolders
        ]
    },
    entry_points={
        'console_scripts': ['ldap_shell=ldap_shell.__main__:main', ],
    },
)
