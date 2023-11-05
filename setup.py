"""
Installation script.
"""
from setuptools import find_packages, setup

with open('README.md', mode='r', encoding='utf-8') as f:
    readme = f.read()

setup(
    name='ldap_shell',
    version='1.0.0',
    description='LDAP shell utility from Impacket',
    long_description=readme,
    author='Riocool and saber-nyan',
    author_email='z-Riocool@gmail.com',
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
    ],
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': ['ldap_shell=ldap_shell.__main__:main', ],
    },
)
