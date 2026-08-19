"""
Installation script.
"""
from setuptools import find_packages, setup

with open('README.md', mode='r', encoding='utf-8') as f:
    readme = f.read()

setup(
    name='ldap_shell',
    version='2.0.0',
    description='Interactive and inline LDAP shell for Active Directory ACL abuse',
    long_description=readme,
    long_description_content_type='text/markdown',
    author='Riocool',
    author_email='Riocool33@gmail.com',
    url='https://github.com/PShlyundin/ldap_shell',
    python_requires='>=3.10',
    install_requires=[
        'ldap3>=2.9.1,<3',
        'ldapdomaindump>=0.9.4',
        'pyasn1>=0.4.8',
        'pycryptodomex>=3.20',
        'dsinternals>=1.2.4',
        'minikerberos>=0.4.0',
        'winsspi>=0.0.10;platform_system=="Windows"',
        'impacket>=0.11.0',
        'pyOpenSSL>=24.0.0',
        'cryptography>=42.0.0',
        'prompt_toolkit>=3.0.36',
        'pydantic>=2.0,<3',
        'oscrypto @ git+https://github.com/wbond/oscrypto.git@d5f3437ed24257895ae1edd9e503cfb352e635a8',
        'colorama>=0.4.6',
    ],
    extras_require={
        'mcp': ['mcp>=1.2'],
        'dev': ['pytest>=8.0', 'mcp>=1.2'],
    },
    packages=find_packages(),
    include_package_data=True,
    package_data={
        'ldap_shell': [
            'ldap_modules/*/ldap_module.py',
            'ldap_modules/*/*',
        ]
    },
    entry_points={
        'console_scripts': [
            'ldap_shell=ldap_shell.__main__:main',
            'ldap_shell-mcp=ldap_shell.mcp_server:main',
        ],
    },
)
