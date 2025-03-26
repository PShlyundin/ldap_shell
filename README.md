# LDAP shell
This project is a fork of ldap_shell from Impacket. It provides an interactive shell for Active Directory enumeration and manipulation via LDAP/LDAPS protocols, making it useful for both system administrators and security professionals.


## Installation
These tools are only compatible with Python 3.5+. Clone the repository from GitHub, install the dependencies and you should be good to go.
Installation with pip:
```bash
git clone https://github.com/PShlyundin/ldap_shell.git
cd ldap_shell
python3 -m pip install .
```

Installation with uv:
```bash
uv venv
uv pip install .
```

## Usage
### Connection options
```bash
# Basic authentication with password
ldap_shell domain.local/user:password

# Specify domain controller IP address
ldap_shell domain.local/user:password -dc-ip 192.168.1.2

# Authentication using NTLM hashes
ldap_shell domain.local/user -hashes aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404e1

# Kerberos authentication using TGT
export KRB5CCNAME=/home/user/ticket.ccache
ldap_shell -k -no-pass domain.local/user
```
### Functionality
```
Get Info
    dump [output_dir] - Dumps the domain
    get_group_users group - Get all users in a group
    get_laps_gmsa [target] - Retrieves LAPS and GMSA passwords associated with a given account (sAMAccountName) or for all. Supported LAPS 2.0
    get_maq [user] - Get Machine Account Quota and allowed users
    get_user_groups user - Retrieves all groups recursively this user is a member of
    search ldap_filter [attributes] - Search AD objects

Abuse ACL
    add_user_to_group user group - Add a user to a group
    change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
    clear_rbcd target [grantee] - Clear RBCD permissions for a target computer
    dacl_modify target grantee action mask - Modify DACL entries for target object
    del_dcsync target - Remove DCSync rights from user/computer by deleting ACEs in domain DACL
    del_user_from_group user group - Delete a user from a group
    get_ntlm target - Get NTLM hash using Shadow Credentials attack (requires write access to msDS-KeyCredentialLink)
    set_dcsync target - If you have write access to the domain object, assign the DS-Replication right to the selected user
    set_dontreqpreauth target flag - Targeted AsRepRoast attack. Set or unset DONT_REQUIRE_PREAUTH flag for a target user.
    set_genericall target [grantee] - Set GenericAll permissions for a target object
    set_owner target [grantee] - Set new owner for target object
    set_rbcd target grantee - Configure RBCD permissions for a target computer
    set_spn target action [spn] - List, add or delete SPN for a target object

Misc
    add_computer computer_name [password] [target_dn] - Add a new computer account to the domain
    add_group group_name [target_dn] - Add new group to Active Directory
    add_user username [password] [target_dn] - Add a new user account to the domain
    del_computer computer_name - Delete a computer account from the domain
    del_group group_name - Delete group from Active Directory
    del_user username - Delete a user account from the domain
    disable_account username - Disable a user account in the domain
    enable_account username - Enable a user account in the domain
    start_tls  - Start TLS connection with LDAP server
    switch_user username [password] - Switch current user to another

Other
    help [command] - Show help
exit - exit from shell
```

## License
Apache License 2.0

## Authors
* [Riocool](https://t.me/riocool)
* My [Telegram channel](https://t.me/RedTeambro)

## Credits
* [Impacket](https://github.com/SecureAuthCorp/impacket)
* [saber-nyan](https://saber-nyan.com)
