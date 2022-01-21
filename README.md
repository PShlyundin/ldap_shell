# LDAP shell
This repository contains a small tool inherited from ldap_shell (https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/ldap_shell.py).


## Installation
These tools are only compatible with Python 3.5+. Clone the repository from GitHub, install the dependencies and you should be good to go:

```bash
git clone https://github.com/z-Riocool/ldap_shell.git
cd ldap_shell
python3 setup.py install
```

## Usage
### Connection options
```
ldap_shell domain.local/user:password
ldap_shell domain.local/user:password -dc-ip 192.168.1.2
ldap_shell domain.local/user -hashes aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404e1
export KRB5CCNAME=/home/user/ticket.ccache
ldap_shell -k -no-pass domain.local/user
```
### Functionality
```
add_computer computer [password] - Adds a new computer to the domain with the specified password. Requires LDAPS.
add_user new_user [parent] - Creates a new user.
add_user_to_group user group - Adds a user to a group.
change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
clear_rbcd target grantee - Clear the resource based constrained delegation configuration information.
disable_account user - Disable the user's account.
enable_account user - Enable the user's account.
dump - Dumps the domain.
search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
set_dcsync user - If you have write access to the domain object, assign the DS-Replication right to the selected user.
del_dcsync user - Delete DS-Replication right to the selected user.
get_user_groups user - Retrieves all groups this user is a member of.
get_group_users group - Retrieves all members of a group.
get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
set_genericall target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
set_owner target grantee - Abuse WriteOwner privilege.
dacl_modify - Modify ACE (add/del). Usage: target, grantee, add/del and mask name or ObjectType for ACE modified.
set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
get_maq user - Get ms-DS-MachineAccountQuota for current user.
exit - Terminates this session.
```
## TODO
- [x] del_computer - Delete computer
- [ ] del_user - Delete user
- [x] set_dcsync - If you have write access to the domain object, assign the DS-Replication right to the selected user
- [x] del_dcsync - Del DS-Replication right to the selected user
- [ ] shadow_credantional - inherited [pywhisker](https://github.com/ShutdownRepo/pywhisker)
- [ ] get_all_laps - Get all LAPS passwords
- [x] set_owner - Abuse WriteOwner privilege
- [x] dacl_modify - Set GenericAll, WriteDacl, WriteProperties or set MASK of privilege

## License
Apache

## Authors
* [saber-nyan](https://saber-nyan.com) (main dev)
* [Riocool](https://t.me/riocool)

## Credits
* [Impacket](https://github.com/SecureAuthCorp/impacket)
* [saber-nyan](https://saber-nyan.com)

## Donate
If you want to support the project or have unnecessary money :)
ETH: 0xAA89044f8BE2F712Cc987Be00F55296B3045c9c3
