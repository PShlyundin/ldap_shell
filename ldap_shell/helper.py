class Helper():
    def __init__(self, text=None):
        if text:
            self.text=text
        else:
            self.text='''
Get Info
    dump - Dumps the domain.
    search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
    get_user_groups user - Retrieves all groups this user is a member of.
    get_group_users group - Retrieves all members of a group.
    get_laps_gmsa [account] - Retrieves the LAPS and GMSA passwords associated with a given account (sAMAccountName) or for all.
    get_maq user - Get ms-DS-MachineAccountQuota for current user.
Abuse ACL
    add_user_to_group user group - Adds a user to a group.
    del_user_from_group user group - Delete a user from a group.
    change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
    set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
    clear_rbcd target - Clear the resource based constrained delegation configuration information.
    set_dcsync user - If you have write access to the domain object, assign the DS-Replication right to the selected user.
    del_dcsync user - Delete DS-Replication right to the selected user.
    set_genericall target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
    set_owner target grantee - Abuse WriteOwner privilege.
    dacl_modify - Modify ACE (add/del). Usage: target, grantee, add/del and mask name or ObjectType for ACE modified.
    set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
    get_ntlm user - Shadow Credentials method to abuse GenericAll, GenericWrite and AllExtendedRights privilege
    write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
Misc
    switch_user user password/NTLM - Switch user shell.
    add_computer computer [password] - Adds a new computer to the domain with the specified password. Requires LDAPS.
    del_computer computer - Remove a new computer from the domain.
    add_user new_user [parent] - Creates a new user.
    del_user user - Deletes an existing user.
    disable_account user - Disable the user's account.
    enable_account user - Enable the user's account.
    start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
exit - Terminates this session.'''.split('\n')

    def show(self):
        return '\n'.join(self.text)

    def get_meta(self):
        meta = {}
        for e in self.text:
            if ' - ' in e:
                command = e.strip().split(' ')[0]
                description = e.strip().split(' - ')[1]
                meta[command] = description
        return meta

    def get_args(self):
        commands = []
        for e in self.text:
            if ' - ' in e:
                commands.append(e.split(' - ')[0].strip()) 
        return commands