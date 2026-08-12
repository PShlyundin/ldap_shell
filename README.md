# LDAP shell

Interactive and **inline** LDAP client for Active Directory enumeration and ACL abuse. Fork of Impacket's ldap_shell.

Version **3.0.0**. Requires **Python 3.10+**.

If a DC rejects plaintext LDAP because signing or channel binding is required, the client tries **StartTLS**, then **LDAPS**. If the installed `ldap3` supports `session_security` / `channel_binding`, those are turned on automatically. Stock `ldap3` 2.9.1 still cannot send EPA tokens; use `-use-ldaps` when you already know the DC is locked down, or an `ldap3` build that implements `channel_binding`.

## Installation

```bash
git clone https://github.com/PShlyundin/ldap_shell.git
cd ldap_shell
python3 -m pip install .
# MCP server extra:
python3 -m pip install ".[mcp]"
```

```bash
uv venv
uv pip install .
```

## Usage

### Connection

```bash
ldap_shell domain.local/user:password
ldap_shell domain.local/user:password -dc-ip 192.168.1.2
ldap_shell domain.local/user -hashes aad3b435b51404eeaad3b435b51404ee:aad3b435b51404eeaad3b435b51404e1
export KRB5CCNAME=/home/user/ticket.ccache
ldap_shell -k -no-pass -dc-host dc.domain.local domain.local/user
ldap_shell domain.local/user -pfx user.pfx -pfx-pass 'pfx-secret' -dc-host dc.domain.local
ldap_shell domain.local/ -pfx user.pfx -cert-auth external
ldap_shell domain.local/user -cert user.pem -key user.key -dc-host dc.domain.local
```

`-pfx` / `-cert` default to **PKINIT** (TGT, then Kerberos LDAP) when `-dc-host` and a username (target or UPN in the cert) are present. `-cert-auth external` forces LDAPS SASL EXTERNAL. `-cert-auth auto` falls back to EXTERNAL if PKINIT fails. Same flags work on `ldap_shell-mcp` / the MCP `connect` tool (`LDAP_SHELL_PFX`, `LDAP_SHELL_CERT_AUTH`).

### Inline CLI

The prompt is optional. Pass a command after the target and the process exits:

```bash
ldap_shell domain.local/user:password whoami
ldap_shell domain.local/user:password search "(sAMAccountName=admin)" sAMAccountName,memberOf
ldap_shell domain.local/user:password get_acl admin
ldap_shell domain.local/user:password -c "get_writable" -c whoami
ldap_shell domain.local/user:password --json whoami
ldap_shell domain.local/user:password get_kerberoast
ldap_shell domain.local/user:password set_delegation WEB01$ add cifs/dc.domain.local
ldap_shell domain.local/user:password set_keycred john add
ldap_shell domain.local/user:password set_dns wpad add A 10.0.0.5
ldap_shell domain.local/user:password set_dns www add CNAME server.domain.local
ldap_shell domain.local/user:password set_badsuccessor add Administrator
```

`-non-interactive` reads commands from stdin (one per line).

### MCP

```bash
ldap_shell domain.local/user:password --mcp
# or
LDAP_SHELL_TARGET='domain.local/user:password' ldap_shell-mcp
```

Tools: `connect`, `status`, `list_commands`, `run`. Every shell module is a `run` command (`get_kerberoast`, `set_keycred john add`, …). `connect` accepts the same `-pfx` / `-cert-auth` options.

## Functionality

```
Get Info
    dump [output_dir] - Dumps the domain
    get_asreproast [target] - Users with DONT_REQUIRE_PREAUTH
    get_children [target] - List child objects of a container
    get_delegation [target] - Unconstrained / constrained / RBCD
    get_dns [name] - AD-integrated DNS nodes
    get_group_users group - Get all users in a group
    get_kerberoast [target] - Users with an SPN
    get_laps_gmsa [target] - LAPS (incl. 2.0) and gMSA secrets
    get_maq [user] - Machine Account Quota
    get_privileged_accounts [group] - Built-in privileged group members
    get_trusts - Domain trusts
    get_user_groups user - Recursive group membership
    search ldap_filter [attributes] - Search AD objects
    whoami - Current bind identity, groups and flags

Abuse ACL
    add_sid_history target sid_or_group - Add a SID to sIDHistory
    set_badsuccessor action [victim] [ou|dmsa] [name] - dMSA / BadSuccessor (+ TGT if readable)
    add_user_to_group user group - Add a user to a group
    change_password user [password] - Change password (needs LDAPS/StartTLS)
    clear_rbcd target [grantee] - Clear RBCD
    dacl_modify target grantee action mask - Modify DACL entries
    del_dcsync target - Remove DCSync rights
    del_user_from_group user group - Remove a user from a group
    get_acl target - Read and pretty-print a DACL
    get_ntlm target - Shadow Credentials -> NT hash
    set_keycred target action [device_id] - Persist/list/remove KeyCredentials
    get_writable [trustee] - Objects with interesting write rights
    set_attr target attribute action [value] - Generic attribute modify
    set_dcsync target - Grant DCSync
    set_delegation target action [spn] - Constrained delegation SPNs
    set_dns name action [A|CNAME] [data] [zone] - Add/delete an ADIDNS A or CNAME
    set_dontreqpreauth target flag - Targeted AS-REP roast flag
    set_genericall target [grantee] - Grant GenericAll
    set_owner target [grantee] - Set owner
    set_rbcd target grantee - Configure RBCD
    set_spn target action [spn] - List/add/delete SPN
    uac_modify target action flags - Add/remove/list UAC flags

Misc
    add_computer computer_name [password] [target_dn]
    add_group group_name [target_dn]
    add_user username [password] [target_dn]
    del_computer / del_group / del_user
    disable_account / enable_account
    restore target [target_dn] - Restore from AD recycle bin
    start_tls
    switch_user username [password]

Other
    help [command]
    exit
```

## License

Apache License 2.0

## Authors

* [Riocool](https://t.me/riocool)
* Telegram channel: [RedTeambro](https://t.me/RedTeambro)

## Credits

* [Impacket](https://github.com/fortra/impacket)
* [saber-nyan](https://saber-nyan.com)
