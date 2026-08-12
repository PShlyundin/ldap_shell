from ldap_shell.__main__ import collect_inline_commands, parse_args


def test_inline_cli_positional_and_dash_c():
    positional = parse_args(['lab.local/user:pass', 'search', '(sAMAccountName=admin)'])
    assert collect_inline_commands(positional) == ["search '(sAMAccountName=admin)'"]

    dashed = parse_args(['lab.local/user:pass', '-c', 'whoami', '-c', 'get_acl admin'])
    assert collect_inline_commands(dashed) == ['whoami', 'get_acl admin']

    empty = parse_args(['lab.local/user:pass'])
    assert collect_inline_commands(empty) == []


def test_inline_cli_entry_exists():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[1] / 'ldap_shell/__main__.py').read_text()
    assert 'inline_command' in source
    assert 'collect_inline_commands' in source
    assert '--mcp' in source


def test_cert_flags_parse():
    pfx = parse_args(['lab.local/', '-pfx', 'user.pfx', '-pfx-pass', 'secret'])
    assert pfx.pfx == 'user.pfx'
    assert pfx.pfx_pass == 'secret'
    pem = parse_args(['lab.local/', '-cert', 'user.pem', '-key', 'user.key'])
    assert pem.cert == 'user.pem'
    assert pem.key == 'user.key'
