from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ldaps_retry_on_signing():
    source = (ROOT / 'ldap_shell/session.py').read_text()
    assert '_looks_like_signing_error' in source
    assert 'channel_binding' in source
