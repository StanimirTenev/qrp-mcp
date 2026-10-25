"""Key-type values, in a key-type context only (ZA-OPRAVYANE row 126; #9 of 18.09).

certbot sets and offers its key type as a value: `key_type = 'rsa'`, `choices=['rsa',
'ecdsa']`, `'--key-type', 'rsa'`. ECDSA on the same line was found and RSA was not, because
`ecdsa` is a word no one writes for anything else and `rsa` alone is refused (it names
logos, file names, variables). Decision 25.10: the value counts where the line says it is a
key type -- `key_type`, `private_key_type`, `--key-type`, `choices=[...]` beside one -- and
RSA and ECDSA are treated alike. A configuration key's NAME (`rsa_enabled`) stays silent.
"""

from pathlib import Path

import pytest

from qrp_mcp import detectors


def _families(line: str, name: str = "a.py") -> set[str]:
    cfg = Path(name).suffix in detectors.CONFIG_EXTENSIONS
    found = detectors.scan_source_file(Path(name), name, lines=[line], cipher_exclusions=cfg)
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("line,expected", [
    ("key_type = 'rsa'", {"RSA"}),
    ("KEY_TYPE = 'ecdsa'", {"ECDSA"}),
    ('config.key_type = "rsa"', {"RSA"}),
    ('cert.private_key_type = "rsa"', {"RSA"}),
    ("RSA_KEY_TYPE = 'rsa'", {"RSA"}),
    ('parser.add_argument("--key-type", choices=[\'rsa\', \'ecdsa\'], type=str)', {"RSA", "ECDSA"}),
    ('"security", "--key-type", choices=[\'rsa\', \'ecdsa\'], type=str,', {"RSA", "ECDSA"}),
    ("args = ['--key-type', 'rsa', '--cert-name', certname]", {"RSA"}),
    ("conf = conf.replace('key_type = rsa', '')", {"RSA"}),
    ("if key_type == 'rsa':", {"RSA"}),
    ("key_type = ed25519", {"Ed25519"}),
])
def test_key_type_values(line, expected):
    assert expected <= _families(line)


@pytest.mark.parametrize("line,name", [
    ("key_type = rsa", "cli.ini"),
    ("key-type: rsa", "config.yaml"),
    ('"key_type": "rsa",', "settings.json"),
])
def test_key_type_values_in_configuration(line, name):
    assert "RSA" in _families(line, name)


@pytest.mark.parametrize("line", [
    "rsa_enabled = False",
    "key_type = 'aes'",
    "token_type = 'rsa'",
    "logo = 'rsa'",
    "choices=['rsa', 'ecdsa']",          # no key type named on the line
    "key_type = 'rsassa_proxy'",
])
def test_no_key_type_context_or_no_family(line):
    assert "RSA" not in _families(line)
