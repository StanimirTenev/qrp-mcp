"""Row 473 (15.11.2026, SITG-Consulting: "the label carries its basis"): a rule that closes a
line as not a use kept no trace of itself.

`HostKeyAlgorithms -ssh-rsa,ssh-dss` and `USE_ML_KEM_768 = False` are rightly not uses, but
`named_but_not_used` said only `["DSA", "ML-KEM", "RSA"]`: no file, no line, no rule, so the
decision could not be reopened. Each such line now keeps them, in `named_but_not_used_lines`
beside the unchanged family list, and in the CBOM as `qrp:named_but_not_used:lines`. The rules:
removal list, ban list, switch off, comment, identifier. The lines listed are those of every
family the inventory does not count as used: named but not used, or identifier only.
"""

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

FILES = {
    "sshd_config": "HostKeyAlgorithms -ssh-rsa,ssh-dss\nPubkeyAcceptedAlgorithms ssh-ed25519\n",
    "app.py": "USE_ML_KEM_768 = False\n# Ed448 was considered and rejected\n",
    "tls.conf": "Groups = DEFAULT:-X448\n",
}
WANT = [
    {"family": "DSA", "path": "sshd_config", "line": 1, "rule": "removal list"},
    {"family": "Ed448", "path": "app.py", "line": 2, "rule": "comment"},
    {"family": "ML-KEM", "path": "app.py", "line": 1, "rule": "switch off"},
    {"family": "RSA", "path": "sshd_config", "line": 1, "rule": "removal list"},
    {"family": "X448", "path": "tls.conf", "line": 1, "rule": "removal list"},
]


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "r"
    root.mkdir()
    for name, text in FILES.items():
        (root / name).write_text(text)
    return root


def _cli(args):
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True)


def test_every_closed_line_keeps_file_line_and_rule(tmp_path):
    root = _tree(tmp_path)
    out = tmp_path / "s.json"
    _cli(["scan", str(root), "--out", str(out)])
    for result in (json.loads(out.read_text()), scan_repo(str(root)), scan_directory(root)):
        assert result["named_but_not_used"] == ["DSA", "Ed448", "ML-KEM", "RSA", "X448"]
        got = sorted(result["named_but_not_used_lines"],
                     key=lambda r: (r["family"], r["path"], r["line"]))
        assert got == WANT


def test_the_cbom_carries_them(tmp_path):
    root = _tree(tmp_path)
    out = tmp_path / "c.json"
    _cli(["cbom", str(root), "--out", str(out)])
    for doc in (json.loads(out.read_text()), export_cbom(str(root)), build(scan_directory(root))):
        (prop,) = [p for p in doc["properties"] if p["name"] == "qrp:named_but_not_used:lines"]
        got = sorted(json.loads(prop["value"]), key=lambda r: (r["family"], r["location"]))
        assert got == sorted(({"family": w["family"], "location": w["path"], "line": w["line"],
                               "rule": w["rule"]} for w in WANT),
                             key=lambda r: (r["family"], r["location"]))


def test_an_identifier_only_family_keeps_its_rule(tmp_path):
    root = tmp_path / "i"
    root.mkdir()
    (root / "w.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "mlkem_key = ec.generate_private_key(ec.SECP256R1())\n")
    lines = scan_directory(root)["named_but_not_used_lines"]
    assert {"family": "ML-KEM", "path": "w.py", "line": 2, "rule": "identifier"} in lines
    assert all(r["family"] != "EC" for r in lines)
