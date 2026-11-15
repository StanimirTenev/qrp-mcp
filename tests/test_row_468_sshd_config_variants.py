"""Row 468 (15.11.2026, QCI CBOM-Benchmark 2.6.6 cross-run): `sshd_config_pq` was
type_not_claimed because only the exact name `sshd_config` was, and its mlkem768x25519 and
sntrup761x25519 key exchanges were lost. A variant after the name or before it is now read
as the file it is; OpenSSH's manual pages (sshd_config.5, ssh_config.0) are not.
"""

import json
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

SSHD = ("Port 22\n"
        "HostKeyAlgorithms ssh-ed25519\n"
        "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256\n")


def _kex_families(result, name):
    return {o["algorithm"] for o in result["evidence"]["source_code"] if o["path"] == name}


def test_variant_names_are_read(tmp_path):
    names = ("sshd_config_pq", "sshd_config.bastion", "bastion.sshd_config", "ssh_config-prod")
    for name in names:
        (tmp_path / name).write_text(SSHD)
    result = scan_directory(tmp_path)
    for name in names:
        assert {"ML-KEM", "NTRU", "X25519"} <= _kex_families(result, name), name
    unclaimed = [p for r in result["coverage"]["not_examined"]
                 if r["reason"] == "type_not_claimed" for p in r.get("paths", [])]
    assert not set(names) & set(unclaimed), unclaimed


def test_manual_pages_are_not_configuration(tmp_path):
    docs = ("sshd_config.5", "ssh_config.0", "sshd_config.md", "ssh_config.txt",
            "ssh_config.5.html")
    for name in docs:
        (tmp_path / name).write_text(".Cm KexAlgorithms mlkem768x25519-sha256\n")
    result = scan_directory(tmp_path)
    assert not result["evidence"]["source_code"]
    unclaimed = {p for r in result["coverage"]["not_examined"]
                 if r["reason"] == "type_not_claimed" for p in r.get("paths", [])}
    assert set(docs) <= unclaimed, unclaimed


def test_a_file_another_type_claims_stays_that_type(tmp_path):
    # As in 0.44.0: ssh_config.py is Python, ssh_config_test.go is Go.
    from qrp_mcp.detectors import CONFIG_FILENAME_PATTERN
    for name in ("ssh_config.py", "ssh_config_test.go"):
        assert not CONFIG_FILENAME_PATTERN.match(name), name


def test_variant_on_every_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "sshd_config_pq").write_text(SSHD)
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    assert "ML-KEM" in _kex_families(json.loads(out.read_text()), "sshd_config_pq")
    assert "ML-KEM" in _kex_families(getattr(scan_repo, "fn", scan_repo)(str(src)), "sshd_config_pq")
    for b in (json.loads(bom.read_text()), build(scan_directory(src)),
              getattr(export_cbom, "fn", export_cbom)(str(src))):
        b = b if isinstance(b, dict) else json.loads(b)
        assert any(c["name"].startswith("ML-KEM") for c in b["components"])
