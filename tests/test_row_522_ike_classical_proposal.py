"""Row 522 (17.11.2026, Gowthami Pagilla; probe `linkedin-postove/2026-11-17/stai-qrp/proba-gowthami/`).

strongSwan `proposals = aes256gcm16-prfsha384-ecp256-ke1_mlkem768, aes256gcm16-prfsha384-ecp256`
(a hybrid proposal and a classical one after it) and the hybrid proposal alone gave the same
`findings_fingerprint` and the same `key_establishment: pqc_ready`, so removing the classical
fallback closed nothing. The same defect was fixed for nginx groups in 0.28.0 (row 5) and for
OpenSSH KexAlgorithms (row 22). A strongSwan proposal whose key exchange is classical only --
no additional key exchange (`keN_`), or one made optional by `keN_none` -- is now a row of its own
in `evidence.ike_proposals` (`offered: alone`), so the two trees differ, `closure` closes it when
it goes, the summary says it is the fallback beside a hybrid, a `--mandate` dates it as key
establishment, and the CBOM has it as a component.

Not claimed: what a connection negotiates (the peers choose); ipsec.conf's Libreswan syntax
(`ike=...;dh20`) and FortiOS/Cisco/Junos proposals are not read for this.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

CONF = """connections {{
    telematics {{
        version = 2
        remote_addrs = backend.example.test
        proposals = {proposals}
        children {{
            ota {{
                esp_proposals = aes256gcm16-ecp256-ke1_mlkem768
            }}
        }}
    }}
}}
"""
WITH = "aes256gcm16-prfsha384-ecp256-ke1_mlkem768, aes256gcm16-prfsha384-ecp256"
WITHOUT = "aes256gcm16-prfsha384-ecp256-ke1_mlkem768"


def _tree(root: Path, proposals: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "swanctl.conf").write_text(CONF.format(proposals=proposals))
    return root


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})


def test_a_classical_proposal_beside_a_hybrid_is_a_row(tmp_path):
    result = scan_directory(_tree(tmp_path / "a", WITH))
    rows = [(r["line"], r["group"], r["family"], r["offered"], r["proposal"])
            for r in result["evidence"]["ike_proposals"]]
    assert rows == [(5, "ecp256", "ECDH", "alone", "aes256gcm16-prfsha384-ecp256")]
    assert result["evidence"]["ike_proposals"][0]["in_test_code"] is False
    b = scan_directory(_tree(tmp_path / "b", WITHOUT))
    assert b["evidence"]["ike_proposals"] == []
    assert result["findings_fingerprint"]["sha256"] != b["findings_fingerprint"]["sha256"]


def test_an_optional_additional_exchange_is_a_classical_fallback(tmp_path):
    result = scan_directory(_tree(tmp_path, "aes128gcm16-ecp256-ke1_mlkem768-ke1_none"))
    [row] = result["evidence"]["ike_proposals"]
    assert (row["group"], row["family"], row["offered"]) == ("ecp256", "ECDH", "alone")
    assert "ke1_none" in row["description"]


def test_other_classical_groups_and_words_that_are_not(tmp_path):
    result = scan_directory(_tree(
        tmp_path, "aes256-sha256-modp3072, aes256-sha256-x25519, aes256-sha256-mlkem768"))
    assert [(r["group"], r["family"]) for r in result["evidence"]["ike_proposals"]] == [
        ("modp3072", "DH"), ("x25519", "X25519")]


def test_the_summary_names_the_fallback_and_the_cbom_has_it(tmp_path):
    result = scan_directory(_tree(tmp_path, WITH))
    notes = json.dumps(result["summary"])
    assert "swanctl.conf:5" in notes and "fallback_beside_hybrid" in notes
    names = [c["name"] for c in build(result)["components"]]
    assert "ecp256 (IKE key exchange offered alone)" in names


def _scan_cli(tree: Path, out: Path) -> Path:
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads(out.read_text())
    # As in test_ssh_kex_fallback: the instrument is this working tree, dirty while it changes.
    data["coverage"]["instrument"]["source_commit"] = {
        "pinned": True, "commit": "instrument", "dirty": False}
    out.write_text(json.dumps(data))
    return out


def test_closure_closes_the_fallback(tmp_path):
    root = _tree(tmp_path / "r", WITH)
    _git(root, "init", "-q")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "a")
    before = _scan_cli(root, tmp_path / "before.json")
    (root / "swanctl.conf").write_text(CONF.format(proposals=WITHOUT))
    _git(root, "commit", "-q", "-am", "b")
    after = _scan_cli(root, tmp_path / "after.json")
    out = tmp_path / "closure.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "closure", str(before),
                        str(after), "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    verdict = json.loads(out.read_text())
    assert verdict["comparability"]["verdict"] == "comparable"
    closed = [c for c in verdict["closure"]["closed"] if c["category"] == "ike_proposals"]
    assert [(c["group"], c["offered"]) for c in closed] == [("ecp256", "alone")]
    assert verdict["closure"]["per_family_before_after"]["ecp256 offered alone"] == [1, 0]


def test_the_command_line_carries_it(tmp_path):
    root = _tree(tmp_path / "t", WITH)
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out), "--level", "full"],
                   check=True, capture_output=True, env=dict(os.environ))
    assert len(json.loads(out.read_text())["evidence"]["ike_proposals"]) == 1


def test_a_mandate_dates_the_fallback_as_key_establishment(tmp_path):
    root = _tree(tmp_path / "t", WITH)
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out), "--mandate", "eu-pqc-roadmap"],
                   capture_output=True, env=dict(os.environ))
    [row] = json.loads(out.read_text())["evidence"]["ike_proposals"]
    assert row["mandates"]["eu-pqc-roadmap"]["deadline"] == "2035-12-31"
    assert row["hndl_exposed"] is True
