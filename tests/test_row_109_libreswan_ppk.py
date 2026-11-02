"""ZA-OPRAVYANE row 109 (agent 0.35.0, 23.10.2026, А): Libreswan's `ppk=` other than
`insist` is an optional PPK too. Checked against the Libreswan ipsec.conf(5) page (v3.32,
v4.0, v4.12 and libreswan.org/man, read 2 Nov 2026 into ~/zadachi/qrp-mcp/izvori/libreswan):
"propose or yes (the default), signifying we propose to use PPK for this connection; insist,
signifying we allow communication only if PPK is used for key derivation; never or no".
Only `insist` makes the PPK required. `permit`, named in the row, is in none of those pages;
a value the page does not give is not read as required either.

Reproduced on 0.39.0: `ppk=permit` read `mechanism_protected`, as a required PPK would."""

import json
import subprocess
import sys

import pytest

CONN = "conn home\n\tikev2=insist\n\tike=aes256-sha2;modp2048\n\tppk={value}\n"


def _scan(tmp_path, value):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "ipsec.conf").write_text(CONN.format(value=value), encoding="utf-8")
    out = tmp_path / "scan.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


@pytest.mark.parametrize("value", ["propose", "yes", "permit"])
def test_a_proposed_ppk_protects_nothing(tmp_path, value):
    result = _scan(tmp_path, value)
    assert result["summary"]["pqc_readiness"] == "classical_only"
    ppk = next(f for f in result["findings"] if f["algorithm_family"] == "PPK (RFC 8784)")
    assert ppk["protects"] == []


def test_insist_still_protects(tmp_path):
    result = _scan(tmp_path, "insist")
    assert result["summary"]["pqc_readiness"] == "mechanism_protected"
