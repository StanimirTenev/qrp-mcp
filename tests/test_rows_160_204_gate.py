"""ZA-OPRAVYANE rows 160 and 204 (LinkedIn, 27.10 and 04.11.2026; fixture from the room's probe
`su-pipe`).

160: `--mandate nist-ir-8547 --lead-months 60` gave `next_deadline: 2030-12-31` and passed,
because the gate counted the disallowance (2035). From 0.41.0 it counts the deprecation, the
date the block's headline gives.

204: RS256 in the one source file read, a `.jar` and a `.so` not read (type_not_claimed), and
the gate said `pass`. A pass over files not read now reads `not_established`, with the count;
the exit code stays that of a pass (0)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOKENS = ("import jwt\n"
          "def issue(claims, key):\n"
          "    return jwt.encode(claims, key, algorithm=\"RS256\")\n")


def _tree(tmp_path: Path, binaries: bool) -> Path:
    tree = tmp_path / "t"
    (tree / "src").mkdir(parents=True)
    (tree / "src" / "tokens.py").write_text(TOKENS)
    (tree / "requirements.txt").write_text("pyjwt[crypto]==2.9.0\n")
    if binaries:
        (tree / "libs").mkdir()
        (tree / "libs" / "sdk.jar").write_bytes(b"PK\x03\x04" + bytes(60))
        (tree / "libs" / "libpay.so").write_bytes(b"\x7fELF" + bytes(60))
    return tree


def _run(tmp_path: Path, tree: Path, *args: str):
    out = tmp_path / "r.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--mandate", "nist-ir-8547", "--as-of", "2026-11-04", *args,
                        "--out", str(out)], capture_output=True, text=True)
    return r.returncode, json.loads(out.read_text())["mandates"]["nist-ir-8547"]


def test_gate_counts_2030_with_a_60_month_lead(tmp_path):
    code, block = _run(tmp_path, _tree(tmp_path, binaries=False), "--lead-months", "60")
    assert block["gate_counts"] == "deprecated_after"
    assert block["next_gate_deadline"] == block["next_deadline"] == "2030-12-31"
    assert block["gate"] == "fail" and code == 1


def test_files_not_read_make_a_pass_not_established(tmp_path):
    code, block = _run(tmp_path, _tree(tmp_path, binaries=True), "--lead-months", "12")
    assert block["gate"] == "not_established", block
    assert block["gate_not_established_because"].startswith("2 of 4 files were not read")
    assert code == 0


def test_every_file_read_still_passes(tmp_path):
    code, block = _run(tmp_path, _tree(tmp_path, binaries=False), "--lead-months", "12")
    assert block["gate"] == "pass" and code == 0
    assert "gate_not_established_because" not in block


def test_a_failing_gate_stays_failed_with_files_not_read(tmp_path):
    code, block = _run(tmp_path, _tree(tmp_path, binaries=True), "--lead-months", "60")
    assert block["gate"] == "fail" and code == 1
