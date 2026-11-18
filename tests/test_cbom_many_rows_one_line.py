"""Third review of 0.50.0 (18.11), found while running the review's fixtures on fa2ac4e: since
setup.py is read token by token, p_binop (200 000 `["cryptography"]` joined by `+` on one line)
gives 200 000 dependency rows on one line, and `qrp-mcp cbom` was killed at 900 s (fddec63
read one row there and wrote the CBOM in 12 s). `_confidence_properties` took, for each
occurrence, the rows of its file:line again: quadratic in the rows that share a line (5 000:
4.8 s, 20 000: 61 s). Each file:line is now graded once per family. Run in a subprocess with a
timeout, so a slow CBOM fails the test instead of hanging the suite.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import qrp_mcp


def test_a_cbom_of_many_rows_on_one_line_is_written_in_seconds(tmp_path):
    n = 30000
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nsetup(install_requires="
        + "+".join(['["cryptography"]'] * n) + ")\n")
    here = str(Path(qrp_mcp.__file__).resolve().parents[1])
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([here, os.environ.get("PYTHONPATH", "")])}
    out = tmp_path / "cbom.json"
    done = subprocess.run(
        [sys.executable, "-c", "import sys; from qrp_mcp import server; server.main(sys.argv[1:])",
         "cbom", str(tmp_path), "--out", str(out)],
        capture_output=True, text=True, timeout=60, env=env)
    assert done.returncode == 0, done.stderr[-500:]
    bom = json.loads(out.read_text())
    levels = [json.loads(p["value"]) for c in bom["components"] for p in c.get("properties", [])
              if p["name"] == "qrp:confidence"]
    assert sum(len(x) for x in levels) >= n
