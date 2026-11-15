"""Row 470 (15.11.2026, QCI CBOM-Benchmark 2.6.6 cross-run): a CBOM consumer had no marker on an
occurrence to filter a not-a-use by -- `qrp:evidence_kind` is a list on the component, and only
comments were tagged in `additionalContext`. Identifier rows are now tagged `[identifier]` on
the occurrence, as comments are `[comment]`; a call stays untagged.
"""

import json
import subprocess
import sys

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom

WASHING = ("from cryptography.hazmat.primitives.asymmetric import ec\n"
           "class MlkemSession:\n"
           "    def __init__(self):\n"
           "        self.mlkem_key = ec.generate_private_key(ec.SECP256R1())\n")


def _contexts(bom, prefix):
    return [o["additionalContext"] for c in bom["components"] if c["name"].startswith(prefix)
            for o in c.get("evidence", {}).get("occurrences", [])]


def _check(bom):
    pq = _contexts(bom, "ML-KEM")
    assert pq and all(c.startswith("[identifier]") for c in pq), pq
    ec = _contexts(bom, "EC")
    assert ec and not any(c.startswith("[") for c in ec), ec


def test_identifier_occurrences_are_tagged(tmp_path):
    (tmp_path / "w.py").write_text(WASHING)
    _check(build(scan_directory(tmp_path)))


def test_tagged_on_every_cbom_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "w.py").write_text(WASHING)
    bom = tmp_path / "bom.json"
    done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                           "cbom", str(src), "--out", str(bom), "--no-config"],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    _check(json.loads(bom.read_text()))
    tool = getattr(export_cbom, "fn", export_cbom)(str(src))
    _check(tool if isinstance(tool, dict) else json.loads(tool))
