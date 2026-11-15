"""Row 476 (15.11.2026, a CBOM consumer): a reader that skips `properties` has only
`compositions[].aggregate` to tell it the inventory is not whole.

Checked before changing anything: a file the scan does not claim (`lib/x.so`) made the aggregate
`incomplete`, as it should, but the same file under `vendor/` -- left out by directory name
before counting -- left it `unknown`, as if every file had been read. A file in an excluded
directory is a file not read, so the aggregate is now `incomplete` there too. `.git` is not
part of the tree being inventoried and changes nothing. The file list stays in `properties`;
no field is added. The denominator (row 451) is not changed by this row.
"""

import json
import subprocess
import sys
from pathlib import Path

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom

SIGN = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")


def _tree(root: Path, extra: str | None) -> Path:
    root.mkdir(parents=True)
    (root / "s.py").write_text(SIGN)
    if extra:
        (root / extra).parent.mkdir(parents=True)
        (root / extra).write_bytes(b"\x7fELF" + bytes(range(256)) * 4)
    return root


def _aggregates(root: Path, tmp_path: Path) -> set[str]:
    out = tmp_path / f"{root.name}.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "cbom",
                    str(root), "--out", str(out)], check=True, capture_output=True)
    return {d["compositions"][0]["aggregate"] for d in (
        json.loads(out.read_text()), export_cbom(str(root)), build(scan_directory(root)))}


def test_a_file_in_an_excluded_directory_makes_the_list_incomplete(tmp_path):
    assert _aggregates(_tree(tmp_path / "v", "vendor/x.so"), tmp_path) == {"incomplete"}


def test_a_file_not_claimed_still_makes_it_incomplete(tmp_path):
    assert _aggregates(_tree(tmp_path / "l", "lib/x.so"), tmp_path) == {"incomplete"}


def test_git_and_a_whole_read_leave_it_unknown(tmp_path):
    root = _tree(tmp_path / "g", None)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    assert _aggregates(root, tmp_path) == {"unknown"}
