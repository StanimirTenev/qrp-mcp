"""Row 471 (15.11.2026, QCI CBOM-Benchmark 2.6.6 cross-run): files removed by a directory
exclusion before counting were counted, not named -- `files_excluded_before_counting:
by_directory:dist 3` with no path, while those files (minified JS under
tier5/javascript/dist/, a jar under build/libs/) held 13 findings that another scanner read.
Row 49 stopped the silence and row 3 named type_not_claimed files; this names each excluding
directory from the root with its files (up to 50, then the count of the rest), as a JSON array
in the CBOM (row 6: no comma-joined lists). `.git` is not listed.
"""

import json
import subprocess
import sys

from qrp_mcp.coverage import EXCLUDED_PATHS_LISTED
from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo


def _tree(root):
    (root / "tier5/javascript/dist").mkdir(parents=True)
    for i in range(3):
        (root / f"tier5/javascript/dist/app{i}.min.js").write_text('require("crypto").createHash("md5")\n')
    (root / "svc/build/libs").mkdir(parents=True)
    (root / "svc/build/libs/ledger.jar").write_bytes(b"PK\x03\x04")
    (root / ".git").mkdir()
    (root / ".git/HEAD").write_text("ref: refs/heads/main\n")
    (root / "app.py").write_text("import hashlib\nhashlib.md5(b'x')\n")


EXPECTED = [
    {"directory": "svc/build", "files": 1, "paths": ["svc/build/libs/ledger.jar"]},
    {"directory": "tier5/javascript/dist", "files": 3,
     "paths": [f"tier5/javascript/dist/app{i}.min.js" for i in range(3)]},
]


def _directories(result):
    return result["coverage"]["scope"]["files_excluded_before_counting"]["directories"]


def test_excluded_directories_are_named(tmp_path):
    _tree(tmp_path)
    result = scan_directory(tmp_path)
    assert _directories(result) == EXPECTED
    # The counts stay as they were.
    by_dir = result["coverage"]["scope"]["files_excluded_before_counting"]["by_directory"]
    assert by_dir["dist"] == 3 and by_dir["build"] == 1


def test_a_large_directory_is_listed_up_to_the_cap(tmp_path):
    (tmp_path / "node_modules/pkg").mkdir(parents=True)
    for i in range(EXCLUDED_PATHS_LISTED + 7):
        (tmp_path / f"node_modules/pkg/f{i:03}.js").write_text("x\n")
    (entry,) = _directories(scan_directory(tmp_path))
    assert entry["files"] == EXCLUDED_PATHS_LISTED + 7
    assert len(entry["paths"]) == EXCLUDED_PATHS_LISTED and entry["paths_not_listed"] == 7


def _cbom_paths(bom):
    props = {p["name"]: p["value"] for p in bom["properties"]}
    out = {}
    for i in range(10):
        key = f"qrp:coverage:scope:files_excluded_before_counting:directories:{i}"
        if f"{key}:directory" not in props:
            break
        out[props[f"{key}:directory"]] = json.loads(props[f"{key}:paths"])
    return out


def test_the_names_leave_by_every_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _tree(src)
    out, bom = tmp_path / "scan.json", tmp_path / "bom.json"
    for args in (("scan", str(src), "--out", str(out), "--no-config"),
                 ("cbom", str(src), "--out", str(bom), "--no-config")):
        done = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                               *args], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    assert _directories(json.loads(out.read_text())) == EXPECTED
    assert _directories(getattr(scan_repo, "fn", scan_repo)(str(src))) == EXPECTED
    want = {e["directory"]: e["paths"] for e in EXPECTED}
    for b in (json.loads(bom.read_text()), build(scan_directory(src)),
              getattr(export_cbom, "fn", export_cbom)(str(src))):
        assert _cbom_paths(b if isinstance(b, dict) else json.loads(b)) == want
