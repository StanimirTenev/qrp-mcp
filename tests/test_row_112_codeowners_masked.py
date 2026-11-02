"""ZA-OPRAVYANE row 112 (agent 0.35.0, 23.10.2026; decided by Stanimir on 2 Nov 2026):
CODEOWNERS handles (`@acme/device-team`, an e-mail) went out whole at level `masked`, on
every evidence item and in the CBOM's `[owners: ... per FILE]`, while the line they sit
beside was starred out. They are masked the same way now, on all three exits: the scan
file, the scan_repo tool and the CBOM. `full` keeps them; `trimmed`, which carries less
than `masked`, masks them too."""

import json
import subprocess
import sys

from qrp_mcp.server import export_cbom, scan_repo

HANDLES = ("@acme/device-team", "sec@acme.example")


def _tree(tmp_path):
    tree = tmp_path / "t"
    (tree / ".github").mkdir(parents=True)
    (tree / ".github" / "CODEOWNERS").write_text(
        "/firmware/ @acme/device-team sec@acme.example\n", encoding="utf-8")
    (tree / "firmware").mkdir()
    (tree / "firmware" / "verify.c").write_text(
        "int ok = RSA_verify(NID_sha256, d, 32, sig, siglen, rsa);\n", encoding="utf-8")
    return tree


def _leaks(document) -> list[str]:
    text = json.dumps(document)
    return [h for h in HANDLES if h in text]


def test_the_scan_file_masks_handles_by_default_and_full_keeps_them(tmp_path):
    tree = _tree(tmp_path)
    for extra, leaked in (([], []), (["--level", "trimmed"], []),
                          (["--level", "full"], list(HANDLES))):
        out = tmp_path / "scan.json"
        r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                            "--out", str(out), *extra], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        result = json.loads(out.read_text())
        assert _leaks(result) == leaked, extra
        owned = [i for i in result["evidence"]["source_code"] if i.get("owners")]
        assert owned and all(len(i["owners"]) == 2 for i in owned)
        assert owned[0]["owners_source"] == ".github/CODEOWNERS:1"


def test_the_tool_masks_handles(tmp_path):
    assert _leaks(scan_repo(str(_tree(tmp_path)))) == []


def test_the_cbom_masks_handles(tmp_path):
    tree = _tree(tmp_path)
    cbom = export_cbom(str(tree))
    assert _leaks(cbom) == []
    assert "[owners: @****/******-**** ***@****.******* per .github/CODEOWNERS:1]" in json.dumps(cbom)
    assert _leaks(export_cbom(str(tree), level="full")) == list(HANDLES)
    out = tmp_path / "cbom.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert _leaks(json.loads(out.read_text())) == []
