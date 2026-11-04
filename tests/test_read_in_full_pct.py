"""Stanimir's decision on rows 229, 333 and 362 (04.11.2026): a file read only in part is counted
separately. `coverage.scope.coverage_pct` stays files opened / files given, so 0.41.0 readers and
`--min-coverage` see no change; beside it `read_in_part` (files) and `read_in_full_pct` (files
read in full / files given). The verdict names both, and the CBOM and SARIF carry them."""

from __future__ import annotations

import json
import subprocess
import sys


def _tree(tmp_path):
    (tmp_path / "srx.conf").write_text("set security ike proposal P1 dh-group group14\n")
    (tmp_path / "nginx.conf").write_text("server {\n    ssl_protocols TLSv1.2;\n}\n")
    (tmp_path / "a.docx").write_bytes(b"x")
    (tmp_path / "b.docx").write_bytes(b"x")
    return tmp_path


def test_scope_counts_read_in_part_separately(tmp_path):
    from qrp_mcp.scan import scan_directory
    scope = scan_directory(_tree(tmp_path))["coverage"]["scope"]
    assert scope["coverage_pct"] == 50.0
    assert scope["read_in_part"] == 1
    assert scope["read_in_full_pct"] == 25.0


def test_verdict_names_the_share_read_in_full(tmp_path):
    from qrp_mcp.scan import scan_directory
    verdict = scan_directory(_tree(tmp_path))["verdict"]
    assert "(50.0%)" in verdict and "25.0% of the files given were read in full" in verdict


def test_clean_tree_reads_in_full(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "nginx.conf").write_text("server {\n    ssl_protocols TLSv1.2;\n}\n")
    scope = scan_directory(tmp_path)["coverage"]["scope"]
    assert (scope["read_in_part"], scope["read_in_full_pct"], scope["coverage_pct"]) == (0, 100.0, 100.0)


def test_min_coverage_still_measures_files_opened(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    _tree(tree)
    run = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                          "--mandate", "cnsa-2.0", "--lead-months", "0", "--min-coverage", "50",
                          "--out", str(tmp_path / "r.json")], capture_output=True, text=True)
    gate = json.loads((tmp_path / "r.json").read_text())
    # 50% opened meets 50; that only 25% was read in full does not fail the gate.
    assert "below --min-coverage" not in json.dumps(gate), run.stderr


def test_cbom_and_sarif_carry_them(tmp_path):
    from qrp_mcp.cyclonedx import build
    from qrp_mcp import sarif
    from qrp_mcp.scan import scan_directory
    result = scan_directory(_tree(tmp_path))
    cbom = json.dumps(build(result))
    assert "read_in_full_pct" in cbom and "read_in_part" in cbom
    keys = {id(i): "k" for items in result["evidence"].values() for i in items}
    coverage = sarif.build(result, keys)["runs"][0]["properties"]["coverage"]
    assert coverage["read_in_part"] == 1 and coverage["read_in_full_pct"] == 25.0
