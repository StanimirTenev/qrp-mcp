"""A baseline: what was already there is told apart from what is new, and never hidden.

Keyed by path + family + the line's text with its whitespace collapsed, not by line number,
so an edit above a known finding does not make it new. Stored as a digest: a baseline gets
committed, and the line it stands for may hold more than the algorithm. A baselined row stays
in `evidence` with `baseline_state: baselined`; `baseline` counts both kinds and what the
baseline held that this run did not find.
"""

import json

import pytest

from qrp_mcp import server
from qrp_mcp.scan import scan_directory

IMPORT = "from cryptography.hazmat.primitives.asymmetric import rsa, ec\n"
OLD = "k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
NEW = "k2 = ec.generate_private_key(ec.SECP256R1())\n"


def _write_baseline(tmp_path, tree):
    out = tmp_path / "baseline.json"
    code = server.scan_to_file([str(tree), "--write-baseline", str(out),
                                "--out", str(tmp_path / "r.json")])
    assert code == 0
    return out


def _tree(tmp_path, text):
    tree = tmp_path / "repo"
    tree.mkdir(exist_ok=True)
    (tree / "app.py").write_text(text)
    return tree


def test_baselined_rows_stay_and_new_rows_are_new(tmp_path):
    tree = _tree(tmp_path, IMPORT + OLD)
    base = _write_baseline(tmp_path, tree)
    doc = json.loads(base.read_text())
    assert doc["format"] == "qrp-mcp baseline 1" and doc["entries"]
    assert all(set(e) == {"key", "path", "family"} for e in doc["entries"])
    # The line itself is not in the file, only its digest.
    assert "generate_private_key" not in base.read_text()

    # An edit above the old line moves it down; it is still the same finding.
    (tree / "app.py").write_text("# header\n" + IMPORT + OLD + NEW)
    r = scan_directory(tree, baseline=base)
    states = {(e["line"], e["algorithm"]): e["baseline_state"]
              for e in r["evidence"]["source_code"]}
    assert states[(3, "RSA")] == "baselined"
    assert states[(4, "EC")] == "new"
    b = r["baseline"]
    assert b["new"] >= 1 and b["baselined"] >= 1
    assert b["file"] == str(base)
    assert b["new_items"] and all(i["baseline_state"] == "new" for i in b["new_items"])


def test_whitespace_on_the_line_does_not_make_it_new(tmp_path):
    tree = _tree(tmp_path, IMPORT + OLD)
    base = _write_baseline(tmp_path, tree)
    (tree / "app.py").write_text(IMPORT + OLD.replace("= rsa", "=   rsa"))
    r = scan_directory(tree, baseline=base)
    assert r["baseline"]["new"] == 0


def test_a_fixed_finding_is_counted_absent(tmp_path):
    tree = _tree(tmp_path, IMPORT + OLD)
    base = _write_baseline(tmp_path, tree)
    (tree / "app.py").write_text(IMPORT)
    r = scan_directory(tree, baseline=base)
    assert r["baseline"]["absent"] >= 1


def test_two_identical_lines_baseline_one_is_one_new(tmp_path):
    tree = _tree(tmp_path, IMPORT + OLD)
    base = _write_baseline(tmp_path, tree)
    (tree / "app.py").write_text(IMPORT + OLD + OLD)
    r = scan_directory(tree, baseline=base)
    rsa = [e["baseline_state"] for e in r["evidence"]["source_code"] if e["algorithm"] == "RSA"]
    assert sorted(rsa) == ["baselined", "new"]


def test_baseline_file_inside_the_tree_is_left_out_and_named(tmp_path):
    tree = _tree(tmp_path, IMPORT + OLD)
    base = tree / ".qrp-baseline.json"
    code = server.scan_to_file([str(tree), "--write-baseline", str(base),
                                "--out", str(tmp_path / "r.json")])
    assert code == 0
    r = scan_directory(tree, baseline=base)
    assert ".qrp-baseline.json" in r["files_left_out"]
    assert r["baseline"]["new"] == 0


def test_cli_baseline_flag(tmp_path):
    tree = _tree(tmp_path, IMPORT + OLD)
    base = _write_baseline(tmp_path, tree)
    (tree / "new.py").write_text(IMPORT + NEW)
    out = tmp_path / "after.json"
    assert server.scan_to_file([str(tree), "--baseline", str(base), "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    assert {i["path"] for i in r["baseline"]["new_items"]} == {"new.py"}


def test_a_missing_baseline_is_an_error_not_an_empty_one(tmp_path, capsys):
    tree = _tree(tmp_path, IMPORT + OLD)
    with pytest.raises(SystemExit) as e:
        server.scan_to_file([str(tree), "--baseline", str(tmp_path / "nope.json")])
    assert e.value.code == 2 and "baseline" in capsys.readouterr().err
