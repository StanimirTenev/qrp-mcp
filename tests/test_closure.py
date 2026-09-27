"""prove_closure: a finding counts as closed only when it really left, under the same reader."""

import copy
import json

from qrp_mcp import closure
from qrp_mcp.server import prove_closure


def _result(items, commit="aaa", **over):
    r = {
        "excerpt_level": "full",
        "coverage": {
            "instrument": {
                "version": "0.19.0",
                "source_commit": {"pinned": True, "commit": "tool1", "dirty": False},
                "ruleset": {"algorithm_patterns": 48},
                "claimed_types": {"source": [".py"]},
                "excluded_dirs": [".git"],
            },
            "corpus": {"target": "/repo", "pinned_at": {"pinned": True, "kind": "git",
                                                        "commit": commit, "dirty": False}},
        },
        "evidence": {"source_code": items},
        "unreadable_files": [],
        "files_left_out": [],
        "unreadable_directories": [],
        "symlinks_not_followed": [],
        # a.py is the file every test edits; it is still there unless a test says not.
        "files_read": sorted({"a.py"} | {i["path"] for i in items}),
    }
    r.update(over)
    return r


def _rsa(path="a.py", line=10, excerpt="k = rsa.generate_private_key(65537, 2048)", test=False):
    return {"path": path, "line": line, "algorithm": "RSA", "description": "RSA usage",
            "excerpt": excerpt, "evidence_kind": "call", "in_test_code": test}


def test_removed_line_is_closed():
    before = _result([_rsa(line=10), _rsa(line=20, excerpt="other = rsa.x()")])
    after = _result([_rsa(line=10)], commit="bbb")
    out = closure.prove_closure(before, after)
    assert out["comparability"]["verdict"] == "comparable"
    assert [c["line"] for c in out["closure"]["closed"]] == [20]
    assert out["closure"]["still_open_count"] == 1


def test_lines_moving_down_is_not_closure():
    before = _result([_rsa(line=10)])
    after = _result([_rsa(line=14)], commit="bbb")
    c = closure.prove_closure(before, after)["closure"]
    assert c["closed"] == [] and c["new"] == []
    assert c["still_open_count"] == 1 and c["still_open_moved_lines"] == 1


def test_whitespace_change_on_the_line_is_not_closure():
    before = _result([_rsa(excerpt="k = rsa.generate_private_key(65537,  2048)")])
    after = _result([_rsa(excerpt="k = rsa.generate_private_key(65537, 2048)")], commit="bbb")
    assert closure.prove_closure(before, after)["closure"]["closed"] == []


def test_two_identical_lines_one_removed_is_one_closed():
    before = _result([_rsa(line=10), _rsa(line=30)])
    after = _result([_rsa(line=10)], commit="bbb")
    assert len(closure.prove_closure(before, after)["closure"]["closed"]) == 1


def test_renamed_file_is_relocated_not_closed():
    before = _result([_rsa(path="old.py")])
    after = _result([_rsa(path="new.py")], commit="bbb")
    c = closure.prove_closure(before, after)["closure"]
    assert c["closed"] == [] and c["new"] == []
    assert c["relocated"][0]["path"] == "old.py" and c["relocated"][0]["now_at"] == "new.py"


def test_moving_into_test_code_is_named_not_closed():
    before = _result([_rsa(test=False)])
    after = _result([_rsa(test=True)], commit="bbb")
    c = closure.prove_closure(before, after)["closure"]
    assert c["closed"] == [] and len(c["moved_into_test_code"]) == 1


def test_file_the_second_run_could_not_read_is_unverifiable():
    before = _result([_rsa(path="locked.py")])
    after = _result([], commit="bbb", unreadable_files=[{"path": "locked.py", "reason": "permission"}])
    c = closure.prove_closure(before, after)["closure"]
    assert c["closed"] == [] and c["unverifiable"][0]["path"] == "locked.py"


def test_directory_the_second_run_could_not_enter_is_unverifiable():
    before = _result([_rsa(path="secret/x.py")])
    after = _result([], commit="bbb", unreadable_directories=["secret"])
    assert closure.prove_closure(before, after)["closure"]["unverifiable"]


def test_new_finding_is_new():
    before = _result([])
    after = _result([_rsa()], commit="bbb")
    assert len(closure.prove_closure(before, after)["closure"]["new"]) == 1


def test_different_instrument_closes_nothing():
    before = _result([_rsa()])
    after = _result([], commit="bbb")
    after["coverage"]["instrument"]["version"] = "0.20.0"
    out = closure.prove_closure(before, after)
    assert out["comparability"]["verdict"] == "not_comparable"
    assert out["closure"] is None and "No finding is reported as closed" in out["statement"]


def test_changed_rules_close_nothing():
    before = _result([_rsa()])
    after = _result([], commit="bbb")
    after["coverage"]["instrument"]["ruleset"] = {"algorithm_patterns": 47}
    assert closure.prove_closure(before, after)["closure"] is None


def test_dirty_tree_closes_nothing():
    before = _result([_rsa()])
    after = _result([], commit="bbb")
    after["coverage"]["corpus"]["pinned_at"]["dirty"] = True
    assert closure.prove_closure(before, after)["comparability"]["verdict"] == "not_comparable"


def test_unpinned_tree_is_unestablished():
    before = _result([_rsa()])
    after = _result([], commit="bbb")
    after["coverage"]["corpus"]["pinned_at"] = {"pinned": False}
    out = closure.prove_closure(before, after)
    assert out["comparability"]["verdict"] == "unestablished" and out["closure"] is None


def test_masked_against_full_closes_nothing():
    before = _result([_rsa()])
    after = _result([], commit="bbb", excerpt_level="masked")
    assert closure.prove_closure(before, after)["comparability"]["verdict"] == "not_comparable"


def test_result_without_excerpt_level_is_unestablished():
    before = _result([_rsa()])
    del before["excerpt_level"]
    after = _result([], commit="bbb")
    assert closure.prove_closure(before, after)["comparability"]["verdict"] == "unestablished"


def test_other_categories_are_matched_on_their_own_fields():
    key = {"path": "k.pem", "line": 1, "type": "RSA PRIVATE KEY", "description": "private key"}
    before = _result([])
    before["evidence"]["embedded_keys"] = [key]
    after = _result([], commit="bbb")
    after["evidence"]["embedded_keys"] = [dict(key, line=3)]
    c = closure.prove_closure(before, after)["closure"]
    assert c["closed"] == [] and c["still_open_count"] == 1


def test_per_family_counts():
    before = _result([_rsa(line=1), _rsa(line=2, excerpt="y = rsa.z()")])
    after = _result([_rsa(line=1)], commit="bbb")
    assert closure.prove_closure(before, after)["closure"]["per_family_before_after"]["RSA"] == [2, 1]


def test_tool_reads_two_files(tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(_result([_rsa()])))
    b.write_text(json.dumps(_result([], commit="bbb")))
    out = prove_closure(str(a), str(b))
    assert len(out["closure"]["closed"]) == 1


def test_inputs_are_not_modified():
    before = _result([_rsa()])
    after = _result([], commit="bbb")
    snap = copy.deepcopy((before, after))
    closure.prove_closure(before, after)
    assert (before, after) == snap


def test_linked_file_and_linked_directory_are_unverifiable():
    before = _result([_rsa(path="linked.py"), _rsa(path="lib/y.py", excerpt="z = rsa.q()")])
    after = _result([], commit="bbb", symlinks_not_followed=[
        {"path": "linked.py", "kind": "file"}, {"path": "lib/", "kind": "directory"}])
    c = closure.prove_closure(before, after)["closure"]
    assert c["closed"] == [] and {u["path"] for u in c["unverifiable"]} == {"linked.py", "lib/y.py"}


def test_scan_command_writes_the_level_it_quoted_at(tmp_path):
    """The comparison depends on it, so check it through the command people run."""
    import subprocess
    import sys
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    for level in ("full", "masked", "trimmed"):
        out = tmp_path / f"{level}.json"
        subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tmp_path),
                        "--out", str(out), "--level", level], check=True, capture_output=True)
        assert json.loads(out.read_text())["excerpt_level"] == level


def _installed(r, version="0.19.0"):
    r["coverage"]["instrument"]["source_commit"] = {"pinned": False, "reason": "no_checkout"}
    r["coverage"]["instrument"]["version"] = version
    return r


def test_same_installed_release_is_comparable_and_says_why():
    before = _installed(_result([_rsa()]))
    after = _installed(_result([], commit="bbb"))
    out = closure.prove_closure(before, after)
    assert out["comparability"]["verdict"] == "comparable"
    assert "installed release" in out["comparability"]["basis"][0]
    assert len(out["closure"]["closed"]) == 1


def test_different_installed_releases_close_nothing():
    before = _installed(_result([_rsa()]), "0.19.0")
    after = _installed(_result([], commit="bbb"), "0.19.1")
    assert closure.prove_closure(before, after)["closure"] is None


def test_installed_against_checkout_is_unestablished():
    before = _installed(_result([_rsa()]))
    after = _result([], commit="bbb")
    assert closure.prove_closure(before, after)["comparability"]["verdict"] == "unestablished"


def test_deleted_file_is_removed_not_closed():
    before = _result([_rsa(path="a.py"), _rsa(path="old.py", excerpt="z = rsa.y()")])
    after = _result([_rsa(path="a.py")], commit="bbb")
    out = closure.prove_closure(before, after)
    c = out["closure"]
    assert c["closed"] == []
    assert [r["path"] for r in c["removed"]] == ["old.py"]
    assert c["removed"][0]["why"] == "the file is not in the second tree"
    assert "0 occurrence(s) closed, 1 removed with their file" in out["statement"]


def test_fixed_line_in_a_file_that_is_still_there_is_closed_not_removed():
    before = _result([_rsa(path="a.py"), _rsa(path="b.py", excerpt="z = rsa.y()")])
    after = _result([_rsa(path="a.py")], commit="bbb", files_read=["a.py", "b.py"])
    c = closure.prove_closure(before, after)["closure"]
    assert [r["path"] for r in c["closed"]] == ["b.py"]
    assert c["removed"] == []


def test_result_without_files_read_is_unestablished():
    before = _result([_rsa(line=10), _rsa(line=20, excerpt="other = rsa.x()")])
    after = _result([_rsa(line=10)], commit="bbb")
    del after["files_read"]
    out = closure.prove_closure(before, after)
    assert out["comparability"]["verdict"] == "unestablished"
    assert "files_read_unknown" in [u["reason"] for u in out["comparability"]["unestablished"]]
    assert out["closure"] is None
