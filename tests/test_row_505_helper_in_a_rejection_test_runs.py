"""ZA-OPRAVYANE row 505, D11 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8
(U-Boot 6487c50, 0.46.0).

U-Boot `test/py/tests/test_vboot.py`: `test_vboot_ext_data_bounds`, whose docstring says
"Test that malformed external-data properties are rejected.", defines a helper inside it,
`create_rsa_pair`, which runs `openssl genpkey -algorithm RSA` (:792) to make the key the test
signs with. A test whose docstring says what it rejects is a rejection test (rel3-rules), so
everything in it was a ban -- the helper's key generation too: `evidence_kind "ban"`,
`not_a_use_rule "ban list"`. The same call in another test (:343) was a use.

A function defined inside the test is a function: what it calls it runs, as the docstring rule
already said of a library function ("Test functions only"). Its body is outside the test's
rejection; the test's own lines stay in it, as before.

Repro: `boot-proba/repro/ban-docstring/a/t.py` (docstring "is rejected") gave `ban`,
`b/t.py` (identical but "is handled") `registry_name`.
"""

import json
from pathlib import Path

from qrp_mcp import cyclonedx, server
from qrp_mcp import detectors as d
from qrp_mcp.scan import scan_directory

REJECTED = '''def test_x(ubman):
    """Test that bad input is rejected.

    More text.
    """
    def make_pair(name):
        run("openssl genpkey -algorithm RSA -out %s.key" % name)
    make_pair("dev")
'''

# The repro's control: the same file with "is handled".
HANDLED = REJECTED.replace("is rejected", "is handled")

# The test's own lines are still governed, after the helper as before it.
AFTER = REJECTED + '''    bad_case("openssl genpkey -algorithm DSA")
'''


def _rows(text, name="test/py/tests/t.py", hot=None):
    lines = text.split("\n")
    return d.scan_source_file(Path(name), name, lines, hot=hot)


def _kinds(rows, family):
    return [(r["line"], r["evidence_kind"]) for r in rows if r["algorithm"] == family]


def test_the_helper_runs_what_it_calls():
    assert _kinds(_rows(REJECTED), "RSA") == _kinds(_rows(HANDLED), "RSA") == [
        (7, "registry_name")], (_kinds(_rows(REJECTED), "RSA"), _kinds(_rows(HANDLED), "RSA"))


def test_the_test_body_after_the_helper_is_still_the_rejection():
    rows = _rows(AFTER)
    assert _kinds(rows, "RSA") == [(7, "registry_name")]
    assert _kinds(rows, "DSA") == [(9, "ban")], _kinds(rows, "DSA")


def test_the_gate_and_the_full_read_agree():
    for text in (REJECTED, AFTER):
        lines = text.split("\n")
        assert _rows(text) == _rows(text, hot=d.hot_lines(lines, ".py"))


def _tree(root):
    root.mkdir()
    (root / "t.py").write_text(REJECTED)
    return root


def _check(result):
    rows = [e for e in result["evidence"]["source_code"] if e["algorithm"] == "RSA"]
    assert [(e["line"], e["evidence_kind"]) for e in rows] == [(7, "registry_name")], rows
    assert "RSA" in result["detected_algorithms"]
    assert not [r for r in result["named_but_not_used_lines"] if r["family"] == "RSA"]


def test_helper_in_the_scan_json(tmp_path):
    tree = _tree(tmp_path / "repo")
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    _check(json.loads(out.read_text()))


def test_helper_in_the_mcp_tool(tmp_path):
    _check(server.scan_repo(str(_tree(tmp_path / "repo"))))


def test_helper_in_the_cbom(tmp_path):
    tree = _tree(tmp_path / "repo")
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        assert "RSA" in {c["name"] for c in doc["components"]}, [
            c["name"] for c in doc["components"]]
