"""The third level of evidence: shape without content.

`full` sends the line of code. `trimmed` sends nothing. Between them a reader
needs enough to see that a finding is a call rather than a string, without the
contents of the line -- which an independent analysis showed can include a
token sitting beside the call.

A rival tool masks by position: keep the first twelve characters, star the rest.
That keeps whatever the line happens to begin with. The rule here is inverted --
only the characters that spell the algorithm survive.
"""

import json

from qrp_mcp.server import _mask_excerpt, scan_to_file


def test_only_the_algorithm_name_survives():
    masked = _mask_excerpt("key = rsa.generate_private_key(key_size=1024)", "RSA")
    assert "rsa" in masked
    assert "generate" not in masked
    assert masked.count("=") == 2, "punctuation keeps the shape of the call"
    assert "(" in masked and ")" in masked


def test_a_secret_on_the_same_line_does_not_survive(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text(
        'key = rsa.generate_private_key(key_size=1024, password="sk_live_9f3a2b7c8d1e")\n',
        encoding="utf-8")
    out = tmp_path / "r.json"
    assert scan_to_file([str(repo), "--level", "masked", "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "sk_live" not in text
    assert "9f3a2b" not in text
    finding = json.loads(text)["evidence"]["source_code"][0]
    assert "rsa" in finding["excerpt"].lower(), "the reader still sees which family"


def test_every_spelling_of_the_family_is_kept():
    """Case does not matter, and it is every occurrence, not the first. The words
    between them are not the algorithm, so they go -- which is the point."""
    masked = _mask_excerpt("RSA and rsa and Rsa", "RSA")
    assert masked == "RSA *** rsa *** Rsa"


def test_a_line_that_never_names_the_family_is_fully_starred():
    """An OID or a label finding: nothing of the line is readable, and that is
    correct -- the family is in its own field."""
    masked = _mask_excerpt("1.2.840.113549.1.1.1", "RSA")
    assert masked == "*.*.***.******.*.*.*"


def test_the_three_levels_differ_as_documented(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text(
        "key = rsa.generate_private_key(key_size=2048)\n", encoding="utf-8")
    seen = {}
    for level in ("full", "masked", "trimmed"):
        out = tmp_path / f"{level}.json"
        assert scan_to_file([str(repo), "--level", level, "--out", str(out)]) == 0
        finding = json.loads(out.read_text(encoding="utf-8"))["evidence"]["source_code"][0]
        seen[level] = finding.get("excerpt")
        assert finding["line"] == 1, "the line number stays at every level"
        assert finding["path"] == "a.py", "the file stays at every level"
    assert "generate_private_key" in seen["full"]
    assert "generate_private_key" not in seen["masked"]
    assert "*" in seen["masked"]
    assert seen["trimmed"] is None


def test_an_empty_excerpt_is_left_alone():
    assert _mask_excerpt("", "RSA") == ""


def test_no_algorithm_name_does_not_crash():
    assert _mask_excerpt("x = 1", "") == "* = *"
