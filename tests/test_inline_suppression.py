"""Inline suppression that the reader can see (ZA-OPRAVYANE row 128).

`qrp:ignore <family> <reason>` on the line, or `qrp:ignore-next-line <family> <reason>` on
the line above, inside a comment. Without a family and a reason it does not apply, and the
result says so. A suppressed occurrence leaves `evidence` and is listed in `suppressed`, and
counted in `coverage.suppressed`, which the CBOM carries as properties: "suppressed by the
owner, with a reason". The inventory (`detected_algorithms`, `findings`) is not changed by it.

The M5 leader's suppression is invisible: CryptoScan #9 (an in-tree config zeroes everything
and no output says so) and #26 (inline ignores are not counted), both open in October 2026.
"""

from qrp_mcp import closure, cyclonedx
from qrp_mcp.scan import scan_directory

KEYGEN = "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
IMPORT = "from cryptography.hazmat.primitives.asymmetric import rsa\n"


def _scan(tmp_path, text, name="app.py"):
    (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)


def _rows(result, path="app.py"):
    return sorted((e["line"], e["algorithm"]) for e in result["evidence"]["source_code"]
                  if e["path"] == path)


def test_marker_on_the_line_with_a_reason_moves_the_row_to_suppressed(tmp_path):
    r = _scan(tmp_path, IMPORT + KEYGEN + "\n" + KEYGEN + "  # qrp:ignore RSA legacy HSM, "
              "replaced in Q3\n")
    assert (3, "RSA") not in _rows(r) and (2, "RSA") in _rows(r)
    s = r["suppressed"]
    assert s["count"] == 1 and s["by_family"] == {"RSA": 1}
    item = s["evidence"]["source_code"][0]
    assert item["line"] == 3 and item["algorithm"] == "RSA"
    assert item["suppression"] == {"family": "RSA", "reason": "legacy HSM, replaced in Q3",
                                   "form": "qrp:ignore", "marker_line": 3}
    cov = r["coverage"]["suppressed"]
    assert cov["count"] == 1 and cov["by_family"] == {"RSA": 1}
    assert cov["items"][0]["reason"] == "legacy HSM, replaced in Q3"
    assert "excerpt" not in cov["items"][0]
    # The inventory still has RSA: suppression is the owner's word, not a fix.
    assert "RSA" in r["detected_algorithms"]
    rsa = next(f for f in r["findings"] if f["algorithm_family"] == "RSA")
    assert rsa["suppressed_occurrences"] == 1


def test_next_line_form_in_a_slash_comment(tmp_path):
    r = _scan(tmp_path, "// qrp:ignore-next-line ECDSA firmware verifier, cannot change\n"
              "const k = crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'}); // ECDSA\n"
              "const j = crypto.generateKeyPairSync('ec', {namedCurve: 'P-256'}); // ECDSA\n",
              name="app.js")
    lines = {(e["line"], e["algorithm"]) for e in r["evidence"]["source_code"]}
    assert not any(line == 2 and alg == "ECDSA" for line, alg in lines)
    assert any(line == 3 and alg == "ECDSA" for line, alg in lines)
    # The marker's own words do not become a comment row of the family it names.
    assert not any(line == 1 for line, _ in lines)
    assert r["suppressed"]["by_family"].get("ECDSA", 0) >= 1


def test_without_a_reason_it_does_not_apply_and_says_so(tmp_path):
    r = _scan(tmp_path, IMPORT + KEYGEN + "  # qrp:ignore RSA\n")
    assert (2, "RSA") in _rows(r)
    assert r["suppressed"]["count"] == 0
    na = r["suppressed"]["markers_not_applied"]
    assert na == [{"path": "app.py", "line": 2, "form": "qrp:ignore", "family": "RSA",
                   "why": "no reason given"}]
    assert r["coverage"]["suppressed"]["markers_not_applied"]["count"] == 1


def test_bare_marker_does_not_apply(tmp_path):
    # The 01-tablo probe's line 7: `# qrp:ignore` with neither family nor reason.
    r = _scan(tmp_path, IMPORT + KEYGEN + "  # qrp:ignore\n")
    assert (2, "RSA") in _rows(r)
    assert r["suppressed"]["markers_not_applied"][0]["why"] == "no family and no reason given"


def test_a_family_not_on_the_line_matches_nothing_and_is_named(tmp_path):
    r = _scan(tmp_path, IMPORT + KEYGEN + "  # qrp:ignore ECDSA wrong family here\n")
    assert (2, "RSA") in _rows(r)
    assert r["suppressed"]["markers_not_applied"][0]["why"] == (
        "no ECDSA occurrence on line 2")


def test_family_is_matched_without_case_or_hyphens(tmp_path):
    r = _scan(tmp_path, IMPORT + KEYGEN + "  # qrp:ignore rsa vendor interop, ticket 41\n")
    assert r["suppressed"]["count"] == 1


def test_marker_inside_a_string_is_not_a_marker(tmp_path):
    r = _scan(tmp_path, IMPORT + "note = 'qrp:ignore RSA because'; " + KEYGEN + "\n")
    assert (2, "RSA") in _rows(r) and r["suppressed"]["count"] == 0
    assert r["suppressed"]["markers_not_applied"] == []


def test_no_marker_counts_zero_rather_than_nothing(tmp_path):
    r = _scan(tmp_path, IMPORT + KEYGEN + "\n")
    assert r["suppressed"]["count"] == 0
    assert r["coverage"]["suppressed"]["count"] == 0


def test_cbom_carries_the_suppression_as_properties(tmp_path):
    r = _scan(tmp_path, IMPORT + KEYGEN + "  # qrp:ignore RSA legacy HSM\n")
    props = {p["name"]: p["value"] for p in cyclonedx.build(r)["properties"]}
    assert props["qrp:coverage:suppressed:count"] == "1"
    assert props["qrp:coverage:suppressed:items:0:reason"] == "legacy HSM"
    assert props["qrp:coverage:suppressed:items:0:path"] == "app.py"


def test_a_suppressed_occurrence_is_not_closed():
    rsa = {"path": "a.py", "line": 10, "algorithm": "RSA", "description": "RSA usage",
           "excerpt": "k = rsa.generate_private_key(65537, 2048)", "evidence_kind": "call",
           "in_test_code": False}
    pin = {"version": "0.36.0", "ruleset": {"x": 1}, "claimed_types": {"source": [".py"]},
           "excluded_dirs": [".git"],
           "source_commit": {"pinned": True, "commit": "tool1", "dirty": False}}

    def result(items, suppressed, commit):
        return {"excerpt_level": "full",
                "coverage": {"instrument": pin, "corpus": {
                    "target": "/repo", "pinned_at": {"pinned": True, "kind": "git",
                                                     "commit": commit, "dirty": False}}},
                "evidence": {"source_code": items}, "unreadable_files": [],
                "files_left_out": [], "unreadable_directories": [],
                "symlinks_not_followed": [], "files_read": ["a.py"],
                "suppressed": {"evidence": {"source_code": suppressed}}}

    after_item = {**rsa, "suppression": {"family": "RSA", "reason": "legacy",
                                         "form": "qrp:ignore", "marker_line": 10}}
    out = closure.prove_closure(result([rsa], [], "aaa"), result([], [after_item], "bbb"))
    assert out["closure"]["closed"] == []
    assert out["closure"]["suppressed"][0]["line"] == 10
