"""`qrp-mcp scan PATH --format sarif`: SARIF 2.1.0, validated against the OASIS schema.

`tests/schema/sarif-2.1.0.schema.json` is the official schema (OASIS, SARIF v2.1.0 errata01,
docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json, fetched
2026-10-25, sha256 c3b4bb2d...a2682e).

Every file the scan did not read is a tool execution notification with its reason, not
dropped: a SARIF viewer shows results, and a clean page over unread files is the silent skip
this tool refuses. Suppressed rows are results with an `inSource` suppression and the owner's
reason as its justification; baselined rows carry `baselineState`.
"""

import json
from pathlib import Path

import pytest

from qrp_mcp import server

jsonschema = pytest.importorskip("jsonschema")
SCHEMA = json.loads((Path(__file__).parent / "schema" / "sarif-2.1.0.schema.json").read_text())

RSA = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
       "k1 = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
       "k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
       "  # qrp:ignore RSA legacy HSM, ticket 41\n"
       "k3 = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # qrp:ignore\n")


def _sarif(tmp_path, *extra):
    tree = tmp_path / "repo"
    tree.mkdir(exist_ok=True)
    (tree / "app.py").write_text(RSA)
    (tree / "logo.png").write_bytes(b"\x89PNG\r\n")
    out = tmp_path / "r.sarif"
    assert server.scan_to_file([str(tree), "--format", "sarif", "--out", str(out), *extra]) == 0
    return json.loads(out.read_text()), tree


def test_valid_against_the_official_schema(tmp_path):
    doc, _ = _sarif(tmp_path)
    jsonschema.Draft4Validator(SCHEMA).validate(doc)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "qrp-mcp"


def test_results_have_rule_location_and_line(tmp_path):
    doc, _ = _sarif(tmp_path)
    run = doc["runs"][0]
    lines = sorted(r["locations"][0]["physicalLocation"]["region"]["startLine"]
                   for r in run["results"] if r["ruleId"] == "qrp/RSA")
    assert lines == [2, 3, 4]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= rule_ids
    for r in run["results"]:
        assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] == "SRCROOT"
        assert r["partialFingerprints"]["qrpBaseline/v1"]


def test_suppressed_row_is_a_result_with_its_reason(tmp_path):
    doc, _ = _sarif(tmp_path)
    by_line = {r["locations"][0]["physicalLocation"]["region"]["startLine"]: r
               for r in doc["runs"][0]["results"] if r["ruleId"] == "qrp/RSA"}
    assert by_line[3]["suppressions"] == [{"kind": "inSource", "status": "accepted",
                                           "justification": "legacy HSM, ticket 41"}]
    assert "suppressions" not in by_line[2] and "suppressions" not in by_line[4]


def test_unread_files_and_unapplied_markers_are_notifications(tmp_path):
    doc, _ = _sarif(tmp_path)
    notes = doc["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    unread = [n for n in notes if n["descriptor"]["id"] == "type_not_claimed"]
    assert [n["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for n in unread] == ["logo.png"]
    marker = [n for n in notes if n["descriptor"]["id"] == "marker_not_applied"]
    assert marker and "no family and no reason given" in marker[0]["message"]["text"]
    assert doc["runs"][0]["invocations"][0]["executionSuccessful"] is True
    props = doc["runs"][0]["properties"]
    assert props["coverage"]["files_present"] == 2 and props["coverage"]["files_examined"] == 1


def test_baseline_state_on_results(tmp_path):
    _, tree = _sarif(tmp_path)
    base = tmp_path / "b.json"
    assert server.scan_to_file([str(tree), "--write-baseline", str(base),
                                "--out", str(tmp_path / "x.json")]) == 0
    (tree / "new.py").write_text("from cryptography.hazmat.primitives.asymmetric import ec\n"
                                 "k = ec.generate_private_key(ec.SECP256R1())\n")
    doc, _ = _sarif(tmp_path, "--baseline", str(base))
    jsonschema.Draft4Validator(SCHEMA).validate(doc)
    states = {(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
               r["baselineState"]) for r in doc["runs"][0]["results"]}
    assert {s for p, s in states if p == "new.py"} == {"new"}
    assert {s for p, s in states if p == "app.py"} == {"unchanged"}


def test_level_is_respected(tmp_path):
    doc, _ = _sarif(tmp_path, "--level", "trimmed")
    for r in doc["runs"][0]["results"]:
        assert "snippet" not in r["locations"][0]["physicalLocation"]["region"]
    doc, _ = _sarif(tmp_path, "--level", "masked")
    snippet = next(r for r in doc["runs"][0]["results"]
                   if r["ruleId"] == "qrp/RSA")["locations"][0]["physicalLocation"]["region"]
    assert "generate" not in snippet["snippet"]["text"]


def test_the_cbom_command_has_no_sarif(tmp_path):
    with pytest.raises(SystemExit):
        server.scan_to_file([str(tmp_path), "--format", "sarif"], cbom=True)
