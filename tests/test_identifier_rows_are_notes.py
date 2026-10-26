"""An identifier row has the lowest severity in SARIF and in the mandates report.

Identifier rows (evidence_kind `identifier`: a family read from a component of a name,
`generate_rsa_keys`) are kept as evidence at confidence `low`, and they never move the headline:
a family whose every use is such a row stays a finding, marked `identifier_only`, and is not
counted (tests/test_identifier_rows_keep_the_headline.py). SARIF still gave them `warning` and
the mandates report a dated clause that could fail the gate -- full severity for rows the
summary declines to count. Now they are what comments and bans are there: SARIF `note`, and no
clause, counted in no block and tripping no gate.

Run the way a CI runs it: `qrp-mcp scan --format sarif` and `--mandate`, through scan_to_file.
"""

from __future__ import annotations

import json

from qrp_mcp import server

IDENTIFIERS = {"ids.py": "import hashlib\nrsa_key_path = load()\n",
               "gen.py": "def generate_rsa_keys():\n    pass\n",
               "enc.py": "def rsa_encrypt_session_key(k):\n    return k\n"}
REAL_RSA = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
            "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")


def _tree(tmp_path, files):
    tree = tmp_path / "tree"
    tree.mkdir()
    for name, text in files.items():
        (tree / name).write_text(text, encoding="utf-8")
    return tree


def _sarif(tmp_path, tree, *args):
    out = tmp_path / "out.sarif"
    server.scan_to_file([str(tree), "--no-config", "--format", "sarif", *args, "--out", str(out)])
    return json.loads(out.read_text())["runs"][0]


def _scan(tmp_path, tree, *args):
    out = tmp_path / "out.json"
    code = server.scan_to_file([str(tree), "--no-config", *args, "--out", str(out)])
    return code, json.loads(out.read_text())


def _by_file(run):
    return {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r
            for r in run["results"]}


def test_identifier_rows_are_sarif_notes(tmp_path):
    run = _sarif(tmp_path, _tree(tmp_path, {**IDENTIFIERS, "r.py": REAL_RSA}))
    rows = _by_file(run)
    ids = [r for path, r in rows.items() if path in IDENTIFIERS]
    assert len(ids) == 3
    assert all(r["properties"]["evidence_kind"] == "identifier" for r in ids)
    assert {r["level"] for r in ids} == {"note"}
    # A use of the same family keeps its severity.
    assert rows["r.py"]["level"] == "warning"


def test_identifier_rows_get_no_mandate_clause_and_trip_no_gate(tmp_path):
    tree = _tree(tmp_path, IDENTIFIERS)
    code, result = _scan(tmp_path, tree, "--mandate", "nist-ir-8547", "--as-of", "2026-10-26",
                         "--lead-months", "200")
    rows = result["evidence"]["source_code"]
    assert rows and all(e["evidence_kind"] == "identifier" for e in rows)
    assert all("mandates" not in e and "hndl_exposed" not in e for e in rows)
    block = result["mandates"]["nist-ir-8547"]
    assert block["in_scope"] == 0 and block["hndl_exposed"] == 0
    assert block["gate"] == "pass" and code == 0


def test_a_real_use_beside_them_still_gets_its_clause(tmp_path):
    tree = _tree(tmp_path, {**IDENTIFIERS, "r.py": REAL_RSA})
    code, result = _scan(tmp_path, tree, "--mandate", "nist-ir-8547", "--as-of", "2026-10-26",
                         "--lead-months", "200")
    with_clause = [e["path"] for e in result["evidence"]["source_code"] if "mandates" in e]
    assert with_clause == ["r.py"]
    assert result["mandates"]["nist-ir-8547"]["gate"] == "fail" and code == 1
