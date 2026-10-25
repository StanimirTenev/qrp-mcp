"""Every occurrence carries a confidence derived from what the scan read (release E).

The levels are calibrated on Cryben and the OWASP Benchmark (confidence.MEASURED): high >
medium > low in precision. These tests pin the mapping, one example per route, so that a
reworded description in a detector fails here instead of silently moving rows between levels.
"""

import json

from qrp_mcp import confidence, cyclonedx, sarif
from qrp_mcp.baseline import key
from qrp_mcp.scan import scan_directory


def _level(category, **item):
    item.setdefault("path", "a.py")
    item.setdefault("line", 1)
    return confidence.assess(category, item)[0]


def test_what_the_line_is_sets_the_level():
    assert _level("source_code", evidence_kind="call", description="RSA usage") == "high"
    assert _level("source_code", evidence_kind="declaration", description="RSA usage") == "medium"
    assert _level("source_code", evidence_kind="reference", description="RSA usage") == "medium"
    assert _level("source_code", evidence_kind="import", description="RSA usage") == "low"
    assert _level("source_code", path="nginx.conf", evidence_kind="declaration",
                  description="RC4 usage") == "high"
    assert _level("source_code", path="a.go", evidence_kind="reference",
                  excerpt="func f(k *rsa.PrivateKey) {", description="RSA usage") == "low"
    assert _level("source_code", path="a.crt", evidence_kind="declaration",
                  certificate={"sha256": "x"}, description="RSA in certificate 1") == "high"


def test_other_categories():
    assert _level("embedded_keys", description="private key material") == "high"
    assert _level("embedded_keys", key_unread=True, description="private key material") == "medium"
    assert _level("tls_groups") == "high"
    assert _level("protocols", description="TLSv1.2 is configured here.") == "high"
    assert _level("protocols", description="TLSv1.2 is named here.") == "medium"
    assert _level("dependencies") == "low"


def test_an_inferred_family_is_one_step_lower():
    for description in ("EC named as a component of EC_KEY_free",
                        "SHA-1 named in a compound name",
                        "RSA object identifier 1.2.840.113549.1.1.1 observed in the file; "
                        "the file was not decoded",
                        "MD5 named by the property hashAlg1 (a.properties:4), read here with "
                        "getProperty",
                        "RSA named in a JCA getInstance call (RSA); read through the constant "
                        "Algs.ASYM in Algs.java"):
        assert _level("source_code", evidence_kind="call", description=description) == "medium"
        assert _level("source_code", evidence_kind="reference",
                      description=description) == "low"


def test_a_getproperty_fallback_is_low():
    """The default literal, used because no properties file sets the key: 27/27 wrong on the
    OWASP subset without benchmark.properties, so not medium."""
    description = 'AES-ECB named as the default of getProperty("x"); no properties file'
    for kind in ("call", "reference", "declaration"):
        assert _level("source_code", evidence_kind=kind, description=description) == "low"


def test_comments_and_bans_are_low():
    assert _level("source_code", evidence_kind="comment", description="RSA usage") == "low"
    assert _level("source_code", evidence_kind="ban", description="RC4 usage") == "low"


def test_measured_precision_is_monotonic():
    levels = confidence.MEASURED["levels"]
    p = [float(levels[lv]["precision"]) for lv in confidence.LEVELS]
    assert p[0] > p[1] > p[2]


def _tree(tmp_path):
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "# rsa.generate_private_key(public_exponent=3, key_size=512)\n")
    return scan_directory(tmp_path)


def test_scan_json_sarif_and_cbom_carry_it(tmp_path):
    result = _tree(tmp_path)
    rows = {(r["line"], r["evidence_kind"]): r["confidence"]
            for r in result["evidence"]["source_code"]}
    assert rows[(2, "call")] == "high"
    assert rows[(3, "comment")] == "low"
    block = result["coverage"]["confidence"]
    assert block["occurrences"]["high"] >= 1
    assert block["precision_by_level"]["levels"]["high"]["precision"] == "1.000"

    keys = {id(r): key("source_code", r) for r in result["evidence"]["source_code"]}
    doc = sarif.build(result, keys)
    ranks = {r["locations"][0]["physicalLocation"]["region"]["startLine"]: r["rank"]
             for r in doc["runs"][0]["results"]}
    assert ranks[2] == 90.0 and ranks[3] == 30.0
    assert all("confidence" in r["properties"] for r in doc["runs"][0]["results"])

    bom = cyclonedx.build(result)
    levels = []
    for rsa in (c for c in bom["components"] if c.get("name", "").startswith("RSA")):
        mine = json.loads(next(p["value"] for p in rsa["properties"]
                               if p["name"] == "qrp:confidence"))
        assert len(mine) == len(rsa["evidence"]["occurrences"])
        levels += mine
    assert "high" in levels
    assert any(p["name"].startswith("qrp:coverage:confidence:") for p in bom["properties"])


def test_baseline_key_does_not_change_with_the_level():
    item = {"path": "a.conf", "line": 3, "group": "x25519", "setting": "Groups"}
    before = key("tls_groups", dict(item))
    after = key("tls_groups", {**item, "confidence": "high", "confidence_basis": "setting"})
    assert before == after
