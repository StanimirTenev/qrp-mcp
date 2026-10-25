"""ZA-OPRAVYANE row 144: a report in the scanned tree is not cryptography.

Reproduced 25.10.2026 (qrp-pokazateli 06-propusnato r01, В): a tree whose only code is
one RSA key generation, with our own scan result and CBOM saved inside it the way
`--out` writes them. The rescan read ML-KEM/ML-DSA/SLH-DSA/XMSS out of the two reports
and the headline went `classical_only` -> `hybrid_partial`, key establishment
`pqc_ready`. A foreign six-line `bom.json` naming ML-KEM-768 did the same.

A report is recognised by what it is, not by what it is called, and is never dropped
silently: it is named under `coverage.not_examined` with its own reason.
"""

from __future__ import annotations

import json
from pathlib import Path

from qrp_mcp import coverage, cyclonedx
from qrp_mcp.scan import scan_directory

RSA = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
       "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
PQC = ("from pqcrypto.kem.ml_kem_768 import generate_keypair\n"
       "pk, sk = generate_keypair()\n")


def _with_own_reports(tmp_path: Path, code: str) -> Path:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text(code)
    # Reports that name every PQC family, so a rescan that reads them cannot miss it.
    rich = tmp_path / "rich"
    rich.mkdir()
    (rich / "pq.py").write_text(
        "from oqs import KeyEncapsulation, Signature\n"
        "kem = KeyEncapsulation('ML-KEM-768')\n"
        "sig = Signature('ML-DSA-65')\n"
        "slh = Signature('SLH-DSA-SHA2-128s')\n"
        "x = 'XMSS-SHA2_10_256'\n")
    result = scan_directory(rich)
    (tree / "scan.json").write_text(json.dumps(result, indent=2))
    (tree / "cbom.json").write_text(json.dumps(cyclonedx.build(result), indent=2))
    return tree


def _reports(result: dict) -> dict:
    return next(r for r in result["coverage"]["not_examined"]
                if r["reason"] == "report_document")


def test_our_own_reports_do_not_turn_an_rsa_tree_ready(tmp_path):
    result = scan_directory(_with_own_reports(tmp_path, RSA))
    assert result["summary"]["pqc_readiness"] == "classical_only"
    assert result["detected_algorithms"] == ["RSA"]
    assert result["summary"]["by_role"]["key_establishment"]["pqc_readiness"] != "pqc_ready"


def test_the_reports_are_named_with_a_reason_not_dropped(tmp_path):
    result = scan_directory(_with_own_reports(tmp_path, RSA))
    reports = _reports(result)
    assert sorted(reports["paths"]) == ["cbom.json", "scan.json"]
    assert reports["count"] == 2
    assert reports["meaning"] == coverage.REASONS["report_document"]
    scope = result["coverage"]["scope"]
    assert scope["files_present"] == 3 and scope["files_examined"] == 1
    assert result["coverage"]["accounts_for_every_file"] is True
    assert "scan.json" not in (result["files_read"] or [])


def test_a_foreign_cyclonedx_document_is_recognised_by_content(tmp_path):
    (tmp_path / "app.py").write_text(RSA)
    # Not called bom.json, on one line: the name and the formatting decide nothing.
    (tmp_path / "vendor-inventory.json").write_text(json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "components": [{"type": "cryptographic-asset", "name": "ML-KEM-768",
                        "cryptoProperties": {"assetType": "algorithm"}}]}))
    result = scan_directory(tmp_path)
    assert result["summary"]["pqc_readiness"] == "classical_only"
    assert _reports(result)["paths"] == ["vendor-inventory.json"]


def test_a_json_that_only_mentions_bomformat_is_still_read(tmp_path):
    # The CycloneDX schema itself names `bomFormat` as a property and is not a report;
    # a config that happens to quote the word is read as before.
    (tmp_path / "settings.json").write_text(json.dumps({
        "properties": {"bomFormat": {"enum": ["CycloneDX"]}},
        "tls": {"groups": "X25519MLKEM768"}}))
    result = scan_directory(tmp_path)
    assert "settings.json" in result["files_read"]
    assert not any(r["reason"] == "report_document"
                   for r in result["coverage"]["not_examined"])


def test_a_committed_report_does_not_withhold_a_ready_headline(tmp_path):
    # The report was read and recognised; nothing in it is unread code. Withholding the
    # headline for it would make every tree that commits its own CBOM "not established".
    result = scan_directory(_with_own_reports(tmp_path, PQC))
    assert result["summary"]["pqc_readiness"] == "pqc_ready"


def test_a_committed_report_does_not_make_the_composition_incomplete(tmp_path):
    # Same reason as the headline: the report holds no assets this list could miss.
    doc = cyclonedx.build(scan_directory(_with_own_reports(tmp_path, RSA)))
    assert doc["compositions"][0]["aggregate"] == "unknown"


SUPPLIER_CBOM = {
    "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
    "metadata": {"tools": {"components": [{"type": "application", "name": "VendorScan"}]}},
    "components": [{"type": "cryptographic-asset", "name": "ML-KEM-768",
                    "cryptoProperties": {"assetType": "algorithm"}}]}


def test_a_supplier_cbom_is_named_as_a_declaration_for_the_dora_report(tmp_path):
    (tmp_path / "app.py").write_text(RSA)
    (tmp_path / "supplier-cbom.json").write_text(json.dumps(SUPPLIER_CBOM))
    reports = _reports(scan_directory(tmp_path))
    assert reports["paths"] == ["supplier-cbom.json"]
    declarations = reports["declarations"]
    assert declarations["paths"] == ["supplier-cbom.json"]
    # What it is and where it goes, in one sentence.
    assert "declar" in declarations["meaning"] and "not a measurement" in declarations["meaning"]
    assert "--ingest" in declarations["meaning"] and "DORA" in declarations["meaning"]


def test_our_own_cbom_is_not_a_supplier_declaration(tmp_path):
    # Ours carries `metadata.tools` naming qrp-mcp; the older 1.4 list shape is read too.
    old_shape = dict(SUPPLIER_CBOM, metadata={"tools": [{"name": "qrp-mcp"}]})
    tree = _with_own_reports(tmp_path, RSA)
    (tree / "old.json").write_text(json.dumps(old_shape))
    reports = _reports(scan_directory(tree))
    assert sorted(reports["paths"]) == ["cbom.json", "old.json", "scan.json"]
    assert "declarations" not in reports


def test_the_cbom_and_sarif_carry_the_declaration_hint(tmp_path):
    from qrp_mcp import sarif
    (tmp_path / "app.py").write_text(RSA)
    (tmp_path / "supplier-cbom.json").write_text(json.dumps(SUPPLIER_CBOM))
    result = scan_directory(tmp_path)
    props = {p["name"]: p["value"] for p in cyclonedx.build(result)["properties"]}
    assert any(k.endswith(":declarations:paths") and v == '["supplier-cbom.json"]'
               for k, v in props.items())
    log = sarif.build(result, {id(i): "k" for items in result["evidence"].values()
                               for i in items})
    notes = [n for n in log["runs"][0]["invocations"][0]["toolExecutionNotifications"]
             if n["descriptor"]["id"] == "report_document"]
    assert len(notes) == 1 and "--ingest" in notes[0]["message"]["text"]
