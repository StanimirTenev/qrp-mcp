"""Release C's certificate rows under release A+B's outputs (the relAB + relC-certs merge).

* A parsed certificate's row is suppressed by `qrp:ignore-next-line` above its BEGIN line,
  and baselined like any other row.
* It reaches SARIF on its own BEGIN line.
* In the CBOM it sits beside a hybrid with dependsOn, its file carries the SHA-256 of the
  bytes read, and the document is byte-identical across two builds and schema-valid.
* A report document that quotes a certificate is still named as a report, never parsed.
"""

import datetime
import hashlib
import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from qrp_mcp import baseline, cyclonedx, server
from qrp_mcp.scan import scan_directory

START = datetime.datetime(2026, 10, 25, tzinfo=datetime.timezone.utc)
MARKER = "# qrp:ignore-next-line RSA lab CA, replaced in Q3\n"


@pytest.fixture(scope="module")
def pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "abc-probe")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(7)
            .not_valid_before(START).not_valid_after(START + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _cert_rows(result):
    return [(e["path"], e["line"], e["algorithm"]) for e in result["evidence"]["source_code"]
            if e.get("certificate")]


def test_a_certificate_row_is_suppressed_and_baselined(tmp_path, pem):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "ca.pem").write_text(MARKER + pem)
    result = scan_directory(str(tree))
    assert _cert_rows(result) == []
    held = [e for e in result["suppressed"]["evidence"]["source_code"] if e.get("certificate")]
    assert [(e["path"], e["line"], e["algorithm"]) for e in held] == [("ca.pem", 2, "RSA")]
    doc = cyclonedx.build(result)
    assert not [c for c in doc["components"]
                if c.get("cryptoProperties", {}).get("assetType") == "certificate"]

    (tree / "ca.pem").write_text(pem)
    assert _cert_rows(scan_directory(str(tree))) == [("ca.pem", 1, "RSA")]
    file = tmp_path / "baseline.json"
    file.write_text(json.dumps(baseline.document(scan_directory(str(tree)))))
    again = scan_directory(str(tree), baseline=str(file))
    rows = [e for e in again["evidence"]["source_code"] if e.get("certificate")]
    assert rows and all(e["baseline_state"] == "baselined" for e in rows)


def test_a_certificate_reaches_sarif_on_its_begin_line(tmp_path, pem):
    jsonschema = pytest.importorskip("jsonschema")
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "bundle.pem").write_text("subject=CN=abc-probe\n" + pem)
    out = tmp_path / "r.sarif"
    assert server.scan_to_file([str(tree), "--format", "sarif", "--out", str(out)]) == 0
    log = json.loads(out.read_text())
    schema = json.loads((Path(__file__).parent / "schema" / "sarif-2.1.0.schema.json").read_text())
    assert not list(jsonschema.Draft7Validator(schema).iter_errors(log))
    hits = [(r["ruleId"], r["locations"][0]["physicalLocation"]["region"]["startLine"])
            for r in log["runs"][0]["results"]
            if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "bundle.pem"]
    assert ("qrp/RSA", 2) in hits


def test_certificate_hybrid_and_evidence_hashes_in_one_cbom(tmp_path, pem, monkeypatch):
    jsonschema = pytest.importorskip("jsonschema")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1798761600")
    (tmp_path / "ca.pem").write_text(pem)
    (tmp_path / "nginx.conf").write_text("ssl_ecdh_curve X25519MLKEM768:X25519;\n")
    first = cyclonedx.build(scan_directory(str(tmp_path)))
    again = cyclonedx.build(scan_directory(str(tmp_path)))
    assert json.dumps(first, sort_keys=True) == json.dumps(again, sort_keys=True)
    refs = {c["bom-ref"]: c for c in first["components"]}
    assert len(refs) == len(first["components"])
    cert = next(c for c in first["components"]
                if c.get("cryptoProperties", {}).get("assetType") == "certificate")
    assert cert["evidence"]["occurrences"][0]["location"] == "ca.pem"
    assert refs["file:ca.pem"]["hashes"] == [
        {"alg": "SHA-256", "content": hashlib.sha256((tmp_path / "ca.pem").read_bytes()).hexdigest()}]
    hybrid = next(c for c in first["components"] if c["name"] == "X25519MLKEM768")
    deps = {d["ref"]: d.get("dependsOn", []) for d in first.get("dependencies", [])}
    # Release 3d: every ML-KEM sighting names 768, so the half is ML-KEM-768's component.
    assert deps[hybrid["bom-ref"]] == ["crypto:ml-kem-768", "crypto:x25519"]
    schema_dir = Path(__file__).parent / "schema"
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schema_dir / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schema_dir / "jsf-0.82.schema.json").read_text()),
    }
    validator = jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store),
        format_checker=jsonschema.FormatChecker())
    assert not list(validator.iter_errors(first))


def test_a_report_quoting_a_certificate_is_not_parsed(tmp_path, pem):
    report = {"bomFormat": "CycloneDX", "specVersion": "1.6",
              "components": [{"type": "cryptographic-asset", "name": "RSA",
                              "description": pem}]}
    (tmp_path / "supplier.cdx.json").write_text(json.dumps(report))
    result = scan_directory(str(tmp_path))
    assert _cert_rows(result) == []
    assert result["evidence"]["embedded_keys"] == []
    reports = next(r for r in result["coverage"]["not_examined"]
                   if r["reason"] == "report_document")
    assert reports["paths"] == ["supplier.cdx.json"]
