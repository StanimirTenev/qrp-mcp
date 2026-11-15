"""Rows 477 and 478 (15.11.2026, RFC 10073 composite ML-DSA; Meir Goldman, FAZON).

477: `{"1.3.6.1.5.5.7.6.45", "1.3.6.1.5.5.7.6.37"}` gave 0 findings, and the verdict said every
file was read. The 18 composite OIDs .37-.54 of RFC 10073 section 7 are now read in code, as
the certificate parser already read them; an OID under 1.3.6.1.5.5.7.6 or 2.16.840.1.101.3.4.3
that this version has no entry for is reported as "an OID this version does not know"
(`oids_not_known`), not passed over in silence.

478: `COMPSIG-MLDSA65-ECDSA-P256-SHA512` and `id-MLDSA44-RSA2048-PSS-SHA256` split into ML-DSA
and ECDSA/RSA with `hybrid_names: []`. A composite is now one entry in `hybrid_names` with both
halves and their parameters, by its name, its label or its OID, and in the CBOM one combiner
component that signs and verifies, with `dependencies` to both halves. Readiness reads it as
the TLS hybrids read: a post-quantum half beside a classical one, `hybrid_partial`.

The inputs are the probe's (`linkedin-postove/2026-11-15/composite-proba/`), written here.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from qrp_mcp import certificates, oids
from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

VERIFY_PY = (
    "# Accepted signature algorithms for signed-data, by OID (RFC 10073 composite ML-DSA)\n"
    "ACCEPTED_SIG_OIDS = {\n"
    '    "1.3.6.1.5.5.7.6.45": "id-MLDSA65-ECDSA-P256-SHA512",\n'
    '    "1.3.6.1.5.5.7.6.37": "id-MLDSA44-RSA2048-PSS-SHA256",\n'
    "}\n"
    "\n"
    "def accept(sig_alg_oid: str) -> bool:\n"
    "    return sig_alg_oid in ACCEPTED_SIG_OIDS\n"
)
SIGNER_CONF = "[signer]\nsignature_algorithm = COMPSIG-MLDSA65-ECDSA-P256-SHA512\n"
OIDS_ONLY = 'ACCEPTED = {"1.3.6.1.5.5.7.6.45", "1.3.6.1.5.5.7.6.37"}\n'
CONTROL = 'ML_DSA_65 = "2.16.840.1.101.3.4.3.18"\n'

# RFC 10073 section 7, as the RFC text gives it (OID, name, label, halves).
RFC_10073 = [
    ("37", "id-MLDSA44-RSA2048-PSS-SHA256", "COMPSIG-MLDSA44-RSA2048-PSS-SHA256", ["44", "RSA", "2048"]),
    ("38", "id-MLDSA44-RSA2048-PKCS15-SHA256", "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256", ["44", "RSA", "2048"]),
    ("39", "id-MLDSA44-Ed25519-SHA512", "COMPSIG-MLDSA44-Ed25519-SHA512", ["44", "Ed25519", None]),
    ("40", "id-MLDSA44-ECDSA-P256-SHA256", "COMPSIG-MLDSA44-ECDSA-P256-SHA256", ["44", "ECDSA", "P-256"]),
    ("41", "id-MLDSA65-RSA3072-PSS-SHA512", "COMPSIG-MLDSA65-RSA3072-PSS-SHA512", ["65", "RSA", "3072"]),
    ("42", "id-MLDSA65-RSA3072-PKCS15-SHA512", "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512", ["65", "RSA", "3072"]),
    ("43", "id-MLDSA65-RSA4096-PSS-SHA512", "COMPSIG-MLDSA65-RSA4096-PSS-SHA512", ["65", "RSA", "4096"]),
    ("44", "id-MLDSA65-RSA4096-PKCS15-SHA512", "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512", ["65", "RSA", "4096"]),
    ("45", "id-MLDSA65-ECDSA-P256-SHA512", "COMPSIG-MLDSA65-ECDSA-P256-SHA512", ["65", "ECDSA", "P-256"]),
    ("46", "id-MLDSA65-ECDSA-P384-SHA512", "COMPSIG-MLDSA65-ECDSA-P384-SHA512", ["65", "ECDSA", "P-384"]),
    ("47", "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512", "COMPSIG-MLDSA65-ECDSA-BP256-SHA512", ["65", "ECDSA", "brainpoolP256r1"]),
    ("48", "id-MLDSA65-Ed25519-SHA512", "COMPSIG-MLDSA65-Ed25519-SHA512", ["65", "Ed25519", None]),
    ("49", "id-MLDSA87-ECDSA-P384-SHA512", "COMPSIG-MLDSA87-ECDSA-P384-SHA512", ["87", "ECDSA", "P-384"]),
    ("50", "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512", "COMPSIG-MLDSA87-ECDSA-BP384-SHA512", ["87", "ECDSA", "brainpoolP384r1"]),
    ("51", "id-MLDSA87-Ed448-SHAKE256", "COMPSIG-MLDSA87-Ed448-SHAKE256", ["87", "Ed448", None]),
    ("52", "id-MLDSA87-RSA3072-PSS-SHA512", "COMPSIG-MLDSA87-RSA3072-PSS-SHA512", ["87", "RSA", "3072"]),
    ("53", "id-MLDSA87-RSA4096-PSS-SHA512", "COMPSIG-MLDSA87-RSA4096-PSS-SHA512", ["87", "RSA", "4096"]),
    ("54", "id-MLDSA87-ECDSA-P521-SHA512", "COMPSIG-MLDSA87-ECDSA-P521-SHA512", ["87", "ECDSA", "P-521"]),
]


def _write(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(args: list[str], **env) -> None:
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args],
                   check=True, capture_output=True, env={**os.environ, **env})


def _scans(root: Path, tmp_path: Path, **env) -> list[dict]:
    out = tmp_path / "s.json"
    _cli(["scan", str(root), "--out", str(out)], **env)
    return [json.loads(out.read_text()), scan_repo(str(root)), scan_directory(root)]


def _cboms(root: Path, tmp_path: Path) -> list[dict]:
    out = tmp_path / "c.json"
    _cli(["cbom", str(root), "--out", str(out)])
    return [json.loads(out.read_text()), export_cbom(str(root)), build(scan_directory(root))]


def test_the_table_is_rfc_10073_section_7():
    assert len(oids.COMPOSITE_ML_DSA) == 18
    for arc, name, label, (mldsa, family, param) in RFC_10073:
        entry = oids.COMPOSITE_ML_DSA[f"1.3.6.1.5.5.7.6.{arc}"]
        assert (entry[0], entry[1]) == (name, label)
        assert entry[2] == (("ML-DSA", mldsa), (family, param))
        # The certificate parser reads the same table.
        assert certificates.COMPOSITE_SIGNATURES[f"1.3.6.1.5.5.7.6.{arc}"] == (
            name, ("ML-DSA", family))


def test_composite_by_oid_and_by_label_is_one_hybrid_entry(tmp_path):
    root = _write(tmp_path / "r", {"verify.py": VERIFY_PY, "signer.conf": SIGNER_CONF})
    for result in _scans(root, tmp_path):
        got = {(h["path"], h["line"], h["name"]): h["halves"] for h in result["hybrid_names"]}
        assert got[("verify.py", 3, "id-MLDSA65-ECDSA-P256-SHA512")] == [
            ["ML-DSA", "65"], ["ECDSA", "P-256"]]
        assert got[("verify.py", 4, "id-MLDSA44-RSA2048-PSS-SHA256")] == [
            ["ML-DSA", "44"], ["RSA", "2048"]]
        assert got[("signer.conf", 2, "id-MLDSA65-ECDSA-P256-SHA512")] == [
            ["ML-DSA", "65"], ["ECDSA", "P-256"]]
        assert result["summary"]["pqc_readiness"] == "hybrid_partial"
        assert result["summary"]["readiness_by_role"]["signature"] == "hybrid_partial"


def test_oids_alone_are_found_and_the_ml_dsa_oid_is_a_use(tmp_path):
    root = _write(tmp_path / "o", {"v.py": OIDS_ONLY, "ctrl.py": CONTROL})
    for result in _scans(root, tmp_path) + _scans(root, tmp_path, QRP_MCP_CORE="0")[:1]:
        families = {f["algorithm_family"]: f["classification"] for f in result["findings"]}
        assert {"ML-DSA", "ECDSA", "RSA"} <= set(families), families
        # The OID string names ML-DSA-65; `ML_DSA_65` beside it is not all the line says.
        assert families["ML-DSA"] == "pqc_ready"
        assert {h["name"] for h in result["hybrid_names"]} == {
            "id-MLDSA65-ECDSA-P256-SHA512", "id-MLDSA44-RSA2048-PSS-SHA256"}
        assert result["oids_not_known"] == []


def test_the_cbom_holds_one_composite_signing_asset_with_both_halves(tmp_path):
    root = _write(tmp_path / "r", {"verify.py": VERIFY_PY, "signer.conf": SIGNER_CONF})
    for doc in _cboms(root, tmp_path):
        by_ref = {c["bom-ref"]: c for c in doc["components"]}
        (composite,) = [c for c in doc["components"]
                        if c["name"] == "id-MLDSA65-ECDSA-P256-SHA512"]
        props = composite["cryptoProperties"]
        assert props["algorithmProperties"]["primitive"] == "combiner"
        assert props["algorithmProperties"]["cryptoFunctions"] == ["keygen", "sign", "verify"]
        assert props["oid"] == "1.3.6.1.5.5.7.6.45"
        (dep,) = [d for d in doc["dependencies"] if d["ref"] == composite["bom-ref"]]
        halves = sorted(by_ref[r]["name"] for r in dep["dependsOn"])
        assert halves[0].startswith("ECDSA") and halves[1].startswith("ML-DSA"), halves


def test_an_oid_this_version_does_not_know_is_said(tmp_path):
    root = _write(tmp_path / "u", {"a.py": 'A = "1.3.6.1.5.5.7.6.99"\nB = "2.16.840.1.101.3.4.3.33"\n'
                                           'C = "1.3.6.1.5.5.7.6.45"\n'})
    for result in _scans(root, tmp_path):
        got = [(o["path"], o["line"], o["oid"]) for o in result["oids_not_known"]]
        assert got == [("a.py", 1, "1.3.6.1.5.5.7.6.99"), ("a.py", 2, "2.16.840.1.101.3.4.3.33")]
        assert all(o["statement"] == "an OID this version does not know"
                   for o in result["oids_not_known"])
    for doc in _cboms(root, tmp_path):
        (prop,) = [p for p in doc["properties"] if p["name"] == "qrp:oids_not_known"]
        assert [o["oid"] for o in json.loads(prop["value"])] == [
            "1.3.6.1.5.5.7.6.99", "2.16.840.1.101.3.4.3.33"]
