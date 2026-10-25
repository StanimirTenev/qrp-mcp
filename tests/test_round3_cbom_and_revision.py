"""Two defects closed in round 3 (qrp-pokazateli kragg-2/kragg-3).

1. A certificate's subject key stood in the CBOM as a top-level component with no
   occurrence: a claim located nowhere, counted by Cryben's scorer as a false positive.
   Now every top-level cryptographic asset has an occurrence, and a subject key is nested
   inside the certificate that carries it.
2. ZA-OPRAVYANE row 148: which code ran was not visible for an installed package. Now
   `instrument.revision` names the commit, or the absence of one in words, in the scan
   JSON and on the CBOM's tool component.
"""

from __future__ import annotations

import datetime
import json
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from qrp_mcp import coverage, cyclonedx
from qrp_mcp.scan import scan_directory

_PKG = Path(__file__).resolve().parents[1] / "src" / "qrp_mcp"


def _cert_pem(key, cn: str) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = datetime.datetime(2026, 10, 25, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(7)
            .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _walk(components):
    for c in components:
        yield c
        yield from _walk(c.get("components", []))


def test_every_top_level_asset_has_an_occurrence_and_keys_are_nested(tmp_path):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "a.crt").write_text(_cert_pem(rsa_key, "a"))
    (tmp_path / "b.crt").write_text(_cert_pem(rsa_key, "b"))      # the same key type twice
    (tmp_path / "c.crt").write_text(_cert_pem(ec.generate_private_key(ec.SECP256R1()), "c"))
    doc = cyclonedx.build(scan_directory(tmp_path))
    top = [c for c in doc["components"] if c["type"] == "cryptographic-asset"]
    assert top and all(c.get("evidence", {}).get("occurrences") for c in top), [
        c["bom-ref"] for c in top if not c.get("evidence", {}).get("occurrences")]
    refs = {}
    for c in _walk(doc["components"]):
        assert c["bom-ref"] not in refs, c["bom-ref"]          # each key once, however shared
        refs[c["bom-ref"]] = c
    certs = [c for c in top if c["cryptoProperties"]["assetType"] == "certificate"]
    assert len(certs) == 3
    for cert in certs:
        key = refs[cert["cryptoProperties"]["certificateProperties"]["subjectPublicKeyRef"]]
        assert key["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"] == "public-key"
        assert key not in top
    nested = [k for c in certs for k in c.get("components", [])]
    assert sorted(k["bom-ref"] for k in nested) == ["public-key:ec-p-256", "public-key:rsa-2048"]


def test_the_revision_of_a_checkout_or_a_tree_is_named(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    result = scan_directory(tmp_path)
    instrument = result["coverage"]["instrument"]
    pin = instrument["source_commit"]
    if pin.get("pinned"):
        assert instrument["revision"].startswith(pin["commit"])
    else:
        assert instrument["revision"] == coverage._revision(pin)
    tool = cyclonedx.build(result)["metadata"]["tools"]["components"][0]
    assert {"name": "qrp:revision", "value": instrument["revision"]} in tool["properties"]


def test_an_installed_wheel_says_it_has_no_vcs(tmp_path):
    site = tmp_path / "lib" / "site-packages"
    site.mkdir(parents=True)
    import shutil
    shutil.copytree(_PKG, site / "qrp_mcp", ignore=shutil.ignore_patterns("__pycache__"))
    code = ("import json; from qrp_mcp import coverage; p = coverage._tool_pin(); "
            "print(json.dumps([p, coverage._revision(p)]))")
    out = subprocess.run([sys.executable, "-I", "-c", code.replace("import json;",
                          f"import sys; sys.path.insert(0, {str(site)!r}); import json;")],
                         capture_output=True, text=True, check=True, cwd=tmp_path)
    pin, revision = json.loads(out.stdout)
    assert pin["reason"] == "no_checkout"
    assert revision == "installed wheel, no VCS" or revision.endswith("(installed from VCS)")


def test_an_installed_package_from_a_vcs_names_its_commit(monkeypatch):
    monkeypatch.setattr(coverage, "_installed_vcs_commit", lambda: "ab" * 20)
    assert coverage._revision({"pinned": False, "reason": "no_checkout"}) == (
        "ab" * 20 + " (installed from VCS)")


def test_each_absence_reads_as_words():
    assert coverage._revision({"pinned": True, "commit": "c" * 40, "dirty": True}) == (
        "c" * 40 + " (with uncommitted changes)")
    assert coverage._revision({"pinned": False, "reason": "not_a_repository"}) == (
        "source tree, no VCS")
