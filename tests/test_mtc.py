"""Row 7 (Delta Li, 5 Oct 2026): Merkle Tree Certificates were not recognised at all.

Reproduced on 0.28.0 + 178dcf2: BoringSSL's `X509_V_FLAG_USE_MTC_DRAFT_PLANTS_05` and
the IANA OID `1.3.6.1.5.5.7.6.67` gave nothing.

What there is to find (research, 7 Oct 2026): the three OIDs IANA assigned on
28 Sep 2026, Cloudflare's experimental arc 1.3.6.1.4.1.44363.47, the draft's ASN.1
names, and BoringSSL/Chrome identifiers -- all in CA, library and browser code, none in
an origin's configuration. A hit means "this code issues or verifies MTCs". It never
means the service's authentication is quantum-safe: the MTC leaf carries an ordinary key
(ECDSA-P256 in Cloudflare's experiment), and the quantum-relevant signatures are the CA's
and the cosigners'. So it is never pqc_ready, and not a mechanism either.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.assets import TLS_TERMINATION
from qrp_mcp.server import export_cbom, scan_repo


def _tool(obj):
    return getattr(obj, "fn", obj)


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _cli(tree: Path, out: Path) -> dict:
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def _both(tmp_path: Path, files: dict[str, str]) -> list[dict]:
    tree = _tree(tmp_path / "tree", files)
    return [_cli(tree, tmp_path / "out.json"), _tool(scan_repo)(str(tree))]


@pytest.mark.parametrize("name, text", [
    ("x509.h", "#define X509_V_FLAG_USE_MTC_DRAFT_PLANTS_05 0x400000\n"),
    ("oids.py", 'ID_ALG_MTC_PROOF = "1.3.6.1.5.5.7.6.67"\n'),
    ("oids.ts", 'export const id_alg_mtcProof_experimental = "1.3.6.1.4.1.44363.47.0";\n'),
    ("proof.go", "var idAlgMTCProofExperimental = encoding_asn1.ObjectIdentifier"
                 "{1, 3, 6, 1, 4, 1, 44363, 47, 0}\n"),
    ("cert.go", "type MTCLogEntry struct{}\n"),
    # Chromium's flag entry. (`BASE_FEATURE(kVerifyMTCs, base::FEATURE_DISABLED_BY_DEFAULT)`
    # is read as a ban by the existing denial rule -- "DISABLED" on the line -- and lands
    # in named_but_not_used, which for a feature off by default is fair.)
    ("about_flags.cc", '{"verify-mtcs", flag_descriptions::kVerifyMTCsName,\n'),
])
def test_mtc_code_is_named_and_never_ready(tmp_path, name, text):
    for result in _both(tmp_path, {name: text}):
        [mtc] = [f for f in result["findings"] if f["algorithm_family"] == "MTC"]
        assert mtc["classification"] == "unknown"
        assert mtc["quantum_vulnerable"] is False
        assert "CA" in mtc["reason"] and "cosigner" in mtc["reason"]
        summary = result["summary"]
        assert summary["pqc_ready_count"] == 0
        assert summary["pqc_readiness"] not in ("pqc_ready", "mechanism_protected")


@pytest.mark.parametrize("text", [
    "OID = '1.3.6.1.5.5.7.1.380'\n",          # boundary: .1.38 inside .1.380
    "OID = '1.3.6.1.5.5.7.25.30'\n",
    "OID = '1.3.6.1.4.1.44363.48.3'\n",        # Cloudflare CA ID, not the MTC arc
    "\tmtctr r0\n",                            # PowerPC, OpenSSL's only 'mtc' hits
    "leaf = MerkleTreeLeaf(entry)\n",          # RFC 6962 CT, not MTC
    "TLSEXT_TYPE_trust_anchors 0xca34\n",      # Trust Anchor IDs: a prerequisite, not MTC
])
def test_near_misses_do_not_match(tmp_path, text):
    result = _tool(scan_repo)(str(_tree(tmp_path, {"a.c": text})))
    assert "MTC" not in {f["algorithm_family"] for f in result["findings"]}


def test_the_cbom_calls_it_other(tmp_path):
    doc = _tool(export_cbom)(str(_tree(tmp_path, {
        "x509.h": "#define X509_V_FLAG_USE_MTC_DRAFT_PLANTS_05 0x400000\n"})))
    mtc = next(c for c in doc["components"] if c["name"] == "MTC")
    assert mtc["cryptoProperties"]["algorithmProperties"]["primitive"] == "other"
    props = {p["name"]: p["value"] for p in mtc["properties"]}
    assert props["qrp:classification"] == "unknown"


def test_the_termination_statement_says_where_mtc_authentication_happens(tmp_path):
    assert "Merkle Tree Certificate" in TLS_TERMINATION
    assert "ECDSA" in TLS_TERMINATION
    result = _tool(scan_repo)(str(_tree(tmp_path, {
        "nginx.conf": "ssl_ecdh_curve X25519MLKEM768:X25519;\n"})))
    assert "Merkle Tree Certificate" in result["tls_termination"]["statement"]
