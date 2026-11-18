"""The twelve gaps of the first self-tuning round (obratna-proba/operacii/KANDIDATI-119.md §3, stage
3b, 18.11.2026): GnuTLS GOST x6, CryptoAPI CALG_DH_* x2, nginx ssl_verify_client x1 and PKCS#11
XEdDSA/X3DH x3. The catalogue (data/operations/) holds each spelling and test_operation_closure.py
runs it; this file pins what the catalogue cannot say -- the neighbours that must stay silent, the
new families' classification, and the three ways a result leaves.

XEdDSA and X3DH are two families under one heading, because a family has one role here: XEdDSA
signs, X3DH agrees keys. Both are Signal's schemes on Curve25519 / Curve448 (CKK_EC_MONTGOMERY in
PKCS#11 3.1): elliptic-curve discrete log, which Shor's algorithm breaks.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx, detectors, remediation
from qrp_mcp.classifier import classify_algorithm
from qrp_mcp.scan import scan_directory


def _families(line: str, name: str = "a.c") -> set[str]:
    found = detectors.scan_source_file(Path(name), name, lines=[line])
    return {f["algorithm"] for f in found if f["evidence_kind"] not in ("ban", "comment")}


@pytest.mark.parametrize("mechanism, family", [
    ("CKM_XEDDSA", "XEdDSA"), ("CKM_X3DH_INITIALIZE", "X3DH"), ("CKM_X3DH_RESPOND", "X3DH")])
def test_a_pkcs11_signal_mechanism_is_its_own_family_and_nothing_else(mechanism, family):
    # not EdDSA or DSA inside XEDDSA, not DH inside X3DH
    assert _families(f"CK_MECHANISM m = {{ {mechanism}, NULL, 0 }};") == {family}


@pytest.mark.parametrize("family, role", [("XEdDSA", "signature"), ("X3DH", "key_exchange")])
def test_xeddsa_and_x3dh_are_classical_and_quantum_vulnerable(family, role):
    finding = classify_algorithm(family, "explicit", source="t", location="t")
    assert finding.algorithm_family == family and not finding.also_present
    assert finding.classification == "classical_vulnerable" and finding.quantum_vulnerable
    assert family in remediation.covered_families() and remediation._BY_FAMILY[family]["options"]


@pytest.mark.parametrize("family", ["XEdDSA", "X3DH"])
def test_the_cbom_gives_xeddsa_and_x3dh_no_quantum_security(family):
    assert family in cyclonedx._SHOR_BROKEN


@pytest.mark.parametrize("name", [
    "GNUTLS_CIPHER_GOST28147_TC26Z_CNT", "GNUTLS_CIPHER_GOST28147_CPA_CFB", "GNUTLS_MAC_GOST28147_TC26Z_IMIT",
    "GNUTLS_DIG_GOSTR_94", "GNUTLS_MAC_GOSTR_94", "GNUTLS_GOST_PARAMSET_TC26_Z"])
def test_the_gost_ciphers_macs_and_digests_of_gnutls_are_not_gost_r_34_10(name):
    """The page lists them beside GNUTLS_PK_GOST_*: GOST 28147-89 is a block cipher, GOST R 34.11
    a hash, the parameter sets are the cipher's. None is a GOST R 34.10 key or signature."""
    assert "GOST R 34.10" not in _families(f"int alg = {name};")


def test_cryptgenkey_with_dh_flags_zero_is_dh_without_a_size():
    assert "DH" in _families("CryptGenKey(hProv, CALG_DH_EPHEM, 0, &hKey);")


def _nginx(tmp_path: Path, directive: str | None) -> Path:
    tree = tmp_path / (directive or "none").replace(" ", "_")
    tree.mkdir()
    body = f"    {directive};\n" if directive else ""
    (tree / "nginx.conf").write_text("http {\n  server {\n    listen 443 ssl;\n"
                                     "    ssl_client_certificate /etc/ssl/ca.pem;\n" + body + "  }\n}\n")
    return tree


def _client_rows(result: dict) -> list[dict]:
    return [p for p in result["evidence"]["protocols"]
            if str(p.get("verification_setting", "")).startswith("ssl_verify_client")]


def test_ssl_verify_client_is_not_inferred_from_its_absence(tmp_path):
    assert _client_rows(scan_directory(_nginx(tmp_path, None))) == []


def test_ssl_verify_client_through_the_command_line_the_tool_and_the_cbom(tmp_path):
    """The three ways a result leaves (scan --out, the MCP tool, the CBOM), each saying what was
    written -- and the CBOM label of an unverified backend stays what it was."""
    from qrp_mcp import server
    tree = _nginx(tmp_path, "ssl_verify_client on")
    out = tmp_path / "scan.json"
    subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree), "--out", str(out),
                    "--no-config", "--level", "full"], check=True, capture_output=True)
    (cli,) = _client_rows(json.loads(out.read_text()))
    assert (cli["line"], cli["peer_verification"]) == (5, "on")
    (tool,) = _client_rows(server.scan_repo(str(tree)))
    assert tool["peer_verification"] == "on" and tool["verification_setting"] == "ssl_verify_client on"
    names = {c["name"] for c in server.export_cbom(str(tree))["components"]}
    assert "TLS peer verification on (ssl_verify_client on)" in names
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / "nginx.conf").write_text("http {\n  server {\n    listen 443 ssl;\n    location / {\n"
                                        "      proxy_pass https://up;\n      proxy_ssl_verify off;\n    }\n  }\n}\n")
    names = {c["name"] for c in server.export_cbom(str(backend))["components"]}
    assert "TLS peer verification off (proxy_ssl_verify off)" in names


@pytest.mark.parametrize("value, verified", [
    ("on", "on"), ("optional", "optional"), ("optional_no_ca", "off"), ("off", "off")])
def test_ssl_verify_client_says_whose_certificate_and_what_happens_to_it(tmp_path, value, verified):
    (row,) = _client_rows(scan_directory(_nginx(tmp_path, f"ssl_verify_client {value}")))
    assert row["peer_verification"] == verified
    assert "client" in row["description"] and "backend" not in row["description"]
