"""Fix list, PEM inside configuration (entered 04.11.2026 from an internal comparison).

A Fabric connection profile carries its CA certificate as a JSON string,
`"pem": "-----BEGIN CERTIFICATE-----\\nMII..."`; the file was read and gave nothing, not even a
note. A Kubernetes manifest carries certificates and keys in indented YAML block scalars
(`key: |`); the certificates gave nothing and the keys "Embedded private key material" without
a family. The blocks are now put together from their base64 and parsed: a certificate is a
row at its BEGIN line, a key's family and size join its embedded-key row, and a block that
does not parse is listed with its reason."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

FIXTURE = Path(__file__).parent / "fixtures" / "fabric" / "profile" / "connection-org1.json"


def _certificate_pem() -> str:
    return json.loads(FIXTURE.read_text())["peers"]["peer0.org1.example.com"]["tlsCACerts"]["pem"]


def test_certificate_in_a_json_string(tmp_path):
    from qrp_mcp.scan import scan_directory
    shutil.copy(FIXTURE, tmp_path / "connection-org1.json")
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e.get("certificate")]
    assert {(e["line"], e["algorithm"]) for e in rows} == {(8, "EC"), (8, "ECDSA")}
    assert [e["curve"] for e in rows if e["algorithm"] == "EC"] == ["P-256"]


def test_certificate_and_key_in_yaml_block_scalars(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from qrp_mcp.scan import scan_directory
    key = ec.generate_private_key(ec.SECP384R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()

    def block(pem: str) -> str:
        return "".join(f"    {line}\n" for line in pem.strip().splitlines())

    (tmp_path / "secret.yaml").write_text(
        "apiVersion: v1\nkind: Secret\nstringData:\n"
        "  cert: |\n" + block(_certificate_pem()) + "  key: |\n" + block(key))
    result = scan_directory(tmp_path)
    certs = [e for e in result["evidence"]["source_code"] if e.get("certificate")]
    assert {e["line"] for e in certs} == {5}
    keys = result["evidence"]["embedded_keys"]
    line = 5 + len(_certificate_pem().strip().splitlines()) + 1
    assert [(k["line"], k["key_algorithm"], k["curve"]) for k in keys] == [(line, "EC", "P-384")]


def test_a_block_that_does_not_parse_is_listed(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "p.json").write_text(
        '{"pem": "-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----\\n"}\n')
    result = scan_directory(tmp_path)
    assert not [e for e in result["evidence"]["source_code"] if e.get("certificate")]
    unparsed = json.dumps(result["coverage"])
    assert "not_parsed_as_certificate" in unparsed
