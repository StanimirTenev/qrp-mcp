"""ZA-OPRAVYANE row 503 (D7, D8 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8,
MCUboot f30be48 and U-Boot 6487c50, 0.46.0).

D7: a public-key PEM (`enc-x25519-pub.pem`, `root-ed25519-2-pub.pem`, `enc-ec256-pub.pem`,
`enc-rsa2048-pub.pem`) gave only "object identifier observed in the file; the file was not
decoded as a certificate", and X25519 and Ed25519 had `key_size None` while their private keys
had 256. A PKCS#1 `RSA PRIVATE KEY` file had `key_size "undetermined"` in source_code and 2048 in
embedded_keys. Now a `PUBLIC KEY` / `RSA PUBLIC KEY` block that parses as a key is said so, with
its size, and marked `key_material: "public key"`; the PKCS#1 row takes the size its key parsed to.

D8: U-Boot's FIT names `"ecdsa256"`, `"ecdsa384"`, `"ecdsa521"` (lib/ecdsa/ecdsa-verify.c)
read `key_size "undetermined"`, while `"rsa2048"` read 2048. The number in the name is now the
size. Not claimed: a curve -- the name gives the size, and the curve is left as unread.

Keys are made at test time with pyca/cryptography; nothing is committed.
"""

import json

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519  # noqa: E402

from qrp_mcp import cyclonedx, server  # noqa: E402
from qrp_mcp.scan import scan_directory  # noqa: E402

PEM = serialization.Encoding.PEM
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def _pub(key, fmt=SPKI):
    return key.public_key().public_bytes(PEM, fmt)


@pytest.fixture
def tree(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "enc-x25519-pub.pem").write_bytes(_pub(x25519.X25519PrivateKey.generate()))
    (t / "root-ed25519-2-pub.pem").write_bytes(_pub(ed25519.Ed25519PrivateKey.generate()))
    (t / "enc-ec256-pub.pem").write_bytes(_pub(ec.generate_private_key(ec.SECP256R1())))
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (t / "enc-rsa2048-pub.pem").write_bytes(_pub(rsa_key))
    (t / "pkcs1-pub.pem").write_bytes(_pub(rsa_key, serialization.PublicFormat.PKCS1))
    (t / "root-rsa-2048.pem").write_bytes(rsa_key.private_bytes(
        PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    (t / "ecdsa-verify.c").write_text(
        "static struct crypto_algo ecdsa_algos[] = {\n"
        "\t{ .name = \"ecdsa256\", .key_len = 32, },\n"
        "\t{ .name = \"ecdsa384\", .key_len = 48, },\n"
        "\t{ .name = \"ecdsa521\", .key_len = 66, },\n"
        "};\n")
    return t


def _rows(evidence, path):
    return [e for e in evidence["source_code"] if e["path"] == path]


def _check(evidence):
    want = {"enc-x25519-pub.pem": ("X25519", 256), "root-ed25519-2-pub.pem": ("Ed25519", 256),
            "enc-ec256-pub.pem": ("EC", 256), "enc-rsa2048-pub.pem": ("RSA", 2048),
            "pkcs1-pub.pem": ("RSA", 2048)}
    for path, (family, size) in want.items():
        rows = [e for e in _rows(evidence, path) if e["algorithm"] == family]
        assert len(rows) == 1, (path, _rows(evidence, path))
        row = rows[0]
        assert row["key_size"] == size, (path, row)
        assert row["key_material"] == "public key", (path, row)
        assert "public key block" in row["description"], row
        assert "parsed as a key" in row["description"], row
        assert "not decoded" not in row["description"], row
    # A public key is not a committed secret: no embedded-key row for it.
    assert not [k for k in evidence["embedded_keys"] if k["path"] in want]
    # PKCS#1 private key: the source row has the size the key parsed to.
    priv = [e for e in _rows(evidence, "root-rsa-2048.pem") if e["algorithm"] == "RSA"]
    assert [e["key_size"] for e in priv] == [2048]
    assert "key_material" not in priv[0]
    # D8: the FIT names give the size.
    sizes = {e["line"]: e.get("key_size") for e in _rows(evidence, "ecdsa-verify.c")
             if e["algorithm"] == "ECDSA"}
    assert sizes[2] == 256 and sizes[3] == 384 and sizes[4] == 521, sizes
    # Line 1 (`ecdsa_algos`) names no size.
    assert sizes[1] == "undetermined"


def test_public_keys_and_sizes_in_the_scan_json(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    _check(json.loads(out.read_text())["evidence"])


def test_public_keys_and_sizes_in_the_mcp_tool(tree):
    _check(server.scan_repo(str(tree))["evidence"])


def test_sizes_reach_the_cbom(tree):
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        names = {c["name"] for c in doc["components"]}
        assert {"ECDSA-256", "ECDSA-384", "ECDSA-521"} <= names, names


@pytest.mark.parametrize("line, size", [
    ('{ .name = "ecdsa256" },', 256),
    ("algo = \"sha256,ecdsa384\";", 384),
    # The number is a hash, or no size a curve has.
    ("sig = 'ecdsa-with-SHA256'", "undetermined"),
    ('Signature.getInstance("SHA256withECDSA")', "undetermined"),
    ("ecdsa512_test()  # ECDSA", "undetermined"),
])
def test_ecdsa_size_from_the_name_only(tmp_path, line, size):
    (tmp_path / "a.c").write_text(line + "\n")
    rows = [e for e in scan_directory(tmp_path)["evidence"]["source_code"]
            if e["algorithm"] == "ECDSA"]
    assert rows, line
    assert {e.get("key_size") for e in rows} == {size}, rows
