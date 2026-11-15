"""ZA-OPRAVYANE row 502 (D6 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8, MCUboot
f30be48 and U-Boot 6487c50, 0.46.0).

In both CBOMs every private key was one `related-crypto-material` component, "Embedded private
key material", whose occurrences said only "private key material in a ... block", though the
scan JSON had the algorithm, size and curve of each key (`root-ec-p384.pem` EC 384 P-384).

Now each key is its own component: `relatedCryptoMaterialProperties.type` `private-key` (and,
with row 503, `public-key` for a public-key PEM that parsed), `size` where it is a number,
`algorithmRef` to the algorithm component found at the same file and line where there is
exactly one, and `qrp:curve`. A key that did not parse keeps the generic name and says why
(`qrp:key_unread`). Keys are made at test time with pyca/cryptography.
"""

import json
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
jsonschema = pytest.importorskip("jsonschema")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa  # noqa: E402

from qrp_mcp import cyclonedx, server  # noqa: E402
from qrp_mcp.scan import scan_directory  # noqa: E402

PEM = serialization.Encoding.PEM
NOENC = serialization.NoEncryption()


@pytest.fixture
def tree(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    p384 = ec.generate_private_key(ec.SECP384R1())
    (t / "root-ec-p384.pem").write_bytes(p384.private_bytes(
        PEM, serialization.PrivateFormat.TraditionalOpenSSL, NOENC))
    r2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (t / "root-rsa-2048.pem").write_bytes(r2048.private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, NOENC))
    (t / "root-ed25519.pem").write_bytes(ed25519.Ed25519PrivateKey.generate().private_bytes(
        PEM, serialization.PrivateFormat.PKCS8, NOENC))
    (t / "enc-rsa2048-pub.pem").write_bytes(r2048.public_key().public_bytes(
        PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    # A header and a body that is not a key.
    (t / "k.tf").write_text('key = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEow...\\n'
                            '-----END RSA PRIVATE KEY-----"\n')
    return t


def _keys(doc):
    return [c for c in doc["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "related-crypto-material"
            and (c["cryptoProperties"].get("relatedCryptoMaterialProperties", {}).get("type")
                 in ("private-key", "public-key")
                 or c["name"] == "Embedded private key material")]


def _by_location(doc):
    out = {}
    for c in _keys(doc):
        (occ,) = c["evidence"]["occurrences"]
        out[occ["location"]] = c
    return out


def _check(doc):
    refs = {c["bom-ref"]: c for c in doc["components"]}
    keys = _by_location(doc)
    assert set(keys) == {"root-ec-p384.pem", "root-rsa-2048.pem", "root-ed25519.pem",
                         "enc-rsa2048-pub.pem", "k.tf"}, sorted(keys)
    want = {"root-ec-p384.pem": ("private-key", 384, "EC"),
            "root-rsa-2048.pem": ("private-key", 2048, "RSA"),
            "root-ed25519.pem": ("private-key", 256, "Ed25519"),
            "enc-rsa2048-pub.pem": ("public-key", 2048, "RSA")}
    for path, (kind, size, family) in want.items():
        c = keys[path]
        rcm = c["cryptoProperties"]["relatedCryptoMaterialProperties"]
        assert rcm["type"] == kind and rcm["size"] == size, (path, c)
        assert family in c["name"], c["name"]
        # The reference resolves, to the algorithm component at the same place.
        target = refs[rcm["algorithmRef"]]
        assert target["cryptoProperties"]["assetType"] == "algorithm"
        assert any(o["location"] == path for o in target["evidence"]["occurrences"])
    props = {p["name"]: p["value"] for p in keys["root-ec-p384.pem"].get("properties", [])}
    assert props["qrp:curve"] == "P-384"
    # The key that did not parse stays generic and says why.
    bad = keys["k.tf"]
    assert bad["name"] == "Embedded private key material"
    assert "algorithmRef" not in bad["cryptoProperties"].get("relatedCryptoMaterialProperties", {})
    bad_props = {p["name"]: p["value"] for p in bad.get("properties", [])}
    assert bad_props.get("qrp:key_unread")
    # The aggregate is gone.
    assert "crypto:embedded-private-key-material" not in refs
    # Every assembly is a component, and the refs are unique.
    assert len(refs) == len(doc["components"])


def test_one_component_per_key(tree):
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        _check(doc)


def test_cli_cbom_has_one_component_per_key(tree, tmp_path):
    out = tmp_path / "r.cbom.json"
    assert server.scan_to_file([str(tree), "--out", str(out)], cbom=True) == 0
    _check(json.loads(out.read_text()))


def test_cbom_with_keys_validates(tree):
    """Against the vendored CycloneDX 1.6 schema, as tests/test_cyclonedx.py does."""
    schema_dir = Path(__file__).parent / "schema"
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schema_dir / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schema_dir / "jsf-0.82.schema.json").read_text()),
    }
    resolver = jsonschema.RefResolver.from_schema(schema, store=store)
    errors = list(jsonschema.Draft7Validator(schema, resolver=resolver).iter_errors(
        cyclonedx.build(scan_directory(tree))))
    assert not errors, [e.message for e in errors[:5]]
