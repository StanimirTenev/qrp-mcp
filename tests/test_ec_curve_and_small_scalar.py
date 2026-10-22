"""EC keys: the curve is named, and a private scalar <= 256 is found from the public key.

ZA-OPRAVYANE row 32 (Bill Buchanan's post, 22.10.2026, and Israr Ahmed's check in the
same thread). On 0.31.0 a P-384 certificate with private scalar 4 and one with a random
scalar scanned identically: "EC" and "ECDSA" from the object identifiers, no curve, no
size. The curve OID was swallowed because the EC family had already been recorded from
id-ecPublicKey.

Now (b) the named-curve OID gives the curve and its size, and (a) every uncompressed EC
public point the scanner can locate -- in DER (SubjectPublicKeyInfo, SEC 1, PKCS#8) and
in OpenSSH keys -- is compared with k*G for k = 1..256. A match is a finding of its own:
the private key is recoverable from the public key.

The fixtures were made with pyca/cryptography (`derive_private_key(k, curve)`); the two
P-384 certificates are the ones from the test of 22.10.2026. Curve parameters in the
scanner are from SEC 2 v2.0 and agree with RFC 5903 section 3 for the NIST curves.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import certificates
from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

FIXTURES = Path(__file__).parent / "fixtures" / "small-scalar"


def _schema_valid(document):
    jsonschema = pytest.importorskip("jsonschema")
    schemas = Path(__file__).parent / "schema"
    schema = json.loads((schemas / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schemas / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schemas / "jsf-0.82.schema.json").read_text()),
    }
    resolver = jsonschema.RefResolver.from_schema(schema, store=store)
    jsonschema.Draft7Validator(schema, resolver=resolver).validate(document)


def _tool(obj):
    return getattr(obj, "fn", obj)


# Private keys are written at test time, not committed: a public repository should not
# carry private key files, even ones whose scalar is the point of the test.
PRIVATE = {"p521-k2-pkcs8.pem": ("SECP521R1", 2, "PKCS8", "PEM"),
           "ec-k9-sec1.key": ("SECP256R1", 9, "TraditionalOpenSSL", "PEM"),
           "id_ecdsa_k5": ("SECP256R1", 5, "OpenSSH", "PEM")}


def _private(name):
    ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
    from cryptography.hazmat.primitives import serialization as s
    curve, k, fmt, enc = PRIVATE[name]
    key = ec.derive_private_key(k, getattr(ec, curve)())
    return key.private_bytes(getattr(s.Encoding, enc), getattr(s.PrivateFormat, fmt),
                             s.NoEncryption())


def _tree(tmp_path, *names):
    for name in names:
        if name in PRIVATE:
            (tmp_path / name).write_bytes(_private(name))
        else:
            shutil.copy(FIXTURES / name, tmp_path / name)
    return tmp_path


def test_the_curve_and_its_size_are_named(tmp_path):
    result = scan_directory(_tree(tmp_path, "p384-k4-cert.pem", "p256-k257-pub.pem"))
    ec = {f["path"]: f for f in result["evidence"]["source_code"] if f["algorithm"] == "EC"}
    assert ec["p384-k4-cert.pem"]["curve"] == "P-384"
    assert ec["p384-k4-cert.pem"]["key_size"] == 384
    assert "P-384" in ec["p384-k4-cert.pem"]["description"]
    assert ec["p256-k257-pub.pem"]["curve"] == "P-256"
    assert result["algorithm_key_sizes_observed"]["EC"] == [256, 384]


@pytest.mark.parametrize("name,curve,k", [
    ("p384-k4-cert.pem", "P-384", 4),
    ("p256-k256-pub.pem", "P-256", 256),
    ("p521-k2-pkcs8.pem", "P-521", 2),
    ("secp256k1-k77-pub.der", "secp256k1", 77),
    ("ec-k9-sec1.key", "P-256", 9),
    ("id_ecdsa_k3.pub", "P-384", 3),
    ("id_ecdsa_k5", "P-256", 5),
])
def test_a_small_scalar_is_found(tmp_path, name, curve, k):
    result = scan_directory(_tree(tmp_path, name))
    weak = result["evidence"]["weak_keys"]
    assert [(w["path"], w["curve"], w["scalar"]) for w in weak] == [(name, curve, k)]
    assert weak[0]["description"].startswith("private key recoverable")


@pytest.mark.parametrize("name", ["p384-random-cert.pem", "p256-k257-pub.pem"])
def test_a_scalar_above_the_bound_is_not_reported(tmp_path, name):
    assert scan_directory(_tree(tmp_path, name))["evidence"]["weak_keys"] == []


def test_the_table_is_k_times_g():
    # k*G by the scanner's own arithmetic against an independent implementation.
    ec = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ec")
    curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1(),
              "secp256k1": ec.SECP256K1()}
    for name, curve in curves.items():
        table = certificates._small_multiples(name)
        assert len(table) == certificates.SMALL_SCALAR_BOUND
        for k in (1, 2, 3, 128, 255, 256):
            numbers = ec.derive_private_key(k, curve).public_key().public_numbers()
            assert table[(numbers.x, numbers.y)] == k


def test_it_reaches_every_way_out(tmp_path):
    tree = _tree(tmp_path, "p384-k4-cert.pem")
    for level in ("full", "masked", "trimmed"):
        weak = _tool(scan_repo)(str(tree), level=level)["evidence"]["weak_keys"]
        assert [w["scalar"] for w in weak] == [4]
    out = tmp_path / "out.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                    "scan", str(tree), "--out", str(out)], check=True, capture_output=True)
    assert json.loads(out.read_text(encoding="utf-8"))["evidence"]["weak_keys"]
    cbom = build(scan_directory(tree))
    _schema_valid(cbom)
    weak = [c for c in cbom["components"] if c["bom-ref"].startswith("weak-key:")]
    assert len(weak) == 1
    props = {p["name"]: p["value"] for p in weak[0]["properties"]}
    assert props["qrp:scalar"] == "4" and props["qrp:curve"] == "P-384"
