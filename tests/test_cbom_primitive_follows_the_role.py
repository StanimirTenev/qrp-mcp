"""ZA-OPRAVYANE row P6, numbered at entry (04.11.2026): in the CBOM an EC key read from
certificates and from ECDSA code was `primitive: pke` -- public-key encryption -- while the
scan JSON gave every occurrence `role: signature`.

For RSA and EC the component's primitive now follows the roles its occurrences show, in the
CycloneDX 1.6 enum: all signature -> `signature`; all key establishment -> `key-agree` for EC,
`pke` for RSA (RSA key transport is public-key encryption). Otherwise -- undetermined or
mixed -- EC is `unknown` and RSA stays `pke`, its primitive as before."""

from __future__ import annotations

import pytest


def _primitives(tmp_path, text):
    from qrp_mcp.server import export_cbom
    (tmp_path / "k.py").write_text(text)
    return {c["name"]: c["cryptoProperties"]["algorithmProperties"]["primitive"]
            for c in export_cbom(str(tmp_path))["components"]
            if "algorithmProperties" in c.get("cryptoProperties", {})}


HEAD = "from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding\n"


@pytest.mark.parametrize("line, family, expected", [
    ("sig = key.sign(data, ec.ECDSA(hashes.SHA256()))  # EC key\n"
     "k = ec.EllipticCurvePrivateKey.sign(key, data, ec.ECDSA(h))\n", "EC", "signature"),
    ("s = key.exchange(ec.ECDH(), peer)  # EC\n"
     "t = ec.EllipticCurvePrivateKey.exchange(key, ec.ECDH(), peer)\n", "EC", "key-agree"),
    ("pub = ec.EllipticCurvePublicKey.from_encoded_point(curve, data)\n", "EC", "unknown"),
    ("sig = key.sign(data, padding.PSS(mgf=padding.MGF1(h), salt_length=32), h)  # RSA\n",
     "RSA", "signature"),
    ("ct = rsa_pub.encrypt(k, padding.OAEP(mgf=padding.MGF1(h), algorithm=h, label=None))\n",
     "RSA", "pke"),
    ("key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n", "RSA", "pke"),
])
def test_primitive_by_role(tmp_path, line, family, expected):
    from qrp_mcp.scan import scan_directory
    got = _primitives(tmp_path, HEAD + line)
    names = [n for n in got if n == family or n.startswith(f"{family}-")]
    assert names, got
    roles = {e.get("role") for e in scan_directory(tmp_path)["evidence"]["source_code"]
             if e["algorithm"] == family}
    assert {got[n] for n in names} == {expected}, (roles, got)
