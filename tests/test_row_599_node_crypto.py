"""ZA-OPRAVYANE row 599 (Juice Shop c9f9922, test/api/helpers/passkey.ts and passkey.test.ts).

Node's crypto (https://nodejs.org/api/crypto.html):
- `crypto.sign(algorithm, data, key)`: "dsaEncoding <string> For DSA and ECDSA, this option specifies
  the format of the generated signature". The option names no family; the key does. Juice Shop signs
  with a P-256 key (`generateKeyPairSync('ec', { namedCurve: 'P-256' })`), and 0.53.0 reported DSA,
  read from the identifier `dsaEncoding`.
- `crypto.createECDH(curveName)` "Creates an Elliptic Curve Diffie-Hellman (ECDH) key exchange object";
  the exchange is `ecdh.computeSecret(...)`. Juice Shop uses it only to make a P-256 key pair from a
  seed (setPrivateKey, getPublicKey, getPrivateKey) for an ES256 credential; 0.53.0 reported ECDH on
  every line that names the variable.
"""

from __future__ import annotations

from qrp_mcp.scan import scan_directory

PASSKEY = """import crypto from 'node:crypto'

export function victim (seed: Buffer) {
  const ecdh = crypto.createECDH('prime256v1')
  ecdh.setPrivateKey(seed)
  const point = ecdh.getPublicKey()
  return { d: ecdh.getPrivateKey(), point }
}

export function sign (data: Buffer) {
  const key = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey
  return crypto.sign('sha256', data, { key, dsaEncoding: 'der' })
}
"""


def _rows(tmp_path, files):
    for name, body in files.items():
        (tmp_path / name).write_text(body)
    return scan_directory(tmp_path)["evidence"]["source_code"]


def test_dsa_encoding_over_an_ec_key_is_ecdsa_and_create_ecdh_without_a_secret_is_ec(tmp_path):
    rows = _rows(tmp_path, {"passkey.ts": PASSKEY})
    fams = {}
    for r in rows:
        fams.setdefault(r["line"], set()).add(r["algorithm"])
    assert "DSA" not in set().union(*fams.values()), fams
    assert "ECDSA" in fams[12], fams
    for n in (4, 5, 6, 7):
        assert "ECDH" not in fams.get(n, set()), (n, fams.get(n))
    assert "EC" in fams[4]


def test_create_ecdh_with_compute_secret_is_still_ecdh(tmp_path):
    rows = _rows(tmp_path, {"kex.js": "const crypto = require('crypto')\n"
                                     "const a = crypto.createECDH('prime256v1')\na.generateKeys()\n"
                                     "const s = a.computeSecret(otherPublicKey)\n"})
    assert any(r["algorithm"] == "ECDH" and r["line"] == 2 for r in rows), rows


def test_dsa_encoding_over_a_dsa_key_is_not_made_ecdsa(tmp_path):
    rows = _rows(tmp_path, {"d.js": "const crypto = require('crypto')\n"
                                   "const { privateKey } = crypto.generateKeyPairSync('dsa', { modulusLength: 2048 })\n"
                                   "const s = crypto.sign('sha256', d, { key: privateKey, dsaEncoding: 'der' })\n"})
    assert not any(r["algorithm"] == "ECDSA" for r in rows), rows
