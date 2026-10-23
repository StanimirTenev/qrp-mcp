"""Rust crates and the curve as an identifier (ZA-OPRAVYANE row 75, swarm A of 22.10.2026,
`roy-2026-10-22/a-pravopisi/test_r11`).

Checked against ring src/rsa/keypair.rs and verification.rs, rustls src/crypto/enums.rs
(corpus copy), RustCrypto md5 and sha1 src/lib.rs, RustCrypto p256 src/lib.rs, noble-curves
src/nist.ts and Go crypto/tls/common.go (read 23.10.2026). Go's tls.CurveP256 is filed as
ECDH, as the TLS group table already files `curvep256`: it is a key-exchange group.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, name, line", [
    ("RSA", "r.rs", "let kp = signature::RsaKeyPair::from_pkcs8(&der)?;"),
    ("RSA", "r.rs", "let alg = &signature::RSA_PKCS1_2048_8192_SHA256;"),
    ("RSA", "r.rs", "SignatureScheme::RSA_PSS_SHA256 => true,"),
    ("MD5", "h.rs", "let mut hasher = Md5::new();"),
    ("SHA1", "h.rs", "use sha1::{Sha1, Digest};"),
    ("EC", "c.rs", "let sk = p256::SecretKey::random(&mut OsRng);"),
    ("EC", "c.js", "import { p256 } from '@noble/curves/nist';"),
    ("ECDH", "c.go", "CurvePreferences: []tls.CurveID{tls.CurveP256},"),
])
def test_identifier(tmp_path, family, name, line):
    (tmp_path / name).write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


@pytest.mark.parametrize("line", [
    "let p256 = load_palette();",
    "const sha1sum = run(cmd);",
])
def test_lookalikes(tmp_path, line):
    (tmp_path / "a.rs").write_text(line + "\n", encoding="utf-8")
    found = set(scan_directory(tmp_path)["detected_algorithms"])
    assert not found & {"EC", "SHA1"}, found
