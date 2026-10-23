"""Ed25519 glued into an identifier (ZA-OPRAVYANE row 66, swarm A of 22.10.2026,
`qrp-kachestvo/roy-2026-10-22/a-pravopisi/test_r1`).

The rule was `\\bed25519\\b`, so ED25519_sign, EVP_PKEY_ED25519 and Ed25519PrivateKey were
invisible. Names checked against the libraries' sources: BoringSSL
include/openssl/curve25519.h and OpenSSL include/openssl/evp.h (corpus copies), wolfSSL
wolfcrypt/ed25519.h, libsodium crypto_sign_ed25519.h, Go crypto/x509/x509.go, pyca
asymmetric/ed25519.py, ring src/ec/curve25519/ed25519/signing.rs, paramiko ed25519key.py
(fetched by the swarm, `verify-out.tsv`).
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("name, line", [
    ("e.c", "ED25519_sign(out_sig, msg, msg_len, private_key);"),
    ("e.c", "EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);"),
    ("e.c", "EVP_PKEY *k = EVP_PKEY_new_raw_private_key(NID_ED25519, NULL, raw, 32);"),
    ("e.py", "k = Ed25519PrivateKey.generate()"),
    ("e.go", "if cert.SignatureAlgorithm == x509.PureEd25519 { ok = true }"),
    ("e.rs", "use ed25519_dalek::{Signer, SigningKey};"),
    ("e.rs", "let kp = Ed25519KeyPair::from_pkcs8(doc.as_ref())?;"),
    ("e.c", "crypto_sign_ed25519_detached(sig, NULL, m, mlen, sk);"),
    ("e.c", "ret = wc_ed25519_sign_msg(msg, msgSz, sig, &sigSz, &key);"),
    ("e.py", "key = paramiko.Ed25519Key.from_private_key_file(path)"),
])
def test_ed25519_in_an_identifier(tmp_path, name, line):
    (tmp_path / name).write_text(line + "\n", encoding="utf-8")
    assert "Ed25519" in scan_directory(tmp_path)["detected_algorithms"]
