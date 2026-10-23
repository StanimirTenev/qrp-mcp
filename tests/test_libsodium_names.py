"""libsodium and PyNaCl never name the algorithm (ZA-OPRAVYANE row 67, swarm A of
22.10.2026, `qrp-kachestvo/roy-2026-10-22/a-pravopisi/test_r2`).

crypto_sign_* is Ed25519, crypto_box_*/crypto_kx_*/crypto_scalarmult* are X25519 -- by the
*_PRIMITIVE each header defines (libsodium include/sodium/crypto_box.h, crypto_kx.h,
crypto_scalarmult.h, crypto_sign.h, read 23.10.2026). A whole libsodium program scanned as
empty. The names the NIST signature API shares (crypto_sign_keypair, crypto_sign_open) are
left alone: every post-quantum reference implementation defines them too.
"""

import pytest

from qrp_mcp.scan import scan_directory


@pytest.mark.parametrize("family, name, line", [
    ("Ed25519", "e.c", "crypto_sign_detached(sig, NULL, m, mlen, sk);"),
    ("Ed25519", "e.py", "from nacl.signing import SigningKey"),
    ("X25519", "x.c", "crypto_box_keypair(pk, sk);"),
    ("X25519", "x.c", "crypto_kx_client_session_keys(rx, tx, cpk, csk, spk);"),
    ("X25519", "x.c", "crypto_scalarmult_base(pk, sk);"),
    ("X25519", "x.py", "from nacl.public import PrivateKey, Box"),
])
def test_libsodium_family(tmp_path, family, name, line):
    (tmp_path / name).write_text(line + "\n", encoding="utf-8")
    assert family in scan_directory(tmp_path)["detected_algorithms"]


def test_whole_libsodium_program(tmp_path):
    (tmp_path / "app.c").write_text(
        "#include <sodium.h>\n"
        "int main(void) {\n"
        "    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];\n"
        "    crypto_sign_keypair(pk, sk);\n"
        "    crypto_sign_detached(sig, NULL, m, mlen, sk);\n"
        "    crypto_box_keypair(bpk, bsk);\n"
        "    return crypto_box_easy(c, m, mlen, n, bpk, bsk);\n"
        "}\n", encoding="utf-8")
    assert {"Ed25519", "X25519"} <= set(scan_directory(tmp_path)["detected_algorithms"])


def test_nist_signature_api_is_not_ed25519(tmp_path):
    # The API every NIST post-quantum submission exports; it says nothing about Ed25519.
    (tmp_path / "sign.c").write_text(
        "int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);\n"
        "int crypto_sign_open(unsigned char *m, unsigned long long *mlen,\n"
        "                     const unsigned char *sm, unsigned long long smlen,\n"
        "                     const unsigned char *pk);\n", encoding="utf-8")
    assert "Ed25519" not in scan_directory(tmp_path)["detected_algorithms"]
