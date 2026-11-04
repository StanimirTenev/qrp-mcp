"""TLS groups given as library constants (row 419).

Measured on 0.41.0 (W2 probe): `MBEDTLS_SSL_IANA_TLS_GROUP_X25519`, `WOLFSSL_ECC_X25519`,
`SSL_GROUP_SECP256R1`, `kx_group::SECP256R1` gave no `tls_groups` row, so the classical group
beside rustls's `kx_group::X25519MLKEM768` was missing from `fallback_beside_hybrid`. Each
constant, from the library's own source:

- mbedTLS ssl.h, "TLS 1.3 NamedGroup values": "#define MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1
  0x0017", "#define MBEDTLS_SSL_IANA_TLS_GROUP_X25519 0x001D"
  https://raw.githubusercontent.com/Mbed-TLS/mbedtls/development/include/mbedtls/ssl.h
- wolfSSL ssl.h, "/* Named Groups */": "WOLFSSL_ECC_SECP256R1 = 23,", "WOLFSSL_ECC_X25519 = 29,"
  https://raw.githubusercontent.com/wolfSSL/wolfssl/master/wolfssl/ssl.h
- BoringSSL ssl.h: "SSL_GROUP_* define TLS group IDs.", "#define SSL_GROUP_SECP256R1 23"
  https://raw.githubusercontent.com/google/boringssl/main/include/openssl/ssl.h
- rustls: SECP256R1 "Ephemeral ECDH on secp256r1 (aka NIST-P256)", X25519 "Ephemeral ECDH on
  curve25519" https://docs.rs/rustls/latest/rustls/crypto/aws_lc_rs/kx_group/index.html
Not read: wolfSSL_CTX_set_groups_list's string (its meaning was not found in wolfSSL's docs).
"""

from qrp_mcp.scan import scan_directory


def test_group_constants_are_groups(tmp_path):
    (tmp_path / "t.c").write_text(
        "#define MBEDTLS_SSL_IANA_TLS_GROUP_X25519 0x001D\n"
        "static const uint16_t g1[] = { MBEDTLS_SSL_IANA_TLS_GROUP_X25519, MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1, 0 };\n"
        "static const uint16_t g2[] = {SSL_GROUP_X25519_MLKEM768, SSL_GROUP_SECP256R1};\n"
        "void f(WOLFSSL *ssl) { wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519); }\n")
    (tmp_path / "r.rs").write_text(
        "let groups = vec![aws_lc_rs::kx_group::X25519MLKEM768, aws_lc_rs::kx_group::SECP256R1];\n")
    r = scan_directory(tmp_path)
    got = {(g["path"], g["line"], g["group"]) for g in r["evidence"]["tls_groups"]}
    assert got == {("t.c", 2, "MBEDTLS_SSL_IANA_TLS_GROUP_X25519"),
                   ("t.c", 2, "MBEDTLS_SSL_IANA_TLS_GROUP_SECP256R1"),
                   ("t.c", 3, "SSL_GROUP_SECP256R1"),
                   ("t.c", 4, "WOLFSSL_ECC_X25519"),
                   ("r.rs", 1, "kx_group::SECP256R1")}
    fallbacks = r["summary"]["by_role"]["key_establishment"].get("fallback_beside_hybrid", {})
    assert any("r.rs:1" in places for places in fallbacks.values()), fallbacks
