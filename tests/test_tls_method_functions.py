"""A TLS method function pins its version (fix list rows 405, 407, 410).

Measured on 0.41.0 (W2 probe): `SSL_CTX_new(TLSv1_method())`, Node's
`secureProtocol: 'TLSv1_method'` and wolfSSL's `wolfTLSv1_client_method()` gave nothing, and
`deprecated_protocols` was empty.

- OpenSSL: "A TLS/SSL connection established with these methods will only understand the
  TLSv1 protocol. These methods are deprecated." https://docs.openssl.org/3.0/man3/SSL_CTX_new/
- Node: "use the function names as strings. For example, use 'TLSv1_1_method' to force TLS
  version 1.1" https://nodejs.org/api/tls.html
- wolfSSL: "wolfTLSv1_client_method() ... will only support the TLS 1.0 protocol."
  https://www.wolfssl.com/documentation/manuals/wolfssl/group__Setup.html
The version-flexible `TLS_method` and `SSLv23_method` pin nothing and are not read.
"""

from qrp_mcp.scan import scan_directory


def _versions(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    r = scan_directory(tmp_path)
    return r, {(p["line"], p["version"]) for p in r["evidence"]["protocols"]}


def test_openssl_and_wolfssl_methods(tmp_path):
    r, got = _versions(tmp_path, "t.c",
                       "void f(void) {\n"
                       "    SSL_CTX *a = SSL_CTX_new(TLSv1_method());\n"
                       "    SSL_CTX *b = SSL_CTX_new(TLSv1_1_client_method());\n"
                       "    WOLFSSL_CTX *c = wolfSSL_CTX_new(wolfTLSv1_client_method());\n"
                       "    WOLFSSL_CTX *d = wolfSSL_CTX_new(wolfTLSv1_3_client_method());\n"
                       "    SSL_CTX *e = SSL_CTX_new(TLS_method());\n"
                       "    SSL_CTX *g = SSL_CTX_new(SSLv23_method());\n"
                       "}\n")
    assert {(2, "TLSv1.0"), (3, "TLSv1.1"), (4, "TLSv1.0"), (5, "TLSv1.3")} <= got
    assert not any(line in (6, 7) for line, _ in got)
    deprecated = {p["version"] for p in r["evidence"]["protocols"] if p.get("deprecated")}
    assert deprecated == {"TLSv1.0", "TLSv1.1"}


def test_node_secure_protocol(tmp_path):
    _, got = _versions(tmp_path, "n.js",
                       "const s = tls.connect({ host: 'h', secureProtocol: 'TLSv1_method' });\n")
    assert (1, "TLSv1.0") in got
