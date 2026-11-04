"""Static RSA key exchange in cipher lists set from C, Java, Node and Ruby (fix list rows
403, 404).

Measured on 0.41.0 (W2 probe): the string "ECDHE-RSA-AES128-GCM-SHA256:AES128-SHA" gave
`static_rsa_kex` through Python's `set_ciphers` and Rust's `set_cipher_list`, and nothing
through `SSL_CTX_set_cipher_list` (the `\\b` before `set_` refused the `_`), wolfSSL's
`wolfSSL_CTX_set_cipher_list`, Java's `SSLParameters.setCipherSuites`, Node's `ciphers:` or
Ruby's `ctx.ciphers =`. OpenSSL: "TLS_RSA_WITH_AES_128_CBC_SHA  AES128-SHA"; "kRSA, aRSA,
RSA -- Cipher suites using RSA key exchange" https://docs.openssl.org/3.0/man1/openssl-ciphers/
Node: "ciphers <string> Cipher suite specification" https://nodejs.org/api/tls.html;
Java: SSLParameters.setCipherSuites(String[])
https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/net/ssl/SSLParameters.html
"""

import pytest

from qrp_mcp.scan import scan_directory

SUITES = "ECDHE-RSA-AES128-GCM-SHA256:AES128-SHA"


@pytest.mark.parametrize("name,line", [
    ("a.c", f'SSL_CTX_set_cipher_list(ctx, "{SUITES}");'),
    ("w.c", f'wolfSSL_CTX_set_cipher_list(ctx, "{SUITES}");'),
    ("s.c", f'SSL_CTX_set_strict_cipher_list(ctx, "{SUITES}");'),
    ("J.java", 'p.setCipherSuites(new String[]{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", '
               '"TLS_RSA_WITH_AES_128_CBC_SHA"});'),
    ("n.js", f"const s = tls.connect({{ host: 'h', ciphers: '{SUITES}' }});"),
    ("r.rb", f"ctx.ciphers = '{SUITES}'"),
])
def test_static_rsa_suite_set_from_code(tmp_path, name, line):
    (tmp_path / name).write_text(line + "\n")
    r = scan_directory(tmp_path)
    assert [i["line"] for i in r["evidence"]["static_rsa_kex"]] == [1]
