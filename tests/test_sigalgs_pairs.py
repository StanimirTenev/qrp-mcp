"""Row 344 (04.11.2026): OpenSSL signature-algorithm pairs, `RSA+SHA1:ECDSA+SHA256`.

ECDSA was found on these lines; RSA and SHA-1 were not. OpenSSL's SignatureAlgorithms list takes
"algorithm+hash" (https://docs.openssl.org/3.0/man3/SSL_CONF_cmd/); mod_ssl's own example is
`SSLOpenSSLConfCmd SignatureAlgorithms RSA+SHA384:ECDSA+SHA256`
(https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslopensslconfcmd)."""

from __future__ import annotations


def test_pairs_name_rsa_and_sha1(tmp_path):
    from qrp_mcp.scan import scan_directory
    (tmp_path / "ssl.conf").write_text(
        "SSLOpenSSLConfCmd SignatureAlgorithms RSA+SHA384:ECDSA+SHA256\n")
    (tmp_path / "haproxy.cfg").write_text(
        "global\n    ssl-default-bind-sigalgs RSA+SHA1:ECDSA+SHA256\n")
    found = {(e["path"], e["algorithm"]) for e in scan_directory(tmp_path)["evidence"]["source_code"]}
    assert {("ssl.conf", "RSA"), ("ssl.conf", "ECDSA"), ("haproxy.cfg", "RSA"),
            ("haproxy.cfg", "SHA1")} <= found
    assert ("ssl.conf", "SHA1") not in found
