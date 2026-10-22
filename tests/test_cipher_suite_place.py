"""A cipher-suite setting is a TLS place too (ZA-OPRAVYANE row 31, 22.10.2026).

0.31.0 put the termination pointer beside protocol pins and group settings, and the
README said "beside every TLS setting". The cipher-suite line went without it: nginx
`ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA` gave ECDH and RSA with no
`tls_termination` and the line was not in `configured_in`; HAProxy's
`ssl-default-bind-ciphers` the same. A suite is negotiated where TLS terminates, like a
group, so the line is now a place with `basis: configured_cipher_suite`.
"""

from qrp_mcp.assets import TLS_SETTING_NOTE
from qrp_mcp.scan import scan_directory

NGINX = ("server {\n  listen 443 ssl;\n"
         "  ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:AES256-SHA;\n}\n")
HAPROXY = "global\n  ssl-default-bind-ciphers ECDHE-RSA-AES256-GCM-SHA384\n"


def _tree(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def _cipher_places(result):
    return {(p["path"], p["line"]) for p in result["tls_termination"]["configured_in"]
            if p["basis"] == "configured_cipher_suite"}


def test_nginx_and_haproxy_cipher_lines_are_places(tmp_path):
    result = scan_directory(_tree(tmp_path, {"nginx.conf": NGINX, "haproxy.cfg": HAPROXY}))
    assert _cipher_places(result) == {("nginx.conf", 3), ("haproxy.cfg", 2)}
    on_lines = [f for f in result["evidence"]["source_code"]
                if (f["path"], f["line"]) in _cipher_places(result)]
    assert {f["algorithm"] for f in on_lines} == {"ECDH", "RSA"}
    assert all(f["tls_termination"] == TLS_SETTING_NOTE for f in on_lines)


def test_other_spellings(tmp_path):
    files = {
        "ssl.conf": "SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256\n",
        "haproxy.cfg": "frontend f\n  bind :443 ssl crt a.pem ciphers ECDHE-RSA-AES128-GCM-SHA256\n",
        "openssl.cnf": "[system_default_sect]\nCipherString = ECDHE-RSA-AES256-GCM-SHA384\n",
        "srv.py": "ctx.set_ciphers('ECDHE-RSA-AES128-GCM-SHA256')\n",
    }
    result = scan_directory(_tree(tmp_path, files))
    assert _cipher_places(result) == {("ssl.conf", 1), ("haproxy.cfg", 2),
                                      ("openssl.cnf", 2), ("srv.py", 1)}


def test_a_suite_constant_in_code_is_not_a_setting(tmp_path):
    files = {"tls1.h": '# define TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256 "ECDHE-RSA-AES128-GCM-SHA256"\n',
             "nginx.conf": "# ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;\n"}
    result = scan_directory(_tree(tmp_path, files))
    assert result["evidence"]["source_code"]
    assert result["tls_termination"] is None
