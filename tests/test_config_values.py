"""Algorithms a product's own setting names by value (ZA-OPRAVYANE rows 347, 348, 349;
fixtures L2/09-caddy, L2/22-postgres, L2/14-openvpn). Each gave no evidence on 0.41.0.

* Caddy, https://caddyserver.com/docs/caddyfile/directives/tls -- "key_type
  ed25519|p256|p384|rsa2048|rsa4096 ... the type of key to use when generating CSRs".
* PostgreSQL, https://www.postgresql.org/docs/current/runtime-config-connection.html --
  password_encryption "md5, which stores the password as an MD5 hash"; pg_hba.conf,
  https://www.postgresql.org/docs/current/auth-pg-hba-conf.html -- `host database user address
  auth-method`, md5 "Perform SCRAM-SHA-256 or MD5 authentication to verify the user's password."
* OpenVPN 2.6, https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/ --
  "--auth alg Authenticate data channel packets ... with HMAC"; "--dh file ... Diffie Hellman
  parameters in .pem format".

Not read (the minimum for 347): `cipher BF-CBC` (Blowfish is not a family in this scanner's
catalogue) and the DH parameter file's size.
"""

from qrp_mcp import remediation
from qrp_mcp.scan import scan_directory


def _rows(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    return result, sorted((f["line"], f["algorithm"], f.get("key_size"))
                          for f in result["evidence"]["source_code"]
                          if f["description"].startswith(("Caddy", "PostgreSQL", "OpenVPN")))


def test_caddy_key_type(tmp_path):
    result, rows = _rows(tmp_path, "Caddyfile", "example.com {\n  tls {\n    key_type rsa2048\n  }\n}\n"
                                                "b.example {\n  tls {\n    key_type p384\n  }\n}\n")
    assert rows == [(3, "RSA", 2048), (8, "ECDSA", 384)]
    assert {remediation.role_of(f) for f in result["evidence"]["source_code"]
            if f["algorithm"] == "RSA"} == {"signature"}


def test_postgres_md5(tmp_path):
    (tmp_path / "postgresql.conf").write_text("ssl = on\npassword_encryption = md5\n")
    (tmp_path / "pg_hba.conf").write_text("# TYPE DATABASE USER ADDRESS METHOD\n"
                                          "host all all 0.0.0.0/0 md5\nhost all all ::1/128 scram-sha-256\n")
    result = scan_directory(tmp_path)
    rows = sorted((f["path"], f["line"]) for f in result["evidence"]["source_code"]
                  if f["algorithm"] == "MD5")
    assert rows == [("pg_hba.conf", 2), ("postgresql.conf", 2)]


def test_openvpn_auth_and_dh(tmp_path):
    _result, rows = _rows(tmp_path, "server.conf", "port 1194\ndev tun\ndh dh1024.pem\nauth SHA1\n"
                                                   "cipher BF-CBC\n")
    assert rows == [(3, "DH", "undetermined"), (4, "SHA1", None)]


def test_auth_and_dh_outside_openvpn_say_nothing(tmp_path):
    _result, rows = _rows(tmp_path, "app.conf", "dh params.pem\nauth SHA1\n")
    assert rows == []
