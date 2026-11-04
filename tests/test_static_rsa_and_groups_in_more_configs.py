"""Static RSA key exchange and classical groups in more configuration formats (rows 339, 343).

Measured on 0.41.0 (L2 probe): `static_rsa_kex` fired for nginx, HAProxy and `zoo.cfg` only.
The same suites in Envoy, Istio, Traefik (YAML lists), Ingress-NGINX, Dovecot, MySQL and Kafka
gave nothing beyond "RSA named in a cipher suite"; `- P-256` in Envoy, `CurveP256` in Traefik
and `P-256:X25519` in Dovecot gave no `tls_groups` row. The suites are static RSA by name
(openssl-ciphers(1), row 43). The settings, each from its documentation:

- Envoy TlsParameters `cipher_suites` "the TLS listener will only support the specified cipher
  list", `ecdh_curves` "the TLS connection will only support the specified ECDH curves"
  https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/common.proto
- Istio ServerTLSSettings `cipherSuites` "If specified, only support the specified cipher list."
  https://istio.io/latest/docs/reference/config/networking/gateway/
- Traefik TLS options `cipherSuites`; `curvePreferences` "The names of the curves defined by
  crypto (e.g. CurveP521) and the RFC defined names (e. g. secp521r1) can be used."
  https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/tls-options/
- Ingress-NGINX ConfigMap `ssl-ciphers`, `ssl-ecdh-curve`
  https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/
- Dovecot `ssl_cipher_list` "The list of SSL ciphers to use for TLSv1.2 and below connections",
  `ssl_curve_list` "Colon separated list of elliptic curves to use"
  https://doc.dovecot.org/2.3/settings/core/
- MySQL `ssl_cipher` "The list of permissible encryption ciphers for connections that use
  TLSv1.2" https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_ssl_cipher
- Kafka `ssl.cipher.suites` "A list of cipher suites"
  https://kafka.apache.org/44/configuration/broker-configs/
F5 BIG-IP's `P256` is not read: its syntax was not checked against F5's documentation.
"""

from qrp_mcp.scan import scan_directory


def _scan(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    r = scan_directory(tmp_path)
    rsa = {(f["line"], s) for f in r["evidence"]["static_rsa_kex"] for s in f["suites"]}
    groups = {(g["line"], g["group"]) for g in r["evidence"]["tls_groups"]}
    return rsa, groups


def test_envoy_lists(tmp_path):
    rsa, groups = _scan(tmp_path, "envoy.yaml",
                        "tls_params:\n"
                        "  cipher_suites:\n"
                        "  - ECDHE-RSA-AES128-SHA\n"
                        "  - AES128-SHA\n"
                        "  ecdh_curves:\n"
                        "    - P-256\n"
                        "    - X25519MLKEM768\n"
                        "  signature_algorithms:\n"
                        "  - AES256-SHA\n")
    assert rsa == {(4, "AES128-SHA")}
    assert groups == {(6, "P-256")}


def test_istio_and_traefik_lists(tmp_path):
    rsa, groups = _scan(tmp_path, "dynamic.yml",
                        "tls:\n"
                        "  options:\n"
                        "    default:\n"
                        "      cipherSuites:\n"
                        "        - TLS_RSA_WITH_AES_128_CBC_SHA\n"
                        "        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n"
                        "      curvePreferences:\n"
                        "        - CurveP256\n"
                        "        - X25519\n"
                        "      sniStrict: true\n"
                        "        - AES256-SHA\n")
    assert rsa == {(5, "TLS_RSA_WITH_AES_128_CBC_SHA")}
    assert groups == {(8, "CurveP256"), (9, "X25519")}


def test_flat_settings(tmp_path):
    (tmp_path / "configmap.yaml").write_text(
        "data:\n"
        "  ssl-ciphers: \"ECDHE-RSA-AES128-GCM-SHA256:AES128-SHA:DES-CBC3-SHA\"\n"
        "  ssl-ecdh-curve: \"X25519MLKEM768:X25519\"\n")
    (tmp_path / "10-ssl.conf").write_text(
        "ssl_cipher_list = ALL:!aNULL:AES128-SHA:!DES-CBC3-SHA\n"
        "ssl_curve_list = P-256:X25519\n")
    (tmp_path / "my.cnf").write_text("[mysqld]\nssl_cipher=AES128-SHA:DHE-RSA-AES256-SHA\n")
    (tmp_path / "server.properties").write_text(
        "ssl.cipher.suites=TLS_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\n")
    r = scan_directory(tmp_path)
    rsa = {(f["path"], f["line"], s) for f in r["evidence"]["static_rsa_kex"] for s in f["suites"]}
    assert rsa == {("configmap.yaml", 2, "AES128-SHA"), ("configmap.yaml", 2, "DES-CBC3-SHA"),
                   ("10-ssl.conf", 1, "AES128-SHA"), ("my.cnf", 2, "AES128-SHA"),
                   ("server.properties", 1, "TLS_RSA_WITH_AES_128_CBC_SHA")}
    groups = {(g["path"], g["line"], g["group"]) for g in r["evidence"]["tls_groups"]}
    assert groups == {("configmap.yaml", 3, "X25519"), ("10-ssl.conf", 2, "P-256"),
                      ("10-ssl.conf", 2, "X25519")}
