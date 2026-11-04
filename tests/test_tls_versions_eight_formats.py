"""TLS 1.0/1.1 configured in eight formats outside nginx-like syntax (ZA-OPRAVYANE row 332).

Each gave `deprecated_protocols: []` and no `protocols` evidence on 0.41.0, while the same
versions in nginx were caught. The setting names and value spellings, from each product's
documentation (read 04.11.2026):

* Ingress-NGINX ConfigMap, https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/
  -- `ssl-protocols` "Sets the SSL protocols to use. The default is: TLSv1.2 TLSv1.3".
* Istio Gateway, https://istio.io/latest/docs/reference/config/networking/gateway/
  -- `minProtocolVersion`; "TLSProtocol enum values: TLS_AUTO, TLSV1_0, TLSV1_1, TLSV1_2, TLSV1_3".
* Traefik TLS options, https://doc.traefik.io/traefik/reference/routing-configuration/http/tls/tls-options/
  -- `minVersion: VersionTLS12` (VersionTLS10/11/13 are the same Go constant names).
* Dovecot 2.3, https://doc.dovecot.org/2.3/settings/core/ -- `ssl_min_protocol` "The minimum
  SSL protocol version Dovecot accepts." Supported values ANY, SSLv3, TLSv1, TLSv1.1, ...
* OpenVPN 2.6, https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/
  -- "tls-version-min version ['or-highest'] Sets the minimum TLS version we will accept".
* Kafka 4.1 broker configs, https://kafka.apache.org/41/configuration/broker-configs/
  -- `ssl.enabled.protocols` "The list of protocols enabled for SSL connections. The default
  is 'TLSv1.2,TLSv1.3'"; `ssl.protocol` "The SSL protocol used to generate the SSLContext".
* ZooKeeper admin guide, https://zookeeper.apache.org/doc/current/zookeeperAdmin.html
  -- `ssl.protocol` "Specifies to protocol to be used in client and quorum TLS negotiation";
  `ssl.enabledProtocols` "Specifies the enabled protocols in client and quorum TLS negotiation".
* MySQL 8.4, https://dev.mysql.com/doc/refman/8.4/en/encrypted-connection-protocols-ciphers.html
  -- `tls_version=TLSv1.2,TLSv1.3` in my.cnf.
"""

import pytest

from qrp_mcp.scan import scan_directory

CASES = [
    ("configmap.yaml", 'data:\n  ssl-protocols: "TLSv1 TLSv1.1 TLSv1.2"\n',
     {"TLSv1.0", "TLSv1.1", "TLSv1.2"}),
    ("gateway.yaml", "spec:\n  servers:\n  - tls:\n      mode: SIMPLE\n"
                     "      minProtocolVersion: TLSV1_0\n      maxProtocolVersion: TLSV1_1\n",
     {"TLSv1.0", "TLSv1.1"}),
    ("dynamic.yml", "tls:\n  options:\n    default:\n      minVersion: VersionTLS10\n",
     {"TLSv1.0"}),
    ("10-ssl.conf", "ssl = required\nssl_min_protocol = TLSv1\n", {"TLSv1.0"}),
    ("server.conf", "port 1194\ntls-version-min 1.0\n", {"TLSv1.0"}),
    ("server.properties", "ssl.enabled.protocols=TLSv1.2,TLSv1.1,TLSv1\nssl.protocol=TLSv1.2\n",
     {"TLSv1.0", "TLSv1.1", "TLSv1.2"}),
    ("zoo.cfg", "ssl.protocol=TLSv1.1\nssl.enabledProtocols=TLSv1.1,TLSv1.2\n",
     {"TLSv1.1", "TLSv1.2"}),
    ("my.cnf", "[mysqld]\ntls_version=TLSv1,TLSv1.1,TLSv1.2\n",
     {"TLSv1.0", "TLSv1.1", "TLSv1.2"}),
]


@pytest.mark.parametrize("name,text,expected", CASES, ids=[c[0] for c in CASES])
def test_tls_versions_in_eight_formats(tmp_path, name, text, expected):
    (tmp_path / name).write_text(text)
    result = scan_directory(tmp_path)
    versions = {p["version"] for p in result["evidence"]["protocols"]
                if p.get("protocol") == "tls" and p.get("version") and not p.get("banned")}
    assert versions == expected
    assert set(result["summary"]["deprecated_protocols"]) == expected & {"TLSv1.0", "TLSv1.1"}


def test_openvpn_version_in_prose_is_not_a_setting(tmp_path):
    # The bare `1.0` is read only after `tls-version-min`/`-max`, never as any number.
    (tmp_path / "server.conf").write_text("# version 1.0 of this file\nverb 1.0\n")
    result = scan_directory(tmp_path)
    assert [p for p in result["evidence"]["protocols"] if p.get("protocol") == "tls"] == []
