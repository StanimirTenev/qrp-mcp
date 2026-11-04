"""Settings that switch protection off, and the TLS version spellings of FortiOS and Vault
(ZA-OPRAVYANE rows 226, 227, 305, 346 and the .NET switch of 386). Each left no trace on
0.41.0. The sources are quoted in qrp_mcp/switches.py and here:

* FortiOS 7.6.4 CLI reference, config system global,
  https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/339914554/config-system-global
  -- `admin-https-ssl-versions` "Allowed TLS versions for web administration.", options
  tlsv1-1, tlsv1-2, tlsv1-3; `strong-crypto` "Enable to use strong encryption and only allow
  strong ciphers and digest for HTTPS/SSH/TLS/SSL functions."; `ssl-static-key-ciphers`
  "Enable/disable static key ciphers in SSL/TLS connections (e.g. AES128-SHA, AES256-SHA,
  AES128-SHA256, AES256-SHA256)."; `ssl-min-proto-version` options SSLv3, TLSv1, TLSv1-1, ...
* FortiOS 7.6.4, config vpn ssl settings,
  https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/114404382/config-vpn-ssl-settings
  -- `ssl-min-proto-ver` "SSL minimum protocol version." options tls1-0 ... tls1-3.
* Vault TCP listener, https://developer.hashicorp.com/vault/docs/configuration/listener/tcp
  -- `tls_disable` "Specifies if TLS will be disabled."; `tls_min_version` "Accepted values
  are "tls10", "tls11", "tls12" or "tls13"". Vault Helm,
  https://developer.hashicorp.com/vault/docs/platform/k8s/helm/configuration -- global.tlsDisable
  "When set to `true`, changes URLs from `https` to `http`".
* .NET, https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls --
  DontEnableSchUseStrongCrypto "A value of true disables strong cryptography for your app."
* Kafka, https://kafka.apache.org/41/security/encryption-and-authentication-using-ssl/ --
  "Server host name verification may be disabled by setting
  ssl.endpoint.identification.algorithm to an empty string."; ZooKeeper,
  https://zookeeper.apache.org/doc/current/zookeeperAdmin.html -- ssl.hostnameVerification
  "Specifies whether the hostname verification is enabled ..." Default: true.
"""

import pytest

from qrp_mcp.scan import scan_directory


def _protocols(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return scan_directory(tmp_path)


FORTIOS = """#config-version=FGT60F-7.6.6-FW-build3652-251020:opmode=0:vdom=0:user=admin
config system global
    set strong-crypto disable
    set admin-https-ssl-versions tlsv1-1 tlsv1-2
    set ssl-static-key-ciphers enable
    set ssl-min-proto-version TLSv1-1
end
config vpn ssl settings
    set ssl-min-proto-ver tls1-0
    set ssl-max-proto-ver tls1-3
end
"""


def test_fortios_tls_versions(tmp_path):
    result = _protocols(tmp_path, "fw.conf", FORTIOS)
    versions = sorted((p["line"], p["version"]) for p in result["evidence"]["protocols"]
                      if p.get("version"))
    assert versions == [(4, "TLSv1.1"), (4, "TLSv1.2"), (6, "TLSv1.1"), (9, "TLSv1.0"),
                        (10, "TLSv1.3")]
    assert result["summary"]["deprecated_protocols"] == ["TLSv1.0", "TLSv1.1"]


def test_fortios_strong_crypto_and_static_key_ciphers(tmp_path):
    result = _protocols(tmp_path, "fw.conf", FORTIOS)
    [weak] = [p for p in result["evidence"]["protocols"] if p.get("weak_crypto_allowed")]
    assert (weak["line"], weak["setting"]) == (3, "strong-crypto")
    [static] = result["evidence"]["static_rsa_kex"]
    assert (static["line"], static["setting"]) == (5, "ssl-static-key-ciphers")
    assert result["tls_termination"] is not None


def test_fortios_safe_values_say_nothing(tmp_path):
    result = _protocols(tmp_path, "fw.conf", "config system global\n    set strong-crypto enable\n"
                                             "    set ssl-static-key-ciphers disable\nend\n")
    assert result["evidence"]["protocols"] == []
    assert result["evidence"]["static_rsa_kex"] == []


VAULT = """listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_disable     = 1
  tls_min_version = "tls10"
}
"""


def test_vault_listener(tmp_path):
    result = _protocols(tmp_path, "vault.hcl", VAULT)
    rows = sorted((p["line"], p.get("version"), bool(p.get("tls_disabled")))
                  for p in result["evidence"]["protocols"])
    assert rows == [(3, None, True), (4, "TLSv1.0", False)]
    assert result["summary"]["deprecated_protocols"] == ["TLSv1.0"]


@pytest.mark.parametrize("text", ['tls_disable = "false"\n', "tls_disable = 0\n",
                                  '# tls_disable = 1\n'])
def test_vault_tls_kept_on(tmp_path, text):
    result = _protocols(tmp_path, "vault.hcl", text)
    assert [p for p in result["evidence"]["protocols"] if p.get("tls_disabled")] == []


def test_vault_helm_values(tmp_path):
    result = _protocols(tmp_path, "values.yaml", "global:\n  tlsDisable: true\n")
    [place] = result["evidence"]["protocols"]
    assert (place["line"], place["setting"], place["tls_disabled"]) == (2, "tlsDisable", True)


def test_dotnet_strong_crypto_switch(tmp_path):
    result = _protocols(tmp_path, "app.config", (
        '<configuration><runtime>\n<AppContextSwitchOverrides value="Switch.System.Net.'
        'DontEnableSchUseStrongCrypto=true;Switch.System.Net.DontEnableSystemDefaultTls'
        'Versions=true" />\n</runtime></configuration>\n'))
    [place] = result["evidence"]["protocols"]
    assert (place["line"], place["weak_crypto_allowed"]) == (2, True)


@pytest.mark.parametrize("name,text,line", [
    ("server.properties", "ssl.endpoint.identification.algorithm=\nssl.protocol=TLSv1.2\n", 1),
    ("client.properties", "ssl.endpoint.identification.algorithm=https\n"
                          "listener.name.x.ssl.endpoint.identification.algorithm=\n", 2),
    ("zoo.cfg", "secureClientPort=2281\nssl.hostnameVerification=false\n", 2),
])
def test_hostname_verification_off(tmp_path, name, text, line):
    result = _protocols(tmp_path, name, text)
    off = [p for p in result["evidence"]["protocols"] if p.get("peer_verification") == "off"]
    assert [p["line"] for p in off] == [line]


def test_switches_reach_the_cbom_as_their_own_components(tmp_path):
    from qrp_mcp.cyclonedx import build
    (tmp_path / "vault.hcl").write_text(VAULT)
    (tmp_path / "fw.conf").write_text(FORTIOS)
    names = {c["name"] for c in build(scan_directory(tmp_path))["components"]}
    assert {"TLS disabled (tls_disable)", "Strong cryptography off (strong-crypto)"} <= names
