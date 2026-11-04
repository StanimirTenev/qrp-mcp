"""Settings that switch protection off, read line by line (batch 0.42.0).

Each is a vendor's own setting, quoted from its documentation, whose value turns TLS off,
lets weak or static-RSA suites in, or stops the peer's certificate being checked. None of
them names an algorithm in use, so each is a TLS place (evidence.protocols), never a family:

* Vault TCP listener, https://developer.hashicorp.com/vault/docs/configuration/listener/tcp:
  `tls_disable` "Specifies if TLS will be disabled. Vault assumes TLS by default, so you must
  explicitly disable TLS to opt-in to insecure communication." (row 305). The Vault Helm
  chart's `global.tlsDisable`, https://developer.hashicorp.com/vault/docs/platform/k8s/helm/configuration:
  "When set to `true`, changes URLs from `https` to `http`".
* .NET, https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls:
  `Switch.System.Net.DontEnableSchUseStrongCrypto` "A value of true disables strong
  cryptography for your app." (row 386).
* FortiOS 7.6.4 CLI reference, config system global,
  https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/339914554/config-system-global:
  `strong-crypto` "Enable to use strong encryption and only allow strong ciphers and digest
  for HTTPS/SSH/TLS/SSL functions."; `ssl-static-key-ciphers` "Enable/disable static key
  ciphers in SSL/TLS connections (e.g. AES128-SHA, AES256-SHA, AES128-SHA256,
  AES256-SHA256)." (row 227).
* Kafka, https://kafka.apache.org/41/security/encryption-and-authentication-using-ssl/:
  "Server host name verification may be disabled by setting
  ssl.endpoint.identification.algorithm to an empty string." ZooKeeper,
  https://zookeeper.apache.org/doc/current/zookeeperAdmin.html: `ssl.hostnameVerification`
  "Specifies whether the hostname verification is enabled in client and quorum TLS
  negotiation process." Default: true (row 346).
"""

from __future__ import annotations

import re
from typing import Any

# Every match below contains one of these, lower-case (the line gate's literals).
LITERALS = ("tls_disable", "dontenableschusestrongcrypto", "strong-crypto",
            "ssl-static-key-ciphers", "ssl.endpoint.identification.algorithm",
            "hostnameverification")

_TRUE = r"""(?:["']?(?:1|true|yes)["']?)"""

_VAULT_TLS_DISABLE = re.compile(rf"^\s*tls_disable\s*=\s*{_TRUE}\s*(?:#.*)?$", re.I)
_HELM_TLS_DISABLE = re.compile(rf"^(\s+)tlsDisable\s*:\s*{_TRUE}\s*(?:#.*)?$")
_YAML_TOP_KEY = re.compile(r"^([A-Za-z_][\w-]*)\s*:")
_DOTNET_STRONG_CRYPTO_OFF = re.compile(
    r"Switch\.System\.Net\.DontEnableSchUseStrongCrypto\s*=\s*true\b", re.I)
_FORTIOS_STRONG_CRYPTO_OFF = re.compile(r"^\s*set\s+strong-crypto\s+disable\s*$", re.I)
_FORTIOS_STATIC_KEY_ON = re.compile(r"^\s*set\s+ssl-static-key-ciphers\s+enable\s*$", re.I)
_KAFKA_NO_HOSTNAME = re.compile(
    r"^\s*(?:[\w.]+\.)?ssl\.endpoint\.identification\.algorithm\s*[=:]\s*[\"']?[\"']?\s*$")
_ZK_NO_HOSTNAME = re.compile(
    r"^\s*ssl\.(?:quorum\.)?hostnameVerification\s*[=:]\s*[\"']?false[\"']?\s*$", re.I)


def _place(setting: str, said: str, **flags: Any) -> dict[str, Any]:
    return {"protocol": "tls", "version": None, "basis": "configured_switch",
            "setting": setting, "deprecated": False, "description": said, **flags}


def scan(line: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(TLS places, static-RSA findings) a switch on this line sets."""
    low = line.lower()
    if not any(word in low for word in LITERALS) or line.lstrip().startswith(("#", "//", "<!--")):
        return [], []
    if _VAULT_TLS_DISABLE.match(line):
        return [_place("tls_disable", (
            "TLS is disabled for this Vault listener (tls_disable): its traffic is not "
            "encrypted. Vault's documentation: \"Vault assumes TLS by default, so you must "
            "explicitly disable TLS to opt-in to insecure communication.\""),
            tls_disabled=True)], []
    if _DOTNET_STRONG_CRYPTO_OFF.search(line):
        return [_place("Switch.System.Net.DontEnableSchUseStrongCrypto", (
            "Strong cryptography is turned off for this .NET application "
            "(DontEnableSchUseStrongCrypto=true): \"A value of true disables strong "
            "cryptography for your app.\" Older protocols and weaker suites may then be "
            "negotiated; which ones depends on the Windows version, not on this file."),
            weak_crypto_allowed=True)], []
    if _FORTIOS_STRONG_CRYPTO_OFF.match(line):
        return [_place("strong-crypto", (
            "FortiOS strong-crypto is disabled: the setting that would \"only allow strong "
            "ciphers and digest for HTTPS/SSH/TLS/SSL functions\" is off, so weaker ciphers "
            "and digests stay allowed on the device's own services."),
            weak_crypto_allowed=True)], []
    if _FORTIOS_STATIC_KEY_ON.match(line):
        return [], [{
            "family": "RSA", "key_exchange": "RSA", "suites": [],
            "setting": "ssl-static-key-ciphers", "basis": "configured_switch",
            "description": ("FortiOS ssl-static-key-ciphers is enabled: \"static key ciphers "
                            "in SSL/TLS connections (e.g. AES128-SHA, AES256-SHA, "
                            "AES128-SHA256, AES256-SHA256)\" are allowed. Those suites carry "
                            "the session key under the server's RSA key, so there is no "
                            "forward secrecy and a recorded session opens to whoever later "
                            "recovers that key, by a quantum computer included."),
        }]
    for pattern, setting in ((_KAFKA_NO_HOSTNAME, "ssl.endpoint.identification.algorithm="),
                             (_ZK_NO_HOSTNAME, "ssl.hostnameVerification=false")):
        if pattern.match(line):
            return [{
                "protocol": "tls", "version": None, "basis": "configured_verification",
                "peer_verification": "off", "verification_setting": setting,
                "deprecated": False,
                "description": (f"The server's host name is not verified ({setting}): this "
                                f"TLS hop is encrypted, but whoever sits on the path can stand "
                                f"in for the server with any certificate the trust store "
                                f"accepts."),
            }], []
    return [], []


def matches(line: str) -> list[dict[str, Any]]:
    """Everything scan() finds on the line, in one list (the line gate's check)."""
    places, static = scan(line)
    return places + static


def helm_tls_disable(lines: list[str]) -> list[dict[str, Any]]:
    """`tlsDisable: true` where the Vault Helm chart puts it: directly under the top-level
    `global:` key of a values file (global.tlsDisable). Anywhere else it is a key of some other
    schema and says nothing here."""
    out: list[dict[str, Any]] = []
    top = None
    child_indent = None
    for number, line in enumerate(lines, 1):
        key = _YAML_TOP_KEY.match(line)
        if key:
            top, child_indent = key.group(1), None
            continue
        if top != "global" or not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if child_indent is None:
            child_indent = indent
        match = _HELM_TLS_DISABLE.match(line)
        if match and indent == child_indent:
            place = _place("global.tlsDisable", (
                "TLS is disabled by global.tlsDisable, the Vault Helm chart's setting (\"When "
                "set to true, changes URLs from https to http\"). Which listener the rendered "
                "configuration carries is not stated by this line."), tls_disabled=True)
            place.update(line=number, excerpt=line.strip()[:200])
            out.append(place)
    return out
