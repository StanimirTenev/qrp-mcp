"""Algorithms a product's own setting names by value (batch 0.42.0, rows 347, 348, 349).

Each setting and its values are quoted from the product's documentation:

* Caddy tls directive, https://caddyserver.com/docs/caddyfile/directives/tls:
  "key_type ed25519|p256|p384|rsa2048|rsa4096 ... the type of key to use when generating
  CSRs" (row 349). The key the certificate is issued for, so a signature key.
* PostgreSQL, https://www.postgresql.org/docs/current/runtime-config-connection.html:
  password_encryption "Possible values are scram-sha-256, ... and md5, which stores the
  password as an MD5 hash." pg_hba.conf, https://www.postgresql.org/docs/current/auth-pg-hba-conf.html:
  records end in their auth-method, and `md5` is "Perform SCRAM-SHA-256 or MD5
  authentication to verify the user's password." Both: "Support for MD5-encrypted passwords
  is deprecated and will be removed in a future release of PostgreSQL." (row 348).
* OpenVPN 2.6 reference manual, https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/:
  "--auth alg Authenticate data channel packets ... with HMAC"; "--dh file ... Diffie Hellman
  parameters in .pem format" (row 347). The DH file's size is not read: only its name is in
  the configuration.
"""

from __future__ import annotations

import re
from typing import Any

_CADDY_KEY_TYPE = re.compile(r"^\s*key_type\s+(ed25519|p256|p384|rsa2048|rsa4096)\s*(?:#.*)?$")
_CADDY_KEYS = {"ed25519": ("Ed25519", None, None), "p256": ("ECDSA", 256, "P-256"),
               "p384": ("ECDSA", 384, "P-384"), "rsa2048": ("RSA", 2048, None),
               "rsa4096": ("RSA", 4096, None)}

_PG_PASSWORD = re.compile(r"""^\s*password_encryption\s*=\s*['"]?md5['"]?\s*(?:#.*)?$""", re.I)
_PG_HBA = re.compile(r"^\s*(?:local|host|hostssl|hostnossl|hostgssenc|hostnogssenc)\s+\S.*\smd5"
                     r"(?:\s+\S.*)?\s*$")

_OPENVPN_FILE = re.compile(r"^\s*(?:client|tls-client|tls-server|dev\s+tun|dev\s+tap|"
                           r"remote\s+\S+|tls-version-min\b|<ca>)", re.M)
_OPENVPN_AUTH = re.compile(r"^\s*auth\s+(SHA1|MD5)\s*(?:#.*)?$", re.I)
_OPENVPN_DH = re.compile(r"^\s*dh\s+(?!none\b)(\S+)\s*(?:#.*)?$", re.I)


def _row(number: int, line: str, family: str, said: str, **extra: Any) -> dict[str, Any]:
    return {"line": number, "algorithm": family, "excerpt": line.strip()[:200],
            "evidence_kind": "declaration", "description": said, **extra}


def scan(file_name: str, lines: list[str]) -> list[dict[str, Any]]:
    """Rows for the settings above, by the file they can appear in."""
    out: list[dict[str, Any]] = []
    lower = file_name.lower()
    openvpn = (lower.endswith(".ovpn")
               or (lower.endswith(".conf") and bool(_OPENVPN_FILE.search("\n".join(lines)))))
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith(("#", ";")):
            continue
        if file_name == "Caddyfile" or lower.endswith(".caddyfile"):
            match = _CADDY_KEY_TYPE.match(line)
            if match:
                family, size, curve = _CADDY_KEYS[match.group(1)]
                extra = {k: v for k, v in (("key_size", size), ("curve", curve)) if v}
                out.append(_row(number, line, family,
                                f"Caddy key_type {match.group(1)}: the certificate's key "
                                f"({family}, signature)", **extra))
        if lower.endswith(".conf") and _PG_PASSWORD.match(line):
            out.append(_row(number, line, "MD5", "PostgreSQL password_encryption = md5: "
                            "passwords are stored as an MD5 hash (deprecated by PostgreSQL)"))
        if lower == "pg_hba.conf" and _PG_HBA.match(line):
            out.append(_row(number, line, "MD5", "PostgreSQL pg_hba.conf md5 method: "
                            "SCRAM-SHA-256 or MD5 password authentication (MD5 deprecated "
                            "by PostgreSQL)"))
        if openvpn:
            auth = _OPENVPN_AUTH.match(line)
            if auth:
                family = auth.group(1).upper()
                out.append(_row(number, line, family, f"OpenVPN auth {family}: the data "
                                f"channel's HMAC digest"))
            dh = _OPENVPN_DH.match(line)
            if dh:
                out.append(_row(number, line, "DH", f"OpenVPN dh {dh.group(1)}: finite-field "
                                f"Diffie-Hellman for the TLS control channel; the parameter "
                                f"file's size is not in this configuration"))
    return out
