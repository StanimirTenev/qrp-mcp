"""FortiOS firmware defaults for settings a configuration backup leaves out (ZA-OPRAVYANE
row 228).

A FortiOS backup holds only what differs from the default: "the "full-config" will also
include all default values within the saved file" (Fortinet technical tip, "Differences
between FortiGate CLI commands 'execute backup config' and 'execute backup full-config'",
https://community.fortinet.com/fortigate-3/technical-tip-differences-between-fortigate-cli-commands-execute-backup-config-and-execute-backup-full-config-98533).
So a setting absent from a section the backup does carry is that firmware's default, and
the scan said nothing about it.

Every default below is quoted from the FortiOS 7.6.4 CLI reference, and only those. A
default the reference marks "** Values may differ between models." is not applied: it is
named as not evaluated. Every other setting the backup omits is not evaluated either, and
the scan says so once per file. The backup's own firmware version (`#config-version=`) is
read and stated beside the documentation's; a default is said as documented for 7.6.4,
never as what this device runs.
"""

from __future__ import annotations

import re
from typing import Any

DOC_VERSION = "7.6.4"
_GLOBAL = ("https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/339914554/"
           "config-system-global")
_SSL_VPN = ("https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/114404382/"
            "config-vpn-ssl-settings")
_PHASE1 = ("https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/305883427/"
           "config-vpn-ipsec-phase1-interface")

# (section, per `edit` entry, setting, default, documented as, source, differs by model)
DEFAULTS: list[tuple[str, bool, str, str, str, str, bool]] = [
    ("system global", False, "ssl-static-key-ciphers", "enable",
     "Enable/disable static key ciphers in SSL/TLS connections (e.g. AES128-SHA, AES256-SHA, "
     "AES128-SHA256, AES256-SHA256). Default: enable", _GLOBAL, False),
    ("system global", False, "strong-crypto", "enable",
     "Enable to use strong encryption and only allow strong ciphers and digest for "
     "HTTPS/SSH/TLS/SSL functions. Default: enable **", _GLOBAL, True),
    ("system global", False, "ssl-min-proto-version", "TLSv1-2",
     "Minimum supported protocol version for SSL/TLS connections (default = TLSv1.2). "
     "Default: TLSv1-2 **", _GLOBAL, True),
    ("system global", False, "admin-https-ssl-versions", "tlsv1-2 tlsv1-3",
     "Allowed TLS versions for web administration. Default: tlsv1-2 tlsv1-3 **", _GLOBAL, True),
    ("vpn ssl settings", False, "ssl-min-proto-ver", "tls1-2",
     "SSL minimum protocol version. Default: tls1-2", _SSL_VPN, False),
    ("vpn ssl settings", False, "ssl-max-proto-ver", "tls1-3",
     "SSL maximum protocol version. Default: tls1-3", _SSL_VPN, False),
    ("vpn ipsec phase1-interface", True, "dhgrp", "14",
     "DH group. Default: 14", _PHASE1, False),
]

_SIGNATURE = re.compile(r"^#config-version=([\w-]+?)-(\d+\.\d+\.\d+)-FW")
_CONFIG = re.compile(r"^\s*config\s+(.+?)\s*$")
_EDIT = re.compile(r"^\s*edit\s+(.+?)\s*$")
_SET = re.compile(r"^\s*set\s+([\w-]+)\b")


def firmware(lines: list[str]) -> tuple[str, str] | None:
    """(model, firmware version) from a FortiOS backup's first line; None for any other file."""
    match = _SIGNATURE.match(lines[0]) if lines else None
    return (match.group(1), match.group(2)) if match else None


def _blocks(lines: list[str]) -> list[tuple[str, int, set[str]]]:
    """(section, line of its `config`/`edit`, settings set there) for each section and each
    `edit` entry of one. A multi-VDOM backup wraps sections in `config global` ... `end` and
    `config vdom` / `edit <vdom>` ... `end`: those wrappers are seen through. A `config`
    nested inside an entry is not that entry's settings."""
    out: list[tuple[str, int, set[str]]] = []
    stack: list[tuple[str, int, set[str]]] = []          # name "" = nested, "^..." = wrapper

    def depth() -> int:
        return sum(1 for name, _, _ in stack if not name.startswith("^"))

    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        config = _CONFIG.match(line)
        if config:
            name = config.group(1).lower()
            if depth() == 0 and name in ("global", "vdom") and not stack:
                stack.append(("^" + name, number, set()))
            else:
                stack.append((name if depth() == 0 else "", number, set()))
            continue
        edit = _EDIT.match(line)
        if edit and stack:
            if stack[-1][0] == "^vdom":
                stack.append(("^vdom-edit", number, set()))
            else:
                top = [b for b in stack if not b[0].startswith("^")]
                named = len(top) == 1 and top[0][0]
                stack.append((top[0][0] + " edit" if named else "", number, set()))
            continue
        if stripped in ("next", "end") and stack:
            block = stack.pop()
            if block[0] and not block[0].startswith("^"):
                out.append(block)
            if (stripped == "end" and block[0] == "^vdom-edit" and stack
                    and stack[-1][0] == "^vdom"):
                stack.pop()
            continue
        setting = _SET.match(line)
        if setting and stack:
            stack[-1][2].add(setting.group(1).lower())
    return out


def defaults(lines: list[str]) -> dict[str, list[dict[str, Any]]] | None:
    """What a FortiOS backup's omitted settings default to, by where it goes in the result:
    `source` (DH group rows), `protocols` (TLS versions and the file's note), `static_rsa`.
    None for a file that is not a FortiOS backup."""
    found = firmware(lines)
    if found is None:
        return None
    model, version = found
    out: dict[str, list[dict[str, Any]]] = {"source": [], "protocols": [], "static_rsa": []}
    applied: list[str] = []
    not_evaluated: list[str] = []
    for section, number, settings in _blocks(lines):
        per_entry = section.endswith(" edit")
        base = section[:-5] if per_entry else section
        for where, entry, setting, default, quote, url, by_model in DEFAULTS:
            if where != base or entry != per_entry or setting in settings:
                continue
            if by_model:
                not_evaluated.append(f"{setting} (config {base}: the CLI reference says its "
                                     f"default values may differ between models)")
                continue
            said = (f"`{setting}` is not in this backup, so it takes the firmware default: "
                    f"{default}, as the FortiOS {DOC_VERSION} CLI reference documents it "
                    f"(\"{quote}\", {url}). The backup is from {model} {version}; whether "
                    f"that firmware has the same default is not established from the file.")
            excerpt = lines[number - 1].strip()[:200]
            common = {"line": number, "excerpt": excerpt, "basis": "firmware_default",
                      "default_setting": setting, "default_value": default}
            applied.append(f"{setting} = {default} (line {number})")
            if setting == "dhgrp":
                out["source"].append({**common, "algorithm": "DH", "key_size": 2048,
                                      "ike_group": 14, "evidence_kind": "default",
                                      "description": "IKE key exchange group 14 (2048-bit "
                                                     "MODP Group, IANA IKEv2 Transform Type "
                                                     "4) by default. " + said})
            elif setting == "ssl-static-key-ciphers":
                out["static_rsa"].append({**common, "family": "RSA", "key_exchange": "RSA",
                                          "suites": [], "setting": setting,
                                          "description": "Static RSA key exchange suites "
                                                         "allowed by default. " + said})
            else:
                minor = default[-1]
                out["protocols"].append({**common, "protocol": "tls",
                                         "version": f"TLSv1.{minor}", "banned": False,
                                         "deprecated": minor in "01", "description": said})
    out["protocols"].append({
        "protocol": "fortios", "version": None, "line": 1, "excerpt": lines[0].strip()[:200],
        "basis": "firmware_defaults", "firmware": f"{model} {version}",
        "defaults_documented_for": f"FortiOS {DOC_VERSION}",
        "defaults_applied": applied, "defaults_not_evaluated": not_evaluated,
        "deprecated": False,
        "description": (f"A FortiOS backup ({model} {version}) leaves out every setting at "
                        f"its default. Applied here, from the FortiOS {DOC_VERSION} CLI "
                        f"reference: {', '.join(applied) or 'none'}. Defaults not evaluated: "
                        + "; ".join(not_evaluated + ["every other setting this backup omits"])
                        + "."),
    })
    return out
