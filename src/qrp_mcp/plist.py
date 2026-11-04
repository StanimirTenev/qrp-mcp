"""Apple property lists (`.plist`, ZA-OPRAVYANE row 306): App Transport Security settings and
keys or certificates stored as base64 strings or data.

Apple's documentation (the JSON its pages load, read 04.11.2026):
* NSAppTransportSecurity, https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity
  -- "ATS requires that all HTTP connections made with the URL Loading System ... use HTTPS".
* NSAllowsArbitraryLoads, .../nsapptransportsecurity/nsallowsarbitraryloads -- "A Boolean value
  indicating whether App Transport Security restrictions are disabled for all network
  connections."; "Disabling ATS means that unsecured HTTP connections are allowed."
* NSExceptionMinimumTLSVersion, .../information-property-list/nsexceptionminimumtlsversion --
  "The minimum Transport Layer Security (TLS) version for network connections." "Require a
  minimum TLS version of 1.0." ... "The value is a string, with a default value of TLSv1.2."

XML and binary plists are both read with the standard library's plistlib. A value that
decodes as a DER key or certificate is reported with its family and size; anything else is
left as text.
"""

from __future__ import annotations

import base64
import plistlib
import re
from typing import Any

from .certificates import _key_info

_TLS_VERSION = re.compile(r"^TLSv1\.([0-3])$")


def _line_of(lines: list[str], needle: str) -> int:
    return next((n for n, text in enumerate(lines, 1) if needle in text), 1)


def _der(value: bytes) -> tuple[dict[str, Any], str] | None:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    for load, kind in ((lambda b: serialization.load_der_private_key(b, None), "private key"),
                       (serialization.load_der_public_key, "public key"),
                       (lambda b: x509.load_der_x509_certificate(b).public_key(), "certificate")):
        try:
            info = _key_info(load(value))
        except Exception:  # noqa: BLE001 -- not that kind of DER
            continue
        if info:
            return info, kind
    return None


def _walk(node: Any, path: tuple[str, ...]):
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _walk(value, path + (str(key),))
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value, path)
    else:
        yield path, node


def scan(rel_path: str, raw: bytes, lines: list[str]) -> dict[str, list[dict[str, Any]]] | None:
    """{"source", "keys", "protocols"} of one plist; None when it does not parse."""
    try:
        data = plistlib.loads(raw)
    except Exception:  # noqa: BLE001 -- not a plist
        return None
    out: dict[str, list[dict[str, Any]]] = {"source": [], "keys": [], "protocols": []}
    for path, value in _walk(data, ()):
        name = path[-1] if path else ""
        in_ats = "NSAppTransportSecurity" in path
        if in_ats and name == "NSAllowsArbitraryLoads" and value is True:
            number = _line_of(lines, name)
            out["protocols"].append({
                "path": rel_path, "line": number, "excerpt": lines[number - 1].strip()[:200]
                if lines else name, "protocol": "tls", "version": None,
                "basis": "configured_switch", "setting": "NSAllowsArbitraryLoads",
                "tls_disabled": True, "deprecated": False,
                "description": ("App Transport Security is disabled for every domain not "
                                "listed (NSAllowsArbitraryLoads true): \"Disabling ATS means "
                                "that unsecured HTTP connections are allowed\", and the "
                                "minimum TLS version check is off.")})
        elif in_ats and name.endswith("MinimumTLSVersion") and isinstance(value, str):
            match = _TLS_VERSION.match(value)
            if match:
                number = _line_of(lines, value) if lines else 1
                version = f"TLSv1.{match.group(1)}"
                out["protocols"].append({
                    "path": rel_path, "line": number, "excerpt": f"{name} {value}",
                    "protocol": "tls", "version": version, "banned": False,
                    "basis": "configured_protocol", "deprecated": match.group(1) in "01",
                    "description": (f"{version} is the minimum ATS allows for "
                                    f"{path[-2] if len(path) > 1 else 'these domains'} "
                                    f"({name}; Apple's default is TLSv1.2).")})
        elif isinstance(value, (bytes, str)):
            blob = value
            if isinstance(value, str):
                if len(value) < 64:
                    continue
                try:
                    blob = base64.b64decode("".join(value.split()), validate=True)
                except (ValueError, TypeError):
                    continue
            found = _der(blob) if blob[:1] == b"\x30" else None
            if found is None:
                continue
            info, kind = found
            family = info["algorithm"]
            number = _line_of(lines, f"<key>{name}</key>") if lines else 1
            row = {"path": rel_path, "line": number, "algorithm": family,
                   "evidence_kind": "declaration", "excerpt": f"<key>{name}</key>",
                   "description": (f"{info['algorithm']} {kind} stored in a property list "
                                   f"(DER under `{name}`)")}
            if info.get("size"):
                row["key_size"] = info["size"]
            if info.get("curve"):
                row["curve"] = info["curve"]
            out["source"].append(row)
            if kind == "private key":
                out["keys"].append({"path": rel_path, "line": number,
                                    "type": "private key in a property list",
                                    "description": f"private key material under `{name}`",
                                    "key_algorithm": info["algorithm"],
                                    **({"key_size": info["size"]} if info.get("size") else {})})
    return out
