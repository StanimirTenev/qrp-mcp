"""IKEv2 fragmentation, named where an IKE configuration carries a post-quantum algorithm.

Until this release an ML-KEM proposal in swanctl.conf read as post-quantum and nothing
more (Saqib Ahmad, 6 Oct 2026). The algorithm is not the whole configuration:

* RFC 7383 fragments only encrypted messages, so never IKE_SA_INIT;
* RFC 9370 puts additional key exchanges in IKE_INTERMEDIATE "to allow the standard IKE
  fragmentation mechanisms ... to be available for the potentially large Key Exchange
  payloads with post-quantum algorithm data";
* draft-ietf-ipsecme-ikev2-pqc-auth-12, 3.2.1: peers using PQ authentication "MUST
  support IKEv2 message fragmentation".

So the setting is named -- enabled, disabled, or not found in the files read -- with the
default each product documents. A configuration file almost never carries the product
version, so a default is said as documented for a version, never as what this box does.
Cisco's is not said at all: IOS XE and ASA document opposite defaults (read only through
an extraction, not grep-checked), and the platform is not established from the file.
Keys and defaults: strongSwan swanctl.conf/ipsec.conf docs (6.1, 5.9.14), Libreswan 5.4
fragmentation.xml, FortiOS 7.6.6 CLI reference, the Junos VPN guide of 8 Sep 2026,
OpenBSD iked.conf(5). Libreswan `ike-frag` and FortiOS `ike-fragmentation` do not exist.
"""

from __future__ import annotations

import re
from typing import Any

WHY = ("draft-ietf-ipsecme-ikev2-pqc-auth-12 makes fragmentation support a MUST for "
       "post-quantum signatures, and RFC 9370 carries additional key exchanges in "
       "IKE_INTERMEDIATE so that they can be fragmented (RFC 7383 cannot fragment "
       "IKE_SA_INIT).")

_CISCO_DEFAULT = ("the default is not confirmed: the IOS XE and ASA documentation give "
                  "opposite defaults (read through an extraction, not checked word for "
                  "word), and the platform is not established from the file")


def _swan(m: re.Match) -> str:
    value = m.group(1).lower()
    return {"yes": "enabled", "no": "disabled"}.get(value, value)


# name, how the file shows it is this product, the fragmentation setting and how to read
# it, the documented default.
PRODUCTS: list[tuple[str, list[re.Pattern], re.Pattern, Any, str | None]] = [
    ("Cisco", [re.compile(r"^\s*crypto\s+ikev2\b", re.M)],
     re.compile(r"^\s*(no\s+)?crypto\s+ikev2\s+fragmentation\b", re.M | re.I),
     lambda m: "disabled" if m.group(1) else "enabled",
     None),
    ("FortiOS", [re.compile(r"^\s*config\s+vpn\s+ipsec\s+phase1-interface\b", re.M)],
     re.compile(r"^\s*set\s+fragmentation\s+(enable|disable)\b", re.M | re.I),
     lambda m: m.group(1).lower() + "d",
     "enable (FortiOS 7.6.6 CLI reference: fragmentation on re-transmission)"),
    ("Junos", [re.compile(r"\bsecurity\s+ike\s+gateway\b", re.M)],
     re.compile(r"^\s*set\s+security\s+ike\s+gateway\s+\S+\s+fragmentation\s+(disable|size)\b",
                re.M | re.I),
     lambda m: "disabled" if m.group(1).lower() == "disable" else "enabled",
     "enabled (Junos VPN guide, 8 Sep 2026)"),
    ("OpenBSD iked", [],          # by file name: iked.conf
     re.compile(r"^\s*set\s+(no)?fragmentation\b", re.M | re.I),
     lambda m: "disabled" if m.group(1) else "enabled",
     "nofragmentation (iked.conf(5), OpenBSD-current)"),
    ("strongSwan", [re.compile(r"^\s*connections\s*\{", re.M),
                    re.compile(r"^\s*proposals\s*=", re.M),
                    re.compile(r"(?<![A-Za-z0-9_])ke[1-7]_[a-z]", re.I),
                    re.compile(r"^\s*charon\s*\{", re.M)],
     re.compile(r"^\s*fragmentation\s*=\s*(\w+)", re.M | re.I), _swan,
     "yes (strongSwan, default since 5.5.1)"),
    ("Libreswan", [re.compile(r"\baddke[1-7]\s*=", re.I),
                   re.compile(r"\bml_kem_\d", re.I),
                   re.compile(r"^\s*intermediate\s*=", re.M)],
     re.compile(r"^\s*fragmentation\s*=\s*(\w+)", re.M | re.I), _swan,
     "yes (Libreswan 5.4)"),
    # ipsec.conf with nothing that tells the two apart. Both document yes.
    ("strongSwan or Libreswan", [re.compile(r"^\s*conn\s+\S+", re.M)],
     re.compile(r"^\s*fragmentation\s*=\s*(\w+)", re.M | re.I), _swan,
     "yes (strongSwan since 5.5.1; Libreswan 5.4)"),
]


def _product(name: str, text: str):
    for product in PRODUCTS:
        if product[0] == "OpenBSD iked":
            if name == "iked.conf":
                return product
            continue
        if any(p.search(text) for p in product[1]):
            return product
    return None


def scan(file_name: str, lines: list[str], post_quantum: dict[str, int]) -> list[dict[str, Any]]:
    """The fragmentation setting of an IKE configuration that carries a post-quantum
    algorithm. `post_quantum` maps each post-quantum family used in the file to the
    first line using it. Nothing when there is none, or no IKE product is recognised."""
    if not post_quantum:
        return []
    text = "\n".join(lines)
    product = _product(file_name, text)
    if product is None:
        return []
    name, _identify, setting, read, default = product
    first = min(post_quantum.values())
    item: dict[str, Any] = {
        "protocol": "ike",
        "version": "IKEv2",
        "product": name,
        "post_quantum": sorted(post_quantum),
        "line": first,
        "excerpt": lines[first - 1].strip()[:200],
        "basis": "configured_protocol",
        "deprecated": False,
    }
    match = setting.search(text)
    if match:
        line_no = text.count("\n", 0, match.start()) + 1
        item["fragmentation"] = read(match)
        item["fragmentation_setting"] = {"line": line_no, "value": match.group(0).strip()
                                         if name in ("Cisco", "Junos", "OpenBSD iked")
                                         else match.group(match.lastindex).strip()}
        said = f"set on line {line_no}: {item['fragmentation']}"
    else:
        item["fragmentation"] = "not_found"
        said = "not set in the files read"
    if default is None:
        item["fragmentation_default"] = "default not confirmed"
        said += f"; {_CISCO_DEFAULT}" if not match else f" ({_CISCO_DEFAULT})"
    else:
        item["fragmentation_default"] = default
        if not match:
            said += f"; the documented default for {name} is {default}"
    item["description"] = (f"IKEv2 configuration ({name}) carrying "
                           f"{', '.join(item['post_quantum'])}. Fragmentation (RFC 7383) is "
                           f"{said}. {WHY}")
    return [item]


# FortiOS names additional key exchanges by number (7.6.6 CLI reference, `set addkeN`).
FORTIOS_ADDKE = re.compile(r"^\s*set\s+addke[1-7]\s+(.+)$", re.I)
FORTIOS_KE_IDS = {
    **{n: "ML-KEM" for n in ("35", "36", "37")},
    **{n: "Kyber" for n in ("1080", "1081", "1082")},
    **{n: "FrodoKEM" for n in ("1083", "1084", "1085")},
    **{n: "BIKE" for n in ("1089", "1090", "1091")},
    **{n: "HQC" for n in ("1092", "1093", "1094")},
}


def fortios_addke(line: str) -> list[tuple[str, int]]:
    """Families a FortiOS `set addkeN <ids>` line names, with their positions."""
    match = FORTIOS_ADDKE.match(line)
    if not match:
        return []
    return [(FORTIOS_KE_IDS[m.group(0)], match.start(1) + m.start())
            for m in re.finditer(r"\d+", match.group(1)) if m.group(0) in FORTIOS_KE_IDS]
