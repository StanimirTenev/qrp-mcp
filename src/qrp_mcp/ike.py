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


# IKE key exchange groups named by number (ZA-OPRAVYANE rows 225, 334). The number is the
# IANA "Transform Type 4 - Key Exchange Method Transform IDs" value
# (https://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml, read 04.11.2026):
# "2 | 1024-bit MODP Group", "14 | 2048-bit MODP Group", "19 | 256-bit random ECP group", ...
# Only where a vendor setting says the number is that registry's: FortiOS `set dhgrp`
# (7.6.4 CLI reference, config vpn ipsec phase1-interface: "dhgrp DH group", options 1, 2,
# 5, 14-21, 27-32), Cisco IOS XE `group` in a `crypto ikev2 proposal` ("2 --1024-bit DH (No
# longer recommended).", "14 --Specifies the 2048-bit DH group.", "19 --Specifies the
# 256-bit elliptic curve DH (ECDH) group.", IOS XE 17 IKEv2 guide), Junos `dh-group groupN`
# and `perfect-forward-secrecy keys groupN` ("group14: Specifies that IKE uses the 2048-bit
# Diffie-Hellman prime modulus group", Junos dynamic security associations). GOST (33, 34)
# and ML-KEM (35-37, FortiOS names those in `addke`, above) are not read here.
IKE_GROUPS: dict[int, tuple[str, str, int | None, str | None]] = {
    1: ("DH", "768-bit MODP Group", 768, None),
    2: ("DH", "1024-bit MODP Group", 1024, None),
    5: ("DH", "1536-bit MODP Group", 1536, None),
    14: ("DH", "2048-bit MODP Group", 2048, None),
    15: ("DH", "3072-bit MODP Group", 3072, None),
    16: ("DH", "4096-bit MODP Group", 4096, None),
    17: ("DH", "6144-bit MODP Group", 6144, None),
    18: ("DH", "8192-bit MODP Group", 8192, None),
    19: ("ECDH", "256-bit random ECP group", 256, "P-256"),
    20: ("ECDH", "384-bit random ECP group", 384, "P-384"),
    21: ("ECDH", "521-bit random ECP group", 521, "P-521"),
    22: ("DH", "1024-bit MODP Group with 160-bit Prime Order Subgroup", 1024, None),
    23: ("DH", "2048-bit MODP Group with 224-bit Prime Order Subgroup", 2048, None),
    24: ("DH", "2048-bit MODP Group with 256-bit Prime Order Subgroup", 2048, None),
    25: ("ECDH", "192-bit Random ECP Group", 192, "P-192"),
    26: ("ECDH", "224-bit Random ECP Group", 224, "P-224"),
    27: ("ECDH", "brainpoolP224r1", 224, "brainpoolP224r1"),
    28: ("ECDH", "brainpoolP256r1", 256, "brainpoolP256r1"),
    29: ("ECDH", "brainpoolP384r1", 384, "brainpoolP384r1"),
    30: ("ECDH", "brainpoolP512r1", 512, "brainpoolP512r1"),
    31: ("X25519", "Curve25519", None, None),
    32: ("X448", "Curve448", None, None),
}

_FORTIOS_DHGRP = re.compile(r"^\s*set\s+dhgrp\s+(\d+(?:\s+\d+)*)\s*$", re.I)
_JUNOS_GROUP = re.compile(r"(?:\bdh-group\s+|\bperfect-forward-secrecy\s+keys\s+|^\s*keys\s+)"
                          r"group(\d+)\s*;?\s*$", re.I)
_CISCO_PROPOSAL = re.compile(r"^crypto\s+ikev2\s+proposal\b", re.I)
_CISCO_GROUP = re.compile(r"^\s+group\s+(\d+(?:\s+\d+)*)\s*$", re.I)


def scan_groups(lines: list[str]) -> list[dict[str, Any]]:
    """IKE key exchange groups a FortiOS, Cisco IOS XE or Junos configuration names by
    number, one row per group, with the size the registry gives it."""
    out: list[dict[str, Any]] = []
    in_cisco_proposal = False
    for number, line in enumerate(lines, 1):
        if line[:1] and not line[:1].isspace():
            in_cisco_proposal = bool(_CISCO_PROPOSAL.match(line))
        if line.lstrip().startswith(("#", "!")):
            continue
        found = None
        for product, setting, pattern in (("FortiOS", "set dhgrp", _FORTIOS_DHGRP),
                                          ("Junos", "dh-group", _JUNOS_GROUP)):
            match = pattern.search(line)
            if match:
                found = product, setting, match
                break
        if found is None and in_cisco_proposal:
            match = _CISCO_GROUP.match(line)
            if match:
                found = "Cisco IOS XE", "crypto ikev2 proposal ... group", match
        if found is None:
            continue
        product, setting, match = found
        for m in re.finditer(r"\d+", match.group(1)):
            group = IKE_GROUPS.get(int(m.group(0)))
            if group is None:
                continue
            family, name, size, curve = group
            item: dict[str, Any] = {
                "line": number, "algorithm": family, "ike_group": int(m.group(0)),
                "description": (f"IKE key exchange group {m.group(0)} ({name}, IANA IKEv2 "
                                f"Transform Type 4), named by {product} `{setting}`"),
                "excerpt": line.strip()[:200], "evidence_kind": "declaration",
            }
            if size:
                item["key_size"] = size
            if curve:
                item["curve"] = curve
            out.append(item)
    return out


# IKE peer authentication by signature (ZA-OPRAVYANE row 342). Cisco IOS XE 17 IKEv2 guide
# (https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-cfg-ikev2-flex.html):
# "authentication remote rsa-sig", "pki trustpoint trustpoint-remote verify". Junos
# `proposal (Security IKE)`
# (https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-proposal.html):
# authentication-method `dsa-signatures` "Specifies that the Digital Signature Algorithm (DSA)
# is used", `ecdsa-signatures-384` "the ECDSA using the 384-bit elliptic curve secp384r1",
# `rsa-signatures` "a public key algorithm, which supports encryption and digital signatures".
_JUNOS_AUTH = re.compile(r"\bauthentication-method\s+(rsa|dsa|ecdsa)-signatures(?:-(256|384|521))?"
                         r"\s*;?\s*$", re.I)
_CISCO_PROFILE = re.compile(r"^crypto\s+ikev2\s+profile\b", re.I)
_CISCO_AUTH = re.compile(r"^\s+authentication\s+(?:remote|local)\s+rsa-sig\s*$", re.I)
_AUTH_FAMILY = {"rsa": "RSA", "dsa": "DSA", "ecdsa": "ECDSA"}


def scan_auth(lines: list[str]) -> list[dict[str, Any]]:
    """IKE peer authentication methods that sign with a named family (Cisco IOS XE, Junos)."""
    out: list[dict[str, Any]] = []
    in_profile = False
    for number, line in enumerate(lines, 1):
        if line[:1] and not line[:1].isspace():
            in_profile = bool(_CISCO_PROFILE.match(line))
        if line.lstrip().startswith(("#", "!")):
            continue
        junos = _JUNOS_AUTH.search(line)
        if junos:
            family, size = _AUTH_FAMILY[junos.group(1).lower()], junos.group(2)
            setting = f"Junos authentication-method {junos.group(0).split()[-1].rstrip(';')}"
        elif in_profile and _CISCO_AUTH.match(line):
            family, size, setting = "RSA", None, "Cisco IOS XE IKEv2 profile authentication rsa-sig"
        else:
            continue
        item: dict[str, Any] = {
            "line": number, "algorithm": family, "excerpt": line.strip()[:200],
            "evidence_kind": "declaration",
            "description": f"IKE peer authentication by {family} signature ({setting})",
        }
        if size:
            item["key_size"], item["curve"] = int(size), f"P-{size}"
        out.append(item)
    return out
