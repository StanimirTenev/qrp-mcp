"""DNSSEC: the algorithm a zone is signed with, and the size budget of its answers.

Raised in public on 22.10.2026 (Georgi Ivanov, post-quantum DNSSEC; ZA-OPRAVYANE row 33).
A BIND `dnssec-policy` with `rsasha256`, `dnssec-keygen -a RSASHA256` and the DNSKEY
records of a signed zone gave nothing: the RSA half of the zone was invisible, and the
ECDSA half was found only because its mnemonic contains the letters ECDSA.

Algorithm numbers and mnemonics are IANA's "Domain Name System Security (DNSSEC)
Algorithm Numbers" registry (read 22.10.2026). The mnemonics are matched in
`detectors.ALGORITHM_PATTERNS`; the numbers here, and only in the shape of a record --
`DNSKEY flags 3 alg`, `DS tag alg digest-type digest`, `RRSIG type alg` and BIND's
trust-anchor `static-key`/`initial-key`/`static-ds`/`initial-ds` -- because a bare 8 is a
number, not RSA. ECC-GOST (12) and ECC-GOST12 (23) were left unnamed until GOST R 34.10
had a family (ZA-OPRAVYANE rows 139 and 141).

The size budget: `max-udp-size` is the largest UDP response BIND sends and
`edns-udp-size` the buffer it advertises for responses it receives. Both default to
1232 (BIND 9 ARM, `max-udp-size`, `edns-udp-size`), so a signed BIND configuration that
names neither still has a budget, and it is stated as the default.
"""

from __future__ import annotations

import re
from typing import Any

from .assets import names_none_of

# number -> (IANA mnemonic, family, curve or None)
ALGORITHMS: dict[int, tuple[str, str, str | None]] = {
    1: ("RSAMD5", "RSA", None),
    2: ("DH", "DH", None),
    3: ("DSA", "DSA", None),
    5: ("RSASHA1", "RSA", None),
    6: ("DSA-NSEC3-SHA1", "DSA", None),
    7: ("RSASHA1-NSEC3-SHA1", "RSA", None),
    8: ("RSASHA256", "RSA", None),
    10: ("RSASHA512", "RSA", None),
    13: ("ECDSAP256SHA256", "ECDSA", "P-256"),
    14: ("ECDSAP384SHA384", "ECDSA", "P-384"),
    15: ("ED25519", "Ed25519", None),
    16: ("ED448", "Ed448", None),
    17: ("SM2SM3", "SM2", None),
    18: ("MLDSA44", "ML-DSA", None),
    # GOST R 34.10 has a family since ZA-OPRAVYANE row 139; named from row 141.
    12: ("ECC-GOST", "GOST R 34.10", None),
    23: ("ECC-GOST12", "GOST R 34.10", None),
}

_RECORDS = re.compile(
    r"(?<![A-Za-z0-9-])(?:"
    r"(?P<kt>C?DNSKEY|(?:static|initial)-key)\s+\d{1,5}\s+3\s+(?P<ka>\d{1,3})\s|"
    r"(?P<dt>C?DS|(?:static|initial)-ds)\s+\d{1,5}\s+(?P<da>\d{1,3})\s+\d{1,3}\s+[\"']?[0-9A-Fa-f]{20}|"
    r"(?P<rt>RRSIG)\s+[A-Z][A-Z0-9]*\s+(?P<ra>\d{1,3})\s+\d{1,3}\s"
    r")")
# One of these is in every match of _RECORDS, in some case (release D).
_RECORD_WORDS = ("dnskey", "-key", "ds", "rrsig")


# Numbers this scanner gives no family, with IANA's mnemonic where the registry has one
# (iana-dnssec.csv, read 23.10.2026). Until 0.35.0 a record with such a number was dropped
# without a word -- a zone signed with 253 (PRIVATEDNS) read as if it had no key at all
# (ZA-OPRAVYANE row 102, Georgi Ivanov's post-quantum DNSSEC experiments). Now it is named
# as a number this scan does not name, never given a family.
UNNAMED_MNEMONICS: dict[int, str] = {
    0: "DELETE", 252: "INDIRECT", 253: "PRIVATEDNS",
    254: "PRIVATEOID",
}


def unnamed_records(line: str) -> list[dict[str, Any]]:
    """A DNSKEY, DS or RRSIG record whose algorithm number has no family here, as a
    protocol asset that says so."""
    out: list[dict[str, Any]] = []
    if names_none_of(line, _RECORD_WORDS):
        return out
    for m in _RECORDS.finditer(line):
        rtype = m.group("kt") or m.group("dt") or m.group("rt")
        number = int(m.group("ka") or m.group("da") or m.group("ra"))
        if number in ALGORITHMS:
            continue
        mnemonic = UNNAMED_MNEMONICS.get(number)
        out.append({
            "protocol": "dns", "version": None, "dnssec_algorithm": number,
            "dnssec_mnemonic": mnemonic, "basis": "unnamed_algorithm_number",
            "deprecated": False,
            "description": (f"DNSSEC algorithm {number}"
                            f"{f' ({mnemonic})' if mnemonic else ' (unassigned or reserved)'} "
                            f"in a {rtype} record: a number this scan does not give a family. "
                            f"What signs with it is not determined here."),
        })
    return out


def scan_records(line: str) -> list[tuple[str, int, str, str | None]]:
    """(family, position, description, curve) for each DNSSEC algorithm number this line
    gives in a record."""
    out = []
    if names_none_of(line, _RECORD_WORDS):
        return out
    for m in _RECORDS.finditer(line):
        rtype = m.group("kt") or m.group("dt") or m.group("rt")
        number = int(m.group("ka") or m.group("da") or m.group("ra"))
        known = ALGORITHMS.get(number)
        if known is None:
            continue
        mnemonic, family, curve = known
        out.append((family, m.start(),
                    f"{family} named by DNSSEC algorithm {number} ({mnemonic}) in a "
                    f"{rtype} record", curve))
    return out


_UDP_SIZE = re.compile(r"^\s*(max-udp-size|edns-udp-size)\s+(\d{3,5})\s*;")
_BIND_SIGNING = re.compile(r"^\s*dnssec-policy\s+\S")
BIND_UDP_DEFAULT = 1232

_SAID = {
    "max-udp-size": "the largest UDP response this server sends",
    "edns-udp-size": "the EDNS buffer this server advertises for the responses it receives",
}


def udp_sizes(lines: list[str]) -> list[dict[str, Any]]:
    """The DNS UDP size budget a BIND configuration sets, as protocol assets; and BIND's
    default where the file signs zones and does not set the response size."""
    out: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        m = _UDP_SIZE.match(line)
        if m:
            setting, size = m.group(1), int(m.group(2))
            out.append({
                "protocol": "dns", "version": None, "udp_setting": setting,
                "udp_size": size, "basis": "configured_protocol", "deprecated": False,
                "line": number, "excerpt": line.strip()[:200],
                "description": (f"{setting} {size}: {_SAID[setting]}, in bytes. A DNSSEC "
                                f"answer larger than this goes over TCP or is truncated."),
            })
    signing = next((n for n, line in enumerate(lines, 1) if _BIND_SIGNING.match(line)), None)
    if signing and not any(a["udp_setting"] == "max-udp-size" for a in out):
        out.append({
            "protocol": "dns", "version": None, "udp_setting": "max-udp-size",
            "udp_size": BIND_UDP_DEFAULT, "default_applied": True,
            "basis": "configured_protocol", "deprecated": False,
            "line": signing, "excerpt": lines[signing - 1].strip()[:200],
            "description": (f"max-udp-size is not set, and BIND's default is "
                            f"{BIND_UDP_DEFAULT} bytes (BIND 9 ARM): the largest UDP "
                            f"response this server sends for the zones it signs."),
        })
    return out
