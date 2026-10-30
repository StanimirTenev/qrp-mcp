"""`--mandate cnsa-2.0|nist-ir-8547`: the dated clause that applies to each occurrence.

Built on the profiles: CNSA 2.0 is the `us-cnsa2` profile's document set, and its dated
clauses live beside its replacements in `profiles.PROFILES["us-cnsa2"]["mandate"]`; NIST IR
8547 is `profiles.NIST_IR_8547`. The sources, quoted, are in the comments there.

Each quantum-vulnerable occurrence in `evidence` gets `mandates.<name>`: the clause, its
source with section, the deadline, a status as of a date, and months until it. Every such
occurrence also gets `hndl_exposed`: true where it establishes keys (false for a signature,
"not determined" for RSA or EC whose line shows no role), which is the exposure
"harvest now, decrypt later" names (IR 8547, section 4.1.2) -- a signature cannot be
forged retroactively, a recorded key exchange can be decrypted later.

The classical half of a hybrid group (`X25519MLKEM768`) on the line that names the hybrid is
not dated as a bare X25519: IR 8547 section 3.2.1 allows the composite even when one input
comes from a disallowed algorithm (rows 170, 177). Its clause says so (`composite_allowed`)
and it is not HNDL-exposed. A classical group offered on its own in the same list
(`X25519MLKEM768:X25519`) is its own `tls_groups` row and keeps its dates.

The gate: `lead_months` given, the run fails when any occurrence's deadline falls within that
many months of the date; a deadline already passed fails without it. The deadline the gate
counts is the clause's `deadline` -- the disallowance for NIST IR 8547 -- and the block says so
(`gate_counts`, `next_gate_deadline`) beside `next_deadline`, the earliest date of any clause,
a deprecation included (row 160: the two disagreed and nothing said which the gate used). An occurrence the owner
suppressed is not in `evidence` and does not count; one in the baseline is listed and does not
trip it either -- a baseline is the owner's statement that it is known. Comments and bans are
not uses and get no clause; nor do identifier rows, which never move the headline either.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from . import profiles
from .classifier import known_algorithms

MANDATES: dict[str, dict[str, Any]] = {
    "cnsa-2.0": profiles.PROFILES["us-cnsa2"]["mandate"],
    "nist-ir-8547": profiles.NIST_IR_8547,
}

# Evidence categories that are key establishment by what they are.
_KEY_ESTABLISHMENT = {"tls_groups", "ssh_kex", "static_rsa_kex"}
_NOT_USE = {"comment", "ban", "named_but_not_used", "identifier"}
_NETWORKING = re.compile(r"ipsec|swanctl|strongswan|libreswan|openswan|racoon|openvpn|"
                         r"wireguard|vpn", re.IGNORECASE)
_WEB = re.compile(r"nginx|apache|httpd|haproxy|caddy|envoy|traefik|lighttpd|tomcat|"
                  r"(^|/)ssl\.conf$", re.IGNORECASE)
# A NIST prime curve named on the line, for the strength of an EC occurrence.
_CURVE = re.compile(r"(?:P-?|secp|prime|nistp)(224|256|384|521)", re.IGNORECASE)
_EDDSA = {"EdDSA", "Ed25519", "Ed448"}
_EC_SIGNATURE = {"ECDSA"}
_EC_AGREEMENT = {"ECDH", "X25519", "X448"}
# Curves named by the algorithm itself (RFC 7748): X25519 is f = 255, X448 f = 448.
_NAMED_CURVE_STRENGTH = {"X25519": "128 bits or more", "X448": "128 bits or more"}


def _add_months(day: date, months: int) -> date:
    y, m = divmod(day.month - 1 + months, 12)
    year, month = day.year + y, m + 1
    for d in (day.day, 30, 29, 28):
        try:
            return date(year, month, d)
        except ValueError:
            continue
    raise ValueError(day)


def _months_until(day: date, deadline: date) -> int:
    months = (deadline.year - day.year) * 12 + deadline.month - day.month
    return months - 1 if deadline.day < day.day else months


def _family(category: str, item: dict[str, Any]) -> str | None:
    if item.get("algorithm"):
        return str(item["algorithm"])
    if item.get("family"):
        return str(item["family"])
    if category == "embedded_keys" and item.get("type"):
        return str(item["type"]).split()[0]
    return None


def _role(category: str, item: dict[str, Any], family: str, kinds: dict[str, str]) -> str:
    if category in _KEY_ESTABLISHMENT:
        return "key_establishment"
    kind = kinds.get(family)
    if kind == "key_exchange" or item.get("role") == "key_establishment":
        return "key_establishment"
    if kind == "signature" or item.get("role") == "signature":
        return "signature"
    return "undetermined"


def _strength(family: str, item: dict[str, Any]) -> str:
    """Security strength by SP 800-57 Part 1 Rev. 5, Table 2 (see profiles.NIST_IR_8547)."""
    if family in _EDDSA:
        return "128 bits or more"
    if family in _NAMED_CURVE_STRENGTH:
        return _NAMED_CURVE_STRENGTH[family]
    size = item.get("key_size")
    if family in ("RSA", "DH") and isinstance(size, int):
        return "below 112 bits" if size < 2048 else "112 bits" if size < 3072 else \
            "128 bits or more"
    if family in ("EC", "ECDSA", "ECDH"):
        found = _CURVE.search(f"{item.get('curve') or ''} {item.get('excerpt') or ''}")
        if found:
            return "112 bits" if found.group(1) == "224" else "128 bits or more"
    return "not determined"


def _nist_row(family: str, role: str) -> str | None:
    """The row of Table 2 or Table 4 the family sits in; None where neither lists it."""
    if family in _EDDSA:
        return "EdDSA [FIPS186]" if role != "key_establishment" else None
    if family in _EC_SIGNATURE:
        return "ECDSA [FIPS186]"
    if family in _EC_AGREEMENT:
        return "Elliptic Curve DH and MQV [SP80056A]"
    if family == "DH":
        return "Finite Field DH and MQV [SP80056A]"
    if family == "EC":
        return {"signature": "ECDSA [FIPS186]",
                "key_establishment": "Elliptic Curve DH and MQV [SP80056A]"}.get(
                    role, "ECDSA [FIPS186] or Elliptic Curve DH [SP80056A] (role not determined)")
    if family == "RSA":
        return {"signature": "RSA [FIPS186]", "key_establishment": "RSA [SP80056B]"}.get(
            role, "RSA [FIPS186 or SP80056B] (role not determined)")
    return None


def _nist(item: dict[str, Any], family: str, role: str, day: date) -> dict[str, Any] | None:
    m = MANDATES["nist-ir-8547"]
    row = _nist_row(family, role)
    if row is None:
        return None
    strength = _strength(family, item)
    table = m["tables"]["key_establishment" if role == "key_establishment" else "signature"]
    if role == "undetermined":
        table = f"{m['tables']['signature']}, or {m['tables']['key_establishment']}"
    out: dict[str, Any] = {"clause": f"{row} at {strength} of security strength",
                           "source": f"{m['document']}, {table}", "strength": strength}
    # The final text deprecates every row after 2030, whatever its strength (row 168).
    out["deprecated_after"] = m["deprecated_after"]
    out["disallowed_after"] = out["deadline"] = m["disallowed_after"]
    if strength == "below 112 bits":
        out["note"] = ("below the tables' lowest row (112 bits); the 112-bit row's dates are "
                       "the latest that can apply")
    passed_dis = day > date.fromisoformat(m["disallowed_after"])
    passed_dep = day > date.fromisoformat(m["deprecated_after"])
    out["status"] = "disallowed" if passed_dis else "deprecated" if passed_dep else "due"
    out["months_until"] = _months_until(day, date.fromisoformat(out["deadline"]))
    return out


def _composite(halves: set[str]) -> dict[str, Any]:
    m = MANDATES["nist-ir-8547"]
    return {"clause": f"classical half of a composite (hybrid) key establishment with "
                      f"{', '.join(sorted(halves))} on this line",
            "source": f"{m['document']}, {m['composite']}",
            "status": "composite_allowed"}


def _hybrid_halves(result: dict[str, Any]) -> dict[tuple[str, int], set[str]]:
    """(path, line) -> the families a hybrid named on that line is made of, with ECDH for an
    elliptic-curve half: the generic family a group setting's line is also read as."""
    out: dict[tuple[str, int], set[str]] = {}
    for h in result.get("hybrid_names") or []:
        halves = {str(name) for name, _ in h.get("halves") or []}
        if halves & _EC_AGREEMENT:
            halves.add("ECDH")
        out.setdefault((h.get("path"), h.get("line")), set()).update(halves)
    return out


def _cnsa(category: str, item: dict[str, Any], day: date) -> dict[str, Any]:
    m = MANDATES["cnsa-2.0"]
    path = str(item.get("path") or "")
    if category == "ci_pipeline":
        cls = "signing"
    elif _NETWORKING.search(path):
        cls = "networking"
    elif category in ("tls_groups", "static_rsa_kex") or _WEB.search(path):
        cls = "web"
    else:
        cls = "custom"
    clause, deadline = m["classes"][cls]
    return {"clause": clause, "class": cls, "source": f"{m['document']}, {m['section']}",
            "deadline": deadline,
            "status": "passed" if day > date.fromisoformat(deadline) else "due",
            "months_until": _months_until(day, date.fromisoformat(deadline))}


def apply(result: dict[str, Any], names: list[str], day: date,
          lead_months: int | None = None) -> bool:
    """Annotate `result` in place; return True when the gate fails."""
    kinds = {a["family"]: a["kind"] for a in known_algorithms()}
    vulnerable = {f["algorithm_family"] for f in result["findings"] if f.get("quantum_vulnerable")}
    raw = {str(f.get("raw_value")): f["algorithm_family"] for f in result["findings"]}
    horizon = _add_months(day, lead_months or 0)
    failed = False
    blocks: dict[str, dict[str, Any]] = {}
    for name in names:
        m = MANDATES[name]
        blocks[name] = {
            "document": m["document"], "url": m["url"], "read_on": m["read_on"],
            "as_of": day.isoformat(), "lead_months": lead_months,
            "in_scope": 0, "not_in_scope": 0, "hndl_exposed": 0, "hndl_not_determined": 0,
            "within_lead": 0,
            "by_status": {}, "next_deadline": None, "gate": "pass",
            "gate_counts": "deadline" if name == "cnsa-2.0" else "disallowed_after",
            "next_gate_deadline": None,
        }
        if name == "cnsa-2.0":
            blocks[name]["new_products"] = m["new_products"]
            blocks[name]["complete_by"] = {"date": m["complete_by"][0],
                                           "clause": m["complete_by"][1]}
        else:
            blocks[name]["hndl_source"] = m["hndl"]
            blocks[name]["composite"] = 0
    hybrid_lines = _hybrid_halves(result)
    for category, items in result["evidence"].items():
        for item in items:
            if not isinstance(item, dict) or "path" not in item:
                continue
            if item.get("evidence_kind") in _NOT_USE:
                continue
            family = _family(category, item)
            signing = category == "ci_pipeline"
            in_vulnerable = family is not None and (
                family in vulnerable or raw.get(family) in vulnerable
                or any(r.startswith(f"{family}-") and v in vulnerable for r, v in raw.items()))
            if not (in_vulnerable or signing):
                for block in blocks.values():
                    block["not_in_scope"] += 1
                continue
            role = "signature" if signing else _role(category, item, family or "", kinds)
            # The classical half of a hybrid named on this very line (source rows only: a
            # group offered alone is a tls_groups row and is dated as itself).
            halves = hybrid_lines.get((item.get("path"), item.get("line")), set())
            composite = category == "source_code" and family in halves
            said: dict[str, Any] = {}
            for name in names:
                if composite and name == "nist-ir-8547":
                    clause = _composite(halves - {family, "ECDH"} or halves)
                    said[name] = clause
                    blocks[name]["in_scope"] += 1
                    blocks[name]["composite"] += 1
                    blocks[name]["by_status"]["composite_allowed"] = blocks[name][
                        "by_status"].get("composite_allowed", 0) + 1
                    continue
                clause = (_cnsa(category, item, day) if name == "cnsa-2.0"
                          else None if signing else _nist(item, family or "", role, day))
                if clause is None:
                    blocks[name]["not_in_scope"] += 1
                    continue
                said[name] = clause
                block = blocks[name]
                block["in_scope"] += 1
                block["by_status"][clause["status"]] = block["by_status"].get(
                    clause["status"], 0) + 1
                if block["next_gate_deadline"] is None or clause["deadline"] < block[
                        "next_gate_deadline"]:
                    block["next_gate_deadline"] = clause["deadline"]
                upcoming = [d for d in (clause.get("deprecated_after"), clause["deadline"])
                            if d and date.fromisoformat(d) >= day]
                if upcoming and (block["next_deadline"] is None
                                 or min(upcoming) < block["next_deadline"]):
                    block["next_deadline"] = min(upcoming)
                if role == "key_establishment":
                    block["hndl_exposed"] += 1
                elif role == "undetermined":
                    block["hndl_not_determined"] += 1
                if date.fromisoformat(clause["deadline"]) <= horizon:
                    block["within_lead"] += 1
                    if item.get("baseline_state") != "baselined":
                        block["gate"] = "fail"
                        failed = True
            if said:
                item["mandates"] = said
                # RSA and EC whose line shows no role may be either: said, not guessed.
                item["hndl_exposed"] = (False if composite else
                                        True if role == "key_establishment" else
                                        "not determined" if role == "undetermined" else False)
    result["mandates"] = blocks
    return failed
