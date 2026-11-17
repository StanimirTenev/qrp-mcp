"""`--mandate NAME`: the dated clause that applies to each occurrence.

NAME is cnsa-2.0 or nist-ir-8547 (United States), or one of `profiles.DATED_MANDATES` (0.48.0):
eu-pqc-roadmap, uk-ncsc, ca-cccs, au-ism, nl-rqs, se-ncsc, jp-gov, sg-csa-cii, in-dst, de-bsi. A
dated mandate's clause is every rule of its document that names the occurrence's family and role,
the earliest date as `deadline`, and the dates for a class of system the scan cannot see
(high-risk, highest priority) as `earlier_if`, never counted by the gate. Every block says how old
its reading of the document is on `as_of` (`read_on_age_days`) and `stale` past
STALE_AFTER_DAYS; it does not move the gate.

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
many months of the date; a deadline already passed fails without it. For NIST IR 8547 the date
the gate counts is the deprecation (2030), from 0.41.0; it counted the disallowance (2035)
while `next_deadline` said 2030 (row 160). The block says which (`gate_counts`,
`next_gate_deadline`). A gate that would pass while files went unread reads `not_established`
with the count (row 204); the exit code is that of a pass, unless `--min-coverage` is given and
the files read fall below it: then the gate fails, with the reason (`gate_failed_because`). An occurrence the owner
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
    **profiles.DATED_MANDATES,
    **profiles.SECTOR_DUTIES,
}

# The table of deadlines is a reading of documents that change. A block whose `read_on` is
# more than this many days before the date the deadlines are counted from (`as_of`) says so.
# 180 days: two editions of the ISM a year, a TR-02102-1 every January.
STALE_AFTER_DAYS = 180

# Evidence categories that are key establishment by what they are.
_KEY_ESTABLISHMENT = {"tls_groups", "ssh_kex", "static_rsa_kex", "ike_proposals"}
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
    # Row 493: the federal date by role, said as a condition; not a deadline the gate counts.
    fed = m["federal_high_value_assets"]
    by_role = {"key_establishment": fed["key_establishment"], "signature": fed["signature"]}
    out["federal_high_value_assets"] = {
        **({"pqc_by": by_role[role]} if role in by_role else {"pqc_by_role": by_role}),
        "applies": fed["applies"], "source": fed["source"]}
    # Row 480: a line that only verifies or decrypts is said, not exempted. IR 8547 section
    # 4.1 (final.txt:778-780) defines legacy use; Tables 2 and 4 give these schemes none.
    if item.get("operation") in ("verify", "decrypt"):
        out["operation"] = item["operation"]
        out["legacy_use"] = (
            f"{item['operation']} only on this line: section 4.1 calls processing already "
            f"protected information (to decrypt ciphertext or verify a signature) legacy use; "
            f"whether what it processes is old is not established, and Tables 2 and 4 give "
            f"these schemes no legacy-use status, so the dates above stand")
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


def _parameter_set(name: str, item: dict[str, Any]) -> dict[str, Any] | None:
    """ZA-OPRAVYANE row 210: a post-quantum parameter set the mandate does not list
    (ML-KEM-768 under CNSA 2.0, which has ML-KEM-1024 only). Said, with no deadline: the gate
    counts deadlines and is not moved by it."""
    if name != "cnsa-2.0" or not item.get("parameter_set"):
        return None
    said = profiles.PROFILES["us-cnsa2"]["parameter_sets"].get(profiles.parameter_set_name(item))
    if said is None:
        return None
    m = MANDATES[name]
    return {"clause": said, "source": f"{m['document']}, {m['section']}",
            "status": "parameter_set_not_in_mandate"}


def _canonical(family: str, role: str) -> list[str]:
    """The family a dated document names: X25519 is ECDH (a curve of SP 800-186), Ed25519 is
    EdDSA, EC is ECDSA or ECDH by its role, and both where the line shows none."""
    if family in _EDDSA:
        return ["EdDSA"]
    if family in _EC_AGREEMENT:
        return ["ECDH"]
    if family == "EC":
        return {"signature": ["ECDSA"], "key_establishment": ["ECDH"]}.get(
            role, ["ECDSA", "ECDH"])
    return [family]


def _date_status(day: date, deadline: str) -> dict[str, Any]:
    return {"status": "passed" if day > date.fromisoformat(deadline) else "due",
            "months_until": _months_until(day, date.fromisoformat(deadline))}


def _dated(name: str, item: dict[str, Any], family: str, role: str,
           day: date) -> dict[str, Any] | None:
    """The clause of a DATED_MANDATES entry: every rule that names this family and role (both
    roles where the line shows none), the earliest of their dates as `deadline`, and the
    conditional dates earlier than it as `earlier_if`."""
    m = MANDATES[name]
    canon = _canonical(family, role)
    size = item.get("key_size")
    curve = _CURVE.search(f"{item.get('curve') or ''} {item.get('excerpt') or ''}")
    hits = []
    for rule in m["rules"]:
        if rule["families"] != "*" and not set(canon) & set(rule["families"]):
            continue
        if rule.get("role") and role != "undetermined" and rule["role"] != role:
            continue
        if family in rule.get("except", ()):
            continue
        if "key_size_below" in rule and not (isinstance(size, int)
                                             and size < rule["key_size_below"]):
            continue
        if "curve" in rule and not (curve and curve.group(1) == rule["curve"]):
            continue
        hits.append(rule)
    if not hits:
        if not m.get("unlisted"):
            return None
        return {"clause": m["unlisted"], "source": m["document"], "status": "not_in_document"}
    deadline = min(r["deadline"] for r in hits)
    first = [r for r in hits if r["deadline"] == deadline]
    out: dict[str, Any] = {"clause": "; ".join(dict.fromkeys(r["clause"] for r in first)),
                           "source": f"{m['document']}, "
                                     + "; ".join(dict.fromkeys(r["source"] for r in first)),
                           "deadline": deadline, **_date_status(day, deadline)}
    if len(hits) > len(first):
        out["also"] = [{"clause": r["clause"], "deadline": r["deadline"], "source": r["source"]}
                       for r in hits if r not in first]
    if role == "undetermined" and len({r.get("role") for r in hits}) > 1:
        out["note"] = ("the line shows no role: the dates for key establishment and for "
                       "signatures both apply, and the earlier is the deadline")
    earlier = [{"date": c["date"], "clause": c["clause"], "if": c["applies"]}
               for c in m.get("conditional") or []
               if c["date"] < deadline and role in c.get("roles", [role])]
    if earlier:
        out["earlier_if"] = earlier
    return out


def _dated_parameter_set(name: str, item: dict[str, Any], day: date) -> dict[str, Any] | None:
    """A post-quantum parameter set the document dates (ML-KEM-768 under the ISM)."""
    m = MANDATES[name]
    rule = (m.get("parameter_sets") or {}).get(profiles.parameter_set_name(item))
    if rule is None:
        return None
    return {"clause": rule["clause"], "source": f"{m['document']}, {rule['source']}",
            "deadline": rule["deadline"], **_date_status(day, rule["deadline"])}


def _composite_dated(name: str, halves: set[str]) -> dict[str, Any]:
    m = MANDATES[name]
    with_ = ", ".join(sorted(halves))
    if m.get("composite"):
        return {"clause": f"classical half of a composite (hybrid) key establishment with "
                          f"{with_} on this line", "source": f"{m['document']}, "
                                                             f"{m['composite']}",
                "status": "composite_allowed"}
    return {"clause": f"classical half of a composite (hybrid) key establishment with {with_} "
                      f"on this line: the document gives no date for the classical half of a "
                      f"hybrid, and none is applied", "source": m["document"],
            "status": "composite_not_addressed"}


def _stale(m: dict[str, Any], day: date) -> dict[str, Any]:
    """How old the reading of the document is on the day the deadlines are counted from."""
    read = date.fromisoformat(m["read_on"])
    age = (day - read).days
    out: dict[str, Any] = {"read_on_age_days": age, "stale_after_days": STALE_AFTER_DAYS,
                           "stale": age > STALE_AFTER_DAYS}
    if out["stale"]:
        out["stale_because"] = (
            f"the deadlines were read from the document on {m['read_on']}, {age} days before "
            f"{day.isoformat()} (more than {STALE_AFTER_DAYS}): a newer version may have moved "
            f"them; check {m['url'] or m['document']}")
    return out


# Row 524: whether the document itself changed since it was read, which `stale` cannot say. A
# scan makes no network call, so it says not_fetched; `qrp-mcp mandate-check` compares copies the
# user downloaded.
DOCUMENT_LIMITS = (
    "qrp-mcp makes no network call: the documents are downloaded by you (`how`) and compared "
    "here by sha256 with the copy read on `read_on`. A changed hash says the bytes changed, not "
    "that a deadline moved: re-read the document. Only PDFs are recorded (an HTML page changes "
    "its bytes without a change to its text); a site that blocks scripts can serve an error "
    "page, which reads as changed.")


# Row 527: four of the documents date symmetric or hash algorithms, which a scan does not read
# (out of scope by design, row 525), so it cannot count AES or SHA sizes against them. Their words,
# as the copies read for qrp-kachestvo/obhvat-razuznavane/01-grover-simetrichno.md give them
# (checked again on 17.11.2026 against srokove-v-skenera/raw/src and razuznavane/profili/src).
# The other documents date public-key cryptography only.
SYMMETRIC_NOT_READ = (
    "this document also dates symmetric or hash algorithms (document_says), and the scan does "
    "not read symmetric ciphers, hashes, MACs or their sizes: whether the code meets those "
    "clauses is not established, whatever the gate says of the public-key occurrences")
SYMMETRIC: dict[str, dict[str, Any]] = {
    "cnsa-2.0": {
        "dates": "AES-128 and AES-192, SHA-256: not compliant now (unchanged from CNSA 1.0)",
        "document_says": [
            {"quote": "Use 256-bit keys for all classification levels.",
             "source": "NSA CSA PP-22-1338, Table II, Advanced Encryption Standard (AES), "
                       "Parameters"},
            {"quote": "Use SHA-384 or SHA-512 for all classification levels.",
             "source": "NSA CSA PP-22-1338, Table II, Secure Hash Algorithm (SHA), "
                       "Parameters"}]},
    "au-ism": {
        "dates": "AES-128, AES-192, SHA-224, SHA-256 and HMAC-SHA256 (IPsec): not approved "
                 "beyond 2030, for reasons the document gives as not quantum",
        "document_says": [
            {"quote": "For interoperability and maintainability reasons, AES-128 and AES-192 "
                      "will not be approved beyond 2030.",
             "source": "Guidelines for cryptography, Using symmetric cryptographic algorithms"},
            {"quote": "For interoperability and maintainability reasons, SHA-224 and SHA-256 "
                      "will not be approved beyond 2030.",
             "source": "Guidelines for cryptography, Using Secure Hashing Algorithms"},
            {"quote": "For interoperability and maintainability reasons, HMAC-SHA256 will not "
                      "be approved beyond 2030.",
             "source": "Guidelines for cryptography, Using cryptographic protocols, Internet "
                       "Protocol Security (Pseudorandom function; Integrity algorithms)"}]},
    "ca-cccs": {
        "dates": "SHA-224 and SHA3-224, and HMAC keys under 128 bits, by the end of 2030; AES-128 "
                 "and SHA-256 stay recommended",
        "document_says": [
            {"quote": "SHA-224 should be phased out by the end of 2030.",
             "source": "ITSP.40.111 v5, section 7.2"},
            {"quote": "SHA3-224 should be phased out by the end of 2030.",
             "source": "ITSP.40.111 v5, section 7.3"},
            {"quote": "The key length should be increased to at least 128 bits by the end of "
                      "2030.",
             "source": "ITSP.40.111 v5, section 9.1 (HMAC)"}]},
    "nist-ir-8547": {
        "dates": "the symmetric standards at the 112-bit security level, in 2030; AES-128 and "
                 "SHA-256 are not dated",
        "document_says": [
            {"quote": "NIST has a few symmetric cryptography standards at the 112-bit security "
                      "level, which will be disallowed in 2030.",
             "source": "NIST IR 8547, section 4.1.3"},
            {"quote": "NIST does not expect to need to transition away from these standards as "
                      "part of the PQC migration.",
             "source": "NIST IR 8547, section 2.1.3"}]},
}


def _documents(name: str, m: dict[str, Any]) -> dict[str, Any]:
    return {"documents": m.get("documents") or [], "document_changed": "not_fetched",
            "document_check": f"not fetched by a scan; compare a fresh download with "
                              f"`qrp-mcp mandate-check {name} --document FILE`"}


def check_documents(name: str, files: list[str]) -> dict[str, Any]:
    """Compare downloaded copies with the mandate's `documents` hashes at read time, matched by
    hash: `document_changed` true, false or not_fetched for each and for the whole."""
    import hashlib
    from pathlib import Path

    m = MANDATES[name]
    docs = m.get("documents") or []
    hashed = [(f, hashlib.sha256(Path(f).expanduser().read_bytes()).hexdigest()) for f in files]
    # A copy is matched to the document whose hash it has, whatever the order; the copies left
    # are paired with the documents left, in order -- those are the changed ones.
    matched = {d["sha256"]: f for f, h in hashed for d in docs if h == d["sha256"]}
    left = [(f, h) for f, h in hashed if f not in matched.values()]
    out: list[dict[str, Any]] = []
    for n, doc in enumerate(docs):
        row = {**doc, "sha256_at_read": doc["sha256"],
               "how": f"curl -sSL -o doc{n + 1}.pdf '{doc['url']}'"}
        del row["sha256"]
        if doc["sha256"] in matched:
            row.update(file=matched[doc["sha256"]], sha256_now=doc["sha256"],
                       document_changed=False)
        elif left:
            f, h = left.pop(0)
            row.update(file=f, sha256_now=h, document_changed=True)
        else:
            row["document_changed"] = "not_fetched"
        out.append(row)
    said = [r["document_changed"] for r in out]
    result: dict[str, Any] = {
        "mandate": name, "document": m["document"], "read_on": m["read_on"], "documents": out,
        "document_changed": (True if True in said else
                             False if said and all(v is False for v in said) else "not_fetched"),
        "limits": DOCUMENT_LIMITS}
    if not docs:
        result["why_not_fetched"] = ("a document address with its hash was not recorded when "
                                     "this mandate was read; `url` is where to look")
        result["url"] = m["url"]
    elif left:
        result["files_not_compared"] = [f for f, _ in left]
    return result


def stale(result: dict[str, Any]) -> list[str]:
    """The names of the mandates whose reading is stale, for the command line's warning."""
    return [n for n, b in (result.get("mandates") or {}).items() if b.get("stale")]


def apply(result: dict[str, Any], names: list[str], day: date,
          lead_months: int | None = None, min_coverage: float | None = None) -> bool:
    """Annotate `result` in place; return True when the gate fails."""
    kinds = {a["family"]: a["kind"] for a in known_algorithms()}
    vulnerable = {f["algorithm_family"] for f in result["findings"] if f.get("quantum_vulnerable")}
    raw = {str(f.get("raw_value")): f["algorithm_family"] for f in result["findings"]}
    horizon = _add_months(day, lead_months or 0)
    failed = False
    blocks: dict[str, dict[str, Any]] = {}
    sectors = {n: _sector_block(MANDATES[n], day) for n in names if n in profiles.SECTOR_DUTIES}
    names = [n for n in names if n not in sectors]
    for name in names:
        m = MANDATES[name]
        blocks[name] = {
            "document": m["document"], "url": m["url"], "read_on": m["read_on"],
            "as_of": day.isoformat(), "lead_months": lead_months,
            "in_scope": 0, "not_in_scope": 0, "hndl_exposed": 0, "hndl_not_determined": 0,
            "within_lead": 0,
            "by_status": {}, "next_deadline": None, "gate": "pass",
            "gate_counts": "deprecated_after" if name == "nist-ir-8547" else "deadline",
            "next_gate_deadline": None,
            **_stale(m, day),
            **_documents(name, m),
        }
        if name in profiles.DATED_MANDATES:
            if m.get("sources"):
                blocks[name]["sources"] = m["sources"]
            blocks[name]["addresses"] = m["addresses"]
            blocks[name]["composite"] = 0
            blocks[name]["conditional"] = [{**c, "counted_by_gate": False}
                                           for c in m.get("conditional") or []]
            if m.get("milestones"):
                blocks[name]["milestones"] = m["milestones"]
        elif name == "cnsa-2.0":
            blocks[name]["new_products"] = m["new_products"]
            blocks[name]["complete_by"] = {"date": m["complete_by"][0],
                                           "clause": m["complete_by"][1]}
        else:
            blocks[name]["hndl_source"] = m["hndl"]
            blocks[name]["composite"] = 0
            blocks[name]["federal_high_value_assets"] = {
                **m["federal_high_value_assets"], "counted_by_gate": False}
            blocks[name]["verify_or_decrypt_only"] = 0
    hybrid_lines = _hybrid_halves(result)
    for category, items in result["evidence"].items():
        for item in items:
            if not isinstance(item, dict) or "path" not in item:
                continue
            if item.get("evidence_kind") in _NOT_USE:
                continue
            family = _family(category, item)
            # Row 479: a public-key encryption command is not a signing step.
            signing = (category == "ci_pipeline"
                       and item.get("operation") != "public_key_encryption")
            # Row 522: every IKE proposal row is a classical key exchange by construction (ECDH,
            # DH, X25519, X448), whether or not another row made its family a finding.
            in_vulnerable = family is not None and (
                family in vulnerable or raw.get(family) in vulnerable or category == "ike_proposals"
                or any(r.startswith(f"{family}-") and v in vulnerable for r, v in raw.items()))
            if not (in_vulnerable or signing):
                for name, block in blocks.items():
                    clause = (_dated_parameter_set(name, item, day)
                              if name in profiles.DATED_MANDATES and item.get("parameter_set")
                              else _parameter_set(name, item))
                    if clause is None:
                        block["not_in_scope"] += 1
                        continue
                    item.setdefault("mandates", {})[name] = clause
                    block["in_scope"] += 1
                    block["by_status"][clause["status"]] = block["by_status"].get(
                        clause["status"], 0) + 1
                    # A dated parameter set (ML-KEM-768 under the ISM) is a deadline.
                    if "deadline" in clause and _count_date(block, clause, item, day, horizon):
                        failed = True
                continue
            role = "signature" if signing else _role(category, item, family or "", kinds)
            # The classical half of a hybrid named on this very line (source rows only: a
            # group offered alone is a tls_groups row and is dated as itself).
            halves = hybrid_lines.get((item.get("path"), item.get("line")), set())
            composite = category == "source_code" and family in halves
            said: dict[str, Any] = {}
            for name in names:
                dated = name in profiles.DATED_MANDATES
                if composite and (name == "nist-ir-8547" or dated):
                    others = halves - {family, "ECDH"} or halves
                    clause = _composite_dated(name, others) if dated else _composite(others)
                    said[name] = clause
                    blocks[name]["in_scope"] += 1
                    blocks[name]["composite"] += 1
                    blocks[name]["by_status"][clause["status"]] = blocks[name][
                        "by_status"].get(clause["status"], 0) + 1
                    continue
                clause = (_cnsa(category, item, day) if name == "cnsa-2.0"
                          # A signing step whose key is not a quantum-vulnerable family (an
                          # ML-DSA key, or one not read) is not dated by these documents.
                          else (_dated(name, item, family or "", role, day) if in_vulnerable
                                else None) if dated
                          else None if signing else _nist(item, family or "", role, day))
                if clause is None:
                    blocks[name]["not_in_scope"] += 1
                    continue
                said[name] = clause
                block = blocks[name]
                block["in_scope"] += 1
                block["by_status"][clause["status"]] = block["by_status"].get(
                    clause["status"], 0) + 1
                if "legacy_use" in clause:
                    block["verify_or_decrypt_only"] += 1
                if role == "key_establishment":
                    block["hndl_exposed"] += 1
                elif role == "undetermined":
                    block["hndl_not_determined"] += 1
                # A family the document does not name has no date (`not_in_document`).
                if "deadline" in clause and _count_date(block, clause, item, day, horizon):
                    failed = True
            if said:
                item["mandates"] = said
                # RSA and EC whose line shows no role may be either: said, not guessed.
                item["hndl_exposed"] = (False if composite else
                                        True if role == "key_establishment" else
                                        "not determined" if role == "undetermined" else False)
    # Row 204: a pass over files the scan did not read is a pass over the files it read. Said
    # in the gate's word; the exit code is the same as for a pass.
    unread = _unread(result)
    # Row 204, decided 04.11.2026: `--min-coverage` makes too few files read a failure of its
    # own, whatever the deadlines say. Without it the pass over unread files is withheld only.
    scope = (result.get("coverage") or {}).get("scope") or {}
    pct = scope.get("coverage_pct")
    short = min_coverage is not None and pct is not None and pct < min_coverage
    for block in blocks.values():
        if min_coverage is not None:
            block["min_coverage"] = min_coverage
        if short:
            block["gate"] = "fail"
            block["gate_failed_because"] = (
                f"coverage {pct}% is below --min-coverage {min_coverage:g}%: "
                f"{scope.get('files_not_examined')} of {scope.get('files_present')} files were "
                f"not read (coverage.not_examined)")
            failed = True
        elif unread and block["gate"] == "pass":
            block["gate"] = "not_established"
            block["gate_not_established_because"] = unread
    # Row 527: a pass that cannot see the symmetric clauses of its own document is not a pass;
    # a fail stays a fail, and the exit code of a pass does not change.
    for name, block in blocks.items():
        if name not in SYMMETRIC:
            continue
        block["symmetric"] = {"status": "not_established", "evaluated": False,
                              "because": SYMMETRIC_NOT_READ, **SYMMETRIC[name]}
        if block["gate"] == "pass":
            block["gate"] = "not_established"
            block["gate_not_established_because"] = SYMMETRIC_NOT_READ
        elif block["gate"] == "not_established":
            block["gate_not_established_because"] += "; and " + SYMMETRIC_NOT_READ
    result["mandates"] = {**blocks, **sectors}
    return failed


def _sector_block(m: dict[str, Any], day: date) -> dict[str, Any]:
    """Row 523: a sector's duty with no date for code. Said, never counted."""
    return {
        "kind": "sector_duty", "document": m["document"], "url": m["url"],
        "read_on": m["read_on"], "as_of": day.isoformat(), "sector": m["sector"],
        "in_force": m["in_force"], "nature": m["nature"], "duties": m["duties"],
        "dates_no_occurrence": True, "in_scope": 0, "gate": "not_applicable",
        **_documents(m["name"], m),
        "gate_not_applicable_because": (
            "the document requires a plan, a roadmap or readiness of the sector by a date and "
            "dates no algorithm, so no occurrence carries its date; whether this repository's "
            "owner is in the sector is not known to the scan"),
        **_stale(m, day),
    }


def _count_date(block: dict[str, Any], clause: dict[str, Any], item: dict[str, Any], day: date,
                horizon: date) -> bool:
    """Count a clause's date on its block; True when it trips the gate."""
    # Row 160: the gate counts the date the headline gives, the deprecation for
    # NIST IR 8547 (2030), not the disallowance five years later.
    gate_date = clause.get("deprecated_after") or clause["deadline"]
    if block["next_gate_deadline"] is None or gate_date < block["next_gate_deadline"]:
        block["next_gate_deadline"] = gate_date
    upcoming = [d for d in (clause.get("deprecated_after"), clause["deadline"])
                if d and date.fromisoformat(d) >= day]
    if upcoming and (block["next_deadline"] is None or min(upcoming) < block["next_deadline"]):
        block["next_deadline"] = min(upcoming)
    if date.fromisoformat(gate_date) <= horizon:
        block["within_lead"] += 1
        if item.get("baseline_state") != "baselined":
            block["gate"] = "fail"
            return True
    return False


def _unread(result: dict[str, Any]) -> str | None:
    scope = (result.get("coverage") or {}).get("scope") or {}
    reports = sum(r["count"] for r in (result.get("coverage") or {}).get("not_examined") or []
                  if r.get("reason") == "report_document")
    unread = (scope.get("files_not_examined") or 0) - reports
    if unread <= 0:
        return None
    return (f"{unread} of {scope.get('files_present')} files were not read "
            f"(coverage.not_examined): no deadline falls within the lead in the files read, "
            f"and the files not read were not judged")
