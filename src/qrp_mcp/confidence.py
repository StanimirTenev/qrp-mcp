"""How sure the scan is of each occurrence: `high`, `medium` or `low` (release E).

Derived from what the scanner itself knows about the line, never from a score it invents.
Two things decide it:

1. **What the line is.** A call, a parsed certificate or key, the value of a setting the
   scanner parsed: `high`. A declaration or reference in source code, a version macro: `medium`.
   An import, a type in a Go function signature, a declared package: `low` -- the line names
   the algorithm and does not use it.
2. **Whether the family was read whole or inferred.** A family read from a piece of an
   identifier (`EC_KEY_free`), from an object identifier in a file the scan did not decode,
   or through an indirection (a property file, an alias, a constant in another file, a
   concatenated literal) is one step lower. The fallback of a `getProperty` lookup, read
   because no properties file in the tree sets the key, is `low` whatever the line: on the
   OWASP subset without benchmark.properties all 27 such rows were wrong.

A comment or a ban is `low` and is not counted as a use anywhere; the calibration below leaves
it out, as the CBOM leaves it out of the inventory.

`role` (signature / key establishment) is not an input: measured on Cryben, rows with a role
were 27/31 on a truth line and rows without one 39/43, so knowing the role did not separate
right from wrong.

The levels are calibrated, not asserted: `MEASURED` is the precision of each level on two
corpora with a foreign ground truth, with the rows counted. Both corpora were used to choose
the mapping, so the table is a regression figure, not a blind one, and it says so.
"""

from __future__ import annotations

import re
from typing import Any

from . import detectors

LEVELS = ("high", "medium", "low")

MEANING = ("how sure the scan is of an occurrence, from what the line is (call, parsed "
           "material or setting > declaration or reference > import, signature type or "
           "declared package) and whether the family was read whole or inferred; comments "
           "and bans are low and are not uses")

# Routes by which a family is inferred rather than read whole. Each is a description the
# detectors write (components.py, oids.py, detectors._join_properties, detectors.indirection);
# tests/test_confidence.py holds one example of each, so a reworded template fails there.
_INFERRED = (
    ("named as a component of", "family read from a piece of an identifier"),
    ("named in a compound name", "family read from a piece of an identifier"),
    ("observed in the file; the file was not decoded",
     "object identifier in a file the scan did not decode"),
    ("read here with getProperty", "joined through a properties file"),
    ("; read through ", "resolved through an indirection"),
)
# A getProperty default, used because no properties file in the tree sets the key.
_FALLBACK = "named as the default of getProperty"
_GO_SIGNATURE = re.compile(r"^\s*func\b")
_SETTINGS = {"tls_groups", "ssh_kex", "static_rsa_kex"}


def _down(level: str) -> str:
    return LEVELS[min(LEVELS.index(level) + 1, len(LEVELS) - 1)]


def assess(category: str, item: dict[str, Any]) -> tuple[str, str]:
    """(level, basis) for one evidence item."""
    kind = item.get("evidence_kind")
    if kind in ("comment", "ban"):
        return "low", f"{kind}: named, not used"
    if category == "embedded_keys":
        if item.get("key_unread"):
            return "medium", "key block seen, its key not read"
        return "high", "key material parsed"
    if category == "weak_keys":
        return "high", "computed from the parsed key"
    if category in _SETTINGS:
        return "high", "value of a setting the scan parsed"
    if category == "protocols":
        if "is named here" in str(item.get("description", "")):
            return "medium", "protocol version named by a constant, not set"
        return "high", "protocol version set by a setting the scan parsed"
    if category == "dependencies":
        return "low", "package declared; the family is what it implements, not observed"
    if category not in ("source_code", "iac"):
        return "medium", f"{category} evidence"
    if item.get("certificate"):
        return "high", "certificate parsed"
    path = str(item.get("path", ""))
    if kind == "call":
        level, basis = "high", "call"
    elif kind == "identifier":
        # Release 3b: a family read from a component of an identifier in a file that holds
        # other crypto (registry.identifiers). No row of the calibration corpora is one, so
        # the level is set below every measured one, not measured.
        return "low", "identifier carrying the family, in a file with other crypto"
    elif kind == "registry_name":
        # A registry's algorithm name, an OpenSSL / ssh-keygen command line or a PEM label
        # (registry.scan): the name is the algorithm, the line need not use it.
        level, basis = "medium", "registry name"
    elif kind == "import":
        return "low", "import: the module is named, not used"
    elif kind == "reference" and path.endswith(".go") and _GO_SIGNATURE.match(
            str(item.get("excerpt", ""))):
        return "low", "type in a function signature"
    elif kind == "declaration" and category == "iac":
        level, basis = "high", "infrastructure setting"
    elif kind == "declaration" and _is_config(path):
        level, basis = "high", "configuration value"
    elif kind in ("declaration", "reference", "default"):
        level, basis = "medium", f"{kind} in code"
    else:
        level, basis = "medium", str(kind)
    description = str(item.get("description", ""))
    if _FALLBACK in description:
        return "low", f"{basis}; the fallback of a property lookup no properties file sets"
    for marker, why in _INFERRED:
        if marker in description:
            return _down(level), f"{basis}; {why}"
    return level, basis


def _is_config(path: str) -> bool:
    """Not a source file: a declaration there is a setting's value, not a constant in code."""
    name = path.rsplit("/", 1)[-1].lower()
    return "." not in name or "." + name.rsplit(".", 1)[-1] not in detectors.SOURCE_EXTENSIONS


def annotate(evidence: dict[str, list[dict[str, Any]]]) -> None:
    """Set `confidence` and `confidence_basis` on every located item, in place."""
    for category, items in evidence.items():
        for item in items:
            if isinstance(item, dict) and "path" in item:
                item["confidence"], item["confidence_basis"] = assess(category, item)


# Measured 25.10.2026 with qrp-mcp release E on two corpora with a foreign ground truth.
# A row is right when the corpus's truth holds it: Cryben (the authors' ground truth, a row on
# a truth file:line, as their location-mode scorer counts it) and the OWASP Benchmark 1.2
# crypto + hash cases with benchmark.properties (a weak-family row in a case the Benchmark
# marks true; rows of other families are not graded). Comments and bans are left out.
# Script: razuznavane/kragg-1/02-tochnost (Cryben) and 06-propusnato (OWASP setup).
MEASURED = {
    "measured_on": "Cryben (authors' ground truth, location mode) + OWASP Benchmark 1.2 "
                   "crypto/hash with benchmark.properties",
    "date": "2026-10-25",
    "note": "both corpora were used to choose the mapping: a regression figure, not a blind one",
    # rows / right per corpus, and the pooled precision. Low has no OWASP row: every weak-family
    # row there is a call or a property join.
    "levels": {
        "high": {"cryben": "60/60", "owasp": "348/348", "precision": "1.000"},
        "medium": {"cryben": "2/3", "owasp": "73/73", "precision": "0.987"},
        "low": {"cryben": "4/11", "owasp": "0/0", "precision": "0.364"},
    },
    "limits": "small medium and low buckets on Cryben (3 and 11 rows); OWASP is Java only and "
              "separates nothing (every graded row right); Cryben's truth does not label Go "
              "signature lines, which decides part of low",
}


def coverage_block(evidence: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Counts per level in this scan (uses only), beside the measured precision per level."""
    counts = {level: 0 for level in LEVELS}
    for items in evidence.values():
        for item in items:
            if (isinstance(item, dict) and item.get("confidence") in counts
                    and item.get("evidence_kind") not in ("comment", "ban")):
                counts[item["confidence"]] += 1
    return {"meaning": MEANING, "occurrences": counts, "precision_by_level": MEASURED}
