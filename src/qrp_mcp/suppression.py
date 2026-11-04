"""Inline suppression that is counted: `qrp:ignore <family> <reason>` (ZA-OPRAVYANE row 128).

Two forms, inside a comment:

    k = rsa.generate_private_key(...)  # qrp:ignore RSA legacy HSM, replaced in Q3
    // qrp:ignore-next-line ECDSA firmware verifier, cannot change

The family and the reason are both required. A marker without them does not apply, and is
listed in `markers_not_applied` with why -- so is one that names a family the line does not
have. A suppressed occurrence leaves `evidence`, is listed under `suppressed` with the owner's
reason, and is counted in `coverage.suppressed`, which the CBOM carries as properties. The
inventory is not changed by it: the code still holds the algorithm.

Measured on the M5 leader before this was built (06-propusnato, 25.10.2026): CryptoScan #9
("a .cryptoscan.yaml in the scanned tree can suppress every finding, and no output says so")
and #26 ("inline ignore directives are uncounted"), both open. A suppression nobody can see is
the silent skip this tool exists to refuse.

An expiry date and an owner (row 221) may stand anywhere after the family, and are taken out
of the reason:

    # qrp:ignore-next-line RSA until=2027-06-30 owner=j.doe HSM firmware 4.2, no ML-DSA

Through the `until` day the marker suppresses, and the suppression carries both. After it the
marker does not apply: the occurrence stays in `evidence` and the marker is listed in
`markers_not_applied` as expired. A reason that calls itself temporary with no `until=` still
applies, and is listed in `markers_flagged`: nothing will ever end it.
"""

from __future__ import annotations

import datetime
import re
from typing import Any

MEANING = ("suppressed by the owner in the code, with a reason: not in `evidence`, not "
           "dropped, and still in the inventory")

# The marker, then everything up to the end of the comment. `-next-line` first, so the
# shorter form does not swallow it.
_MARKER = re.compile(r"qrp:ignore(?P<next>-next-line)?(?![\w-])(?P<rest>.*?)(?=\*/|-->|$)")
# What opens a comment on the line before the marker: #, //, /*, <!--, --, ;, %, REM, or a
# line inside a block comment that starts with *.
_OPENER = re.compile(r"(#|//|/\*|<!--|--|;|%|\bREM\b)")
# `until=YYYY-MM-DD` and `owner=NAME`, anywhere after the family.
_FIELD = re.compile(r"(?:^|\s)(?P<key>until|owner)=(?P<value>\S+)")
# A reason that promises an end.
_TEMPORARY = re.compile(r"\b(temporar(?:y|ily)|for now|interim)\b", re.IGNORECASE)


def _normal(name: str) -> str:
    return re.sub(r"[\s_\-]", "", name).upper()


def read_markers(rel_path: str, lines: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    """The markers in one file, and the lines with the marker text blanked out.

    Blanked to spaces of the same length, so a marker's own words (`qrp:ignore RSA ...`) do
    not become a comment occurrence of the family it names, and columns do not move."""
    markers: list[dict[str, Any]] = []
    out = list(lines)
    for number, line in enumerate(lines, 1):
        if "qrp:ignore" not in line:
            continue
        match = _MARKER.search(line)
        if match is None:
            continue
        before = line[:match.start()]
        if not (_OPENER.search(before) or before.lstrip().startswith("*")):
            continue
        rest = match.group("rest").strip()
        family, _, reason = rest.partition(" ")
        fields = {m.group("key"): m.group("value") for m in _FIELD.finditer(reason)}
        reason = " ".join(_FIELD.sub(" ", reason).split())
        form = "qrp:ignore-next-line" if match.group("next") else "qrp:ignore"
        markers.append({
            "path": rel_path, "line": number, "form": form, "family": family,
            "reason": reason,
            "target_line": number + 1 if match.group("next") else number,
            **{k: fields[k] for k in ("until", "owner") if k in fields},
        })
        out[number - 1] = line[:match.start()] + " " * (match.end() - match.start()) \
            + line[match.end():]
    return markers, out


def _names(item: dict[str, Any], family_of: dict[str, str]) -> set[str]:
    """Every name an occurrence answers to: its own and the family it is classified under."""
    names = set()
    for key in ("algorithm", "family", "protocol"):
        if item.get(key):
            names.add(str(item[key]))
    names.update(str(f) for f in item.get("families") or [])
    if item.get("type"):
        names.add(str(item["type"]).split()[0])
    names.update(family_of[n] for n in list(names) if n in family_of)
    return {_normal(n) for n in names}


def apply(evidence: dict[str, list[dict[str, Any]]], markers: list[dict[str, Any]],
          family_of: dict[str, str], today: datetime.date | None = None) -> dict[str, Any]:
    """Move the occurrences a valid marker names out of `evidence`; return the block."""
    today = today or datetime.date.today()
    suppressed: dict[str, list[dict[str, Any]]] = {}
    not_applied: list[dict[str, Any]] = []
    flagged: list[dict[str, Any]] = []
    for marker in markers:
        brief = {k: marker[k] for k in ("path", "line", "form", "family", "until", "owner")
                 if k in marker}
        if not marker["family"]:
            not_applied.append({**brief, "why": "no family and no reason given"})
            continue
        if not marker["reason"]:
            not_applied.append({**brief, "why": "no reason given"})
            continue
        if "until" in marker:
            try:
                until = datetime.date.fromisoformat(marker["until"])
            except ValueError:
                until = None
            if until is None or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", marker["until"]):
                not_applied.append({**brief, "why": f"until={marker['until']} is not a date "
                                                    f"(YYYY-MM-DD)"})
                continue
            if until < today:
                not_applied.append({**brief, "why": f"expired on {marker['until']}: the "
                                                    f"occurrence is in evidence again"})
                continue
        elif _TEMPORARY.search(marker["reason"]):
            flagged.append({**brief, "why": "the reason says it is temporary and gives no "
                                            "until= date: it cannot expire"})
        wanted = _normal(marker["family"])
        hit = False
        for kind, items in evidence.items():
            keep = []
            for item in items:
                if (item.get("path") == marker["path"]
                        and item.get("line") == marker["target_line"]
                        and wanted in _names(item, family_of)):
                    suppressed.setdefault(kind, []).append({**item, "suppression": {
                        "family": marker["family"], "reason": marker["reason"],
                        "form": marker["form"], "marker_line": marker["line"],
                        **{k: marker[k] for k in ("until", "owner") if k in marker}}})
                    hit = True
                else:
                    keep.append(item)
            items[:] = keep
        if not hit:
            not_applied.append({**brief, "why": f"no {marker['family']} occurrence on line "
                                                f"{marker['target_line']}"})
    by_family: dict[str, int] = {}
    for items in suppressed.values():
        for item in items:
            name = item["suppression"]["family"]
            by_family[name] = by_family.get(name, 0) + 1
    return {
        "meaning": MEANING,
        "count": sum(by_family.values()),
        "by_family": dict(sorted(by_family.items())),
        "evidence": suppressed,
        "markers_not_applied": not_applied,
        "markers_flagged": flagged,
    }


def coverage_block(block: dict[str, Any]) -> dict[str, Any]:
    """The same, for `coverage`: named and counted, without the quoted lines, because the
    coverage block travels into the CBOM and is never masked."""
    items = [{"path": i["path"], "line": i["line"], "evidence": kind,
              "family": i["suppression"]["family"], "reason": i["suppression"]["reason"],
              "form": i["suppression"]["form"],
              **{k: i["suppression"][k] for k in ("until", "owner") if k in i["suppression"]}}
             for kind, rows in sorted(block["evidence"].items()) for i in rows]
    items.sort(key=lambda i: (i["path"], i["line"], i["evidence"]))
    return {
        "meaning": block["meaning"],
        "count": block["count"],
        "by_family": block["by_family"],
        "items": items,
        "markers_not_applied": {"count": len(block["markers_not_applied"]),
                                "items": block["markers_not_applied"]},
        "markers_flagged": {"count": len(block["markers_flagged"]),
                            "items": block["markers_flagged"]},
    }
