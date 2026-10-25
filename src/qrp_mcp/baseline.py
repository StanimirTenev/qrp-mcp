"""A baseline: findings already known, told apart from new ones, and never hidden.

`--write-baseline FILE` records every occurrence of a run; `--baseline FILE` marks each
occurrence of a later run `baseline_state: baselined` or `new`. The row stays in `evidence`
either way -- the inventory is what the code holds, not what is new -- and `baseline` counts
both, plus what the baseline held that this run did not find (`absent`).

The key is path + family + the line's text with its whitespace collapsed, never the line
number: an edit above a known finding moves it down without making it new. It is stored as a
digest, because a baseline gets committed and the line it stands for can hold more than the
algorithm. Two identical lines in one file are two entries; one baseline entry matches one
occurrence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

FORMAT = "qrp-mcp baseline 1"
MEANING = ("occurrences already recorded in the baseline file, told apart from new ones; "
           "both stay in `evidence`")
# Fields that are not the occurrence itself (closure keeps the same list for the same reason),
# and what this run adds.
_NOT_IDENTITY = {"line", "in_test_code", "role", "provider", "tls_termination", "signing_key",
                 "provider_pin", "fips_provider_configured_in", "group_places", "serves",
                 "serves_group_places", "owners", "owners_source", "baseline_state",
                 "mandates", "hndl_exposed", "suppression", "path", "confidence",
                 "confidence_basis"}


def family(item: dict[str, Any]) -> str:
    for key in ("algorithm", "family", "type", "protocol", "command_type", "package"):
        if item.get(key):
            return str(item[key])
    return ",".join(str(f) for f in item.get("families") or []) or "?"


def key(category: str, item: dict[str, Any]) -> str:
    """Path + family + normalised line text. An occurrence that carries no line text (a TLS
    group has file, setting and group) is keyed by the fields that identify it instead."""
    text = item.get("excerpt")
    if isinstance(text, str) and text:
        text = " ".join(text.split())
    else:
        text = json.dumps({k: v for k, v in item.items() if k not in _NOT_IDENTITY},
                          sort_keys=True, ensure_ascii=False, default=str)
    material = "\0".join((str(item.get("path")), category, family(item), text))
    return "sha256:" + hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()


def _occurrences(evidence: dict[str, list[dict[str, Any]]]):
    for category, items in sorted(evidence.items()):
        for item in items:
            if isinstance(item, dict) and "path" in item and "line" in item:
                yield category, item


def document(result: dict[str, Any]) -> dict[str, Any]:
    """The baseline file for one full-level result: every occurrence, suppressed ones too."""
    entries = []
    for evidence in (result["evidence"], (result.get("suppressed") or {}).get("evidence") or {}):
        for category, item in _occurrences(evidence):
            entries.append({"key": key(category, item), "path": item["path"],
                            "family": family(item)})
    entries.sort(key=lambda e: (e["path"], e["family"], e["key"]))
    return {"format": FORMAT, "tool": "qrp-mcp", "version": result["coverage"]["instrument"]
            ["version"], "target": result["target"], "entries": entries}


def read(path: str | Path) -> dict[str, Any]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise ValueError(f"no baseline file at {path}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except ValueError:
        raise ValueError(f"not a JSON baseline: {path}") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise ValueError(f"not a qrp-mcp baseline ({FORMAT!r}): {path}")
    return doc


def apply(result: dict[str, Any], doc: dict[str, Any], file: str | Path) -> dict[str, Any]:
    """Mark every occurrence new or baselined; return the `baseline` block."""
    remaining: dict[str, int] = {}
    for entry in doc.get("entries") or []:
        remaining[entry["key"]] = remaining.get(entry["key"], 0) + 1
    new_items, counts = [], {"new": 0, "baselined": 0}
    for evidence in (result["evidence"], (result.get("suppressed") or {}).get("evidence") or {}):
        for category, item in _occurrences(evidence):
            k = key(category, item)
            if remaining.get(k):
                remaining[k] -= 1
                item["baseline_state"] = "baselined"
            else:
                item["baseline_state"] = "new"
                if "suppression" not in item:
                    new_items.append({"category": category, "path": item["path"],
                                      "line": item["line"], "family": family(item),
                                      "baseline_state": "new"})
            if "suppression" not in item:
                counts[item["baseline_state"]] += 1
    return {
        "meaning": MEANING,
        "file": str(file),
        "entries": len(doc.get("entries") or []),
        "new": counts["new"],
        "baselined": counts["baselined"],
        # In the baseline, not found by this run: fixed, moved out of what was read, or
        # the line changed. Counted, not claimed as fixed -- `prove_closure` says which.
        "absent": sum(remaining.values()),
        "new_items": new_items,
    }
