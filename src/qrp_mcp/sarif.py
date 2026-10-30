"""SARIF 2.1.0 for code-scanning pipelines: `qrp-mcp scan PATH --format sarif`.

Built from the scan result at the level asked for, so a masked run quotes masked snippets.
One result per occurrence in `evidence`, ruled by family (`qrp/RSA`); comments, bans and
identifier rows (which never move the headline) are `note`, uses are `warning`.

What a SARIF viewer would otherwise not show is put where the format has room for it:

  every file not read   a tool execution notification with its reason (`type_not_claimed`,
                        `unreadable`, `excluded_by_config`, ...), one per file. A clean page
                        over files nobody opened is the silent skip this tool refuses.
  a suppressed row      a result with an `inSource` suppression whose justification is the
                        owner's reason. GitHub hides it from the alert list and counts it.
  a marker that did     a notification `marker_not_applied`, with why.
  not apply
  a baseline            `baselineState` new / unchanged on each result.
  coverage              `run.properties.coverage`: present, examined, the verdict.
  confidence            `rank` (high 90, medium 60, low 30) and `properties.confidence` with
                        its basis (release E; see confidence.py). `level` stays the severity.

`partialFingerprints["qrpBaseline/v1"]` is the baseline key (path + family + normalised
line), computed on the full line before any masking.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import baseline as baseline_mod

SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
_NOTE = {"comment", "ban", "named_but_not_used", "identifier"}
_RANK = {"high": 90.0, "medium": 60.0, "low": 30.0}


def _location(path: str, line: int | None = None, excerpt: str | None = None) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": path, "uriBaseId": "SRCROOT"}}
    if isinstance(line, int) and line > 0:
        region: dict[str, Any] = {"startLine": line}
        if excerpt:
            region["snippet"] = {"text": excerpt}
        physical["region"] = region
    return {"physicalLocation": physical}


def _notification(rule: str, text: str, level: str = "warning",
                  path: str | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"descriptor": {"id": rule}, "level": level,
                           "message": {"text": text}}
    if path:
        out["locations"] = [_location(path)]
    return out


def _result(category: str, item: dict[str, Any], keys: dict[int, str]) -> dict[str, Any]:
    family = baseline_mod.family(item)
    kind = item.get("evidence_kind") or category
    out: dict[str, Any] = {
        "ruleId": f"qrp/{family}",
        "level": "note" if kind in _NOTE else "warning",
        "message": {"text": str(item.get("description") or f"{family} ({kind})")},
        "locations": [_location(str(item["path"]), item.get("line"), item.get("excerpt"))],
        "partialFingerprints": {"qrpBaseline/v1": keys[id(item)]},
        "properties": {"evidence": category, "evidence_kind": kind,
                       **{k: item[k] for k in ("in_test_code", "role", "key_size", "mandates",
                                               "hndl_exposed", "hndl", "confidence",
                                               "confidence_basis") if k in item}},
    }
    if item.get("confidence") in _RANK:
        out["rank"] = _RANK[item["confidence"]]
    if "suppression" in item:
        out["suppressions"] = [{"kind": "inSource", "status": "accepted",
                                "justification": item["suppression"]["reason"]}]
    if item.get("baseline_state"):
        out["baselineState"] = "unchanged" if item["baseline_state"] == "baselined" else "new"
    return out


def build(result: dict[str, Any], keys: dict[int, str]) -> dict[str, Any]:
    """`keys` maps id(item) to its baseline key, computed before masking."""
    cov = result["coverage"]
    rows = [(c, i) for c, items in sorted(result["evidence"].items()) for i in items]
    rows += [(c, i) for c, items in sorted(((result.get("suppressed") or {})
                                             .get("evidence") or {}).items()) for i in items]
    results = [_result(c, i, keys) for c, i in rows
               if isinstance(i, dict) and "path" in i and "line" in i]
    rules = sorted({r["ruleId"] for r in results})

    notes: list[dict[str, Any]] = []
    for entry in cov.get("not_examined") or []:
        declared = (entry.get("declarations") or {}).get("paths") or []
        for path in entry.get("paths") or []:
            text = f"not read: {entry['meaning']}"
            if path in declared:
                text += f"; {entry['declarations']['meaning']}"
            notes.append(_notification(entry["reason"], text, path=path))
    for path in result.get("files_left_out") or []:
        notes.append(_notification("left_out", "not read: the run's own output, config or "
                                   "baseline file", level="note", path=path))
    for path in (cov.get("directories_not_entered") or {}).get("paths") or []:
        notes.append(_notification("directory_not_entered", "could not be entered; the files "
                                   "inside are unknown", path=path))
    for path in result.get("claimed_but_not_decoded") or []:
        notes.append(_notification("claimed_but_not_decoded", "read, and no algorithm could "
                                   "be decoded from it", level="note", path=path))
    by_dir = (cov["scope"].get("files_excluded_before_counting") or {}).get("by_directory") or {}
    for name, count in by_dir.items():
        if name != ".git":
            notes.append(_notification("excluded_dir", f"{count} file(s) in {name}/ left out "
                                       f"before counting", level="note"))
    for marker in (result.get("suppressed") or {}).get("markers_not_applied") or []:
        note = _notification("marker_not_applied", f"{marker['form']} {marker['family']} at "
                             f"line {marker['line']} not applied: {marker['why']}")
        note["locations"] = [_location(marker["path"], marker["line"])]
        notes.append(note)

    scope = cov["scope"]
    run: dict[str, Any] = {
        "tool": {"driver": {
            "name": "qrp-mcp",
            "version": str(cov["instrument"]["version"]).split()[0],
            "informationUri": "https://github.com/StanimirTenev/qrp-mcp",
            "rules": [{"id": r, "name": r.split("/", 1)[1],
                       "shortDescription": {"text": f"{r.split('/', 1)[1]} in the code"}}
                      for r in rules],
        }},
        "originalUriBaseIds": {"SRCROOT": {"uri": Path(cov["corpus"]["target"]).as_uri() + "/"}},
        "invocations": [{"executionSuccessful": True,
                         "toolExecutionNotifications": notes}],
        "results": results,
        "properties": {
            "coverage": {k: scope[k] for k in ("files_present", "files_examined",
                                               "files_not_examined", "coverage_pct")},
            "verdict": result.get("verdict"),
            "accounts_for_every_file": cov.get("accounts_for_every_file"),
            "suppressed": (cov.get("suppressed") or {}).get("count", 0),
            **({"baseline": {k: result["baseline"][k] for k in ("new", "baselined", "absent")}}
               if result.get("baseline") else {}),
            **({"mandates": result["mandates"]} if result.get("mandates") else {}),
            **({"findings_fingerprint": result["findings_fingerprint"]}
               if result.get("findings_fingerprint") else {}),
        },
    }
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
