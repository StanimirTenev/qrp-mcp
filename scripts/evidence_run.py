#!/usr/bin/env python3
"""Produce the evidence artefacts for the scan-coverage page from ONE run.

Both files come from the same pass over the same five repositories, because a
JSON from one run beside a CSV from another is the defect the page is about --
it happened once already and was caught by the agent building the page rather
than by us.

The corpus lives at ~/qrp-evidence/corpus and not in /tmp, deliberately. The five
clones are shallow at depth one, so each holds exactly the commit the published
page cites and nothing else. A fresh shallow clone gets the current head instead,
and recovering these commits would need a full clone of each repository. The
artefact behind a cited claim cannot sit in a directory that a reboot empties.

Usage:  scripts/evidence_run.py [corpus-root] [out-dir]
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from qrp_mcp.scan import scan_directory  # noqa: E402

REPOS = ["openssl", "openssh", "bitcoin", "vault", "certbot"]

COLUMNS = [
    "repository", "commit", "committed_at", "shallow_clone",
    "files_present", "files_examined",
    "not_examined_type_not_claimed", "not_examined_unreadable",
    "files_excluded_before_counting", "coverage_pct", "read_seconds",
    "read_started_at", "tool_version", "tool_commit",
    # Added 10.09.2026. Which kind of claim every figure in the row is, and
    # whether a control licenses it. Without these the row states a reading
    # figure and invites the stronger reading.
    "claims_axis", "control_held", "control_absent_reason",
    # Added 11.09.2026. The aggregate travels with its concentration or a reader
    # takes the headline alone: where the mass of the gap sits, and how many kinds
    # that share is out of, which is the null it is read against.
    "gap_partition", "gap_top_kinds", "gap_top_share_pct", "gap_distinct_kinds",
    "present_top2_share_pct",
]


def row(name: str, block: dict) -> dict:
    pin = block["corpus"]["pinned_at"]
    scope = block["scope"]
    reasons = {r["reason"]: r for r in block["not_examined"]}
    control = block["claims"]["control"]
    gapc = (reasons.get("type_not_claimed") or {}).get("concentration") or {}
    gap = gapc if gapc.get("largest_group") else None
    return {
        "repository": name,
        "commit": pin["commit"],
        "committed_at": pin["committed_at"][:10],
        "shallow_clone": pin["shallow"],
        "files_present": scope["files_present"],
        "files_examined": scope["files_examined"],
        "not_examined_type_not_claimed": reasons["type_not_claimed"]["count"],
        "not_examined_unreadable": reasons["unreadable"]["count"],
        "files_excluded_before_counting": scope["files_excluded_before_counting"]["total"],
        "coverage_pct": scope["coverage_pct"],
        "read_seconds": round(block["window"]["seconds"], 2),
        "read_started_at": block["window"]["started_at"],
        "tool_version": block["instrument"]["version"],
        "tool_commit": (block["instrument"]["source_commit"] or {}).get("commit"),
        "claims_axis": block["claims"]["axis"],
        "control_held": control["held"],
        "control_absent_reason": control.get("reason", ""),
        "gap_partition": gapc.get("partition", "") if gapc else "",
        "gap_top_kinds": " ".join(gap["largest_group"]["kinds"]) if gap else "",
        "gap_top_share_pct": gap["largest_group"]["share_pct"] if gap else "",
        "gap_distinct_kinds": gapc.get("distinct_kinds", "") if gapc else "",
        "present_top2_share_pct": (scope.get("concentration") or {})
            .get("largest_group", {}).get("share_pct", ""),
    }


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path.home() / "qrp-evidence" / "corpus")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else ".")
    out.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat().replace("-", "_")

    blocks, rows = {}, []
    for name in REPOS:
        target = root / name
        if not target.is_dir():
            print(f"missing: {target}", file=sys.stderr)
            return 1
        block = scan_directory(target)["coverage"]
        # The identity is checked here rather than trusted, because it is the one
        # claim on the page a reader can verify with arithmetic.
        scope = block["scope"]
        assert scope["files_examined"] + scope["files_not_examined"] == scope["files_present"]
        assert block["accounts_for_every_file"], name
        blocks[name] = block
        rows.append(row(name, block))
        print(f"{name:<9} {scope['coverage_pct']:>6}%  "
              f"{scope['files_examined']}/{scope['files_present']}")

    json_path = out / f"pokritie-blok-{stamp.replace('_', '-')}.json"
    csv_path = out / f"scan_coverage_{stamp}.csv"
    json_path.write_text(json.dumps(blocks, indent=1, ensure_ascii=False) + "\n")
    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"\n{json_path}\n{csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
