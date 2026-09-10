"""The coverage block: what was in scope, what was read, and what was not — with why.

A coverage number on its own is not comparable to another coverage number. Two runs
can disagree because the estate moved, because the instrument moved, or because the
corpus was collected differently — and the totals show none of the three. This block
carries the conditions alongside the count so a reader can tell which happened.

Four things go in it, and each answers a question the bare percentage cannot:

  instrument  what did the reading. A changed ruleset moves coverage with nothing
              else changing, so a comparison across instruments is not a comparison.
  corpus      what was read, pinned. A commit makes the run recomputable; without
              one the number is an anecdote, because the repository moves underneath.
  window      when it was read. A finding can be true at read time and false when
              the document is signed.
  scope       the denominator, the numerator, and every file that is in the first
              but not the second WITH A REASON. Never a bare count.

The reason codes are a closed set. `type_not_claimed` and `unreadable` are kept
apart deliberately: one is a boundary the tool declares, the other is a failure it
hit. Collapsing them is the same defect as letting `unknown` stand for both absent
and not-looked-at.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

# Closed set. A file that is in files_present but not in files_examined carries
# exactly one of these, and adding a sixth means adding it here first.
REASONS = {
    "type_not_claimed": "the tool does not claim this file type; a declared boundary, not a failure",
    "unreadable": "opened and could not be read; attempted and failed",
}


def _git_pin(repo_path: Path) -> dict[str, Any] | None:
    """The commit under the path, if it is a checkout. None is a valid answer.

    Reported rather than assumed: a run over an unpinned directory is not
    recomputable by anyone, including its author, and the block has to say so
    instead of leaving the reader to guess.
    """
    def git(*args: str) -> str | None:
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_path), *args],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return out.stdout.strip() if out.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    if not commit:
        return None

    shallow = (repo_path / ".git" / "shallow").exists()
    return {
        "kind": "git",
        "commit": commit,
        "committed_at": git("log", "-1", "--format=%cI"),
        "dirty": bool(git("status", "--porcelain")),
        # A shallow clone has no history and, more to the point here, none of the
        # build output or dependency trees a working checkout carries. The same
        # tool over the same commit counts a different denominator in the two,
        # which is a condition of collection rather than a property of the estate.
        "shallow": shallow,
    }


def _tool_pin() -> dict[str, Any] | None:
    """The commit of the tool itself, when it is running from a checkout.

    A version string does not identify the instrument. This package reported
    0.6.0 across two runs whose emitter differed by a commit, because the code
    changed without the version changing -- so two documents can name the same
    version and not be comparable, which is the exact failure the block exists
    to make visible. Where the tool is running from a checkout, say which one.
    None where it is not: an installed wheel has no commit, and inventing one
    is worse than an honest absence.
    """
    root = Path(__file__).resolve().parent
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    commit = out.stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    return {"commit": commit, "dirty": bool(dirty.stdout.strip())}


def build(
    *,
    repo_path: Path,
    scan_result: dict[str, Any],
    started_at: str,
    finished_at: str,
    seconds: float,
    tool_version: str,
    ruleset: dict[str, int],
    claimed_types: dict[str, list[str]],
    excluded_dirs: list[str],
) -> dict[str, Any]:
    """Assemble the block. Every number here is derived, none is asserted."""
    present = scan_result["files_present"]
    examined = sum(scan_result["files_scanned"].values())
    skipped = scan_result["files_skipped_by_type"]
    unreadable = scan_result["unreadable_files"]

    not_examined = [
        {
            "reason": "type_not_claimed",
            "meaning": REASONS["type_not_claimed"],
            "count": sum(skipped.values()),
            "by_extension": skipped,
        },
        {
            "reason": "unreadable",
            "meaning": REASONS["unreadable"],
            "count": len(unreadable),
            "paths": unreadable,
        },
    ]
    accounted = examined + sum(r["count"] for r in not_examined)

    excluded = scan_result.get("files_excluded_by_dir", {})

    return {
        "instrument": {
            "tool": "qrp-mcp",
            "version": tool_version,
            # The version alone does not pin the emitter; the code can change
            # without it. Null when running from an installed wheel.
            "source_commit": _tool_pin(),
            "ruleset": ruleset,
            "claimed_types": claimed_types,
            # Declared because it filters the denominator before anything is counted.
            # A filter that shapes the number and is not stated is the defect this
            # block exists to refuse.
            "excluded_dirs": sorted(excluded_dirs),
        },
        "corpus": {
            "target": str(repo_path),
            "pinned_at": _git_pin(repo_path),
        },
        "window": {
            "started_at": started_at,
            "finished_at": finished_at,
            "seconds": round(seconds, 2),
        },
        "scope": {
            # Removed by the directory exclusions before files_present counted
            # anything. Declared with its size because git will not report it:
            # build output is usually ignored, and an ignored file leaves the
            # tree reporting clean, so the same tool at the same commit counts
            # a different denominator in a working checkout than in a fresh
            # clone with nothing said about it. Kept beside files_present rather
            # than folded into it -- .git is in here too, and git metadata is
            # not part of the estate, so neither total is the denominator on
            # its own and the reader is given both.
            "files_excluded_before_counting": {
                "total": sum(excluded.values()),
                "by_directory": excluded,
            },
            "files_present": present,
            "files_examined": examined,
            "files_not_examined": present - examined,
            "coverage_pct": round(100 * examined / present, 2) if present else None,
        },
        "not_examined": not_examined,
        # present == examined + every not-examined reason. Asserted in the output
        # rather than in a test, so a reader can check it without trusting us.
        "accounts_for_every_file": accounted == present,
    }
