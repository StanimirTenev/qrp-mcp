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

# The same discipline one level up, applied to the pins rather than the files.
# A pin that is simply absent is the defect this block exists to prevent, arriving
# in the field added to prevent it: `null` was standing for four different states
# with four different repairs. Adding a fourth means adding it here first.
PIN_ABSENT = {
    "no_checkout": "installed rather than checked out; no commit exists to name, "
                   "and the version is the only identifier available",
    "not_a_repository": "a source tree not under version control; a commit could "
                        "exist and does not",
    "vcs_unavailable": "git could not be run here; a pin may exist and was not "
                       "reachable from this run",
}


def _absent(reason: str) -> dict[str, Any]:
    return {"pinned": False, "reason": reason, "meaning": PIN_ABSENT[reason]}


# Which of two different kinds of claim a figure is. Dong Nguyen's distinction,
# and it retires the search for a third state on the second axis: there is no
# third state, because the second axis is not the instrument's to report.
#
# The asymmetry is structural rather than a gap in this tool. `reached` is
# self-measurable -- the scanner knows whether it opened the file and can be held
# to it, which is what `accounts_for_every_file` confesses when it fails.
# `answered` never is: "no RSA found" and "no RSA present" are the same output,
# and separating them requires knowing what was there, which is the question.
# So a figure on the second axis is licensed by a control, not by the instrument.
AXES = {
    "reached": "whether the instrument opened the file; measurable by the instrument "
               "about itself, and confessed when it fails",
    "answered": "whether what was present was found; NOT measurable by the instrument "
                "about itself, because a silent rule and an absent algorithm produce "
                "the same output. Only a control licenses a figure on this axis",
}

# Why no control backs the figures. A closed set, and each member names a
# different repair: build one, run it, re-run it against this instrument.
CONTROL_ABSENT = {
    "none_held": "no corpus with independently established contents exists for this "
                 "instrument; nothing here claims the second axis",
    "not_run": "a control exists and was not run in this window",
    "stale": "the control was last run against a different instrument, so it does not "
             "license figures produced by this one",
}


def _claims(control: dict[str, Any] | None) -> dict[str, Any]:
    """What kind of claim every figure in this block is, stated rather than implied.

    Every number this scanner produces is a reading claim. That was true before
    this field existed and the document did not say so, which left a reader to
    take the stronger reading from a correct number -- the failure this block was
    written against, occurring inside the block itself.
    """
    if control is None:
        control = {"held": False, "reason": "none_held",
                   "meaning": CONTROL_ABSENT["none_held"]}
    return {
        "axis": "reached",
        "meaning": AXES["reached"],
        "second_axis_not_claimed": AXES["answered"],
        "control": control,
    }


def _git_pin(repo_path: Path) -> dict[str, Any]:
    """The commit under the path, if it is a checkout. An absence is a valid answer.

    Reported rather than assumed: a run over an unpinned directory is not
    recomputable by anyone, including its author, and the block has to say so
    instead of leaving the reader to guess. An absence carries which absence,
    because "not a repository" is repaired by putting the tree under version
    control and "git is missing" is repaired by the environment.
    """
    reachable = True

    def git(*args: str) -> str | None:
        nonlocal reachable
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_path), *args],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            reachable = False
            return None
        return out.stdout.strip() if out.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    if not commit:
        return _absent("vcs_unavailable" if not reachable else "not_a_repository")

    shallow = (repo_path / ".git" / "shallow").exists()
    return {
        "pinned": True,
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


def _tool_pin() -> dict[str, Any]:
    """The commit of the tool itself, when it is running from a checkout.

    A version string does not identify the instrument. This package reported
    0.6.0 across two runs whose emitter differed by a commit, because the code
    changed without the version changing -- so two documents can name the same
    version and not be comparable, which is the exact failure the block exists
    to make visible. Where the tool is running from a checkout, say which one.
    Where it is not, say which absence: an installed wheel has no commit and
    never will, a source tree outside version control could have one, and a
    missing git leaves the question unanswered rather than answered "no". The
    three want different repairs, so one `null` for all three is the collapse
    this block was written against.
    """
    root = Path(__file__).resolve().parent
    installed = any(part in ("site-packages", "dist-packages") for part in root.parts)
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return _absent("no_checkout" if installed else "vcs_unavailable")
    if out.returncode != 0:
        return _absent("no_checkout" if installed else "not_a_repository")
    commit = out.stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    return {"pinned": True, "commit": commit, "dirty": bool(dirty.stdout.strip())}


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
            # Beside the size, so a reader can tell whether a figure describes the
            # instrument or describes what the corpus is made of. The commit makes
            # the number reproducible; this makes it interpretable. Named by
            # Nguyen Xuan Dong, 10.09.2026.
            "files_present_by_extension": dict(
                sorted(scan_result["files_present_by_extension"].items(),
                       key=lambda kv: (-kv[1], kv[0]))
            ),
            "files_examined": examined,
            "files_not_examined": present - examined,
            "coverage_pct": round(100 * examined / present, 2) if present else None,
        },
        # Every figure above is a reading claim. Said here rather than left to be
        # inferred: a correct number invites the stronger reading, and nothing in
        # a coverage figure distinguishes "I read this file" from "I found what
        # was in it".
        "claims": _claims(None),
        "not_examined": not_examined,
        # present == examined + every not-examined reason. Asserted in the output
        # rather than in a test, so a reader can check it without trusting us.
        "accounts_for_every_file": accounted == present,
    }


# Why two runs are not comparable. A closed set, for the reason the other two in
# this module are closed: "not comparable" on its own is `unknown` rebuilt at the
# comparison layer, and a reader who cannot see which condition moved cannot tell
# whether to re-run, re-clone or ignore the difference.
# `different_target` was here and was removed. A filesystem path is checkable --
# it ships in the block -- and it licenses nothing: /srv/build/certbot on two
# machines is the same string and not the same estate, and two clones of one
# commit at different paths are comparable while it called them incomparable.
# A pin that is true and does not support the conclusion, arriving in the table
# built to enumerate that failure. Corpus identity is the commit; the path is an
# operator convenience and is reported below rather than compared.
INCOMPARABLE = {
    "instrument_version_differs": "a different version of the tool did the reading",
    "instrument_commit_differs": "the same version, built from different code; the "
                                 "version does not pin the emitter",
    "ruleset_differs": "the pattern counts differ, so a change in the number can come "
                       "from the instrument rather than from the estate",
    "claimed_types_differ": "the tool claimed different file types, which moves the "
                            "denominator without the estate moving",
    "excluded_dirs_differ": "different directories were filtered out before counting",
    "corpus_commit_differs": "the corpus moved between the runs",
    "corpus_dirty": "at least one run read a working tree with uncommitted changes, "
                    "so what was read is not recoverable from the commit",
    "corpus_depth_differs": "one run read a shallow clone and the other a full "
                            "checkout; the same commit carries a different file count",
}

# Why comparability itself could not be established. Separate from INCOMPARABLE
# because the repairs differ: an incomparable pair is a fact about two runs, an
# unestablished one is a gap in what the documents carry.
UNESTABLISHED = {
    "instrument_unpinned": "at least one run does not name the commit of its own "
                           "emitter, so two identical version strings cannot be "
                           "shown to be the same code",
    "corpus_unpinned": "at least one run read an unpinned directory, so no commit "
                       "identifies what was read",
}


def _pin_of(block: dict[str, Any], *keys: str) -> dict[str, Any]:
    node: Any = block
    for key in keys:
        node = (node or {}).get(key)
    return node or {}


def compare(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    """Whether two coverage blocks describe runs whose numbers can be compared.

    Three verdicts rather than a boolean, and the third is the point. `comparable`
    and `not_comparable` are both answers; `unestablished` says the documents do
    not carry enough to decide, which is a different situation with a different
    repair and is the state a bare true/false silently absorbs.
    """
    unestablished: list[str] = []
    reasons: list[str] = []

    tool_a, tool_b = _pin_of(first, "instrument", "source_commit"), _pin_of(second, "instrument", "source_commit")
    corpus_a, corpus_b = _pin_of(first, "corpus", "pinned_at"), _pin_of(second, "corpus", "pinned_at")

    if not (tool_a.get("pinned") and tool_b.get("pinned")):
        unestablished.append("instrument_unpinned")
    elif tool_a["commit"] != tool_b["commit"]:
        reasons.append("instrument_commit_differs")

    if not (corpus_a.get("pinned") and corpus_b.get("pinned")):
        unestablished.append("corpus_unpinned")
    else:
        if corpus_a["commit"] != corpus_b["commit"]:
            reasons.append("corpus_commit_differs")
        if corpus_a.get("dirty") or corpus_b.get("dirty"):
            reasons.append("corpus_dirty")
        if corpus_a.get("shallow") != corpus_b.get("shallow"):
            reasons.append("corpus_depth_differs")

    if first["instrument"]["version"] != second["instrument"]["version"]:
        reasons.append("instrument_version_differs")
    if first["instrument"]["ruleset"] != second["instrument"]["ruleset"]:
        reasons.append("ruleset_differs")
    if first["instrument"]["claimed_types"] != second["instrument"]["claimed_types"]:
        reasons.append("claimed_types_differ")
    if first["instrument"]["excluded_dirs"] != second["instrument"]["excluded_dirs"]:
        reasons.append("excluded_dirs_differ")

    if reasons:
        verdict = "not_comparable"
    elif unestablished:
        verdict = "unestablished"
    else:
        verdict = "comparable"

    return {
        "verdict": verdict,
        "differences": [{"reason": r, "meaning": INCOMPARABLE[r]} for r in reasons],
        "unestablished": [{"reason": r, "meaning": UNESTABLISHED[r]} for r in unestablished],
        "coverage_pct": [first["scope"]["coverage_pct"], second["scope"]["coverage_pct"]],
        # Shown, not compared. Two paths differing says nothing about whether the
        # runs read the same estate, and a reader who wants that reads the commits.
        "targets": [first["corpus"]["target"], second["corpus"]["target"]],
    }


def verdict_line(block: dict[str, Any]) -> str:
    """One sentence for the person who signs the report rather than runs the tool.

    Derived from the block's own identity flag rather than recomputed from the
    counts. Recomputing would let this sentence and the block disagree, which is
    the version-versus-commit failure in miniature.
    """
    scope = block["scope"]
    if not block["accounts_for_every_file"]:
        return (f"This scan cannot account for every file: {scope['files_present']} were "
                f"present and the reasons given do not add up to them.")
    if scope["files_not_examined"] == 0:
        return (f"This scan read every one of the {scope['files_present']} files it was "
                f"given.")
    return (f"This scan read {scope['files_examined']} of {scope['files_present']} files "
            f"({scope['coverage_pct']}%); the remaining {scope['files_not_examined']} are "
            f"listed with a reason each.")
