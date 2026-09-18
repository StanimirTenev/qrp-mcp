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

import os
import subprocess
from pathlib import Path
from typing import Any

# Closed set. A file that is in files_present but not in files_examined carries
# exactly one of these, and adding a sixth means adding it here first.
REASONS = {
    "type_not_claimed": "the tool does not claim this file type; a declared boundary, not a failure",
    "unreadable": "opened and could not be read; attempted and failed",
    "claimed_but_not_decoded": ("a claimed file type that was read and gave up no "
                                "algorithm: encrypted content, or a structure this "
                                "tool does not parse"),
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
    "not_tracked": "inside a repository that does not track this directory (ignored "
                   "or untracked); the repository's commit does not describe it",
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


def _concentration(composition: dict[str, int], present: int, partition: str,
                   top: int = 2) -> dict[str, Any]:
    """How much of a total its largest members are, over a named partition.

    An aggregate over a lopsided population describes its largest members and
    reads as describing all of them. Reported as a share rather than a breakdown
    because a share survives being quoted and a breakdown does not.

    Three values, not two, and the third is the one that was missing. A
    concentration is not a property of an aggregate: it is a property of the
    aggregate crossed with the partition it was measured over, and nothing in
    "two kinds are 50 per cent" says what a kind is. The same five repositories
    partitioned by directory, by language, or by vendored-or-not give different
    shares with nothing changing on disk -- and .txt dominating Vault's unread
    files is striking precisely because extension is a partition a reader does
    not expect. Govardhan Yadava found this by computing his own two ways: the
    same two sessions are 53.4 per cent of his test cases and 33.8 per cent of
    his vector sets, because cases and sets partition one run differently.

    Without the partition named beside the share, the field reproduces the defect
    it was added to prevent, one level up.
    """
    kinds = list(composition.items())
    if not kinds or not present:
        return {"distinct_kinds": len(kinds), "largest": None, "largest_two": None}
    kinds = sorted(kinds, key=lambda kv: (-kv[1], kv[0]))
    head = kinds[:top]
    return {
        # What a "kind" is. Not a qualifier: the share is only meaningful against it.
        "partition": partition,
        "distinct_kinds": len(kinds),
        "largest": {
            "kind": head[0][0],
            "files": head[0][1],
            "share_pct": round(100 * head[0][1] / present, 2),
        },
        "largest_group": {
            "kinds": [k for k, _ in head],
            "files": sum(n for _, n in head),
            "share_pct": round(100 * sum(n for _, n in head) / present, 2),
        },
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
            out = _run_git(repo_path, *args)
        except (OSError, subprocess.SubprocessError):
            reachable = False
            return None
        return out.stdout.strip() if out.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    if not commit:
        return _absent("vcs_unavailable" if not reachable else "not_a_repository")
    if not git("ls-files", "--", "."):
        # An ignored build directory inside a checkout: HEAD exists, but nothing
        # scanned here is in it.
        return _absent("not_tracked")

    # `git status` is the one call here that can run programs the scanned repository
    # configured for itself: an fsmonitor hook, or a clean filter consulted while
    # comparing a changed file. The scanned code is not the user's, so its
    # configuration is not trusted. fsmonitor is switched off on every call; if the
    # repository still names an external program, status is not run at all and the
    # flag says it was not checked rather than guessing.
    runs_programs = git("config", "--local", "--includes", "--get-regexp", _REPO_PROGRAM_KEYS)
    dirty_state: dict[str, Any]
    if runs_programs:
        dirty_state = {
            "dirty": None,
            "dirty_not_checked": "the repository configures external programs "
                                 "(filters or hooks); status was not run on it",
        }
    else:
        dirty_state = {"dirty": bool(git("status", "--porcelain", "--", "."))}

    shallow = git("rev-parse", "--is-shallow-repository") == "true"
    return {
        "pinned": True,
        "kind": "git",
        "commit": commit,
        "committed_at": git("log", "-1", "--format=%cI"),
        **dirty_state,
        # A shallow clone has no history and, more to the point here, none of the
        # build output or dependency trees a working checkout carries. The same
        # tool over the same commit counts a different denominator in the two,
        # which is a condition of collection rather than a property of the estate.
        "shallow": shallow,
    }


# Repository-local keys under which git may start a program during status.
_REPO_PROGRAM_KEYS = r"^(filter\..*\.(clean|smudge|process)|core\.fsmonitor|core\.hookspath)$"


def _run_git(where: Path, *args: str) -> subprocess.CompletedProcess:
    """git with the scanned repository's program hooks disarmed.

    No pager, no prompt, no optional locks (a read must not write the index), and
    fsmonitor off regardless of what the repository's own config says.
    """
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
               GIT_PAGER="cat", PAGER="cat")
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
         "--no-optional-locks", "-C", str(where), *args],
        capture_output=True, text=True, timeout=10, check=False, env=env,
    )


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
    if installed:
        # Asking git from inside site-packages answers for whatever repository the
        # environment happens to sit in -- a virtualenv inside the client's checkout
        # reported the client's commit as this tool's. An installed wheel has no
        # commit of its own, so git is not asked.
        return _absent("no_checkout")
    try:
        out = _run_git(root, "rev-parse", "HEAD")
        tracked = _run_git(root, "ls-files", "--error-unmatch", Path(__file__).name)
    except (OSError, subprocess.SubprocessError):
        return _absent("vcs_unavailable")
    if out.returncode != 0 or tracked.returncode != 0:
        # Not a repository, or a repository that does not track this file: in the
        # second case the commit would belong to someone else's tree.
        return _absent("not_a_repository")
    commit = out.stdout.strip()
    dirty = _run_git(root, "status", "--porcelain")
    return {"pinned": True, "commit": commit, "dirty": bool(dirty.stdout.strip())}


def build(
    *,
    repo_path: Path,
    scan_result: dict[str, Any],
    started_at: str,
    finished_at: str,
    seconds: float,
    tool_version: str | None,
    tool_name: str = "qrp-mcp",
    ruleset: dict[str, int],
    claimed_types: dict[str, list[str]],
    excluded_dirs: list[str],
) -> dict[str, Any]:
    """Assemble the block. Every number here is derived, none is asserted."""
    present = scan_result["files_present"]
    composition = dict(
        sorted(scan_result["files_present_by_extension"].items(),
               key=lambda kv: (-kv[1], kv[0]))
    )
    examined = sum(scan_result["files_scanned"].values())
    skipped = scan_result["files_skipped_by_type"]
    unreadable = scan_result["unreadable_files"]
    undecoded = scan_result.get("claimed_but_not_decoded", [])

    not_examined = [
        {
            "reason": "type_not_claimed",
            "meaning": REASONS["type_not_claimed"],
            "count": sum(skipped.values()),
            "by_extension": skipped,
            # Where the gap sits. The reader's question is what was missed, so the
            # concentration that changes the reading is of the misses rather than
            # of the total -- Govardhan Yadava's correction to my first attempt,
            # which reported it of the denominator.
            "concentration": _concentration(skipped, sum(skipped.values()),
                                           partition="unread files by extension", top=3),
        },
        {
            "reason": "unreadable",
            "meaning": REASONS["unreadable"],
            "count": len(unreadable),
            "paths": unreadable,
        },
    ]
    accounted = examined + sum(r["count"] for r in not_examined)
    # Counted as read -- it was read -- and named anyway: a claimed type that
    # yields nothing is exactly the silent skip this block exists to refuse, and
    # staying silent about our own would be the same defect under our own roof.
    read_but_empty = {
        "reason": "claimed_but_not_decoded",
        "meaning": REASONS["claimed_but_not_decoded"],
        "count": len(undecoded),
        "paths": undecoded,
    }
    dirs_not_entered = scan_result.get("unreadable_directories", [])

    excluded = scan_result.get("files_excluded_by_dir", {})

    return {
        "instrument": {
            "tool": tool_name,
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
            "files_present_by_extension": composition,
            # One figure a reader carries because it is a clause rather than a
            # table. Nguyen Xuan Dong's point, 10.09.2026: a breakdown gets left
            # behind, a concentration figure gets quoted with the number, and the
            # failure we kept observing was a person lifting a headline out of a
            # document whose composition was one scroll away. The test he set is
            # whether it can be lifted along with the number by someone who is not
            # being careful.
            "concentration": _concentration(composition, present,
                                            partition="files by extension", top=2),
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
        # Read, counted as read, and empty anyway.
        "examined_without_result": read_but_empty,
        # Directories the walk could not enter. Their files are not in any count
        # above, because nobody knows how many there are.
        "directories_not_entered": {
            "count": len(dirs_not_entered),
            "paths": dirs_not_entered,
            "meaning": "could not be entered or listed; the files inside are unknown "
                       "and are not in files_present",
        },
        # present == examined + every not-examined reason, and nothing was hidden
        # from the walk. Asserted in the output rather than in a test, so a reader
        # can check it without trusting us.
        "accounts_for_every_file": accounted == present and not dirs_not_entered,
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
    "block_incomplete": "at least one block lacks fields the comparison needs, so "
                        "whether the runs can be compared is not known from them",
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

    inst_a, inst_b = _pin_of(first, "instrument"), _pin_of(second, "instrument")
    for field, reason in (("version", "instrument_version_differs"),
                          ("ruleset", "ruleset_differs"),
                          ("claimed_types", "claimed_types_differ"),
                          ("excluded_dirs", "excluded_dirs_differ")):
        if field not in inst_a or field not in inst_b:
            if "block_incomplete" not in unestablished:
                unestablished.append("block_incomplete")
        elif inst_a[field] != inst_b[field]:
            reasons.append(reason)

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
        "coverage_pct": [_pin_of(first, "scope").get("coverage_pct"),
                         _pin_of(second, "scope").get("coverage_pct")],
        # Shown, not compared. Two paths differing says nothing about whether the
        # runs read the same estate, and a reader who wants that reads the commits.
        "targets": [_pin_of(first, "corpus").get("target"),
                    _pin_of(second, "corpus").get("target")],
    }


def verdict_line(block: dict[str, Any]) -> str:
    """One sentence for the person who signs the report rather than runs the tool.

    Derived from the block's own identity flag rather than recomputed from the
    counts. Recomputing would let this sentence and the block disagree, which is
    the version-versus-commit failure in miniature.
    """
    scope = block["scope"]
    hidden = (block.get("directories_not_entered") or {}).get("count", 0)
    if hidden:
        return (f"This scan cannot account for every file: {hidden} "
                f"director{'y' if hidden == 1 else 'ies'} could not be entered, so the "
                f"{scope['files_present']} files counted are not all there were.")
    if not block["accounts_for_every_file"]:
        return (f"This scan cannot account for every file: {scope['files_present']} were "
                f"present and the reasons given do not add up to them.")
    if scope["files_not_examined"] == 0:
        return (f"This scan read every one of the {scope['files_present']} files it was "
                f"given.")
    # One clause, naming where the mass of the gap sits. Not the breakdown: a
    # breakdown is a table and gets left behind, a clause travels with the number
    # and a reader who strips it has removed something visible from a sentence.
    gap = next((r for r in block["not_examined"]
                if r["count"] and (r.get("concentration") or {}).get("largest_group")), None)
    clause = ""
    if gap:
        c = gap["concentration"]
        g = c["largest_group"]
        kinds = [("files with no extension" if k == "(no extension)" else k)
                 for k in g["kinds"]]
        named = kinds[0] if len(kinds) == 1 else f"{', '.join(kinds[:-1])} and {kinds[-1]}"
        # Three values, and each earns its room. The cardinality is the null the
        # share is read against: three of 24 kinds at 69% is five times a flat
        # split, three of five at 69% is barely more than one (Nguyen Xuan Dong).
        # The partition says what a kind is, because the same repository split by
        # directory or by language gives a different share with nothing changing
        # on disk (Govardhan Yadava). Bracketed mid-sentence, because a trailing
        # clause can be dropped by stopping early and a bracket has to be cut into.
        unit = c["partition"].split()[-1] if c.get("partition") else "kinds"
        clause = (f" ({len(kinds)} of {c['distinct_kinds']}, by {unit} — {named} — "
                  f"being {g['share_pct']}% of them)")
    remaining = scope["files_not_examined"]
    tail = "is listed with a reason" if remaining == 1 else "are listed with a reason each"
    return (f"This scan read {scope['files_examined']} of {scope['files_present']} files "
            f"({scope['coverage_pct']}%); the remaining {remaining}{clause} {tail}.")
