"""Whether a fix closed what a scan found: two scans, before and after, compared occurrence by occurrence.

A finding that is absent from the second scan has not necessarily been fixed. It may
have moved down the file, moved to another file, landed in a directory the second run
could not open, or stopped matching because the scanner changed. Each of those reads
exactly like a fix when the only question asked is "is it still in the list", and each
is a way to certify work that was not done. So this module answers two questions, in
order:

1. Can these two runs be compared for closure at all? The instrument must be the same
   code with the same rules, both runs pinned and clean. The corpus is allowed to
   differ -- that difference is what is being measured -- which is why this is a
   sibling of `coverage.compare` rather than a call to it.
2. Only if they can: what happened to each occurrence -- closed, still open (and
   whether it only moved lines), relocated to another path, new, or unverifiable
   because the second run did not read the file it was in.

Nothing here is estimated. The comparison works on the two documents as written.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from .coverage import _pin_of

# Fields that locate an occurrence rather than identify it. Everything else in an
# evidence item is identity, so a category added later is compared without being
# listed here.
_LOCATION_FIELDS = ("line",)
# Kept out of identity and reported as its own transition: code moved into a test
# directory has not been fixed, and it must not look as if it had.
# The role is an interpretation of the line, not the line: two readers that read the
# same line the same way are looking at the same occurrence whatever they call its role.
_CONTEXT_FIELDS = ("in_test_code", "role")

NOT_CLOSABLE = {
    "instrument_version_differs": "a different version of the tool read the second tree; "
                                  "a finding can disappear because the reader changed",
    "instrument_commit_differs": "the same version, built from different code",
    "ruleset_differs": "the pattern counts differ, so a finding can stop matching "
                       "without the code changing",
    "claimed_types_differ": "the tool claimed different file types",
    "excluded_dirs_differ": "different directories were filtered out",
    "instrument_dirty": "an emitter with uncommitted changes did one of the readings",
    "corpus_dirty": "at least one run read uncommitted changes, so the tree it read "
                    "cannot be recovered from the commit it names",
    "excerpt_level_differs": "the two results quote their lines at different levels "
                             "(full, masked, trimmed), so the same line does not look the same",
}

UNESTABLISHED = {
    "block_incomplete": "at least one result lacks fields this comparison needs",
    "instrument_unpinned": "at least one run does not name the commit of its own emitter",
    "corpus_unpinned": "at least one run read an unpinned directory; no commit identifies "
                       "what was read",
    "instrument_cleanliness_unknown": "whether an emitter had uncommitted changes could "
                                      "not be checked",
    "corpus_cleanliness_unknown": "whether a scanned tree had uncommitted changes could not "
                                  "be checked",
    "excerpt_level_unknown": "at least one result does not say at what level it quotes "
                             "its lines (results from before 0.19.0 do not)",
    "files_read_unknown": "the second result does not list the files it read (results "
                          "from before 0.20.0 do not), so a fixed finding cannot be told "
                          "from a deleted file",
}

REPAIR = ("Scan the commit the first run read again with the instrument that did the "
          "second, from a clean checkout, and compare that pair.")


def closure_comparability(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Three verdicts, as `coverage.compare` gives them, for the question of closure."""
    cov_a, cov_b = before.get("coverage") or {}, after.get("coverage") or {}
    reasons: list[str] = []
    unestablished: list[str] = []

    def clean(a: dict[str, Any], b: dict[str, Any], dirty: str, unknown: str) -> None:
        states = [a.get("dirty"), b.get("dirty")]
        if any(s is True for s in states):
            reasons.append(dirty)
        elif any(not isinstance(s, bool) for s in states):
            unestablished.append(unknown)

    basis: list[str] = []
    tool_a = _pin_of(cov_a, "instrument", "source_commit")
    tool_b = _pin_of(cov_b, "instrument", "source_commit")
    if (not tool_a.get("pinned") and not tool_b.get("pinned")
            and tool_a.get("reason") == "no_checkout" and tool_b.get("reason") == "no_checkout"):
        # Both runs used an installed release, which is how almost everyone runs this.
        # There is no commit to name, but a published version cannot be replaced on
        # the index, so the version -- compared below, with the rules and file types --
        # identifies the code. Said in the result, because it is weaker than a commit:
        # a locally modified install would carry the same version string.
        basis.append("both runs used the same installed release; the version, not a "
                     "commit, identifies the instrument")
    elif not (tool_a.get("pinned") and tool_b.get("pinned")):
        unestablished.append("instrument_unpinned")
    elif not (tool_a.get("commit") and tool_b.get("commit")):
        unestablished.append("block_incomplete")
    else:
        if tool_a["commit"] != tool_b["commit"]:
            reasons.append("instrument_commit_differs")
        clean(tool_a, tool_b, "instrument_dirty", "instrument_cleanliness_unknown")

    corpus_a = _pin_of(cov_a, "corpus", "pinned_at")
    corpus_b = _pin_of(cov_b, "corpus", "pinned_at")
    if not (corpus_a.get("pinned") and corpus_b.get("pinned")):
        unestablished.append("corpus_unpinned")
    elif not (corpus_a.get("commit") and corpus_b.get("commit")):
        unestablished.append("block_incomplete")
    else:
        clean(corpus_a, corpus_b, "corpus_dirty", "corpus_cleanliness_unknown")

    inst_a, inst_b = _pin_of(cov_a, "instrument"), _pin_of(cov_b, "instrument")
    for field, reason in (("version", "instrument_version_differs"),
                          ("ruleset", "ruleset_differs"),
                          ("claimed_types", "claimed_types_differ"),
                          ("excluded_dirs", "excluded_dirs_differ")):
        if field not in inst_a or field not in inst_b:
            if "block_incomplete" not in unestablished:
                unestablished.append("block_incomplete")
        elif inst_a[field] != inst_b[field]:
            reasons.append(reason)

    level_a, level_b = before.get("excerpt_level"), after.get("excerpt_level")
    if level_a is None or level_b is None:
        unestablished.append("excerpt_level_unknown")
    elif level_a != level_b:
        reasons.append("excerpt_level_differs")

    if not isinstance(after.get("files_read"), list):
        unestablished.append("files_read_unknown")

    verdict = "not_comparable" if reasons else "unestablished" if unestablished else "comparable"
    return {
        "verdict": verdict,
        "differences": [{"reason": r, "meaning": NOT_CLOSABLE[r]} for r in reasons],
        "unestablished": [{"reason": r, "meaning": UNESTABLISHED[r]} for r in unestablished],
        "basis": basis,
        # Shown, not compared: nothing in the two documents proves they describe the
        # same repository, and this does not claim it.
        "targets": [_pin_of(cov_a, "corpus").get("target"), _pin_of(cov_b, "corpus").get("target")],
        "commits": [corpus_a.get("commit"), corpus_b.get("commit")],
    }


def _identity(category: str, item: dict[str, Any], with_path: bool = True) -> str:
    fields = {k: v for k, v in item.items()
              if k not in _LOCATION_FIELDS + _CONTEXT_FIELDS and (with_path or k != "path")}
    if isinstance(fields.get("excerpt"), str):
        fields["excerpt"] = " ".join(fields["excerpt"].split())
    return category + "|" + json.dumps(fields, sort_keys=True, ensure_ascii=False)


def _occurrences(result: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out = []
    for category, items in sorted((result.get("evidence") or {}).items()):
        if isinstance(items, list):
            out.extend((category, item) for item in items if isinstance(item, dict))
    return out


def _unread_paths(result: dict[str, Any]) -> tuple[set[str], list[str]]:
    """Files the run did not read, and directory prefixes it could not enter."""
    files: set[str] = set()
    for key in ("unreadable_files", "files_left_out"):
        for entry in result.get(key) or []:
            path = entry.get("path") if isinstance(entry, dict) else entry
            if isinstance(path, str):
                files.add(path)
    dirs = [d.rstrip("/") + "/" for d in result.get("unreadable_directories") or []
            if isinstance(d, str)]
    # A linked file is a file not read; a linked directory hides everything under it.
    for entry in result.get("symlinks_not_followed") or []:
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            if entry.get("kind") == "directory" or entry["path"].endswith("/"):
                dirs.append(entry["path"].rstrip("/") + "/")
            else:
                files.add(entry["path"])
    return files, dirs


def _brief(category: str, item: dict[str, Any]) -> dict[str, Any]:
    keep = ("path", "line", "algorithm", "type", "protocol", "version", "package",
            "group", "setting", "offered",
            "evidence_kind", "excerpt", "in_test_code", "role")
    return {"category": category, **{k: item[k] for k in keep if k in item}}


def _family(item: dict[str, Any]) -> str:
    # Counted apart from the X25519 family it belongs to: the fallback going away is
    # the change to see, and inside the family count it is one of several.
    if item.get("offered") and item.get("group"):
        return f"{item['group']} offered {item['offered']}"
    for key in ("algorithm", "type", "protocol", "package"):
        if item.get(key):
            return str(item[key])
    return "?"


def prove_closure(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two full scan results of the same tree, before and after a change."""
    comparability = closure_comparability(before, after)
    if comparability["verdict"] != "comparable":
        return {
            "comparability": comparability,
            "closure": None,
            "statement": ("No finding is reported as closed: these two runs cannot be "
                          "compared for closure. " + REPAIR),
        }

    groups_a: dict[str, list] = defaultdict(list)
    groups_b: dict[str, list] = defaultdict(list)
    for category, item in _occurrences(before):
        groups_a[_identity(category, item)].append((category, item))
    for category, item in _occurrences(after):
        groups_b[_identity(category, item)].append((category, item))

    still_open, moved_lines, into_test, out_of_test = [], 0, [], []
    left_a, left_b = [], []
    for key in set(groups_a) | set(groups_b):
        a = sorted(groups_a.get(key, []), key=lambda ci: ci[1].get("line") or 0)
        b = sorted(groups_b.get(key, []), key=lambda ci: ci[1].get("line") or 0)
        for (cat, ia), (_, ib) in zip(a, b):
            still_open.append(_brief(cat, ib))
            if ia.get("line") != ib.get("line"):
                moved_lines += 1
            if ia.get("in_test_code") is False and ib.get("in_test_code") is True:
                into_test.append(_brief(cat, ib))
            elif ia.get("in_test_code") is True and ib.get("in_test_code") is False:
                out_of_test.append(_brief(cat, ib))
        left_a.extend(a[len(b):])
        left_b.extend(b[len(a):])

    # What vanished from one path and appeared on another, unchanged, was renamed or
    # moved -- not fixed.
    pool: dict[str, list] = defaultdict(list)
    for cat, item in left_b:
        pool[_identity(cat, item, with_path=False)].append((cat, item))
    relocated, gone = [], []
    for cat, item in left_a:
        match = pool.get(_identity(cat, item, with_path=False))
        if match:
            _, moved_to = match.pop(0)
            relocated.append({**_brief(cat, item), "now_at": moved_to.get("path"),
                              "now_line": moved_to.get("line")})
        else:
            gone.append((cat, item))
    new = [_brief(cat, item) for bucket in pool.values() for cat, item in bucket]

    unread_files, unread_dirs = _unread_paths(after)
    read_after = set(after["files_read"])
    closed, removed, unverifiable = [], [], []
    for cat, item in gone:
        path = str(item.get("path") or "")
        if path in unread_files or any(path.startswith(d) for d in unread_dirs):
            unverifiable.append({**_brief(cat, item),
                                 "why": "the second run did not read this file"})
        elif path not in read_after:
            # The whole file is gone. Deleting code does remove it, but it is also the
            # cheapest way to make a finding disappear, and a rival tool counts it as
            # fixed. Named apart, not counted as closed.
            removed.append({**_brief(cat, item),
                            "why": "the file is not in the second tree"})
        else:
            closed.append(_brief(cat, item))

    per_family: dict[str, list[int]] = {}
    count_a = Counter(_family(i) for _, i in _occurrences(before))
    count_b = Counter(_family(i) for _, i in _occurrences(after))
    for fam in sorted(set(count_a) | set(count_b)):
        per_family[fam] = [count_a.get(fam, 0), count_b.get(fam, 0)]

    return {
        "comparability": comparability,
        "closure": {
            "closed": closed,
            "removed": removed,
            "still_open_count": len(still_open),
            "still_open_moved_lines": moved_lines,
            "relocated": relocated,
            "moved_into_test_code": into_test,
            "moved_out_of_test_code": out_of_test,
            "new": new,
            "unverifiable": unverifiable,
            "per_family_before_after": per_family,
        },
        "statement": (f"{len(closed)} occurrence(s) closed, {len(removed)} removed with "
                      f"their file, {len(still_open)} still open "
                      f"({moved_lines} of them only moved lines), {len(relocated)} relocated to "
                      f"another path, {len(new)} new, {len(unverifiable)} unverifiable. "
                      f"Closed means present in the first tree and absent from every file "
                      f"the second run read, under the same instrument. Removed means the "
                      f"whole file is gone; whether its cryptography is still needed "
                      f"elsewhere is not something this comparison can see."),
    }
