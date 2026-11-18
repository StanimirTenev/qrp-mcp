#!/usr/bin/env python3
"""Look again at the pages the operation catalogue cites, for spellings it does not have yet.

A maintainer's tool, never part of a scan: the scanner stays offline and deterministic, and
nothing here changes a detector or the catalogue. It proposes; a person (or an agent) confirms.

For every `[[ecosystems.refresh]]` entry of src/qrp_mcp/data/operations/*.toml:
  1. fetch the page at `source` (or read a saved copy, --pages);
  2. find every match of `pattern` on it -- an explicit regular expression written for that
     page, never a learned one; group 1 is the candidate if the pattern has a group;
  3. keep the matches the catalogue does not know: not a word of any spelling or snippet of
     that ecosystem, not in `ignore`, and -- when `window` is set -- no farther than `window`
     characters from a match the catalogue does know (a new value next to known ones);
  4. write each candidate with its page and context line to a report, and to the candidates
     file that tests/test_operation_candidates.py turns into an xfail("candidate,
     unconfirmed") closure test, built from the entry's `snippet` and `expect` with
     `{candidate}` put in.

A candidate is confirmed by moving it into the catalogue with its source and quote; from then
on it is an ordinary closure case, and it fails until the detector covers it.

Every entry also gets two controls, written beside the candidates: a positive one -- the first
name on the page the catalogue knows (or the entry's `control`), through the same snippet and
expectation -- and a negative one, NEGATIVE (or the entry's `negative`, where NEGATIVE does not
have the shape of the page's names), a name that exists nowhere. A candidate's XFAIL is
silence only if the positive control passes and the negative one fails. An entry whose
negative control is read anyway says `discriminates = false`, and its candidates are listed,
not tried. A file entry gives `material` (key material made by the test) and `relabel` (the
PEM label to put on it, `{candidate}`) instead of a snippet.

Every source is reported with how it went, so that silence is never read as "nothing new":
  fetched / saved copy / unreachable, its sha256, the known spellings of that page the pattern
  finds again (k of n; 0 of n is a blind pattern), and the candidates. A source the catalogue
  cites with no refresh entry is listed as not examined.

    python tools/catalogue_refresh.py --report refresh.md
    python tools/catalogue_refresh.py --pages saved/ --report refresh.md     # offline
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import html
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = ROOT / "src" / "qrp_mcp" / "data" / "operations"
CANDIDATES = ROOT / "tests" / "fixtures" / "operation_candidates.json"
NEGATIVE = "QRP_NO_SUCH_NAME"
USER_AGENT = "catalogue-refresh/1 (documentation re-read; maintainer tool)"
_WORD = re.compile(r"[A-Za-z0-9_@.+:/-]+")
_BLOCK_TAG = re.compile(r"</?(?:p|div|br|li|tr|td|th|h[1-6]|pre|dt|dd|table|section|code)\b[^>]*>", re.I)


def page_text(raw: bytes) -> str:
    """A page as lines of text: tags off, entities read, block elements on lines of their own."""
    text = raw.decode("utf-8", errors="replace")
    if "<html" in text[:2000].lower() or "<!doctype html" in text[:2000].lower():
        text = re.sub(r"<script.*?</script>|<style.*?</style>", " ", text, flags=re.S | re.I)
        text = _BLOCK_TAG.sub("\n", text)
        text = html.unescape(re.sub(r"<[^>]+>", "", text))
    return "\n".join(" ".join(line.split()) for line in text.splitlines() if line.strip())


def words(text: str) -> set[str]:
    """The words of a spelling or snippet, lower-cased, whole and cut at punctuation
    (`ECCurve.NamedCurves.nistP256` is also `nistp256`), and without the dashes at their ends
    (`-----BEGIN PKCS7-----` is also `begin` and `pkcs7`)."""
    out: set[str] = set()
    for w in _WORD.findall(text):
        out.add(w.lower())
        out.add(w.strip("-").lower())
        out.update(p.lower() for p in re.split(r"[(),;:=\"'/.]", w) if p)
    return out


class Known(set):
    """What the ecosystem's spellings and snippets already hold: their words, and their text, so
    that a candidate of several words (a PEM label, `PRIVATE KEY`) is known when the text has it."""

    def __init__(self, ecosystem: dict[str, Any]):
        texts = [str(s.get(f, "")) for s in ecosystem.get("spellings", []) for f in ("spelling", "snippet")]
        super().__init__(w for text in texts for w in words(text))
        self.text = "\n".join(texts).lower()

    def __contains__(self, candidate: object) -> bool:
        c = str(candidate)
        return set.__contains__(self, c) or (" " in c and re.search(
            r"(?<!\w)" + re.escape(c) + r"(?!\w)", self.text) is not None)


def known_words(ecosystem: dict[str, Any]) -> Known:
    return Known(ecosystem)


def fetch(url: str, pages: dict[str, Path] | None) -> tuple[str, bytes | None]:
    if pages is not None:
        path = pages.get(url)
        return ("saved copy", path.read_bytes()) if path and path.exists() else ("unreachable", None)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            return "fetched", resp.read()
    except Exception as exc:  # any failure is reported, never taken for an empty page
        return f"unreachable ({type(exc).__name__})", None


def examine(entry: dict[str, Any], text: str, known: Known, cited: list[dict[str, Any]]) -> dict[str, Any]:
    pattern = re.compile(entry["pattern"])
    ignore = {i.lower() for i in entry.get("ignore", [])}
    window = int(entry.get("window", 0))
    hits = [(m.group(1) if pattern.groups else m.group(0), m.start()) for m in pattern.finditer(text)]
    known_at = [pos for cand, pos in hits if cand.lower() in known]
    control = entry.get("control") or next((cand for cand, _ in hits if cand.lower() in known), None)
    found_known = {cand.lower() for cand, _ in hits if cand.lower() in known}
    # the spellings citing this page whose words the pattern finds there again
    refound = sum(1 for s in cited
                  if (words(s["spelling"]) | words(s.get("snippet", ""))) & found_known
                  or any(" " in k and k in (s["spelling"] + "\n" + s.get("snippet", "")).lower() for k in found_known))
    candidates: dict[str, str] = {}
    seen: set[str] = set()
    for cand, pos in hits:
        key = cand.lower()
        if key in known or key in ignore or key in seen:
            continue
        if window and not any(abs(pos - k) <= window for k in known_at):
            continue
        start = text.rfind("\n", 0, pos) + 1
        end = text.find("\n", pos)
        line = text[start:end if end >= 0 else len(text)]
        seen.add(key)
        candidates[cand] = line if len(line) <= 300 else line[max(0, pos - start - 140):pos - start + 160]
    return {"matches": len(hits), "known_refound": refound, "known_cited": len(cited),
            "candidates": candidates, "control": control}


def _fill(value: Any, candidate: str) -> Any:
    if isinstance(value, str):
        return value.replace("{candidate}", candidate)
    if isinstance(value, list):
        return [_fill(v, candidate) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, candidate) for k, v in value.items()}
    return value


def _case(entry: dict[str, Any], candidate: str) -> dict[str, Any]:
    """The entry's file, snippet (or material and relabel) and expectation, with the name in."""
    case: dict[str, Any] = {"candidate": candidate, "file": entry["file"]}
    for key in ("snippet", "material", "relabel", "expect"):
        if key in entry:
            case[key] = _fill(entry[key], candidate)
    return case


def refresh(catalogue: Path = CATALOGUE, pages: dict[str, Path] | None = None) -> dict[str, Any]:
    sources, cases, not_examined, controls = [], [], [], []
    for path in sorted(catalogue.glob("*.toml")):
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
        for eco in doc["ecosystems"]:
            known = known_words(eco)
            entries = eco.get("refresh", [])
            examined = {e["source"] for e in entries}
            for url in sorted({s["source"] for s in eco["spellings"] if s["source"] != "none"} - examined):
                not_examined.append({"operation": doc["operation"], "ecosystem": eco["ecosystem"], "source": url,
                                     "spellings": sum(1 for s in eco["spellings"] if s["source"] == url)})
            for entry in entries:
                status, raw = fetch(entry["source"], pages)
                row: dict[str, Any] = {"operation": doc["operation"], "ecosystem": eco["ecosystem"],
                                       "source": entry["source"], "pattern": entry["pattern"], "status": status}
                if raw is None:
                    sources.append(row)
                    continue
                row["sha256"] = hashlib.sha256(raw).hexdigest()
                cited = [s for s in eco["spellings"] if s["source"] == entry["source"]]
                row.update(examine(entry, page_text(raw), known, cited))
                control = row.pop("control")
                discriminates = entry.get("discriminates", True)
                controls.append({"operation": doc["operation"], "ecosystem": eco["ecosystem"],
                                 "source": entry["source"], "discriminates": discriminates,
                                 "positive": _case(entry, control) if control else None,
                                 "negative": _case(entry, entry.get("negative", NEGATIVE))})
                if row["known_cited"] and not row["known_refound"]:
                    row["status"] += "; blind pattern (finds none of the page's known spellings)"
                sources.append(row)
                for cand, context in row["candidates"].items():
                    cases.append({"operation": doc["operation"], "ecosystem": eco["ecosystem"],
                                  "source": entry["source"], "context": context,
                                  "discriminates": discriminates, **_case(entry, cand)})
    return {"sources": sources, "not_examined": not_examined, "candidates": cases, "controls": controls}


def report(result: dict[str, Any], when: str) -> str:
    out = [f"# Catalogue refresh, {when}", "",
           "Candidates are proposals, not findings: each is a word on a cited page that the "
           "catalogue does not hold. None is in the catalogue until a person moves it there with "
           "its source.", "",
           f"- sources examined: {len(result['sources'])}; not examined (no refresh entry): "
           f"{len(result['not_examined'])}; candidates: {len(result['candidates'])}", "",
           "## Sources", "", "| operation | ecosystem | source | status | sha256 | matches | known re-found | candidates |",
           "|---|---|---|---|---|---|---|---|"]
    for s in result["sources"]:
        out.append(f"| {s['operation']} | {s['ecosystem']} | {s['source']} | {s['status']} | "
                   f"{s.get('sha256', '')[:12]} | {s.get('matches', '')} | "
                   f"{s.get('known_refound', '')}/{s.get('known_cited', '')} | {len(s.get('candidates', {}))} |")
    out += ["", "## Not examined", "", "| operation | ecosystem | source | spellings citing it |", "|---|---|---|---|"]
    out += [f"| {n['operation']} | {n['ecosystem']} | {n['source']} | {n['spellings']} |" for n in result["not_examined"]]
    out += ["", "## Candidates", "", "| operation | ecosystem | candidate | source | context |", "|---|---|---|---|---|"]
    out += [f"| {c['operation']} | {c['ecosystem']} | `{c['candidate']}` | {c['source']} | "
            f"{c['context'].replace('|', '/')[:200]} |" for c in result["candidates"]]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--catalogue", type=Path, default=CATALOGUE)
    p.add_argument("--pages", type=Path, help="offline: a directory with URLS.tsv (url<TAB>file) and the saved pages")
    p.add_argument("--report", type=Path, help="write the report here (default: standard output)")
    p.add_argument("--candidates", type=Path, default=CANDIDATES, help="the file the xfail tests read")
    a = p.parse_args(argv)
    pages = None
    if a.pages:
        pages = {}
        for line in (a.pages / "URLS.tsv").read_text(encoding="utf-8").splitlines():
            if line.strip():
                url, name = line.split("\t")
                pages[url] = a.pages / name.strip()
    result = refresh(a.catalogue, pages)
    when = datetime.date.today().isoformat()
    text = report(result, when)
    if a.report:
        a.report.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    a.candidates.parent.mkdir(parents=True, exist_ok=True)
    a.candidates.write_text(json.dumps({"generated": when, "by": "tools/catalogue_refresh.py",
                                        "candidates": result["candidates"], "controls": result["controls"]},
                                       indent=1, ensure_ascii=False) + "\n",
                            encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
