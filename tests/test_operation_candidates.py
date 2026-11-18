"""Candidate spellings that tools/catalogue_refresh.py found on the pages the catalogue cites and
the catalogue does not hold (tests/fixtures/operation_candidates.json, written by that tool).

Each is a closure case marked xfail("candidate, unconfirmed"): nobody has yet said it is a
spelling of the operation. Its snippet and expectation are the refresh entry's own, with the
candidate put in, and the expectation asks only that the scanner say something on that line.
An XPASS is a candidate the scanner already reads; a failure is one it is silent on.

A candidate is confirmed by moving it into data/operations/<operation>.toml with its source and
quote; from then on test_operation_closure.py runs it for real, and this file leaves it out.
The file never fetches anything: the tool does that, by hand, and this test only reads.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qrp_mcp import operations
from qrp_mcp.scan import scan_directory
from test_operation_closure import _check, _write

CANDIDATES = Path(__file__).parent / "fixtures" / "operation_candidates.json"


def _in_catalogue() -> set[tuple[str, str, str]]:
    return {(doc["operation"], eco["ecosystem"], word.lower())
            for doc in operations.catalogue() for eco in doc["ecosystems"]
            for s in eco["spellings"] for word in s["spelling"].replace("(", " ").split()}


def _cases():
    if not CANDIDATES.exists():
        return
    confirmed = _in_catalogue()
    for c in json.loads(CANDIDATES.read_text(encoding="utf-8"))["candidates"]:
        if (c["operation"], c["ecosystem"], c["candidate"].lower()) in confirmed:
            continue
        yield pytest.param(c, id=f"{c['operation']}/{c['ecosystem']}/{c['candidate']}",
                           marks=pytest.mark.xfail(reason="candidate, unconfirmed", strict=False))


@pytest.mark.parametrize("candidate", list(_cases()))
def test_the_candidate_is_read(tmp_path, candidate):
    _write(tmp_path, candidate)
    missing = _check(scan_directory(tmp_path), candidate["expect"])
    assert not missing, f"{candidate['candidate']!r} ({candidate['source']}): " + "; ".join(missing)


def test_every_candidate_names_its_page():
    if not CANDIDATES.exists():
        pytest.skip("no candidates file: tools/catalogue_refresh.py has not been run")
    data = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    assert data["by"] == "tools/catalogue_refresh.py"
    for c in data["candidates"]:
        assert c["source"].startswith("https://") and c["context"] and c["candidate"] in c["snippet"], c
