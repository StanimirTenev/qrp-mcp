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

import importlib.util
import json
from pathlib import Path

import pytest

from qrp_mcp import operations
from qrp_mcp.scan import scan_directory
from test_operation_closure import _check, _write

CANDIDATES = Path(__file__).parent / "fixtures" / "operation_candidates.json"


def _tool():
    spec = importlib.util.spec_from_file_location(
        "catalogue_refresh", Path(__file__).resolve().parents[1] / "tools" / "catalogue_refresh.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _confirmed(catalogue: list[dict]):
    """Whether a candidate is in the catalogue now, by the tool's own test of "known"."""
    tool = _tool()
    known = {(doc["operation"], eco["ecosystem"]): tool.Known(eco)
             for doc in catalogue for eco in doc["ecosystems"]}
    return lambda c: (c["operation"], c["ecosystem"]) in known and c["candidate"].lower() in known[
        (c["operation"], c["ecosystem"])]


def _cases():
    if not CANDIDATES.exists():
        return
    confirmed = _confirmed(operations.catalogue())
    for c in json.loads(CANDIDATES.read_text(encoding="utf-8"))["candidates"]:
        if confirmed(c):
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


def test_a_confirmed_candidate_leaves_this_file():
    catalogue = [{"operation": "ssh", "ecosystem": "SSH", "ecosystems": [{"ecosystem": "SSH", "spellings": [
        {"spelling": "KexAlgorithms sntrup761x25519-sha512@openssh.com", "snippet": "x"},
        {"spelling": "-----BEGIN PRIVATE KEY-----", "snippet": "x"}]}]}]
    confirmed = _confirmed(catalogue)
    assert confirmed({"operation": "ssh", "ecosystem": "SSH", "candidate": "sntrup761x25519-sha512@openssh.com"})
    assert confirmed({"operation": "ssh", "ecosystem": "SSH", "candidate": "PRIVATE KEY"})
    assert not confirmed({"operation": "ssh", "ecosystem": "SSH", "candidate": "sntrup761x25519-sha512"})
