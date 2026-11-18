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


def _data():
    return json.loads(CANDIDATES.read_text(encoding="utf-8")) if CANDIDATES.exists() else {}


def _cases():
    if not CANDIDATES.exists():
        return
    confirmed = _confirmed(operations.catalogue())
    for c in _data()["candidates"]:
        if confirmed(c):
            continue
        # An entry whose negative control is read too says nothing by XFAIL or XPASS: its
        # candidates are listed for a person, not run (test_the_negative_control_... holds it).
        mark = (pytest.mark.skip(reason="entry does not discriminate: a name that exists nowhere is read too")
                if c.get("discriminates") is False
                else pytest.mark.xfail(reason="candidate, unconfirmed", strict=False))
        yield pytest.param(c, id=f"{c['operation']}/{c['ecosystem']}/{c['candidate']}", marks=mark)


def _controls(kind):
    for n, e in enumerate(_data().get("controls", [])):
        if e.get(kind):
            yield pytest.param(e, id=f"{e['operation']}/{e['ecosystem']}/{n}/{e[kind]['candidate']}")


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
        assert c["source"].startswith("https://") and c["context"], c
        assert c["candidate"] in c.get("snippet", "") or c.get("relabel") == c["candidate"], c


@pytest.mark.parametrize("entry", list(_controls("positive")))
def test_the_positive_control_of_each_entry_is_read(tmp_path, entry):
    """A name the catalogue holds, through the entry's own snippet and expectation. If this
    fails, the entry's XFAILs are the expectation's blindness, not the scanner's silence."""
    case = entry["positive"]
    _write(tmp_path, case)
    missing = _check(scan_directory(tmp_path), case["expect"])
    assert not missing, f"{entry['source']}: {case['candidate']!r}: " + "; ".join(missing)


@pytest.mark.parametrize("entry", list(_controls("negative")))
def test_the_negative_control_of_each_entry_is_not_read_unless_it_says_so(tmp_path, entry):
    """A name that exists nowhere, the same way. Read, it means the entry passes anything: then
    the entry must say `discriminates = false`, and its candidates are not run."""
    case = entry["negative"]
    _write(tmp_path, case)
    read = not _check(scan_directory(tmp_path), case["expect"])
    assert read is (entry["discriminates"] is False), (
        f"{entry['source']}: {case['candidate']!r} is {'read' if read else 'not read'}; "
        f"the entry says discriminates = {entry['discriminates']}")


def test_every_examined_entry_has_its_controls():
    data = _data()
    if not data:
        pytest.skip("no candidates file")
    assert data.get("controls"), "the candidates file has no controls: rerun tools/catalogue_refresh.py"
    for e in data["controls"]:
        assert e["negative"], e["source"]
        assert e["positive"], f"{e['source']}: no name on the page the catalogue knows, so no positive control"


def test_any_and_relabel_in_the_closure_helpers(tmp_path):
    _write(tmp_path, {"file": "c.pem", "material": "CERT_RSA2048_PEM", "relabel": "X509 CERTIFICATE"})
    text = (tmp_path / "c.pem").read_text()
    assert text.startswith("-----BEGIN X509 CERTIFICATE-----") and "-----END X509 CERTIFICATE-----" in text
    result = scan_directory(tmp_path)
    hit = {"rows": [{"at": "evidence.source_code", "match": {"path": "c.pem"}}]}
    miss = {"rows": [{"at": "trust_stores.places", "match": {"path": "c.pem"}}]}
    assert not _check(result, {"any": [miss, hit]})
    assert _check(result, {"any": [miss, miss]})


def test_a_confirmed_candidate_leaves_this_file():
    catalogue = [{"operation": "ssh", "ecosystem": "SSH", "ecosystems": [{"ecosystem": "SSH", "spellings": [
        {"spelling": "KexAlgorithms sntrup761x25519-sha512@openssh.com", "snippet": "x"},
        {"spelling": "-----BEGIN PRIVATE KEY-----", "snippet": "x"}]}]}]
    confirmed = _confirmed(catalogue)
    assert confirmed({"operation": "ssh", "ecosystem": "SSH", "candidate": "sntrup761x25519-sha512@openssh.com"})
    assert confirmed({"operation": "ssh", "ecosystem": "SSH", "candidate": "PRIVATE KEY"})
    assert not confirmed({"operation": "ssh", "ecosystem": "SSH", "candidate": "sntrup761x25519-sha512"})
