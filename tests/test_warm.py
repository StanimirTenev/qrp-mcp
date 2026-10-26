"""The start-up cache (_warm, release 3c) answers exactly as computing afresh would."""

from __future__ import annotations

import marshal
import re

import pytest

from qrp_mcp import _warm, detectors, linegate


@pytest.fixture
def fresh_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.delenv("QRP_MCP_CACHE", raising=False)
    saved = dict(_warm._state)
    _warm._state.update(loaded=False, path=None, data=None, dirty=False, original=None)
    yield tmp_path
    _warm.stop_regex()
    _warm._state.clear()
    _warm._state.update(saved)


def _rule_patterns() -> list[re.Pattern]:
    found = [p for _, _, p in detectors.ALGORITHM_PATTERNS]
    for module in (detectors, detectors.components, detectors.oids, detectors.dnssec,
                   detectors.opcua, detectors.aws_tls, detectors.ike, linegate):
        found += [v for v in vars(module).values() if isinstance(v, re.Pattern)]
    return found


def test_a_kept_regex_is_the_regex_compiled_afresh(fresh_cache):
    patterns = _rule_patterns()
    assert len(patterns) > 300
    _warm.start_regex()
    try:
        first = [re._compiler.compile(p.pattern, p.flags) for p in patterns]   # kept now
        second = [re._compiler.compile(p.pattern, p.flags) for p in patterns]  # read back
    finally:
        _warm.stop_regex()
    afresh = [re._compiler.compile(p.pattern, p.flags) for p in patterns]
    # Pattern equality compares the pattern, the flags and the compiled code.
    assert first == afresh and second == afresh
    assert all(a.groupindex == b.groupindex and a.groups == b.groups
               for a, b in zip(second, afresh))


def test_the_file_is_written_and_read_back(fresh_cache):
    _warm.start_regex()
    try:
        re._compiler.compile(r"(?P<x>rsa)-(\d+)", re.IGNORECASE)
        assert _warm.derived("t", ("k",), lambda: ("a", None)) == ("a", None)
    finally:
        _warm.stop_regex()
    _warm.save()
    files = list((fresh_cache / "qrp-mcp").glob("start-*.marshal"))
    assert len(files) == 1
    data = marshal.loads(files[0].read_bytes())
    assert (r"(?P<x>rsa)-(\d+)", int(re.IGNORECASE)) in data["regex"]
    _warm._state.update(loaded=False, path=None, data=None, dirty=False)
    assert _warm.derived("t", ("k",), lambda: pytest.fail("not read back")) == ("a", None)


def test_a_damaged_file_is_computed_around(fresh_cache):
    path = _warm._path()
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\x00not marshal")
    assert _warm.derived("t", 1, lambda: 7) == 7
    _warm._state["data"]["regex"][("abc", 0)] = ("wrong", "shape")
    _warm.start_regex()
    try:
        assert re._compiler.compile("abc", 0) == re._compiler.compile("abc", 0)
        assert re._compiler.compile("abc", 0).match("abc")
    finally:
        _warm.stop_regex()


def test_off_reads_and_writes_nothing(fresh_cache, monkeypatch):
    monkeypatch.setenv("QRP_MCP_CACHE", "0")
    assert _warm.derived("t", 1, lambda: 7) == 7
    _warm.save()
    assert not (fresh_cache / "qrp-mcp").exists()


def test_the_derived_rule_data_is_what_the_rules_give():
    for _, _, pattern, literals in detectors._FILTERED_PATTERNS:
        assert literals == detectors._prefilter(pattern)
    gate = detectors.LINE_GATE
    words = set(linegate.LITERALS) | {n.lower() for n in detectors.HYBRIDS}
    assert gate.words == sorted(w for w in words if not any(v != w and v in w for v in words))
    everything = detectors._ALL_LITERALS
    assert detectors._INSIDE == {s: frozenset(t for t in everything if t in s)
                                 for s in everything}
