"""Release D: the line gate may only cost time, never a finding.

linegate marks the lines any rule could match and every other line is passed over by every
rule (src/qrp_mcp/linegate.py). Two engines do the marking: the pure-Python search, always
there, and the compiled core (qrp-mcp-core), when installed. Both are checked here against
reading every line, over this repository's own tests and source -- thousands of lines
written to name, ban, quote and almost-name algorithms -- and over lines made to sit on
the gate's edges. The batches read in parallel are checked against one pass.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qrp_mcp import (assets, aws_tls, components, detectors as d, dnssec, ike, linegate, oids,
                     opcua)
from qrp_mcp.scan import scan_directory

ROOT = Path(__file__).resolve().parent.parent
TREES = [ROOT / "tests", ROOT / "src"]

try:
    import qrp_mcp_core  # noqa: F401
    HAVE_CORE = True
except ImportError:
    HAVE_CORE = False


def _gate(core: bool) -> linegate.Gate:
    gate = linegate.Gate([f[3] for f in d._FILTERED_PATTERNS],
                         [f[2] for f in d._FILTERED_PATTERNS], d._BLOB.pattern, use_core=core)
    if core and gate.compiled() is None:
        pytest.skip("qrp-mcp-core is not installed")
    return gate


ENGINES = [pytest.param(False, id="python"), pytest.param(True, id="core")]


def _files():
    for tree in TREES:
        for path in d.iter_repo_files(tree, {}, []):
            read = d._read_file(path, tree)
            if read is not None:
                yield path, path.relative_to(tree).as_posix(), read[1]


# Edges: a block comment and a docstring opened and closed on lines no rule matches, a
# denial block whose body names algorithms, a control character Python's \s matches and
# an ASCII-only \s does not, a line beyond ASCII, a name beside a base64 run.
EDGES = {
    "edge.c": ("/* the text below\n   says nothing\n   RSA_new() in a comment */\n"
               "int x = RSA_new();\n/*\n*/ EC_KEY_new();\n"),
    "edge.py": ('"""\nnothing here\nhashlib.md5() in a docstring\n"""\nhashlib.md5(b"")\n'
                "def f():\n    '''\n    plain\n    '''\n    return hashlib.sha1()\n"),
    "edge.yaml": ("disabled_algorithms:\n  - plain\n  - rsa\n  - md5\nallowed:\n  - ECDSA\n"
                  "groups = X25519\x1fP-256\n"),
    "edge.go": "// café rsa\nk, _ := rsa.GenerateKey(rand.Reader, 2048) // é\n",
    "edge.js": ("const blob = 'QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2"
                "d3h5ejAxMjM0NTY3ODk=RSA'; createHash('md5')\n"),
    "edge.conf": "ssl_ciphers 'AES128-SHA:!MD5';\nKexAlgorithms -diffie-hellman-group1-sha1\n",
}


@pytest.mark.parametrize("core", ENGINES)
def test_the_gate_finds_what_reading_every_line_finds(core, tmp_path):
    gate = _gate(core)
    files = list(_files())
    for name, text in EDGES.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
        files.append((tmp_path / name, name, text.splitlines()))
    assert len(files) > 150
    for path, rel, lines in files:
        hot = gate.hot_lines(lines, read_all=path.suffix.lower() == ".properties")
        for exclusions in (False, True):
            every = d.scan_source_file(path, rel, lines, cipher_exclusions=exclusions, hot=None)
            gated = d.scan_source_file(path, rel, lines, cipher_exclusions=exclusions, hot=hot)
            assert gated == every, f"{rel} (cipher_exclusions={exclusions})"


RULES = [assets.scan_protocols, assets.scan_tls_groups, assets.scan_hybrid_groups,
         d.scan_hybrid_names, assets.scan_static_rsa_kex, assets.scan_ssh_kex, d._policy_assets,
         dnssec.unnamed_records, d.scan_openssl3_names, d.scan_cose_algorithms, d.scan_jca_names,
         opcua.scan, aws_tls.scan, ike.fortios_addke, dnssec.scan_records, d.scan_cipher_suites,
         assets.static_rsa_positions, d.PPK_CONFIG_ASSIGN.search, d._DENIAL_WORDS.search]
ON_MASKED = [d._key_type_values, components.scan, oids.scan]


@pytest.mark.parametrize("core", ENGINES)
def test_no_rule_matches_a_line_the_gate_passes_over(core):
    gate = _gate(core)
    passed_over = 0
    for path, rel, lines in _files():
        hot = gate.hot_lines(lines, read_all=path.suffix.lower() == ".properties")
        if hot is None:
            continue
        for i, line in enumerate(lines):
            if i in hot.lines:
                continue
            passed_over += 1
            masked = d._masked(line, d._blob_spans(line))
            for rule in RULES:
                assert not rule(line), f"{rule.__name__} on {rel}:{i + 1}: {line!r}"
            for rule in ON_MASKED:
                assert not rule(masked), f"{rule.__name__} on {rel}:{i + 1}: {line!r}"
            if i not in hot.patterns:
                assert not d._a_pattern_matches(line), f"a pattern on {rel}:{i + 1}: {line!r}"
    assert passed_over > 10_000


def test_the_core_names_every_pattern_that_matches():
    """The compiled core's `allowed` narrows the patterns tried on a line; every pattern
    that matches the line outside a blob must be in it."""
    gate = _gate(True)
    for path, rel, lines in _files():
        hot = gate.hot_lines(lines)
        for i, allowed in (hot.allowed or {}).items():
            blobs = d._blob_spans(lines[i])
            searched = d._masked(lines[i], blobs)
            lowered = searched.lower()
            matched = {k for k, f in enumerate(d._FILTERED_PATTERNS)
                       if any(s in lowered for s in f[3])
                       and any(not d._in_blob(m.start(), blobs) for m in f[2].finditer(searched))}
            assert matched <= allowed, f"{rel}:{i + 1}: {sorted(matched - allowed)}"


def test_every_algorithm_pattern_ports_to_the_core():
    """A pattern the core's dialect cannot hold makes the core vouch for none of them: right,
    and slow. A new pattern should port, or this says which one does not."""
    unported = [f[0] + ": " + f[2].pattern[:60] for f in d._FILTERED_PATTERNS
                if linegate.rust_regex(f[2]) is None]
    assert not unported


def _without_window(result):
    window = result["coverage"].get("window", {})
    for key in ("started_at", "finished_at", "seconds"):
        window.pop(key, None)
    return result


def test_parallel_batches_give_the_single_pass(monkeypatch):
    tree = ROOT / "tests"
    monkeypatch.setenv("QRP_MCP_JOBS", "1")
    single = d.scan_repo(tree)
    monkeypatch.setenv("QRP_MCP_JOBS", "3")
    parallel = d.scan_repo(tree)
    assert parallel == single
    assert single["files_present"] > 150


@pytest.mark.parametrize("core", ENGINES)
def test_the_scan_is_the_same_whichever_gate(core, monkeypatch):
    tree = ROOT / "tests"
    monkeypatch.setattr(d, "LINE_GATE", _gate(core))
    gated = _without_window(scan_directory(tree))
    monkeypatch.setattr(d, "hot_lines", lambda lines, ext: None)
    every = _without_window(scan_directory(tree))
    assert gated == every
