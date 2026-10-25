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

from qrp_mcp import (assets, aws_tls, components, detectors as d, dnssec, ike, indirection,
                     linegate, oids, opcua)
from qrp_mcp.scan import scan_directory

ROOT = Path(__file__).resolve().parent.parent
TREES = [ROOT / "tests", ROOT / "src"]

try:
    import qrp_mcp_core  # noqa: F401
    HAVE_CORE = True
except ImportError:
    HAVE_CORE = False


def _gate(core: bool) -> linegate.Gate:
    gate = d.line_gate(use_core=core)
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
    # Release 3c: the suite, version and hybrid gates as their rules read them, and denial
    # blocks opened on lines no rule matches, behind a comment or a docstring.
    "edge3c.c": ("static const char *deny_list[] = {  /* forbidden, see below */\n"
                 "  \"RSA\", \"MD5\",\n};\nCurl_ssl_init(); ssl_config.version = x;\n"
                 "int s = TLS_RSA_WITH_AES_128_CBC_SHA; /* SSL_RSA_WITH_RC4_128_SHA */\n"
                 "x = TLS1_TXT_RSA_WITH_AES_128_SHA; y = SSL3_CK_RSA_DES_192_CBC3_SHA;\n"
                 "v = SSL3_VERSION; w = TLS1_2_VERSION; z = curl_version();\n"),
    "edge3c.py": ('BLOCKED = [\n    "ecdsa",\n]\n"""\nunsupported:\n"""\nk = rsa.generate()\n'
                  "following = 'x-wing and x25519kyber768draft00'\n"
                  "groups = ['X25519MLKEM768']\n"),
    "edge3c.tf": 'tls_min_version = "1.0"\nTLS_MIN_VERSION = "1.1"\n',
    "edge3c.yaml": ("rejected:\n  - sha1\n  # removed:\nallowed:\n  - rsa\n"
                    "no longer supported:\n  - DES\n"),
    "edge3c.cfg": ("global\n  ssl-default-bind-ciphers AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256\n"
                   "  ssl-default-bind-curves X25519:P-256\nfrontend f\n"
                   "  bind :443 ssl crt /x.pem curves X25519MLKEM768:X25519 ciphers AES256-SHA\n"
                   "  server s 10.0.0.1:443 ssl ciphersuites TLS_AES_128_GCM_SHA256\n"
                   "groups = X25519:secp384r1\nCipherString = DEFAULT:AES128-SHA\n"
                   "ssl_ecdh_curve X25519:prime256v1;\nssl_ciphers 'DES-CBC3-SHA';\n"),
}


def test_the_setting_patterns_port_to_both_engines():
    """The cipher and group settings are searched as their own regexes (release 3c); one that
    did not port would make the gate read every line."""
    assert all(linegate.scoped_regex(p) and literals for p, literals in d._SETTING_PATTERNS)
    assert not d.LINE_GATE.everything


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
         assets.static_rsa_positions, d.PPK_CONFIG_ASSIGN.search]
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
            # A line that may open a denial block is read for that (Hot.state, release 3c).
            if i not in hot.state:
                assert not d._DENIAL_WORDS.search(line), f"a denial word on {rel}:{i + 1}"
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
    # A certificate's `expired` is relative to the scan's clock unless this is set (release C).
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1792886400")
    monkeypatch.setenv("QRP_MCP_JOBS", "1")
    single = d.scan_repo(tree)
    monkeypatch.setenv("QRP_MCP_JOBS", "3")
    parallel = d.scan_repo(tree)
    assert parallel == single
    assert single["files_present"] > 150


@pytest.mark.parametrize("core", ENGINES)
def test_the_scan_is_the_same_whichever_gate(core, monkeypatch):
    tree = ROOT / "tests"
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1792886400")
    monkeypatch.setattr(d, "LINE_GATE", _gate(core))
    gated = _without_window(scan_directory(tree))
    monkeypatch.setattr(d, "hot_lines", lambda lines, ext: None)
    every = _without_window(scan_directory(tree))
    assert gated == every


# --- the rules after release AB: certificates and keys (C), indirection and confidence (E) ---
# Release C reads certificates and keys from the file's bytes, and scan_embedded_keys,
# key_in_source and getproperty_reads read every line: none of them is behind the gate.
# Release E's indirection rewrites lines (an alias, folded literals, another file's constant)
# and reads the rewritten lines with scan_source_file again, whose gate is then computed on
# the REWRITTEN text: a line that names nothing until it is rewritten is cold in the file
# and hot after. Passing the file's own `hot` to that second reading would lose exactly
# those rows; the tree below holds them, and both tests fail if they are lost.
INDIRECT = {
    "alias.py": ("from cryptography.hazmat.primitives.asymmetric import rsa as keyalg\n"
                 "key = keyalg.generate_private_key(public_exponent=65537, key_size=2048)\n"),
    "consts.py": "from algs import DIGEST\nh = hashlib.new(DIGEST)\n",
    "algs.py": 'DIGEST = "md5"\n',
    "main.go": ('package main\n\nimport (\n\t"crypto/rand"\n\tasym "crypto/rsa"\n)\n\n'
                "func main() {\n\tk, _ := asym.GenerateKey(rand.Reader, 2048)\n\t_ = k\n}\n"),
    "mk.js": ("const { generateKeyPairSync: mk } = require('crypto');\n"
              "const kp = mk('rsa', { modulusLength: 2048 });\n"),
    "req.js": ("const crypto = require('crypto');\nconst { ALG } = require('./algs');\n"
               "const h = crypto.createHash(ALG);\n"),
    "algs.js": "module.exports = { ALG: 'md5' };\n",
    "Sig.java": ('class Sig { void f() throws Exception {\n'
                 '  java.security.Signature.getInstance("EC" + "DSA");\n'
                 '  java.security.KeyPairGenerator.getInstance(Algs.ASYM);\n'
                 '  String a = props.getProperty("cryptoAlg1", "AES/ECB/PKCS5Padding");\n} }\n'),
    "Algs.java": 'final class Algs {\n  static final String ASYM = "RSA";\n}\n',
    "fold.js": ("const crypto = require('crypto');\n"
                "crypto.generateKeyPairSync('r' + 'sa', { modulusLength: 2048 });\n"),
    "key.c": ('static const char *k =\n  "-----BEGIN EC PRIVATE KEY-----\\n"\n'
              '  "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\\n"\n'
              '  "-----END EC PRIVATE KEY-----\\n";\n'),
}


def _indirect_tree(tmp_path):
    for name, text in INDIRECT.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def _rewritten(path, rel, lines, root):
    """The lines indirection.resolve reads a second time (None if it rewrote none)."""
    seen = []

    def spy(p, r, rewritten):
        seen.append(rewritten)
        return d.scan_source_file(p, r, rewritten)
    indirection.resolve(path, rel, lines, d.scan_source_file(path, rel, lines), root, spy)
    return seen[0] if seen else None


@pytest.mark.parametrize("core", ENGINES)
def test_rows_found_only_through_indirection_survive_the_gate(core, tmp_path, monkeypatch):
    tree = _indirect_tree(tmp_path)
    monkeypatch.setenv("QRP_MCP_JOBS", "1")          # the patch below reaches every file
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1792886400")
    monkeypatch.setattr(d, "LINE_GATE", _gate(core))
    gated = _without_window(scan_directory(tree))
    rows = gated["evidence"]["source_code"]
    through = {(r["path"], r["line"]) for r in rows if "; read through " in r["description"]}
    # Each of these lines names nothing until it is rewritten: cold in the file.
    cold_first = {("consts.py", 2), ("req.js", 3), ("main.go", 9), ("alias.py", 2)}
    for rel, line in cold_first:
        hot = d.LINE_GATE.hot_lines(INDIRECT[rel].splitlines())
        assert hot is not None and line - 1 not in hot.lines, f"{rel}:{line} is not cold"
    assert cold_first <= through, sorted(cold_first - through)
    assert {("Sig.java", 2), ("Sig.java", 3), ("fold.js", 2), ("mk.js", 2)} <= through
    levels = {(r["path"], r["line"]): r["confidence"] for r in rows}
    assert levels[("Sig.java", 4)] == "low"              # the getProperty fallback
    assert gated["evidence"]["embedded_keys"]
    monkeypatch.setattr(d, "hot_lines", lambda lines, ext: None)
    assert gated == _without_window(scan_directory(tree))


@pytest.mark.parametrize("core", ENGINES)
def test_no_rule_matches_a_rewritten_line_the_gate_passes_over(core, tmp_path):
    """The cold-line check above, on the lines indirection reads a second time."""
    gate = _gate(core)
    tree = _indirect_tree(tmp_path)
    files = [(p, r, ls, next(t for t in TREES if t in p.parents)) for p, r, ls in _files()]
    files += [(tree / n, n, t.splitlines(), tree) for n, t in INDIRECT.items()]
    rewritten_files = 0
    for path, rel, lines, root in files:
        if path.suffix.lower() not in d.SOURCE_EXTENSIONS:
            continue
        rewritten = _rewritten(path, rel, lines, root)
        if rewritten is None:
            continue
        rewritten_files += 1
        hot = gate.hot_lines(rewritten)
        every = d.scan_source_file(path, rel, rewritten, hot=None)
        assert d.scan_source_file(path, rel, rewritten, hot=hot) == every, rel
        if hot is None:
            continue
        for i, line in enumerate(rewritten):
            if i in hot.lines:
                continue
            masked = d._masked(line, d._blob_spans(line))
            for rule in RULES:
                assert not rule(line), f"{rule.__name__} on rewritten {rel}:{i + 1}: {line!r}"
            for rule in ON_MASKED:
                assert not rule(masked), f"{rule.__name__} on rewritten {rel}:{i + 1}: {line!r}"
            if i not in hot.patterns:
                assert not d._a_pattern_matches(line), f"a pattern on rewritten {rel}:{i + 1}"
    assert rewritten_files >= 8
