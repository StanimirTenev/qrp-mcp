"""Release 3c made engine functions faster. Each must give exactly the answer it gave before:
the old version is kept here as the reference and both are run on the same inputs."""

from __future__ import annotations

import random

from qrp_mcp import detectors as d


def _comment_spans_before(line, ext, inside_block):
    """detectors._comment_spans as it was before release 3c: one character at a time."""
    slash, hash_, dash = (ext in d._SLASH_COMMENT_EXT, ext in d._HASH_COMMENT_EXT,
                          ext in d._DASH_COMMENT_EXT)
    spans = []
    n, i, quote = len(line), 0, ""
    if inside_block:
        end = line.find("*/")
        if end == -1:
            return [(0, n)], True
        spans.append((0, end + 2))
        i = end + 2
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
            i += 1
            continue
        if c in "\"'":
            quote = c
            i += 1
            continue
        if slash and line.startswith("//", i):
            spans.append((i, n))
            return spans, False
        if slash and line.startswith("/*", i):
            end = line.find("*/", i + 2)
            if end == -1:
                spans.append((i, n))
                return spans, True
            spans.append((i, end + 2))
            i = end + 2
            continue
        if hash_ and c == "#":
            spans.append((i, n))
            return spans, False
        if dash and line.startswith("--", i):
            spans.append((i, n))
            return spans, False
        i += 1
    return spans, False


_EXTS = [".c", ".py", ".sql", ".txt", ".yaml", ".go", ".lua", ""]


def _lines(count: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    alphabet = ["/", "*", "#", "-", "\"", "'", "\\", " ", "a", "R", "é", "\t", "//", "/*",
                "*/", "--", "\\\"", "\\'"]
    return ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24)))
            for _ in range(count)]


def test_comment_spans_answers_as_before_on_random_lines():
    for line in _lines(20000, 3):
        for ext in _EXTS:
            for inside in (False, True):
                assert d._comment_spans(line, ext, inside) == \
                    _comment_spans_before(line, ext, inside), (line, ext, inside)


def test_comment_spans_answers_as_before_on_real_shapes():
    real = ['x = "/*" + y  # rsa', "int a; /* RSA */ b(); // c", "-- comment", "a - b",
            "'it''s' -- x", 'printf("%s\\" /* no", a); /* yes', "#define RSA 1",
            "*/ after", "s = '\\\\' # c", "", "   ", "/", '"unterminated # x']
    for line in real:
        for ext in _EXTS:
            for inside in (False, True):
                assert d._comment_spans(line, ext, inside) == \
                    _comment_spans_before(line, ext, inside), (line, ext, inside)


def test_embedded_keys_without_a_header_is_still_nothing():
    lines = ["key = load()", "-----BEGIN", "PUBLIC KEY-----"]
    assert d.scan_embedded_keys("a.py", lines) == []
    pem = ["-----BEGIN RSA PRIVATE KEY-----", "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
           "-----END RSA PRIVATE KEY-----"]
    assert [f["line"] for f in d.scan_embedded_keys("a.py", pem)] == [1]
