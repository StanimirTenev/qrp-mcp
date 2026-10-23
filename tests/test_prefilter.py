"""The literal prefilter may skip a pattern only on a line it could not have matched.

ZA-OPRAVYANE row 114: 0.35.0 runs 95 patterns per line, and a full OpenSSH scan went from
88.7 s to 133.5 s. Each pattern now carries the literals one of which every match of it
contains, read off the regex. A literal that a match can lack would drop a finding without
a sound, so this pins the property itself: every match, of every pattern, over every string
the test suite already holds -- in its own case, upper and lower -- contains one of its
pattern's literals and passes the line gate.
"""

import ast
import re
from pathlib import Path

from qrp_mcp import detectors


def _test_strings() -> set[str]:
    return {node.value for path in Path(__file__).parent.glob("*.py")
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)}


def test_every_match_holds_one_of_its_patterns_literals():
    matched, patterns_hit, missed = 0, set(), []
    for text in _test_strings():
        for variant in {text, text.upper(), text.lower()}:
            for _, description, pattern, literals in detectors._FILTERED_PATTERNS:
                for m in pattern.finditer(variant):
                    matched += 1
                    patterns_hit.add(description)
                    found = m.group().lower()
                    if literals and not any(s in found for s in literals):
                        missed.append((description, m.group()))
                    if not detectors._ANY_LITERAL.search(found):
                        missed.append(("line gate", m.group()))
    assert not missed
    assert matched > 1000 and len(patterns_hit) >= 85    # 90 of the 91 rules, 2026-10-23


def test_a_regex_that_promises_no_literal_always_runs():
    assert detectors._prefilter(re.compile(r"\w+")) is None
    assert detectors._prefilter(re.compile(r"(?:abc|\d+)x?")) is None
    assert detectors._prefilter(re.compile(r"(?:abc)?[a-z]")) is None
    assert detectors._prefilter(re.compile(r"(?:Abc)?XYZ", re.IGNORECASE)) == ("xyz",)
