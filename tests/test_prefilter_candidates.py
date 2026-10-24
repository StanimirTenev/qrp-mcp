"""The patterns a line is tried with are chosen from the literals it holds (ZA-OPRAVYANE
row 114, extended when rows 136-143 doubled the patterns).

One prefix-tree regex finds the longest literal at each position, and the literals inside
those are taken as the literals present. That must be exactly the set a substring test of
every literal gives, and the patterns chosen exactly those the per-pattern literal check
lets through -- otherwise a finding is lost without a sound.
"""

import ast
import random
from pathlib import Path

from qrp_mcp import detectors


def _present(text: str) -> set[str]:
    found: set[str] = set()
    for m in detectors._LITERAL_AT.finditer(text):
        found |= detectors._INSIDE[m.group(1)]
    return found


def _old_selection(lowered: str) -> list:
    if not detectors._ANY_LITERAL.search(lowered):
        return []
    return [f for f in detectors._FILTERED_PATTERNS
            if not f[3] or any(s in lowered for s in f[3])]


def _lines() -> list[str]:
    strings = {node.value for path in Path(__file__).parent.glob("*.py")
               for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
               if isinstance(node, ast.Constant) and isinstance(node.value, str)}
    rng = random.Random(143)
    literals = detectors._ALL_LITERALS
    glued = ["".join(rng.choice(literals + [" ", "_", "-", "x"]) for _ in range(rng.randint(1, 6)))
             for _ in range(5000)]
    return [s.lower() for s in strings if s.isascii()] + glued


def test_the_literals_found_are_exactly_the_literals_present():
    for text in _lines():
        assert _present(text) == {s for s in detectors._ALL_LITERALS if s in text}, text


def test_the_patterns_chosen_are_the_ones_the_literal_check_lets_through():
    for text in _lines():
        assert detectors._candidate_patterns(text) == _old_selection(text), text


def test_a_non_ascii_line_is_tried_with_every_pattern():
    assert detectors._candidate_patterns(None) is detectors._FILTERED_PATTERNS
