"""jsonout.dumps writes exactly what json.dumps(obj, indent=2, ensure_ascii=False) writes."""

from __future__ import annotations

import enum
import json
import random

import pytest

from qrp_mcp import jsonout


def _same(document) -> None:
    assert jsonout.dumps(document) == json.dumps(document, indent=2, ensure_ascii=False)


class _Str(str):
    pass


class _Int(enum.IntEnum):
    A = 3


def test_the_shapes_a_result_has():
    _same({"a": [], "b": {}, "c": [{}], "d": [[], [[]]], "e": None, "f": True, "g": False,
           "h": 0, "i": -7, "j": 1.5, "k": 1e100, "l": 0.1 + 0.2, "m": "x\"y\\z\n\t\x00\x1f",
           "n": "ünïcödé ✓ 𝄞", "o": (1, "two", (3,)), "p": [1, 2.0, "3", None, True]})


def test_keys_json_turns_into_strings():
    _same({1: "a", 2.5: "b", True: "c", None: "d", _Str("e"): 1, _Int.A: 2})
    _same({"x": _Str("sub"), "y": _Int.A, "z": [_Int.A, _Str("q")]})


def test_nan_and_infinity_as_json_writes_them():
    _same([float("nan"), float("inf"), -float("inf"), {"a": float("nan")}])


def test_what_json_refuses_it_refuses_the_same_way():
    for bad in ({"a": {1, 2}}, {(1, 2): "tuple key"}, [object()]):
        with pytest.raises(TypeError):
            json.dumps(bad, indent=2, ensure_ascii=False)
        with pytest.raises(TypeError):
            jsonout.dumps(bad)
    loop: list = []
    loop.append(loop)
    with pytest.raises(ValueError):
        jsonout.dumps(loop)


def test_deep_nesting_and_dict_subclasses_go_to_json():
    deep: object = "leaf"
    for _ in range(100):
        deep = {"d": [deep]}
    _same(deep)

    class Ordered(dict):
        def items(self):
            return reversed(list(super().items()))
    _same({"o": Ordered(a=1, b=2)})


def test_random_documents():
    rng = random.Random(7)
    leaves = [None, True, False, 0, 1, -3, 2.25, float("nan"), "", "a", "é\n", " "]

    def build(depth):
        roll = rng.random()
        if depth > 5 or roll < 0.3:
            return rng.choice(leaves)
        if roll < 0.65:
            return [build(depth + 1) for _ in range(rng.randint(0, 4))]
        return {rng.choice(["k", "é", "", "a b", "1"]) + str(i): build(depth + 1)
                for i in range(rng.randint(0, 4))}

    for _ in range(300):
        _same(build(0))


def test_a_scan_result_and_its_cbom(tmp_path):
    from qrp_mcp import cyclonedx
    from qrp_mcp.scan import scan_directory
    (tmp_path / "a.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "# md5 is weak — ünïcödé\n", encoding="utf-8")
    result = scan_directory(tmp_path)
    _same(result)
    _same(cyclonedx.build(result))
