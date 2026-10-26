"""`json.dumps(obj, indent=2, ensure_ascii=False)`, the same text, in less time (release 3c).

With an indent the standard library encodes in Python through a chain of generators, one
per container: 0.11 s of an OpenSSH scan's 2.3, after everything else had finished. This
walks the document once, appending to one list, with the standard library's own string
escaping (json.encoder.encode_basestring) and number formatting (int.__repr__,
float.__repr__, NaN/Infinity). Anything it does not know -- a type json would hand to
`default`, a cycle, nesting deeper than 60 -- is given to json.dumps itself, which then
produces its own text or its own error. tests/test_jsonout.py holds the two to the same
bytes.
"""

from __future__ import annotations

import json
from json.encoder import encode_basestring as _string
from typing import Any

_INFINITY = float("inf")
_INDENTS = ["\n" + "  " * level for level in range(62)]


class _Unknown(Exception):
    pass


def _float(value: float) -> str:
    if value != value:
        return "NaN"
    if value == _INFINITY:
        return "Infinity"
    if value == -_INFINITY:
        return "-Infinity"
    return float.__repr__(value)


def _key(key: Any) -> str:
    if isinstance(key, str):
        return key
    if isinstance(key, float):
        return _float(key)
    if key is True:
        return "true"
    if key is False:
        return "false"
    if key is None:
        return "null"
    if isinstance(key, int):
        return int.__repr__(key)
    raise _Unknown


def dumps(document: Any) -> str:
    out: list[str] = []
    put = out.append

    def value(o: Any, level: int) -> None:
        kind = type(o)
        if kind is str:
            put(_string(o))
        elif kind is dict:
            if not o:
                put("{}")
                return
            inner = _INDENTS[level + 1]
            between = "," + inner
            put("{" + inner)
            first = True
            for k, v in o.items():
                if type(k) is not str:
                    k = _key(k)
                if first:
                    first = False
                    put(_string(k) + ": ")
                else:
                    put(between + _string(k) + ": ")
                kind_v = type(v)
                if kind_v is str:
                    put(_string(v))
                elif kind_v is int:
                    put(int.__repr__(v))
                else:
                    value(v, level + 1)
            put(_INDENTS[level] + "}")
        elif isinstance(o, str):
            put(_string(o))
        elif o is None:
            put("null")
        elif o is True:
            put("true")
        elif o is False:
            put("false")
        elif isinstance(o, int):
            put(int.__repr__(o))
        elif isinstance(o, float):
            put(_float(o))
        elif isinstance(o, (list, tuple)):
            if not o:
                put("[]")
                return
            inner = _INDENTS[level + 1]
            between = "," + inner
            put("[" + inner)
            first = True
            for v in o:
                if first:
                    first = False
                else:
                    put(between)
                value(v, level + 1)
            put(_INDENTS[level] + "]")
        else:   # a dict subclass among them: its own items() is json's to call
            raise _Unknown

    try:
        value(document, 0)
    except (_Unknown, IndexError, RecursionError):
        return json.dumps(document, indent=2, ensure_ascii=False)
    return "".join(out)
