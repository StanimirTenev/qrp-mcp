"""What starting a scan computes that does not change between runs, kept on disk (release 3c).

Every run compiled ~490 regular expressions and derived, from the algorithm patterns, the
literals each needs (detectors._prefilter) and the compiled core's version of each
(linegate.rust_regex): a quarter of a second of a two-second scan, before the first file
was read, and the same every time. Both are kept here, in one file under the user's cache
directory, and read back on the next run:

* a regex is kept as what CPython's own compiler hands to `_sre.compile` (the same call
  re._compiler.compile ends with), keyed by its pattern and flags; a pattern built from
  the kept values compares equal (`==`, which compares the compiled code) to one compiled
  afresh, and tests/test_warm.py checks that for every pattern the rules compile;
* a derived value is keyed by its kind and input.

The file's name carries the interpreter's version, the regex engine's MAGIC and CODESIZE
and a digest of every module of this package, so a different Python or any change to the
rules or to the code deriving from them reads a different file, never a stale answer.
Nothing found here can change a finding: a value missing, unreadable or of the wrong
shape is computed as before. QRP_MCP_CACHE=0 turns the file off (nothing read, nothing
written); so does a cache directory that cannot be written.
"""

from __future__ import annotations

import hashlib
import marshal
import os
import sys
from pathlib import Path
from typing import Any, Callable

try:  # CPython 3.11+; elsewhere the regex half is off and only derived values are kept.
    import _sre
    from re import _compiler, _parser
except ImportError:  # pragma: no cover
    _sre = _compiler = _parser = None  # type: ignore[assignment]

_FORMAT = 1
_state: dict[str, Any] = {"loaded": False, "path": None, "data": None, "dirty": False,
                          "original": None}


def _enabled() -> bool:
    return os.environ.get("QRP_MCP_CACHE", "").strip() not in ("0", "off", "no")


def _path() -> Path | None:
    here = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    digest.update(f"{_FORMAT}|{sys.version}|{sys.implementation.cache_tag}".encode())
    if _sre is not None:
        digest.update(f"|{_sre.MAGIC}|{_sre.CODESIZE}".encode())
    try:
        for module in sorted(here.glob("*.py")):
            digest.update(module.name.encode() + b"\0" + module.read_bytes() + b"\0")
    except OSError:
        return None
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    if not os.path.isabs(base):
        return None
    return Path(base) / "qrp-mcp" / f"start-{digest.hexdigest()[:24]}.marshal"


def _load() -> dict[str, Any] | None:
    if not _state["loaded"]:
        _state["loaded"] = True
        if _enabled():
            path = _path()
            _state["path"] = path
            data: Any = None
            if path is not None:
                try:
                    data = marshal.loads(path.read_bytes())
                except (OSError, EOFError, ValueError, TypeError):
                    data = None
            if not (isinstance(data, dict) and isinstance(data.get("regex"), dict)
                    and isinstance(data.get("derived"), dict)):
                data = {"regex": {}, "derived": {}}
            _state["data"] = data
    return _state["data"]


def save() -> None:
    """Write the file if this run added to it; silently not, where it cannot be written."""
    data, path = _state["data"], _state["path"]
    if not _state["dirty"] or data is None or path is None:
        return
    _state["dirty"] = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        tmp.write_bytes(marshal.dumps(data))
        os.replace(tmp, path)
        for other in path.parent.glob("start-*.marshal"):
            if other != path:
                other.unlink(missing_ok=True)
    except (OSError, ValueError):
        pass


def derived(kind: str, key: Any, compute: Callable[[], Any]) -> Any:
    """compute(), or the value it gave for this kind and key on an earlier run."""
    data = _load()
    if data is None:
        return compute()
    table = data["derived"].setdefault(kind, {})
    if key in table:
        return table[key]
    value = compute()
    try:
        marshal.dumps(value)
    except ValueError:
        return value
    table[key] = value
    _state["dirty"] = True
    return value


def _compile(p: Any, flags: int = 0) -> Any:
    original = _state["original"]
    data = _state["data"]
    if data is None or not isinstance(p, (str, bytes)) or flags & _compiler.SRE_FLAG_DEBUG:
        return original(p, flags)
    key = (p, int(flags))
    kept = data["regex"].get(key)
    if kept is not None:
        try:
            return _sre.compile(p, *kept)
        except Exception:  # noqa: BLE001 -- a kept value of the wrong shape: compile it
            pass
    # re._compiler.compile, with the arguments it hands to _sre.compile kept.
    parsed = _parser.parse(p, flags)
    code = _compiler._code(parsed, flags)
    groupindex = parsed.state.groupdict
    indexgroup = [None] * parsed.state.groups
    for name, index in groupindex.items():
        indexgroup[index] = name
    # Plain ints: the code holds named constants (MAXREPEAT), which marshal refuses.
    args = (int(flags | parsed.state.flags), [int(c) for c in code],
            int(parsed.state.groups - 1), {k: int(v) for k, v in groupindex.items()},
            tuple(indexgroup))
    compiled = _sre.compile(p, *args)
    if compiled != original(p, flags):   # this interpreter compiles some other way: stop
        stop_regex()
        return original(p, flags)
    data["regex"][key] = args
    _state["dirty"] = True
    return compiled


def start_regex() -> None:
    """Compile regexes through the file until stop_regex(): detectors.py brackets its import
    with the two, so the patching lasts as long as the rules take to load."""
    if _sre is None or _state["original"] is not None or _load() is None:
        return
    _state["original"] = _compiler.compile
    _compiler.compile = _compile


def stop_regex() -> None:
    if _state["original"] is not None:
        _compiler.compile = _state["original"]
        _state["original"] = None
