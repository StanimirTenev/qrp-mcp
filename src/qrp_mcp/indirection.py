"""Uses reached through one step of indirection (release E; 05-novi-merki metric T5).

The metamorphic pilot of 25.10.2026 rewrote five seeds sixteen ways without changing what
they do, and the scan lost five rewrites: a JS destructured alias, a string concatenated
from two literals (Java, JS) and a constant from another file (Java, JS). It kept four more
only through the import line, not the call: an aliased module (`rsa as keyalg`, Go
`asym "crypto/rsa"`).

Each case is resolved lexically, on the line, never by running anything:

  alias       `from ...asymmetric import rsa as keyalg`, Go `asym "crypto/rsa"`: `keyalg.`
              and `asym.` read as `rsa.`, only where the alias's own line already names a
              family, and a row found that way must be of that family. JS `{ generateKeyPairSync:
              mk } = require('crypto')` (or `import { x as mk } from 'node:crypto'`): `mk(`
              reads as `generateKeyPairSync(`.
  literals    `"R" + "SA"` on one line folds to `"RSA"`, when the result is an algorithm name.
              A name assembled across statements or at run time stays out of reach.
  constant    `Algs.ASYM` (Java, `Algs.java` beside the file) and a name taken from a
              relative `require`/`import` (JS) or `from x import NAME` (Python, `x.py` beside
              the file) read as the string the other file assigns it, when that string is an
              algorithm name and is assigned once.

A row found only this way is added with the original line as its excerpt and says how it was
read (`; read through ...`), which also lowers its confidence one step. Rows the scan already
had are not touched, so nothing here can remove a finding.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

from . import detectors

_PY_ALIAS = re.compile(r"^\s*(?:from\s+[\w.]+\s+)?import\s+(.+)$")
_PY_AS = re.compile(r"([\w.]+)\s+as\s+(\w+)")
_GO_ALIAS = re.compile(r"^\s*(?:import\s+)?(\w+)\s+\"([\w./\-]+)\"")
_JS_DESTRUCTURE = re.compile(
    r"\{([^}]*)\}\s*=\s*require\(\s*['\"](?:node:)?crypto['\"]\s*\)"
    r"|import\s*\{([^}]*)\}\s*from\s*['\"](?:node:)?crypto['\"]")
_JS_PAIR = re.compile(r"(\w+)\s*(?::|\bas\b)\s*(\w+)")
_CONCAT = re.compile(r"([\"'])([^\"'\\]*)\1\s*\+\s*([\"'])([^\"'\\]*)\3")
_JAVA_CONST_USE = re.compile(r"(?<![\w.])([A-Z]\w*)\.([A-Z][A-Z0-9_]*)\b")
_JS_REL_REQUIRE = re.compile(
    r"(?:const|let|var)\s+(?:\{([^}]*)\}|(\w+))\s*=\s*require\(\s*['\"](\.{1,2}/[^'\"]+)['\"]\s*\)"
    r"|import\s*\{([^}]*)\}\s*from\s*['\"](\.{1,2}/[^'\"]+)['\"]")
_PY_REL_IMPORT = re.compile(r"^\s*from\s+(\.?)(\w+)\s+import\s+([\w\s,]+)$")
_ASSIGN = r"(?:^|[\s{{,]|\bexports\.|\bconst\s+|\blet\s+|\bvar\s+){name}\s*[:=]\s*([\"'])([^\"'\\]*)\1"
_LIMIT = 1 << 20


def _vocabulary() -> set[str]:
    return {k.upper() for table in (detectors._JCA_NAME_FAMILY, detectors._FETCH_NAME_FAMILY,
                                    detectors._KEY_TYPE_FAMILY, detectors._VALUE_FAMILY)
            for k in table}


_VOCABULARY: set[str] | None = None


def _is_algorithm_name(value: str) -> bool:
    global _VOCABULARY
    if _VOCABULARY is None:
        _VOCABULARY = _vocabulary()
    head = value.strip().upper()
    return bool(head) and (head in _VOCABULARY or head.split("/")[0] in _VOCABULARY
                           or detectors._algorithm_value(value) is not None)


def _read(path: Path, root: Path) -> list[str] | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _LIMIT:
            return None
        if not path.resolve().is_relative_to(root.resolve()):
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _assigned_once(lines: list[str], name: str, pattern: str = _ASSIGN) -> str | None:
    values = {m.group(2) for text in lines
              for m in re.finditer(pattern.format(name=re.escape(name)), text)}
    if len(values) == 1:
        value = values.pop()
        return value if _is_algorithm_name(value) else None
    return None


def _aliases(lines: list[str], ext: str, named: dict[int, set[str]]
             ) -> list[tuple[re.Pattern[str], str, str, set[str] | None]]:
    """(use pattern, replacement, how, families allowed or None) for each alias in the file."""
    out = []
    in_import = False
    for number, text in enumerate(lines, 1):
        if ext == ".go":
            stripped = text.strip()
            if stripped.startswith("import ("):
                in_import = True
                continue
            if in_import and stripped.startswith(")"):
                in_import = False
            if not (in_import or stripped.startswith("import ")):
                continue
        if ext == ".py" and " as " in text:
            match = _PY_ALIAS.match(text)
            if match and named.get(number):
                for target, alias in _PY_AS.findall(match.group(1)):
                    canonical = target.rsplit(".", 1)[-1]
                    if alias != canonical:
                        out.append((re.compile(rf"(?<![\w.]){re.escape(alias)}(?=\s*[.(])"),
                                    canonical, f"the alias {alias} for {canonical}",
                                    named[number]))
        elif ext == ".go" and '"' in text:
            match = _GO_ALIAS.match(text)
            if match and named.get(number) and match.group(1) not in ("import", "_"):
                alias, canonical = match.group(1), match.group(2).rsplit("/", 1)[-1]
                if alias != canonical:
                    out.append((re.compile(rf"(?<![\w.]){re.escape(alias)}(?=\.)"), canonical,
                                f"the alias {alias} for {canonical}", named[number]))
        elif ext in (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx") and "crypto" in text:
            for match in _JS_DESTRUCTURE.finditer(text):
                for target, alias in _JS_PAIR.findall(match.group(1) or match.group(2) or ""):
                    if alias != target:
                        out.append((re.compile(rf"(?<![\w.]){re.escape(alias)}(?=\s*\()"),
                                    target, f"the alias {alias} for {target}", None))
    return out


def _constants(path: Path, lines: list[str], ext: str, root: Path
               ) -> list[tuple[re.Pattern[str], str, str]]:
    """(use pattern, quoted value, how) for constants another file assigns."""
    out: list[tuple[re.Pattern[str], str, str]] = []
    here = path.parent
    if ext == ".java":
        classes: dict[str, list[str] | None] = {}
        for text in lines:
            if "(" not in text:
                continue
            for cls, name in _JAVA_CONST_USE.findall(text):
                if cls not in classes:
                    classes[cls] = (_read(here / f"{cls}.java", root)
                                    if cls != path.stem else None)
                other = classes[cls]
                if other is None:
                    continue
                value = _assigned_once(other, name, r"\bstatic\s+final\s+String\s+{name}\s*="
                                                    r"\s*(\")([^\"]*)\"\s*;")
                if value:
                    out.append((re.compile(rf"(?<![\w.]){cls}\.{name}\b"), f'"{value}"',
                                f"the constant {cls}.{name} in {cls}.java"))
    elif ext in (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"):
        for text in lines:
            for m in _JS_REL_REQUIRE.finditer(text):
                names, module, spec = m.group(1) or m.group(4), m.group(2), m.group(3) or m.group(5)
                other = None
                for suffix in ("", ".js", ".mjs", ".cjs", ".ts", "/index.js"):
                    other = _read(here / f"{spec}{suffix}", root)
                    if other is not None:
                        break
                if other is None:
                    continue
                if names:
                    for part in names.split(","):
                        bits = re.findall(r"\w+", part)
                        if not bits:
                            continue
                        source, local = bits[0], bits[-1]
                        value = _assigned_once(other, source)
                        if value:
                            out.append((re.compile(rf"(?<![\w.'\"]){local}\b(?!\s*[:=(])"),
                                        f"'{value}'", f"the constant {source} in {spec}"))
                elif module:
                    for name in sorted(set(re.findall(rf"\b{module}\.(\w+)", "\n".join(lines)))):
                        value = _assigned_once(other, name)
                        if value:
                            out.append((re.compile(rf"(?<![\w.]){module}\.{name}\b"),
                                        f"'{value}'", f"the constant {name} in {spec}"))
    elif ext == ".py":
        for text in lines:
            m = _PY_REL_IMPORT.match(text)
            if not m:
                continue
            other = _read(here / f"{m.group(2)}.py", root)
            if other is None:
                continue
            for name in re.findall(r"\w+", m.group(3)):
                value = _assigned_once(other, name, r"^{name}\s*(?::\s*\w+\s*)?=\s*([\"'])([^\"'\\]*)\1")
                if value:
                    out.append((re.compile(rf"(?<![\w.'\"]){name}\b(?!\s*=)"), f'"{value}"',
                                f"the constant {name} in {m.group(2)}.py"))
    return out


def _fold(text: str) -> str:
    previous = None
    while previous != text:
        previous = text
        text = _CONCAT.sub(lambda m: (m.group(0) if not _is_algorithm_name(m.group(2) + m.group(4))
                                      else f"{m.group(1)}{m.group(2)}{m.group(4)}{m.group(1)}"),
                           text)
    return text


def resolve(path: Path, rel_path: str, lines: list[str], found: list[dict[str, Any]],
            root: Path, scan: Callable[..., list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """The rows reached only through an alias, a folded literal or another file's constant."""
    ext = path.suffix.lower()
    named: dict[int, set[str]] = {}
    for f in found:
        if f.get("evidence_kind") not in ("comment", "ban"):
            named.setdefault(f["line"], set()).add(f["algorithm"])
    aliases = _aliases(lines, ext, named)
    constants = _constants(path, lines, ext, root)
    changed: dict[int, tuple[str, list[str], set[str] | None]] = {}
    for number, text in enumerate(lines, 1):
        new, how = text, []
        # The families a row found through a Python or Go alias may have: the alias line's.
        # None while nothing restricts the line (a JS alias, a constant, folded literals).
        allowed: set[str] | None = None
        for pattern, canonical, said, families in aliases:
            replaced = pattern.sub(canonical, new)
            if replaced != new:
                new = replaced
                how.append(said)
                if families is not None:
                    allowed = (allowed or set()) | families
        defining = _JS_REL_REQUIRE.search(text) or _PY_REL_IMPORT.match(text)
        for pattern, value, said in constants:
            if "(" in new and not defining:
                replaced = pattern.sub(value, new)
                if replaced != new:
                    new = replaced
                    how.append(said)
        if "+" in new:
            folded = _fold(new)
            if folded != new:
                new = folded
                how.append("literals concatenated on the line")
        if new != text:
            changed[number] = (new, how, allowed)
    if not changed:
        return []
    rewritten = [changed[n][0] if n in changed else t for n, t in enumerate(lines, 1)]
    have = {(f["line"], f["algorithm"]) for f in found}
    out = []
    for f in scan(path, rel_path, rewritten):
        line = f["line"]
        if line not in changed or (line, f["algorithm"]) in have:
            continue
        if f.get("evidence_kind") in ("comment", "ban"):
            continue
        _, how, allowed = changed[line]
        if allowed is not None and f["algorithm"] not in allowed:
            continue
        have.add((line, f["algorithm"]))
        f["excerpt"] = lines[line - 1].strip()[:200]
        f["description"] = f"{f['description']}; read through {', '.join(how)}"
        out.append(f)
    return out
