"""Row 554: where in the tree a Python module's cryptography is reached from.

`libs/cryptoutil/sign.py` signs with RSA and `svc-payments/app.py` imports it; the findings were on
the wrapper's lines only, and nothing said which services depend on it. Each Python occurrence
inside a module of the tree gets the places in other files read that import the top-level function
or class it is in and call it -- or, where no call is seen, the import -- read by import and name as
the Python reference documents the import statement
(https://docs.python.org/3/reference/simple_stmts.html#the-import-statement): `from a.b import f`,
`from a.b import f as g`, `import a.b`, `import a.b as m`, `from a import b` (b a module), relative
`from .b import f`. A dotted name resolves to the one file whose path ends with it; a name of one
part only to a file at the top of the tree or beside the importer (the script's directory). A call
through another name, a re-export, `importlib` or a module outside the tree is not followed, and
the statement on each row says so.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_FROM = re.compile(r"^\s*from\s+(\.*)([\w.]*)\s+import\s+(.+)$")
_IMPORT = re.compile(r"^\s*import\s+(.+)$")
_TOP = re.compile(r"^(?:async\s+def|def|class)\s+([A-Za-z_]\w*)")
_ALIAS = re.compile(r"^([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_]\w*))?$")
REACHED = ("imported and called from {n} place(s) in other files read, the first ten in "
           "reached_from: static, by import and name -- a call through another name, a "
           "re-export, importlib or a module outside the tree is not followed, so the list can "
           "be short")
LIMIT = 10


def _dotted(rel: str) -> list[str]:
    parts = rel[:-3].split("/")
    return parts[:-1] if parts[-1] == "__init__" else parts


class _Modules:
    def __init__(self, modules: list[str]) -> None:
        self.suffix: dict[str, list[str]] = {}
        self.exact: dict[str, str] = {}
        for rel in modules:
            parts = _dotted(rel)
            self.exact[".".join(parts)] = rel
            for i in range(len(parts) - 1):
                self.suffix.setdefault(".".join(parts[i:]), []).append(rel)

    def absolute(self, dotted: str, importer: str) -> str | None:
        if "." not in dotted:
            # One part: the top of the tree, or the importer's own directory.
            here = ".".join(_dotted(importer)[:-1] + [dotted])
            return self.exact.get(here) or self.exact.get(dotted)
        if dotted in self.exact:
            return self.exact[dotted]
        found = self.suffix.get(dotted) or []
        return found[0] if len(found) == 1 else None


def _statements(lines: list[str]):
    """(line number, import statement), a parenthesised name list joined onto its first line."""
    n = 0
    while n < len(lines):
        text = lines[n].split("#", 1)[0]
        start = n + 1
        if "import" in text and "(" in text and ")" not in text:
            while n + 1 < len(lines) and ")" not in text:
                n += 1
                text += " " + lines[n].split("#", 1)[0]
        n += 1
        if "import" in text:
            yield start, text.replace("(", " ").replace(")", " ").replace("\\", " ")


def _imports(rel: str, lines: list[str], modules: _Modules):
    """(line, module file, name or None, local alias) for each import of a module of the tree.
    A name of None: the module itself is bound to the alias."""
    own = _dotted(rel)
    package = own if rel.endswith("__init__.py") else own[:-1]
    for number, text in _statements(lines):
        m = _FROM.match(text)
        if m:
            dots, module, names = m.groups()
            if dots:
                up = len(dots) - 1
                if up > len(package):
                    continue
                target = ".".join(package[:len(package) - up] + ([module] if module else []))
                look = modules.exact.get
            else:
                target, look = module, (lambda d: modules.absolute(d, rel))
            for piece in names.split(","):
                a = _ALIAS.match(piece.strip())
                if not a:
                    continue
                name, alias = a.group(1), a.group(2) or a.group(1)
                sub = look(f"{target}.{name}" if target else name)
                if sub:
                    yield number, sub, None, alias
                    continue
                file = look(target) if target else None
                if file:
                    yield number, file, name, alias
            continue
        m = _IMPORT.match(text)
        if m:
            for piece in m.group(1).split(","):
                a = _ALIAS.match(piece.strip())
                file = modules.absolute(a.group(1), rel) if a else None
                if file:
                    yield number, file, None, a.group(2) or a.group(1)


def _top_level(lines: list[str]) -> dict[int, str]:
    """Line number -> the top-level def or class it is in."""
    out: dict[int, str] = {}
    current = None
    for n, text in enumerate(lines, 1):
        if text.strip() and text[:1] not in (" ", "\t", "#", "@", ")", "]", "}"):
            m = _TOP.match(text)
            current = m.group(1) if m else None
        if current:
            out[n] = current
    return out


def annotate(root: Path, files_read: list[str], items: list[dict[str, Any]]) -> None:
    """`reached_from`, `reached_from_count` and `reached` on each Python occurrence a file read
    reaches. Beside the row and outside its identity (closure, baseline), as `imported_in`."""
    py = [i for i in items if str(i.get("path", "")).endswith(".py")
          and i.get("evidence_kind") not in ("comment", "ban")]
    if not py:
        return
    wanted = {i["path"] for i in py}
    paths = [r for r in files_read if r.endswith(".py")]
    modules = _Modules(paths)
    reached: dict[tuple[str, str | None], set[str]] = {}
    texts: dict[str, list[str]] = {}
    for rel in paths:
        try:
            lines = (root / rel).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if rel in wanted:
            texts[rel] = lines
        bound = [b for b in _imports(rel, lines, modules) if b[1] in wanted and b[1] != rel]
        for n, file, name, alias in bound:
            reached.setdefault((file, None), set()).add(f"{rel}:{n}")
            if name is not None:
                call = re.compile(rf"(?<![\w.]){re.escape(alias)}\s*\(")
                hits = {f"{rel}:{k}" for k, t in enumerate(lines, 1)
                        if k != n and not t.lstrip().startswith("#") and call.search(t)}
                reached.setdefault((file, name), set()).update(hits or {f"{rel}:{n}"})
            else:
                attr = re.compile(rf"(?<![\w.]){re.escape(alias)}\.([A-Za-z_]\w*)\s*\(")
                for k, t in enumerate(lines, 1):
                    if not t.lstrip().startswith("#"):
                        for m in attr.finditer(t):
                            reached.setdefault((file, m.group(1)), set()).add(f"{rel}:{k}")
    if not reached:
        return
    tops = {rel: _top_level(lines) for rel, lines in texts.items()}
    for item in py:
        name = tops.get(item["path"], {}).get(item["line"])
        places = reached.get((item["path"], name))
        if places:
            ordered = sorted(places)
            item["reached_from"] = ordered[:LIMIT]
            item["reached_from_count"] = len(ordered)
            item["reached"] = REACHED.format(n=len(ordered))
