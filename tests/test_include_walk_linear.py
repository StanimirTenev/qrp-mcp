"""Third review of 0.50.0 (18.11), item 5: the include link of 40d2fd4 takes every file of a glob,
and the walk up from each "<module>_ssl_verify not set" row went over the whole include graph
again, once per row. With 3000 files that each `include *.conf;` (every file includes every
file) the scan was killed at 600 s / 466 MB (22 s on fddec63); 1000 files took 17.5 s (4.1 s).

Now each (target, directory) is resolved once, and the files below a file that sets the
directive are found by one walk per module from the setting files, each file visited at most
twice -- linear in the include links. The answer is the same as the old walk's (checked against
it on random graphs with cycles and self-includes).
"""

from __future__ import annotations

import random
from pathlib import Path

from qrp_mcp import adaptive
from qrp_mcp.scan import scan_directory


def _tree(root: Path, n: int) -> None:
    (root / "conf.d").mkdir()
    (root / "nginx.conf").write_text("http {\n  proxy_ssl_verify on;\n  include conf.d/*.conf;\n}\n")
    for i in range(n):
        (root / "conf.d" / f"s{i:04}.conf").write_text(
            f"include *.conf;\nserver {{\n location / {{\n  proxy_pass https://up{i:04};\n }}\n}}\n")


def test_each_include_target_is_resolved_once_per_directory(tmp_path, monkeypatch):
    _tree(tmp_path, 60)
    calls = []
    real = adaptive._resolve

    def counting(target, rel, *args, **kwargs):
        if kwargs.get("limit", args[2] if len(args) > 2 else 20) is None:
            calls.append((target, rel))
        return real(target, rel, *args, **kwargs)

    monkeypatch.setattr(adaptive, "_resolve", counting)
    result = scan_directory(tmp_path)
    # nginx.conf's `conf.d/*.conf` and conf.d's `*.conf`: two, not 61.
    assert len(calls) == 2, len(calls)
    # Every upstream row is under nginx.conf's `proxy_ssl_verify on`: none is left.
    assert [r for r in result.get("protocol_findings") or []
            if r.get("basis") == "configured_verification"] == []


def _old_set_above(parents: dict[str, set[str]], sets: dict[str, set[str]], path: str,
                   module: str) -> bool:
    # 40d2fd4's walk, kept as the oracle.
    seen, todo = {path}, list(parents.get(path, ()))
    while todo:
        parent = todo.pop()
        if parent in seen:
            continue
        seen.add(parent)
        if module in sets.get(parent, ()):
            return True
        todo.extend(parents.get(parent, ()))
    return False


def test_the_walk_gives_the_old_answer_on_random_graphs():
    from qrp_mcp.scan import _covered_below

    rng = random.Random(20261118)
    for _ in range(400):
        nodes = [f"f{i}" for i in range(rng.randint(1, 12))]
        children = {n: [rng.sample(nodes, rng.randint(0, len(nodes)))] for n in nodes
                    if rng.random() < 0.8}
        sets = {n: {m for m in ("proxy", "grpc") if rng.random() < 0.3} for n in nodes}
        parents: dict[str, set[str]] = {}
        for parent, groups in children.items():
            for group in groups:
                for child in group:
                    parents.setdefault(child, set()).add(parent)
        for module in ("proxy", "grpc"):
            setters = [n for n in nodes if module in sets[n]]
            covered = _covered_below(children, setters)
            for node in nodes:
                assert (node in covered) == _old_set_above(parents, sets, node, module), (
                    children, sets, node, module)
