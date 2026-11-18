"""The catalogue of operations (data/operations/*.toml): for each operation and ecosystem, the
documented spellings that tests/test_operation_closure.py scans one by one.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

CATALOGUE = Path(__file__).parent / "data" / "operations"


@lru_cache(maxsize=1)
def _load() -> tuple[dict[str, Any], ...]:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            return ()
    return tuple(tomllib.loads(path.read_text(encoding="utf-8"))
                 for path in sorted(CATALOGUE.glob("*.toml")))


def catalogue() -> list[dict[str, Any]]:
    return list(_load())

