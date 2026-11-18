"""The catalogue of operations (data/operations/*.toml): for each operation and ecosystem, the
documented spellings that tests/test_operation_closure.py scans one by one.

The scan reports which (operation, ecosystem) pairs the catalogue holds, as `operation_closure`.
That list is a statement about this version's tests, never about the scanned code: it does not
enter the findings, their fingerprint, a gate or the exit code.
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


def closure_section() -> dict[str, Any]:
    families = [{"operation": doc["operation"], "ecosystem": eco["ecosystem"],
                 "spellings_count": sum(1 for s in eco["spellings"] if s["source"] != "none"),
                 "catalogue_version": doc["catalogue_version"]}
                for doc in _load() for eco in doc["ecosystems"]]
    return {
        "meaning": ("the (operation, ecosystem) pairs whose documented spellings this version "
                    "tests one by one, each written to a file and scanned "
                    "(tests/test_operation_closure.py); spellings_count counts those with a "
                    "documentation source. It says what this version was tested against, not "
                    "what the scanned code contains, and a spelling outside the catalogue can "
                    "still be missed. It does not affect the findings, their fingerprint, a "
                    "gate or the exit code"),
        "families": families,
    }
