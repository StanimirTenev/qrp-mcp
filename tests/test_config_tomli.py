"""`.qrp.toml` on Python 3.10: `requires-python` is >=3.10, and `tomllib` is 3.11+.

Without `tomli` declared, an installed 3.10 copy refused every `.qrp.toml` with "needs
Python 3.11 or the `tomli` package" -- a setting the owner wrote, not applied. The package is
declared for 3.10 only, and read when `tomllib` is not there.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # 3.10: the dependency under test
    import tomli as tomllib

from qrp_mcp import config

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def test_tomli_is_a_dependency_below_3_11():
    project = tomllib.loads(PYPROJECT.read_text())["project"]
    assert project["requires-python"] == ">=3.10"
    deps = ["".join(d.split()) for d in project["dependencies"]]
    assert 'tomli;python_version<"3.11"' in deps


def test_without_tomllib_the_file_is_read_with_tomli(monkeypatch):
    # 3.10 simulated: `import tomllib` fails, `tomli` (same API) is what is installed.
    monkeypatch.setitem(sys.modules, "tomllib", None)
    monkeypatch.setitem(sys.modules, "tomli", tomllib)
    assert config._toml(b'profile = "nist"\nexclude = ["legacy/"]\n') == {
        "profile": "nist", "exclude": ["legacy/"]}
