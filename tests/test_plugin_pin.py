"""The plugin runs the package pinned to this release, through a lockfile.

The Claude plugin directory blocks an unpinned launcher ("Unpinned uvx launcher"): both
qrp versions submitted were "Blocked by directory policy" with `uvx qrp-mcp` (2026-10-01).
A pinned `uvx qrp-mcp==X` was then held from 0.29.0 on (LAUNCHER_PACKAGE_REVIEW,
LAUNCHER_LOCK_MISSING): the pin fixes the package but not its dependencies. So the pin
lives in plugin/pyproject.toml + plugin/uv.lock, and the launcher is `uv run --locked`,
which installs exactly the lock and fails rather than re-resolving.
A pin that lags the release would run an old scanner, so it is held to pyproject.
"""
import json
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: the declared tomli backport
    import tomli as tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugin"


def _version():
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_the_launcher_runs_through_the_lock():
    server = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]["qrp"]
    assert server["command"] == "uv", server
    assert server["args"] == ["run", "--locked", "--no-dev", "--project",
                              "${CLAUDE_PLUGIN_ROOT}", "qrp-mcp"], server["args"]


def test_the_plugin_project_pins_the_released_version():
    deps = tomllib.loads((PLUGIN / "pyproject.toml").read_text())["project"]["dependencies"]
    assert deps == [f"qrp-mcp=={_version()}"], deps


def test_the_lock_holds_the_released_version_with_hashes():
    lock = tomllib.loads((PLUGIN / "uv.lock").read_text())
    pkgs = {p["name"]: p for p in lock["package"]}
    assert pkgs["qrp-mcp"]["version"] == _version()
    for p in lock["package"]:
        if p["name"] == "qrp-plugin":  # the virtual project itself
            continue
        assert p["source"] == {"registry": "https://pypi.org/simple"}, p["name"]
        files = p.get("wheels", []) + ([p["sdist"]] if "sdist" in p else [])
        assert files and all(f["hash"].startswith("sha256:") for f in files), p["name"]


def test_the_lock_stays_under_the_directory_file_limit():
    assert (PLUGIN / "uv.lock").stat().st_size < 256 * 1024
