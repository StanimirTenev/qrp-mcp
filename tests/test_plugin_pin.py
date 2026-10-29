"""The plugin runs the package pinned to this release, through a lockfile.

The Claude plugin directory blocks an unpinned launcher ("Unpinned uvx launcher"): both
qrp versions submitted were "Blocked by directory policy" with `uvx qrp-mcp` (2026-10-01).
A pinned `uvx qrp-mcp==X` was then held from 0.29.0 on (LAUNCHER_PACKAGE_REVIEW,
LAUNCHER_LOCK_MISSING): the pin fixes the package but not its dependencies. So a uv.lock
ships next to .mcp.json (plugin/pyproject.toml + plugin/uv.lock).
`uv run --locked` with UV_PROJECT_ENVIRONMENT in env was then Failed (b6b5c5e, 2026-10-28):
LAUNCHER_REGISTRY_REDIRECT on the env, LAUNCHER_LOCK_INVALID asking for `uvx <package>==<version>`.
So the launcher is `uvx qrp-mcp==X` with no env, and the lock beside it.
A pin that lags the release would run an old scanner, so all three are held to pyproject.
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


def test_the_launcher_is_uvx_pinned_to_the_release():
    server = json.loads((PLUGIN / ".mcp.json").read_text())["mcpServers"]["qrp"]
    assert server["command"] == "uvx", server
    assert server["args"] == [f"qrp-mcp=={_version()}"], server["args"]
    # Any env on the launcher is read as a registry redirect (LAUNCHER_REGISTRY_REDIRECT).
    assert "env" not in server, server


def test_the_plugin_project_pins_the_released_version():
    project = tomllib.loads((PLUGIN / "pyproject.toml").read_text())["project"]
    assert project["dependencies"] == [f"qrp-mcp=={_version()}"], project["dependencies"]
    assert project["version"] == _version()


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
