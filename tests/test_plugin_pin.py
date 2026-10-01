"""The plugin runs the package pinned to this release.

The Claude plugin directory blocks an unpinned launcher ("Unpinned uvx launcher"): both
qrp versions submitted were "Blocked by directory policy" with `uvx qrp-mcp` (2026-10-01).
A pin that lags the release would run an old scanner, so it is held to pyproject.
"""
import json
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_the_plugin_pins_the_released_version():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    args = json.loads((ROOT / "plugin" / ".mcp.json").read_text())["mcpServers"]["qrp"]["args"]
    assert args == [f"qrp-mcp=={version}"], args
