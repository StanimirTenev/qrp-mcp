"""MCP server exposing the local, deterministic crypto scan as agent tools."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from . import __version__
from .classifier import known_algorithms
from .scan import scan_directory

mcp = MCPServer("qrp-mcp", version=__version__)


@mcp.tool()
def scan_repo(path: str) -> dict[str, Any]:
    """Scan a local directory for cryptography that a quantum computer would break.

    Reads source code, CI/CD pipeline configs and infrastructure-as-code under `path`,
    and returns the algorithms in use, per-finding detail, and a summary of how exposed
    the project is. Runs entirely on this machine -- no network calls, nothing uploaded.

    `files_scanned` counts only files that were actually read. Files the scanner could
    not open are listed in `unreadable_files` instead of being counted as scanned: no
    findings in a file nobody could read is not the same as a file that is clean, and
    the difference is the coverage of the whole report.

    Args:
        path: Directory to scan (e.g. a checked-out repository).
    """
    return scan_directory(path)


@mcp.tool()
def list_algorithms() -> dict[str, Any]:
    """List the algorithm families this server recognises and how each is classified
    (classical and quantum-vulnerable, post-quantum, or neither)."""
    return {"algorithms": known_algorithms()}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
