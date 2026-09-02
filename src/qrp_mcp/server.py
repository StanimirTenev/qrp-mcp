"""MCP server exposing the local, deterministic crypto scan as agent tools."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__
from .classifier import known_algorithms
from .scan import scan_directory

mcp = MCPServer("qrp-mcp", version=__version__)

# Declared rather than described. Read-only, idempotent and closed-world are the
# three promises this server is built on, and an annotation is the only form of
# them an agent can check without reading prose.
_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


@mcp.tool(annotations=_READ_ONLY)
def scan_repo(
    path: Annotated[
        str,
        Field(
            description=(
                "Directory to scan, absolute or relative to the working directory: a "
                "checked-out repository, a service directory, a config tree. Vendored "
                "and build directories (.git, node_modules, vendor, dist, build, "
                "target) are excluded and do not count toward files_present."
            )
        ),
    ],
) -> dict[str, Any]:
    """Inventory the cryptography inside one local directory tree, file by file.

    Reads source, configuration (nginx.conf, sshd_config, .ini, .toml), CI pipelines,
    Terraform and Kubernetes manifests under `path`. Returns each algorithm found with
    its file and line, the mathematical family and standing of every post-quantum
    scheme, and a coverage count.

    Use this to answer what a specific project on this machine actually uses. Do not
    use it to ask whether this server knows a given algorithm, or to explain how one is
    classified without scanning anything -- `list_algorithms` answers that from the same
    table and reads no files. It is also the wrong tool for a network endpoint, a
    running host or a certificate store: it opens files on disk and nothing else.

    Coverage is reported as a fraction with a base. `files_scanned + unreadable_files +
    files_skipped_by_type == files_present`. A file that could not be opened is listed,
    never counted as scanned, because no findings in a file nobody read is not the same
    as a file that is clean. Files skipped because this tool does not claim their type
    are counted by extension, so the reader can judge the boundary rather than assume
    past it.

    Cost scales with the size of the tree, so a large monorepo takes proportionally
    longer; there is no cache and no partial mode.
    """
    return scan_directory(path)


@mcp.tool(annotations=_READ_ONLY)
def list_algorithms() -> dict[str, Any]:
    """List every algorithm family this server can recognise, and how each is classified.

    Returns the whole table: family name, classification (classical and
    quantum-vulnerable, post-quantum, symmetric, hash, or deprecated) and the kind of
    use it stands for. Reads no files and takes no arguments.

    Use this to check coverage before trusting a scan -- whether a scheme the project
    depends on is one this server knows at all -- or to explain a classification without
    scanning. To find what a particular directory uses, use `scan_repo` instead; this
    tool never looks at a codebase.

    An algorithm absent from this table is reported as `unknown` by a scan, which is not
    the same as absent from the code.
    """
    return {"algorithms": known_algorithms()}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
