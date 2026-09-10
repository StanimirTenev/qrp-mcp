"""MCP server exposing the local, deterministic crypto scan as agent tools."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__, coverage, cyclonedx
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


@mcp.tool(annotations=_READ_ONLY)
def export_cbom(
    path: Annotated[
        str,
        Field(description="Directory to scan and export, same argument as `scan_repo`."),
    ],
) -> dict[str, Any]:
    """Scan one directory and return a CycloneDX 1.6 CBOM that carries its own coverage.

    Same reading as `scan_repo`; a different document. Use this when the result has to
    leave the machine -- an auditor, a customer, a pipeline artefact -- and `scan_repo`
    when a person or an agent is going to read it here.

    What the document carries beyond the components: `compositions.aggregate` states how
    complete the list is in the schema's own vocabulary, `complete` only when every file
    present was examined; `properties` carries the whole coverage block flattened,
    including every file not examined with its reason; and each asset carries
    `evidence.occurrences` with file, line and matched text.

    The coverage block travels as `properties` because the CycloneDX root object is
    `additionalProperties: false` and the format has no field for it. That is the point
    of emitting it this way rather than a limitation to work around.

    Output is deterministic: the timestamp comes from the scan window and the serial
    number from the target and the two pins, so two runs of the same code over the same
    corpus produce the same document and two runs of different code do not.
    """
    return cyclonedx.build(scan_directory(path))


@mcp.tool(annotations=_READ_ONLY)
def compare_coverage(
    first: Annotated[
        dict,
        Field(description="The `coverage` block from one scan result."),
    ],
    second: Annotated[
        dict,
        Field(description="The `coverage` block from another scan result."),
    ],
) -> dict[str, Any]:
    """Say whether two scans produced numbers that can be compared at all.

    Two coverage percentages can differ because the estate moved, because the instrument
    moved, or because the corpus was collected differently, and the percentages show
    none of the three. This reads the pins and conditions in both blocks and answers
    with one of three verdicts.

    `comparable` means nothing that moves the number differs. `not_comparable` lists
    which conditions differ, each with what it means, so the reader knows whether to
    re-run, re-clone or ignore it. `unestablished` means the blocks do not carry enough
    to decide -- an unpinned corpus, or an emitter that names no commit -- which is a
    different situation from a known difference and has a different repair.

    Use it before putting two coverage figures in one table. Do not use it to compare
    findings; it reads conditions, not results.
    """
    return coverage.compare(first, second)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
