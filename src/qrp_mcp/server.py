"""MCP server exposing the local, deterministic crypto scan as agent tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__, closure, coverage, cyclonedx
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
    level: Annotated[
        Literal["full", "masked", "trimmed"],
        Field(
            description=(
                "How much of each matched line to return. `masked` (the default) keeps "
                "the characters that spell the algorithm and stars every other letter "
                "and digit; `full` returns the line as written; `trimmed` returns no "
                "line at all. File and line number are the same at every level."
            )
        ),
    ] = "masked",
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

    Quoted lines are masked by default. Reading happens on this machine, but this
    result does not stay on it: it is returned to a model, which is a place the
    scanned line has not been before. A secret sharing a line with a finding -- a
    token in the call that names the cipher -- would travel with it. Masking keeps
    what a reader needs (the algorithm, the file, the line number, the shape of the
    call) and removes what nobody asked for. Pass `level="full"` when the line
    itself is the thing being examined.
    """
    return _at_level(scan_directory(path), level)


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
    level: Annotated[
        Literal["full", "masked", "trimmed"],
        Field(
            description=(
                "How much of each matched line to carry in `evidence.occurrences`. "
                "Same three levels and the same default as `scan_repo`."
            )
        ),
    ] = "masked",
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

    The serial number is derived from the target, the two pins and a digest of the
    findings, so two runs of the same code over the same corpus that find the same things
    share it and a different result does not. The timestamp and coverage window record
    when each run happened.

    The matched text in `evidence.occurrences` is masked by default, for the reason
    given on `scan_repo` and one more: this document is the one built to be sent.
    An auditor needs the algorithm, the file and the line; the contents of the line
    are not part of the claim being made.
    """
    return cyclonedx.build(_at_level(scan_directory(path), level))


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


@mcp.tool(annotations=_READ_ONLY)
def prove_closure(
    before: Annotated[
        str,
        Field(description="Path to the JSON result of the scan made BEFORE the change "
                          "(`qrp-mcp scan PATH --out FILE`)."),
    ],
    after: Annotated[
        str,
        Field(description="Path to the JSON result of the scan made AFTER the change, "
                          "same tree, same instrument, same level."),
    ],
) -> dict[str, Any]:
    """Say which findings a change actually closed, by comparing two saved scans of one tree.

    First it decides whether the two runs can be compared for closure at all: the
    same instrument commit, version, rules, file types and exclusions, both trees
    pinned to a commit and clean, both results quoting lines at the same level. The
    trees themselves may differ -- that difference is what is measured. If the runs
    cannot be compared, nothing is reported as closed and the repair is named.

    Only then does it match every occurrence without its line number: `closed`
    (present before, absent from every file the second run read), still open (and
    how many only moved lines), `relocated` to another path (renamed or moved, not
    fixed), `removed` (the whole file is gone from the second tree -- not counted as
    closed), moved into or out of test code, `new`, and `unverifiable` (in a file the
    second run did not read). A file the second run could not open is never counted
    as fixed.

    To keep the verdict as a file that names the two scans it judged, run
    `qrp-mcp closure BEFORE AFTER --out FILE`.

    Use it after a fix, to evidence the fix. Do not use it to compare coverage
    figures between two estates -- `compare_coverage` answers that. It reads two
    local files and nothing else.
    """
    return closure.prove_closure(_load_result(before), _load_result(after))


def _load_result(path: str) -> dict[str, Any]:
    p = Path(path).expanduser()
    if not p.is_file():
        raise FileNotFoundError(f"no scan result at {p}")
    return json.loads(p.read_text(encoding="utf-8"))


def _strip_excerpts(result: dict[str, Any]) -> dict[str, Any]:
    """The 'trimmed' level: every occurrence keeps its file and line, but not the
    line of code itself."""
    for items in result.get("evidence", {}).values():
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    item.pop("excerpt", None)
    return result


def _mask_excerpt(excerpt: str, algorithm: str) -> str:
    """Keep what names the algorithm; turn everything else into asterisks.

    Between `full`, which sends the line of code, and `trimmed`, which sends
    nothing, there is a third thing a reader actually needs: enough shape to see
    that this is a call rather than a string, without the contents of the line.

    A rival tool does this by position -- first twelve characters, then stars --
    which keeps whatever the line happens to begin with. A line that begins with a
    token, a key or a password would give up its first characters. Here the rule is
    the other way round: only the characters that spell the algorithm survive, and
    every other letter and digit becomes a star. Punctuation and spacing stay,
    because the shape of a call is not a secret and is the whole reason to keep an
    excerpt at all.
    """
    if not excerpt:
        return excerpt
    keep = [False] * len(excerpt)
    if algorithm:
        # Every spelling of the family that appears, not just the first.
        for match in re.finditer(re.escape(algorithm), excerpt, re.IGNORECASE):
            for i in range(match.start(), match.end()):
                keep[i] = True
    out = []
    for index, character in enumerate(excerpt):
        if keep[index] or not character.isalnum():
            out.append(character)
        else:
            out.append("*")
    return "".join(out)


def _mask_excerpts(result: dict[str, Any]) -> dict[str, Any]:
    """The 'masked' level: the line is kept in shape, emptied of its content."""
    for items in result.get("evidence", {}).values():
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("excerpt"):
                    item["excerpt"] = _mask_excerpt(
                        str(item["excerpt"]), str(item.get("algorithm") or ""))
    return result


def _at_level(result: dict[str, Any], level: str) -> dict[str, Any]:
    """One place that turns a level into what the result carries.

    There were two paths out of this scan and only one of them had a level. The
    export to a file, the rare one, could mask; the tools, which run on every agent
    call and hand their result to a model, always sent the line as written. The
    control had been built for the path we thought left the machine rather than the
    one that leaves on every call.

    So the levels live here, and both paths ask this function rather than spelling
    the rule out again. A second spelling is how the two drift apart.
    """
    # Said in the result, so a later comparison can tell a masked line from a real
    # one; two results quoting at different levels are not the same text.
    result["excerpt_level"] = level
    if level == "trimmed":
        return _strip_excerpts(result)
    if level == "masked":
        return _mask_excerpts(result)
    return result


def scan_to_file(argv: list[str], cbom: bool = False) -> int:
    """`qrp-mcp scan PATH --out FILE`: the same result as the scan_repo tool,
    written to a file the owner can inspect and send on. Nothing leaves the machine.

    `qrp-mcp cbom` is the same run written as the export_cbom document. One function
    for both, so the rules about the output file -- left out of the tree it describes,
    its digest printed -- cannot be kept on one path and forgotten on the other."""
    p = argparse.ArgumentParser(
        prog="qrp-mcp cbom" if cbom else "qrp-mcp scan",
        description=("Scan a directory and write a CycloneDX 1.6 CBOM that carries its "
                     "own coverage. Nothing is sent anywhere." if cbom else
                     "Scan a directory and write the result as JSON. Nothing is sent anywhere."))
    p.add_argument("path", help="directory to scan")
    p.add_argument("--out", metavar="FILE", help="write here instead of standard output")
    # The CBOM is the document built to be sent, so it quotes masked by default, as
    # export_cbom does.
    p.add_argument("--level", choices=("full", "masked", "trimmed"),
                   default="masked" if cbom else "full",
                   help="what the quoted line of evidence carries: 'full' the line "
                        "itself, 'masked' its shape with everything but the algorithm "
                        "name starred out, 'trimmed' nothing. Files and line numbers "
                        "stay in all three. Default: " + ("masked" if cbom else "full"))
    a = p.parse_args(argv)
    # A path or file name the console cannot encode must not fail the run after the
    # scan has finished.
    sys.stderr.reconfigure(errors="backslashreplace")
    if not Path(a.path).expanduser().is_dir():
        p.error(f"not a directory: {a.path}")
    # Normalised once, then used for the check, the write and the message. Checking
    # the expanded path and writing the raw one meant `--out ~/x.json`, quoted so the
    # shell never saw the tilde, passed the check and then raised FileNotFoundError.
    out_path = Path(a.out).expanduser() if a.out else None
    if out_path is not None and not out_path.resolve().parent.is_dir():
        p.error(f"the folder for --out does not exist: {out_path.parent}")

    # The result must not become part of the next run's input. Writing it inside
    # the scanned tree made a second run see one more file, quote the findings out
    # of its own output and produce a different corpus digest for an unchanged
    # tree. Excluding the same path every run keeps two runs comparable.
    result = scan_directory(a.path, out_path)
    result = _at_level(result, a.level)
    if cbom:
        result = cyclonedx.build(result)
    return _write(result, out_path, a.level)


def _write(result: dict[str, Any], out_path: Path | None, label: str) -> int:
    data = (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode()
    if out_path is not None:
        try:
            out_path.write_bytes(data)
        except OSError as err:
            print(f"qrp-mcp: could not write {out_path}: {err.strerror}", file=sys.stderr)
            return 1
        print(f"wrote {out_path} ({label})", file=sys.stderr)
    else:
        sys.stdout.buffer.write(data)
    # The digest of the exact bytes written: what a recipient will quote back.
    print(f"sha256 {hashlib.sha256(data).hexdigest()}", file=sys.stderr)
    return 0


def closure_to_file(argv: list[str]) -> int:
    """`qrp-mcp closure BEFORE AFTER --out FILE`: the prove_closure verdict as a file.

    The verdict names the two files it judged by digest. A statement that something
    was closed, which does not say closed between what and what, is not evidence."""
    p = argparse.ArgumentParser(
        prog="qrp-mcp closure",
        description="Compare two saved scans of one tree (`qrp-mcp scan PATH --out FILE`, "
                    "before and after a change) and write what the change closed.")
    p.add_argument("before", help="scan result from before the change")
    p.add_argument("after", help="scan result from after the change")
    p.add_argument("--out", metavar="FILE", help="write here instead of standard output")
    a = p.parse_args(argv)
    sys.stderr.reconfigure(errors="backslashreplace")
    inputs, loaded = [], []
    for name in (a.before, a.after):
        path = Path(name).expanduser()
        if not path.is_file():
            p.error(f"no scan result at {name}")
        raw = path.read_bytes()
        try:
            loaded.append(json.loads(raw))
        except ValueError:
            p.error(f"not a JSON scan result: {name}")
        inputs.append({"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()})
    out_path = Path(a.out).expanduser() if a.out else None
    if out_path is not None and not out_path.resolve().parent.is_dir():
        p.error(f"the folder for --out does not exist: {out_path.parent}")
    result = {"inputs": {"before": inputs[0], "after": inputs[1]},
              **closure.prove_closure(*loaded)}
    return _write(result, out_path, "closure")


USAGE = """usage: qrp-mcp                 start the MCP server on stdio (what MCP clients run)
       qrp-mcp scan PATH [--out FILE] [--level full|masked|trimmed]
                               scan a directory and write the result as JSON
       qrp-mcp cbom PATH [--out FILE] [--level full|masked|trimmed]
                               scan a directory and write a CycloneDX 1.6 CBOM
       qrp-mcp closure BEFORE AFTER [--out FILE]
                               compare two saved scans and write what a change closed
       qrp-mcp --version
"""


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        mcp.run()
        return
    if argv[0] == "scan":
        raise SystemExit(scan_to_file(argv[1:]))
    if argv[0] == "cbom":
        raise SystemExit(scan_to_file(argv[1:], cbom=True))
    if argv[0] == "closure":
        raise SystemExit(closure_to_file(argv[1:]))
    if argv[0] in ("-h", "--help", "help"):
        print(USAGE, end="")
        raise SystemExit(0)
    if argv[0] in ("-V", "--version"):
        print(f"qrp-mcp {__version__}")
        raise SystemExit(0)
    # Anything else used to start the server silently, which looks like a hang.
    print(f"qrp-mcp: unknown argument {argv[0]!r}\n\n{USAGE}", end="", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    main()
