"""Wire the repo detectors into the classifier: directory in, findings out."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path
from typing import Any

from . import __version__, certificates, coverage, detectors
from .classifier import _OID_FAMILIES, FingerprintRequest, fingerprint


def _version() -> str:
    """The version that did the reading.

    The package's own `__version__` is the answer, not the installed
    distribution's: a run from a source checkout is still a run by a known
    version, and reporting "unknown" there put a placeholder into an artefact
    whose whole purpose is to say what produced it. Installed metadata is
    consulted only to catch the two disagreeing.
    """
    declared = __version__
    try:
        installed = _pkg_version("qrp-mcp")
    except PackageNotFoundError:
        return declared
    return declared if installed == declared else f"{declared} (installed: {installed})"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def scan_directory(path: str | Path) -> dict[str, Any]:
    """Scan a directory for classical crypto usage and classify what was found.

    Everything runs locally: no network calls, no data leaves the machine.
    """
    repo_path = Path(path).expanduser().resolve()
    if not repo_path.is_dir():
        raise NotADirectoryError(f"not a directory: {repo_path}")

    started_at, clock = _now(), time.monotonic()
    scan_result = detectors.scan_repo(repo_path)
    seconds, finished_at = time.monotonic() - clock, _now()

    # Detected algorithms are passed as explicit algorithms so each one is classified.
    # (The gateway's ingest contract routes them through package_metadata instead, which
    # deliberately leaves them unclassified for server-side correlation -- not useful here.)
    # A family whose key size was read on the line travels with it, so the classifier
    # can call a 1024-bit RSA weak instead of reporting every RSA the same way.
    sizes = scan_result.get("algorithm_key_sizes", {})
    named = [f"{alg}-{sizes[alg]}" if alg in sizes else alg
             for alg in scan_result["detected_algorithms"]]

    request = FingerprintRequest(
        # A filesystem root has no name ("/" or "D:\\"); the model requires one.
        asset_name=detectors.display_path(repo_path.name or str(repo_path)),
        algorithms=named,
        crypto_evidence={"repo_scan": scan_result},
    )
    response = fingerprint(request)

    coverage_block = coverage.build(
        repo_path=repo_path,
        scan_result=scan_result,
        started_at=started_at,
        finished_at=finished_at,
        seconds=seconds,
        tool_version=_version(),
        ruleset={
            "algorithm_patterns": len(detectors.ALGORITHM_PATTERNS),
            "iac_algorithm_patterns": len(detectors.IAC_ALGORITHM_PATTERNS),
            "signing_command_patterns": len(detectors.SIGNING_COMMAND_PATTERNS),
            # Rules that are not line patterns and were missing from this count: the
            # object identifiers resolved inside certificates and the PEM labels that
            # name an algorithm on their own.
            "certificate_oid_names": len(_OID_FAMILIES),
            "pem_labels": len(certificates._LABEL_ALGORITHMS),
            "cipher_suite_components": len(detectors._SUITE_COMPONENT),
            "openssl3_fetch_names": len(detectors._FETCH_NAME_FAMILY),
        },
        claimed_types={
            "source": sorted(detectors.SOURCE_EXTENSIONS),
            "iac": sorted(detectors.IAC_EXTENSIONS),
            "config": sorted(detectors.CONFIG_EXTENSIONS),
            "config_filenames": sorted(detectors.CONFIG_FILENAMES),
            "ci_filenames": sorted(detectors.CI_CONFIG_FILENAMES),
            # Read as bytes rather than lines, and missing from this list while the
            # scan was reporting findings from them.
            "certificate": sorted(certificates.CERTIFICATE_EXTENSIONS),
        },
        excluded_dirs=list(detectors.EXCLUDED_DIRS),
    )

    return {
        "target": detectors.display_path(str(repo_path)),
        # One sentence for whoever signs the report rather than runs the tool.
        # The block below is the evidence for it.
        "verdict": coverage.verdict_line(coverage_block),
        # What was in scope, what was read, what was not and why, and what did the
        # reading. Emitted on every scan: a coverage figure without its conditions
        # is not comparable to another coverage figure.
        "coverage": coverage_block,
        "files_scanned": scan_result["files_scanned"],
        "files_present": scan_result["files_present"],
        "files_skipped_by_type": scan_result["files_skipped_by_type"],
        "named_but_not_used": scan_result["named_but_not_used"],
        "unreadable_files": scan_result["unreadable_files"],
        "symlinks_not_followed": scan_result["symlinks_not_followed"],
        "claimed_but_not_decoded": scan_result["claimed_but_not_decoded"],
        "unreadable_directories": scan_result["unreadable_directories"],
        "detected_algorithms": scan_result["detected_algorithms"],
        # The smallest key size read for a family, where a line named one. A number
        # nobody can see is a number nobody can check.
        "algorithm_key_sizes": scan_result.get("algorithm_key_sizes", {}),
        "findings": [f.model_dump() for f in response.findings],
        "summary": response.summary.model_dump(),
        "evidence": {
            "source_code": scan_result["source_code_findings"],
            "ci_pipeline": scan_result["ci_pipeline_findings"],
            "iac": scan_result["iac_findings"],
            "embedded_keys": scan_result["embedded_key_findings"],
            # Assets with no algorithm of their own. Kept apart from the
            # findings above so that nothing downstream reads a protocol
            # version or an installed library as an observed algorithm.
            "protocols": scan_result["protocol_findings"],
            "dependencies": scan_result["dependency_findings"],
        },
    }
