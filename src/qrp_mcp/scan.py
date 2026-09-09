"""Wire the repo detectors into the classifier: directory in, findings out."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path
from typing import Any

from . import coverage, detectors
from .classifier import FingerprintRequest, fingerprint


def _version() -> str:
    try:
        return _pkg_version("qrp-mcp")
    except PackageNotFoundError:
        return "unknown"


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
    request = FingerprintRequest(
        asset_name=repo_path.name,
        algorithms=scan_result["detected_algorithms"],
        crypto_evidence={"repo_scan": scan_result},
    )
    response = fingerprint(request)

    return {
        "target": str(repo_path),
        # What was in scope, what was read, what was not and why, and what did the
        # reading. Emitted on every scan: a coverage figure without its conditions
        # is not comparable to another coverage figure.
        "coverage": coverage.build(
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
            },
            claimed_types={
                "source": sorted(detectors.SOURCE_EXTENSIONS),
                "iac": sorted(detectors.IAC_EXTENSIONS),
                "config": sorted(detectors.CONFIG_EXTENSIONS),
                "config_filenames": sorted(detectors.CONFIG_FILENAMES),
                "ci_filenames": sorted(detectors.CI_CONFIG_FILENAMES),
            },
            excluded_dirs=list(detectors.EXCLUDED_DIRS),
        ),
        "files_scanned": scan_result["files_scanned"],
        "files_present": scan_result["files_present"],
        "files_skipped_by_type": scan_result["files_skipped_by_type"],
        "unreadable_files": scan_result["unreadable_files"],
        "detected_algorithms": scan_result["detected_algorithms"],
        "findings": [f.model_dump() for f in response.findings],
        "summary": response.summary.model_dump(),
        "evidence": {
            "source_code": scan_result["source_code_findings"],
            "ci_pipeline": scan_result["ci_pipeline_findings"],
            "iac": scan_result["iac_findings"],
            "embedded_keys": scan_result["embedded_key_findings"],
        },
    }
