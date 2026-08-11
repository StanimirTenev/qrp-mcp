"""Wire the repo detectors into the classifier: directory in, findings out."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import detectors
from .classifier import FingerprintRequest, fingerprint


def scan_directory(path: str | Path) -> dict[str, Any]:
    """Scan a directory for classical crypto usage and classify what was found.

    Everything runs locally: no network calls, no data leaves the machine.
    """
    repo_path = Path(path).expanduser().resolve()
    if not repo_path.is_dir():
        raise NotADirectoryError(f"not a directory: {repo_path}")

    scan_result = detectors.scan_repo(repo_path)

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
        "files_scanned": scan_result["files_scanned"],
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
