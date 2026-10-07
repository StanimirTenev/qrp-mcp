"""Wire the repo detectors into the classifier: directory in, findings out."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path
from typing import Any

from . import __version__, assets, certificates, coverage, detectors, profiles, remediation
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


def scan_directory(path: str | Path, exclude: Path | None = None,
                   profile: str = "nist") -> dict[str, Any]:
    """Scan a directory for classical crypto usage and classify what was found.

    Everything runs locally: no network calls, no data leaves the machine.
    """
    if profile not in profiles.names():
        raise ValueError(f"unknown profile {profile!r}; known: {', '.join(profiles.names())}")
    repo_path = Path(path).expanduser().resolve()
    if not repo_path.is_dir():
        raise NotADirectoryError(f"not a directory: {repo_path}")

    started_at, clock = _now(), time.monotonic()
    # Passed only when there is one, so every existing caller -- and every test
    # that substitutes this function -- keeps the one-argument shape it had.
    scan_result = (detectors.scan_repo(repo_path, exclude) if exclude is not None
                   else detectors.scan_repo(repo_path))
    seconds, finished_at = time.monotonic() - clock, _now()
    roles = _read_roles(scan_result)

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
    # The modules named for each family, from the lines that use it. Absent where
    # none was named: an empty list would read as "checked, none", which it is not.
    providers: dict[str, set[str]] = {}
    for item in scan_result["source_code_findings"] + scan_result["iac_findings"]:
        if item.get("provider"):
            providers.setdefault(item["algorithm"], set()).add(item["provider"])
    detected_by_name = dict(zip(named, scan_result["detected_algorithms"]))

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
            "tls_group_names": len(assets.CLASSICAL_GROUPS),
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
        # Named, not silently dropped: the one file a run is told to leave out is
        # its own output, and a scan that quietly omits a file is the defect this
        # tool spends its time finding in others.
        "files_left_out": scan_result.get("files_left_out", []),
        "files_skipped_by_type": scan_result["files_skipped_by_type"],
        # By name, beside the counts: what `prove_closure` needs to tell a fix from a
        # deleted file. Outside `coverage`, so it does not travel into the CBOM.
        "files_read": scan_result.get("files_read"),
        # Test code is counted apart and never dropped: the rule travels with the
        # numbers it produced. Three outputs leave this tool and a field added to one
        # of them reaches nobody -- that cost a whole report on 2026-09-21.
        #
        # ⚠️ `counted: false` rather than two zeros when the result did not come from
        # `scan_repo`. A zero nobody counted is the same defect as a coverage figure
        # with no denominator: "none here" and "not measured" are different facts and
        # this tool exists to keep them apart.
        "test_code": scan_result.get("test_code", {
            "rule": detectors.TEST_PATH_RULE,
            "meaning": "whether the finding sits in test code; named, not excluded",
            "counted": False,
        }),
        # Where the tree configures TLS, and that a terminator outside it may negotiate
        # otherwise. None when nothing here configures TLS. Outside `coverage`, so it
        # does not travel into the CBOM.
        "tls_termination": assets.tls_termination(scan_result),
        "named_but_not_used": scan_result["named_but_not_used"],
        "unreadable_files": scan_result["unreadable_files"],
        "symlinks_not_followed": scan_result["symlinks_not_followed"],
        "claimed_but_not_decoded": scan_result["claimed_but_not_decoded"],
        "unreadable_directories": scan_result["unreadable_directories"],
        "detected_algorithms": scan_result["detected_algorithms"],
        # The smallest key size read for a family, where a line named one. A number
        # nobody can see is a number nobody can check.
        "algorithm_key_sizes": scan_result.get("algorithm_key_sizes", {}),
        "algorithm_key_sizes_observed": scan_result.get("algorithm_key_sizes_observed", {}),
        # A replacement travels with the finding it is for, and only where one is due;
        # a suggestion, never an action.
        "findings": [_with_providers(_with_replacement(f.model_dump(), roles, profile),
                                     providers, detected_by_name)
                     for f in response.findings],
        # Whose rules the replacements follow; NIST unless asked.
        "replacement_profile": profile,
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
            # A classical group offered as a group of its own in a TLS group setting.
            # No excerpt: its identity is file, setting and group, so `closure` can
            # tell a removed fallback from an edited line.
            "tls_groups": scan_result.get("tls_group_findings", []),
        },
    }


def _read_roles(scan_result: dict[str, Any]) -> dict[str, dict[str, int]]:
    """Mark each RSA and EC occurrence with the role its line shows, and count them per
    family. Read here, before any level masks the line, so masking never changes a role.
    Comments carry a role but are not counted: what a comment says is not what the code does."""
    counts: dict[str, dict[str, int]] = {}
    for key in ("source_code_findings", "ci_pipeline_findings", "iac_findings",
                "embedded_key_findings"):
        for item in scan_result.get(key) or []:
            role = remediation.role_of(item)
            if role is None:
                continue
            item["role"] = role
            if item.get("evidence_kind") != "comment":
                fam = counts.setdefault(item["algorithm"], {
                    "signature": 0, "key_establishment": 0, "undetermined": 0})
                fam[role] += 1
    return counts


def _with_providers(finding: dict[str, Any], providers: dict[str, set[str]],
                    detected_by_name: dict[str, str]) -> dict[str, Any]:
    family = detected_by_name.get(finding.get("raw_value"))
    if family in providers:
        finding["providers"] = sorted(providers[family])
    return finding


def _with_replacement(finding: dict[str, Any],
                      roles: dict[str, dict[str, int]] | None = None,
                      profile: str = "nist") -> dict[str, Any]:
    suggestion = remediation.suggest(finding, (roles or {}).get(finding.get("algorithm_family")),
                                     profile)
    if suggestion is not None:
        finding["replacement"] = suggestion
    return finding

