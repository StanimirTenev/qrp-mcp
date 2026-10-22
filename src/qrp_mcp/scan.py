"""Wire the repo detectors into the classifier: directory in, findings out."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path
from typing import Any

from . import (__version__, assets, aws_tls, certificates, coverage, detectors, dnssec, ike,
               opcua, profiles, remediation)
from .classifier import _OID_FAMILIES, FingerprintRequest, fingerprint, summarize


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
    # The version pinned for a provider, and where OpenSSL's FIPS provider is activated,
    # by family: what the evidence items carry, said once on the finding.
    pins: dict[str, dict[str, set[str]]] = {}
    fips: dict[str, set[str]] = {}
    for item in scan_result["source_code_findings"] + scan_result["iac_findings"]:
        if item.get("provider"):
            providers.setdefault(item["algorithm"], set()).add(item["provider"])
        if item.get("provider_pin"):
            pin = item["provider_pin"]
            pins.setdefault(item["algorithm"], {}).setdefault(item["provider"], set()).add(
                f"{pin['version']} ({pin['pinned_in']})")
        if item.get("fips_provider_configured_in"):
            fips.setdefault(item["algorithm"], set()).update(item["fips_provider_configured_in"])
    detected_by_name = dict(zip(named, scan_result["detected_algorithms"]))
    # What the evidence says about a finding that the finding alone does not: a TLS
    # place the pinned image cannot negotiate. Joined here, where the evidence is, and
    # the summary counted again with it.
    notes, set_aside, protected = _what_the_evidence_adds(scan_result, response.findings,
                                                          detected_by_name)
    summary = summarize(response.findings, set_aside, protected)

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
            # Names that stand for several algorithms at once, each from its own table.
            "opcua_security_policies": len(opcua.POLICIES),
            "aws_tls_policies": len(aws_tls.POLICIES),
            "ike_fragmentation_products": len(ike.PRODUCTS),
            "dnssec_algorithm_numbers": len(dnssec.ALGORITHMS),
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
            # Read only when the file names an OPC UA SecurityPolicy URI; otherwise
            # counted under type_not_claimed like any other unclaimed file.
            "config_when_naming_opcua_security_policy": sorted(opcua.SNIFF_EXTENSIONS),
            # Read by the scan and missing here until a CAP-1 examiner counted 44 such
            # files in certbot as examined outside the declared types (13.10.2026).
            "yaml": [".yaml", ".yml"],
            "manifest": sorted(assets._NUGET_SUFFIXES),
            "manifest_filenames": sorted(set(assets.MANIFEST_FILENAMES) | assets._NUGET_FILENAMES),
            # A file no type claims is still read when its first bytes are a key.
            "any_type_beginning_with_key_material": ["*"],
        },
        excluded_dirs=list(detectors.EXCLUDED_DIRS),
    )

    _withhold_reassurance(summary, coverage_block, scan_result, response.findings)
    # ZA-OPRAVYANE row 63: evidence.protocols said TLSv1.0 was enabled; the summary did not.
    summary.deprecated_protocols = sorted({
        p["version"] for p in scan_result["protocol_findings"]
        if p.get("deprecated") and not p.get("banned") and p.get("version")})

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
        "findings": [{**_with_providers(_with_replacement(f.model_dump(), roles, profile),
                                        providers, detected_by_name, pins, fips),
                      **notes.get(f.algorithm_family, {})}
                     for f in response.findings],
        # Whose rules the replacements follow; NIST unless asked.
        "replacement_profile": profile,
        "summary": summary.model_dump(),
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
            # The same for SSH, in a KexAlgorithms list. Apart from tls_groups: an
            # sshd_config is not a TLS configuration.
            "ssh_kex": scan_result.get("ssh_kex_findings", []),
            # RSA key exchange (static RSA) enabled by a cipher-suite setting: AES256-SHA
            # names no key exchange and is TLS_RSA_WITH_AES_256_CBC_SHA.
            "static_rsa_kex": scan_result.get("static_rsa_kex_findings", []),
            # A TLS server image pinned in the tree beside the hybrid groups the tree
            # configures: whether that image's library can negotiate them, where known.
            "library_support": scan_result.get("library_support_findings", []),
            # An EC public key equal to k*G for a small k: the private key is recoverable
            # from it. Checked on the keys and certificates the scan opens as bytes.
            "weak_keys": scan_result.get("weak_key_findings", []),
            # OpenSSL's FIPS provider brought in by an openssl.cnf: activated in
            # configuration, never "validated".
            "fips_provider": scan_result.get("fips_provider_findings", []),
        },
    }


# strongSwan's `ppk_required = no` (its default) and a PPK switched off outright: the value,
# not the key, says whether the preshared key is required.
_PPK_NOT_REQUIRED = re.compile(r"(?<![A-Za-z])ppk(?:_required)?\s*=\s*(?:no|false|never)\b",
                               re.IGNORECASE)


# Values that say nothing classical is present. Each is withheld while the scan did not
# read every file or did not determine a private key's algorithm (ZA-OPRAVYANE rows 52,
# 62): `pqc_ready` beside an unread Caddyfile was about the one file not opened.
_REASSURING = ("pqc_ready", "pqc_pre_standard", "mechanism_protected",
               "no_quantum_vulnerable_detected")


def _withhold_reassurance(summary: Any, block: dict[str, Any], scan_result: dict[str, Any],
                          findings: list[Any]) -> None:
    if summary.pqc_readiness not in _REASSURING:
        return
    because: list[str] = []
    scope = block["scope"]
    hidden = (block.get("directories_not_entered") or {}).get("count", 0)
    if hidden:
        because.append(f"{hidden} director{'y' if hidden == 1 else 'ies'} could not be entered")
    linked = (block.get("symlinks_not_followed") or {}).get("directories", 0)
    if linked:
        because.append(f"{linked} linked director{'y was' if linked == 1 else 'ies were'} "
                       f"not followed")
    if not block["accounts_for_every_file"]:
        because.append("the reasons given for files not read do not add up to the files "
                       "present")
    if scope["files_not_examined"]:
        because.append(f"{scope['files_not_examined']} of {scope['files_present']} files were "
                       f"not read ({scope['coverage_pct']}% read); see coverage.not_examined")
    # A key whose algorithm no line of the same place names: what it is was not determined.
    named_at = {(i["path"], i["line"]) for items in _in_use(scan_result).values()
                for i in items}
    for f in findings:
        if f.algorithm_family == "private_key" and f.classification == "unknown":
            path, _, line = f.location.rpartition(":")
            if (path, int(line) if line.isdigit() else line) not in named_at:
                because.append(f"a private key at {f.location} whose algorithm was not "
                               f"determined")
    if because:
        summary.readiness_not_established = {"would_read": summary.pqc_readiness,
                                             "because": because}
        summary.pqc_readiness = "not_established"


def _in_use(scan_result: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Occurrences that are neither a comment nor a ban, by the detector's family name."""
    out: dict[str, list[dict[str, Any]]] = {}
    for item in scan_result["source_code_findings"] + scan_result["iac_findings"]:
        if item.get("evidence_kind") not in {"comment", "ban"} and item.get("algorithm"):
            out.setdefault(item["algorithm"], []).append(item)
    return out


def _what_the_evidence_adds(scan_result: dict[str, Any], findings: list[Any],
                            detected_by_name: dict[str, str]
                            ) -> tuple[dict[str, dict[str, Any]], set[str], set[str]]:
    """Fields to add to findings, by family, and the families the summary sets aside.

    A post-quantum family whose every use is a TLS place that a pinned image cannot
    negotiate (`evidence.library_support`, not_negotiable) is named with the image and
    not counted as ready (ZA-OPRAVYANE row 55). Only where every use is such a place:
    the image limits the place, not ML-KEM used by the code beside it.

    An RFC 8784 preshared key `protects` the families used in the files that configure
    it, and nothing in a file where it is optional or off (`ppk_required = no`):
    ZA-OPRAVYANE rows 57 and 58. Per family, not per occurrence."""
    family_of = {detected_by_name[f.raw_value]: f.algorithm_family for f in findings
                 if f.raw_value in detected_by_name}
    pqc = {f.algorithm_family for f in findings
           if f.classification in ("pqc_ready", "pqc_pre_standard")}
    uses = _in_use(scan_result)
    notes: dict[str, dict[str, Any]] = {}
    set_aside: set[str] = set()

    unable: dict[str, list[str]] = {}
    for item in scan_result.get("library_support_findings") or []:
        if item.get("not_negotiable"):
            for place in item.get("group_places") or []:
                unable.setdefault(place, []).append(
                    f"{item['image']} ({item['path']}:{item['line']})")
    for name, items in uses.items():
        family = family_of.get(name)
        if family not in pqc or not unable:
            continue
        places = {f"{i['path']}:{i['line']}" for i in items}
        if places <= set(unable):
            notes.setdefault(family, {})["not_negotiable_by"] = sorted(
                {image for place in places for image in unable[place]})
            set_aside.add(family)

    # A family found only in test code says so on its finding, and a post-quantum one is
    # not counted as deployed: the CBOM already marked it `scope: excluded` while the
    # summary said hybrid_partial (ZA-OPRAVYANE row 62). Never the other way round: test-only
    # classical still counts as vulnerable.
    for name, items in uses.items():
        family = family_of.get(name)
        if family and all(i.get("in_test_code") for i in items):
            notes.setdefault(family, {})["in_test_code"] = True
            if family in pqc:
                set_aside.add(family)

    # A private key recoverable from its public key raises the finding of its family,
    # so the finding, weak_count and the severity say what evidence.weak_keys says
    # (ZA-OPRAVYANE row 51: 4*G on P-384 beside an EC finding with weak_key false).
    recoverable: dict[str, list[str]] = {}
    for weak in scan_result.get("weak_key_findings") or []:
        recoverable.setdefault(weak["algorithm"], []).append(
            f"{weak['path']}:{weak['line']} ({weak['scalar']}*G on {weak['curve']})")
    for f in findings:
        if f.raw_value in detected_by_name and detected_by_name[f.raw_value] in recoverable:
            f.weak_key = True
            f.severity = "critical"
            f.reason += (" Private key recoverable from the public key at "
                         + ", ".join(recoverable[detected_by_name[f.raw_value]])
                         + "; see evidence.weak_keys.")

    protected: set[str] = set()
    ppk_files: dict[str, bool] = {}
    for item in uses.get("PPK", []):
        optional = bool(_PPK_NOT_REQUIRED.search(item.get("excerpt") or ""))
        ppk_files[item["path"]] = ppk_files.get(item["path"], False) or optional
    if ppk_files:
        for name, items in uses.items():
            if name != "PPK" and name in family_of and any(
                    ppk_files.get(i["path"]) is False for i in items):
                protected.add(family_of[name])
        mechanism = family_of.get("PPK")
        if mechanism:
            notes.setdefault(mechanism, {})["protects"] = sorted(protected)
            if not protected and all(ppk_files.values()):
                set_aside.add(mechanism)
                notes[mechanism]["reason"] = (
                    "RFC 8784 postquantum preshared key, configured as optional or switched "
                    "off (ppk_required = no): the exchange falls back to classical key "
                    "derivation when the peer has no PPK, so it protects nothing here.")
    return notes, set_aside, protected


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
                    detected_by_name: dict[str, str],
                    pins: dict[str, dict[str, set[str]]] | None = None,
                    fips: dict[str, set[str]] | None = None) -> dict[str, Any]:
    family = detected_by_name.get(finding.get("raw_value"))
    if family in providers:
        finding["providers"] = sorted(providers[family])
    # One version per provider, or none: two pins for the same provider are not chosen.
    pinned = {name: next(iter(said)) for name, said in ((pins or {}).get(family) or {}).items()
              if len(said) == 1}
    if pinned:
        finding["provider_pins"] = pinned
    if (fips or {}).get(family):
        finding["fips_provider_configured_in"] = sorted(fips[family], key=_by_place)
    return finding


def _by_place(where: str) -> tuple[str, int]:
    path, _, line = where.rpartition(":")
    return path, int(line) if line.isdigit() else 0


def _with_replacement(finding: dict[str, Any],
                      roles: dict[str, dict[str, int]] | None = None,
                      profile: str = "nist") -> dict[str, Any]:
    suggestion = remediation.suggest(finding, (roles or {}).get(finding.get("algorithm_family")),
                                     profile)
    if suggestion is not None:
        finding["replacement"] = suggestion
    return finding

