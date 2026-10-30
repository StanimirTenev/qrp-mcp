"""Wire the repo detectors into the classifier: directory in, findings out."""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path
from typing import Any

from . import (__version__, assets, aws_tls, baseline as baseline_mod, certificates, confidence,
               config, coverage, detectors, dnssec, ike, opcua, profiles, remediation, suppression)
from .classifier import _OID_FAMILIES, FingerprintRequest, fingerprint, known_algorithms, summarize


def _version() -> str:
    """The version that did the reading: the running code's own `__version__`.

    Until 0.36.0 this read "0.36.0 (installed: 0.33.0)" whenever the distribution
    metadata disagreed (ZA-OPRAVYANE row 148). The 0.33.0 was written once by an
    editable install and never refreshed, so it described no code that ran; the
    disagreement is now said beside the version, in `_installed_distribution`.
    """
    return __version__


def _installed_distribution() -> dict[str, Any] | None:
    """What the installed distribution's metadata says, only where it disagrees with
    the code that is running. None when they agree or when nothing is installed."""
    try:
        installed = _pkg_version("qrp-mcp")
    except PackageNotFoundError:
        return None
    if installed == __version__:
        return None
    return {
        "version": installed,
        "matches_running_code": False,
        "meaning": (f"the code that ran is {__version__} (see source_commit); the "
                    f"installed distribution's metadata says {installed}. An editable "
                    f"install writes that metadata once, at install time, so it lags the "
                    f"source; a different package on the path would also show here"),
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# `settings` not given: read `<root>/.qrp.toml` if there is one.
DISCOVER = object()


def scan_directory(path: str | Path, exclude: Path | list[Path] | None = None,
                   profile: str = "nist", *, settings: Any = DISCOVER,
                   baseline: str | Path | None = None,
                   use_baseline: bool = True) -> dict[str, Any]:
    """Scan a directory for classical crypto usage and classify what was found.

    Everything runs locally: no network calls, no data leaves the machine.

    `settings` is a loaded `config.load(...)` (or None for none); left out, the tree's own
    `.qrp.toml` is read, so the MCP tools and the command line apply the same file. Its
    excludes and baseline apply here; profile and level are the caller's to read.
    `baseline` names a baseline file (the config's when not given); `use_baseline=False`
    applies none, for the run that writes a fresh one.
    """
    if profile not in profiles.names():
        raise ValueError(f"unknown profile {profile!r}; known: {', '.join(profiles.names())}")
    repo_path = Path(path).expanduser().resolve()
    if not repo_path.is_dir():
        raise NotADirectoryError(f"not a directory: {repo_path}")
    if settings is DISCOVER:
        settings = config.load(repo_path)
    values = (settings or {}).get("values", {})
    baseline_file = (baseline or values.get("baseline")) if use_baseline else None
    baseline_doc = baseline_mod.read(baseline_file) if baseline_file else None
    # Files this run reads for itself are not part of what it reads: the result, the config
    # and the baseline. Each is left out and named in files_left_out.
    left_out = [] if exclude is None else exclude if isinstance(exclude, list) else [exclude]
    left_out = [*left_out, *([settings["file"]] if settings else []),
                *([Path(values["baseline"])] if values.get("baseline") else []),
                *([Path(baseline)] if baseline else [])]

    # The checkout's commit and state, asked now: its `git status` runs beside the reading
    # instead of after it (release 3c).
    corpus_pin = coverage.start_git_pin(repo_path)
    started_at, clock = _now(), time.monotonic()
    # Passed only when there is one, so every existing caller -- and every test
    # that substitutes this function -- keeps the one-argument shape it had.
    if values.get("exclude"):
        scan_result = detectors.scan_repo(repo_path, left_out or None, values["exclude"])
    elif left_out:
        scan_result = detectors.scan_repo(repo_path, left_out)
    else:
        scan_result = detectors.scan_repo(repo_path)
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
    # A family whose only use is identifier rows (release 3b/3e: `generate_rsa_keys`,
    # `RSAUtil`) stays a finding and says so, and is not counted: identifier rows are low
    # and never move the headline or by_role (rel3-rules; 20 of the 30 rows rel3e's mini
    # hold-out added were such names, none strong enough to decide anything).
    by_name_only = _identifier_only(scan_result)
    for f in response.findings:
        if detected_by_name.get(f.raw_value) in by_name_only:
            notes.setdefault(f.algorithm_family, {})["identifier_only"] = True
    counted = [f for f in response.findings
               if detected_by_name.get(f.raw_value) not in by_name_only]
    summary = summarize(counted, set_aside, protected)
    summary.by_role = _by_role(counted, roles, detected_by_name, set_aside, protected)

    coverage_block = coverage.build(
        repo_path=repo_path,
        scan_result=scan_result,
        started_at=started_at,
        finished_at=finished_at,
        seconds=seconds,
        tool_version=_version(),
        installed_distribution=_installed_distribution(),
        corpus_pin=corpus_pin,
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
            "jca_names": len(detectors._JCA_NAME_FAMILY),
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
            "config_filename_pattern": [detectors.CONFIG_FILENAME_PATTERN.pattern],
            "config_extensionless_in_directories": sorted(detectors.CONFIG_DIRECTORIES),
            # Read for owners only (ZA-OPRAVYANE row 94), never matched for algorithms.
            "codeowners": list(detectors.CODEOWNERS_LOCATIONS),
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
            # Read as the file they render (kragg-3); a template rendering documentation
            # (detectors.TEMPLATE_DOCUMENTS: .md, .rst, ...) is not claimed.
            "jinja_template": list(detectors.TEMPLATE_SUFFIXES),
            # A file no type claims is still read when its first bytes are a key.
            "any_type_beginning_with_key_material": ["*"],
        },
        excluded_dirs=list(detectors.EXCLUDED_DIRS),
    )

    _withhold_reassurance(summary, coverage_block, scan_result, response.findings)
    if summary.readiness_not_established:
        for part in ("key_establishment", "signature"):
            if summary.by_role[part]["pqc_readiness"] in _REASSURING:
                summary.by_role[part]["pqc_readiness"] = "not_established"
    # ZA-OPRAVYANE row 63: evidence.protocols said TLSv1.0 was enabled; the summary did not.
    summary.deprecated_protocols = sorted({
        p["version"] for p in scan_result["protocol_findings"]
        if p.get("deprecated") and not p.get("banned") and p.get("version")})

    result = {
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
        # Where the owners on evidence items come from: a CODEOWNERS file, read as an
        # assumption about who owns a path. None when the tree has none.
        "codeowners": scan_result.get("codeowners"),
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
        # Hybrids named on a line with their two halves, for the CBOM's hybrid components
        # and their `dependencies`. Outside `evidence`: the halves are already there, and
        # counting the hybrid again would count one line twice.
        "hybrid_names": scan_result.get("hybrid_names", []),
        # The SHA-256 of every file the evidence cites, as it was read (release A): what
        # lets a third party re-locate a finding and tell a moved line from another file.
        "evidence_file_sha256": _cited_digests(scan_result),
    }

    # How sure the scan is of each occurrence, from what it read (release E); before the
    # suppression below, so a suppressed occurrence keeps its level.
    confidence.annotate(result["evidence"])
    # Applied last, on the finished evidence, so the inventory above is the code as it is:
    # a suppressed RSA is still RSA in the code.
    family_of ={detected_by_name[f.raw_value]: f.algorithm_family for f in response.findings
                 if f.raw_value in detected_by_name}
    held = suppression.apply(result["evidence"], scan_result.get("suppression_markers") or [],
                             family_of)
    result["suppressed"] = held
    coverage_block["suppressed"] = suppression.coverage_block(held)
    coverage_block["confidence"] = confidence.coverage_block(result["evidence"])
    if held["count"]:
        per_family: dict[str, int] = {}
        for items in held["evidence"].values():
            for item in items:
                name = family_of.get(item.get("algorithm"), item.get("algorithm"))
                per_family[name] = per_family.get(name, 0) + 1
        for finding in result["findings"]:
            if per_family.get(finding["algorithm_family"]):
                finding["suppressed_occurrences"] = per_family[finding["algorithm_family"]]
    if settings:
        coverage_block["config"] = config.coverage_block(settings)
    if baseline_doc is not None:
        result["baseline"] = baseline_mod.apply(result, baseline_doc, baseline_file)
        # Counted where the CBOM reads, as `suppressed` is; the rows and the file's path
        # stay in `baseline`, the path being this machine's.
        coverage_block["baseline"] = {k: result["baseline"][k] for k in
                                      ("meaning", "entries", "new", "baselined", "absent")}
    _library_default_key_exchange(result)
    result["findings_fingerprint"] = findings_fingerprint(result)
    return result


# ZA-OPRAVYANE rows 164 and 167 (Daniel Stokes): a TLS server that sets no group negotiates
# whatever its library defaults to -- X25519 with OpenSSL 3.2, X25519MLKEM768 with 3.5 -- and
# the scan said nothing, with the same `unknown` an empty directory gets.
LIBRARY_DEFAULT_KEY_EXCHANGE = (
    "No TLS group or curve is set in the files read: the key exchange is the TLS library's "
    "default, which depends on the library version that runs (OpenSSL 3.5 offers a hybrid "
    "first, earlier versions a classical group), and this scan does not resolve it.")


KEY_EXCHANGE_NOT_SET = "library default, not resolved: no group is set in the files read"


def _library_default_key_exchange(result: dict[str, Any]) -> None:
    tls = result.get("tls_termination")
    if not tls or any(place.get("basis") == "configured_group"
                      for place in tls.get("configured_in") or []):
        return
    tls["key_exchange"] = {
        "configured": False,
        "statement": LIBRARY_DEFAULT_KEY_EXCHANGE,
        # The versions a manifest pins, which decide the default; named, not resolved.
        "libraries_pinned": [{"package": d["package"], "version": d["version"],
                              "path": d["path"], "line": d["line"]}
                             for d in result["evidence"]["dependencies"] if d.get("version")],
    }
    # On each TLS place, so the CBOM's protocol component carries it. Read from the rest of
    # the tree, not the line: closure and the baseline leave it out of an occurrence's identity.
    for asset in result["evidence"]["protocols"]:
        if asset.get("protocol") == "tls" and asset.get("tls_termination"):
            asset["key_exchange"] = KEY_EXCHANGE_NOT_SET
    summary = result["summary"]
    role = summary["by_role"]["key_establishment"]
    if role["families"]:
        return
    role["pqc_readiness"] = "not_established"
    if summary["pqc_readiness"] in ("unknown", *_REASSURING):
        because = ("TLS is configured and no key exchange is set in the files read: the TLS "
                   "library's default applies and is not resolved (tls_termination.key_exchange)")
        summary["readiness_not_established"] = {
            "would_read": summary["pqc_readiness"], "because": [because]}
        summary["pqc_readiness"] = "not_established"


# ZA-OPRAVYANE row 178 (Mark McGovern, 29.10.2026): two scans of one commit matched in every
# field but the read window, yet the printed SHA-256 differed, because it is the digest of the
# whole file, times included. That digest stays -- it is the file's integrity. Beside it, a
# fingerprint of the findings alone, normalised by these rules, says whether two runs reached
# the same result.
FINGERPRINT_FORMAT = "qrp-mcp findings fingerprint 1"
FINGERPRINT_RULES = (
    "each finding as [algorithm_family, raw_value, classification, severity]",
    "each evidence occurrence as [category, path, line, family, role, key_size]; family is "
    "algorithm, else family, type, protocol, command_type or package; an absent field is null",
    "left out: the read window (start, end, duration), excerpts (they differ by --level), "
    "confidence, owners, baseline state, mandate clauses, suppressed rows, coverage, the "
    "target's absolute path and the tool's version",
    "both lists sorted; serialised as JSON with sorted keys, separators ',' and ':', UTF-8, "
    "no ASCII escaping; SHA-256 of those bytes, in hex",
)


def findings_fingerprint(result: dict[str, Any]) -> dict[str, Any]:
    """The SHA-256 of the normalised findings (FINGERPRINT_RULES), with the rules beside it."""
    import hashlib
    import json

    def family(item: dict[str, Any]) -> Any:
        for key in ("algorithm", "family", "type", "protocol", "command_type", "package"):
            if item.get(key):
                return item[key]
        return None

    findings = sorted([f.get("algorithm_family"), f.get("raw_value"), f.get("classification"),
                       f.get("severity")] for f in result["findings"])
    occurrences = sorted(
        [category, item.get("path"), item.get("line"), family(item), item.get("role"),
         item.get("key_size")]
        for category, items in result["evidence"].items() for item in items
        if isinstance(item, dict))
    material = json.dumps({"findings": findings, "evidence": occurrences}, sort_keys=True,
                          separators=(",", ":"), ensure_ascii=False, default=str)
    return {"sha256": hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest(),
            "format": FINGERPRINT_FORMAT, "rules": list(FINGERPRINT_RULES),
            "meaning": ("the same findings give the same fingerprint on every run and at every "
                        "--level; the sha256 printed for the file is its integrity, which the "
                        "read times change")}


def _cited_digests(scan_result: dict[str, Any]) -> dict[str, str]:
    digests = scan_result.get("file_digests") or {}
    cited = {item["path"] for key, items in scan_result.items()
             if key.endswith("_findings") and isinstance(items, list)
             for item in items if isinstance(item, dict) and isinstance(item.get("path"), str)}
    cited.update(item["path"] for item in scan_result.get("hybrid_names", []))
    return {path: digests[path] for path in sorted(cited) if path in digests}


# strongSwan's `ppk_required = no` (its default) and a PPK switched off outright: the value,
# not the key, says whether the preshared key is required.
_PPK_NOT_REQUIRED = re.compile(r"(?<![A-Za-z])ppk(?:_required)?\s*=\s*(?:no|false|never)\b",
                               re.IGNORECASE)
# strongSwan's connection options. `ppk_required` defaults to `no` (swanctl.opt:
# "connections.<conn>.ppk_required = no"), so a `ppk_id` without `ppk_required = yes` is an
# optional PPK too (ZA-OPRAVYANE row 89).
_PPK_ID = re.compile(r"(?<![A-Za-z])ppk_id\s*=", re.IGNORECASE)
_PPK_REQUIRED = re.compile(r"(?<![A-Za-z])ppk_required\s*=\s*(?:yes|true)\b", re.IGNORECASE)


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
    # A report found in the tree was read and recognised (row 144): nothing in it is
    # unread code, so it does not withhold the headline on its own.
    unread = scope["files_not_examined"] - sum(
        r["count"] for r in block["not_examined"] if r["reason"] == "report_document")
    if unread:
        because.append(f"{unread} of {scope['files_present']} files were "
                       f"not read ({scope['coverage_pct']}% read); see coverage.not_examined")
    # A zone signed with an algorithm number this scan gives no family (row 102). 0 is
    # DELETE, a signal and not an algorithm.
    for asset in scan_result.get("protocol_findings") or []:
        if asset.get("dnssec_algorithm") not in (None, 0):
            because.append(f"DNSSEC algorithm {asset['dnssec_algorithm']} at "
                           f"{asset['path']}:{asset['line']} is not named by this scan")
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


def _by_role(findings: list[Any], roles: dict[str, dict[str, int]],
             detected_by_name: dict[str, str], set_aside: set[str],
             protected: set[str]) -> dict[str, Any]:
    """Readiness for key establishment and for signatures apart (ZA-OPRAVYANE row 100: nginx
    with X25519MLKEM768 and an ECDSA certificate read only `hybrid_partial`, which says
    nothing about which half is post-quantum).

    A family's role is the classifier's own `kind`. RSA and EC have none of their own; they
    go where the lines read for them showed a role (`_read_roles`), to both where both, and
    are named under `role_not_determined` where any line's role could not be read. The
    readiness of each part is `summarize` over that part's findings only; `none_found` where
    the part has none."""
    kinds = {a["family"]: a["kind"] for a in known_algorithms()}
    parts: dict[str, list[Any]] = {"key_establishment": [], "signature": []}
    undetermined: set[str] = set()
    for f in findings:
        kind = kinds.get(f.algorithm_family)
        if kind == "key_exchange":
            parts["key_establishment"].append(f)
        elif kind == "signature":
            parts["signature"].append(f)
        elif kind == "public_key":
            seen = roles.get(detected_by_name.get(f.raw_value, f.algorithm_family)) or {}
            for part in parts:
                if seen.get(part):
                    parts[part].append(f)
            if seen.get("undetermined") or not (seen.get("key_establishment")
                                                or seen.get("signature")):
                undetermined.add(f.algorithm_family)
    out: dict[str, Any] = {}
    for part, chosen in parts.items():
        out[part] = {
            "families": sorted({f.algorithm_family for f in chosen}),
            "pqc_readiness": (summarize(chosen, set_aside, protected).pqc_readiness
                              if chosen else "none_found"),
        }
    out["role_not_determined"] = sorted(undetermined)
    return out


def _in_use(scan_result: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Occurrences that are neither a comment nor a ban, by the detector's family name."""
    out: dict[str, list[dict[str, Any]]] = {}
    for item in scan_result["source_code_findings"] + scan_result["iac_findings"]:
        if item.get("evidence_kind") not in {"comment", "ban"} and item.get("algorithm"):
            out.setdefault(item["algorithm"], []).append(item)
    return out


def _identifier_only(scan_result: dict[str, Any]) -> set[str]:
    """Families, by the detector's name, whose every use is an identifier row."""
    return {name for name, items in _in_use(scan_result).items()
            if all(i.get("evidence_kind") == "identifier" for i in items)}


def _what_the_evidence_adds(scan_result: dict[str, Any], findings: list[Any],
                            detected_by_name: dict[str, str]
                            ) -> tuple[dict[str, dict[str, Any]], set[str], set[str]]:
    """Fields to add to findings, by family, and the families the summary sets aside.

    A post-quantum family whose every use is a TLS place that a pinned image cannot
    negotiate (`evidence.library_support`, not_negotiable) is named with the image and
    not counted as ready (ZA-OPRAVYANE row 55). Only where every use is such a place:
    the image limits the place, not ML-KEM used by the code beside it.

    An RFC 8784 preshared key `protects` the families used in the files that configure
    it, and nothing in a file where it is optional or off (`ppk_required = no`, or a
    strongSwan `ppk_id` without `ppk_required = yes`): ZA-OPRAVYANE rows 57, 58 and 89. A
    family is protected only when every use of it is in such a file (row 92)."""
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
    with_id: set[str] = set()
    required: set[str] = set()
    for item in uses.get("PPK", []):
        excerpt = item.get("excerpt") or ""
        optional = bool(_PPK_NOT_REQUIRED.search(excerpt))
        ppk_files[item["path"]] = ppk_files.get(item["path"], False) or optional
        if _PPK_ID.search(excerpt):
            with_id.add(item["path"])
        if _PPK_REQUIRED.search(excerpt):
            required.add(item["path"])
    for path in with_id - required:
        ppk_files[path] = True
    if ppk_files:
        # Every use of the family, not any: EC in a second tunnel with no PPK is not
        # covered by the PPK of the first (ZA-OPRAVYANE row 92).
        for name, items in uses.items():
            if name != "PPK" and name in family_of and all(
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
    Comments carry a role but are not counted: what a comment says is not what the code does.
    Nor are identifier rows: a name is too weak to set a role (rel3-rules)."""
    counts: dict[str, dict[str, int]] = {}
    for key in ("source_code_findings", "ci_pipeline_findings", "iac_findings",
                "embedded_key_findings"):
        for item in scan_result.get(key) or []:
            role = remediation.role_of(item)
            if role is None:
                continue
            item["role"] = role
            if item.get("evidence_kind") not in ("comment", "identifier"):
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
    # A family the chosen profile recommends beyond NIST's standards (ZA-OPRAVYANE row 101:
    # Classic McEliece under de-bsi read only "candidate").
    said = profiles.standing(profile, finding.get("algorithm_family"))
    if said:
        finding["profile_standing"] = said
    return finding

