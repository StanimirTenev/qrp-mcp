"""Defects found by a review of 0.7.2, each reproduced before it was fixed.

The scanner is pointed at code its user did not write. Nothing in that code, its
file names or its repository configuration may run a program, crash the scan, or
disappear from the count.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

needs_git = pytest.mark.skipif(not shutil.which("git"), reason="needs git")
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
not_root = pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                              reason="root ignores permissions")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    _git(repo, "init", "-q")
    _git(repo, "add", "a.py")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
    return repo


# --- 1. a scanned repository must not be able to run programs ------------------

@needs_git
@posix_only
def test_repository_fsmonitor_is_not_executed(tmp_path):
    repo = _repo(tmp_path)
    marker = tmp_path / "PWNED"
    _git(repo, "config", "core.fsmonitor", f"touch {marker}; false")
    scan_directory(str(repo))
    assert not marker.exists()


@needs_git
@posix_only
def test_repository_clean_filter_is_not_executed(tmp_path):
    repo = _repo(tmp_path)
    marker = tmp_path / "PWNED-filter"
    (repo / ".gitattributes").write_text("*.py filter=evil\n")
    _git(repo, "config", "filter.evil.clean", f"sh -c 'touch {marker}; cat'")
    _git(repo, "config", "filter.evil.smudge", "cat")
    # A changed file is what makes status consult the clean filter.
    (repo / "a.py").write_text("import hashlib\nhashlib.md5(b'y')\n")
    result = scan_directory(str(repo))
    assert not marker.exists()
    pin = result["coverage"]["corpus"]["pinned_at"]
    assert pin["dirty"] is None and pin["dirty_not_checked"]


# --- 9. the corpus pin describes the scanned directory, not its repository -----

@needs_git
def test_ignored_directory_is_not_pinned_to_the_repository_commit(tmp_path):
    repo = _repo(tmp_path)
    (repo / ".gitignore").write_text("out/\n")
    _git(repo, "add", ".gitignore")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "ignore")
    (repo / "out").mkdir()
    (repo / "out" / "gen.c").write_text("RSA_generate_key_ex(r, 2048, e, NULL);\n")
    pin = scan_directory(str(repo / "out"))["coverage"]["corpus"]["pinned_at"]
    assert pin["pinned"] is False and pin["reason"] == "not_tracked"


@needs_git
def test_dirty_flag_is_scoped_to_the_scanned_directory(tmp_path):
    repo = _repo(tmp_path)
    (repo / "sub").mkdir()
    (repo / "sub" / "b.py").write_text("x = 1\n")
    _git(repo, "add", "sub/b.py")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "sub")
    (repo / "sibling.txt").write_text("untracked elsewhere\n")
    pin = scan_directory(str(repo / "sub"))["coverage"]["corpus"]["pinned_at"]
    assert pin["dirty"] is False


@needs_git
def test_shallow_clone_is_detected_from_a_subdirectory(tmp_path):
    repo = _repo(tmp_path)
    (repo / "sub").mkdir()
    (repo / "sub" / "b.py").write_text("x = 1\n")
    _git(repo, "add", "sub/b.py")
    _git(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "sub")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{repo}", str(clone)],
                   check=True, capture_output=True)
    pin = scan_directory(str(clone / "sub"))["coverage"]["corpus"]["pinned_at"]
    assert pin["shallow"] is True


# --- 2, 3. what the walk cannot see is reported, never dropped ------------------

@posix_only
@not_root
def test_directory_that_cannot_be_entered_is_reported_not_fatal(tmp_path):
    (tmp_path / "ok.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    nox = tmp_path / "nox"
    nox.mkdir()
    (nox / "a.py").write_text("x = 1\n")
    nox.chmod(0o644)  # listable, not enterable
    try:
        r = scan_directory(str(tmp_path))
    finally:
        nox.chmod(0o755)
    # The file is visible by name, so it is counted, as unreadable -- not dropped.
    assert "nox/a.py" in r["unreadable_files"]
    assert "read every one" not in r["verdict"]


@posix_only
@not_root
def test_directory_that_cannot_be_read_is_reported_not_silent(tmp_path):
    (tmp_path / "ok.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    nor = tmp_path / "nor"
    nor.mkdir()
    (nor / "b.c").write_text("int x;\n")
    nor.chmod(0o000)
    try:
        r = scan_directory(str(tmp_path))
    finally:
        nor.chmod(0o755)
    assert r["unreadable_directories"] == ["nor/"]
    assert r["coverage"]["directories_not_entered"]["count"] == 1
    assert r["coverage"]["accounts_for_every_file"] is False
    assert "read every one" not in r["verdict"]


@posix_only
def test_broken_symlink_is_counted_as_a_link_not_followed(tmp_path):
    """Reclassified in 0.10.0: a broken link is still a link.

    It used to be counted as unreadable, which described the attempt rather than
    the policy. Nothing is attempted on a link now, so it belongs in the category
    that says so -- and the file count still has to add up.
    """
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "gone.py").symlink_to(tmp_path / "does-not-exist.py")
    r = scan_directory(str(tmp_path))
    assert [e["path"] for e in r["symlinks_not_followed"]] == ["gone.py"]
    fs = sum(r["files_scanned"].values())
    links = len([e for e in r["symlinks_not_followed"] if e["kind"] == "file"])
    assert fs + len(r["unreadable_files"]) + sum(r["files_skipped_by_type"].values()) \
        + links == r["files_present"]


def test_a_file_named_like_an_excluded_directory_is_scanned(tmp_path):
    (tmp_path / "build").write_text("x\n")      # a file, not a directory
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "bundle.js").write_text("x\n")
    r = scan_directory(str(tmp_path))
    excluded = r["coverage"]["scope"]["files_excluded_before_counting"]["by_directory"]
    assert excluded == {"dist": 1}
    assert r["files_present"] == 1


# --- 4, 5. names the filesystem allows must not break the output ----------------

@pytest.mark.skipif(sys.platform != "linux", reason="needs a byte-oriented filesystem")
def test_file_name_that_is_not_utf8_is_scanned_and_serialisable(tmp_path):
    name = os.fsdecode(b"k\\xffey.c".replace(b"\\\\xff", b"\\xff"))
    name = os.fsdecode(b"k\xffey.c")
    (tmp_path / name).write_text("RSA_generate_key_ex(r, 2048, e, NULL);\n")
    r = scan_directory(str(tmp_path))
    text = json.dumps(r)                      # used to raise
    text.encode("utf-8")
    assert any("\\\\xff" in e["path"] or "\\xff" in e["path"]
               for e in r["evidence"]["source_code"])


def test_filesystem_root_name_does_not_break_the_request(monkeypatch):
    from qrp_mcp import scan as scan_mod
    empty = {"detected_algorithms": [], "source_code_findings": [], "ci_pipeline_findings": [],
             "iac_findings": [], "embedded_key_findings": [], "files_scanned": {},
             "files_present": 0, "files_present_by_extension": {}, "files_skipped_by_type": {},
             "unreadable_files": [], "unreadable_directories": [], "files_excluded_by_dir": {},
             "claimed_but_not_decoded": [], "protocol_findings": [], "dependency_findings": [],
             "symlinks_not_followed": [], "named_but_not_used": []}
    monkeypatch.setattr(scan_mod.detectors, "scan_repo", lambda p: empty)
    monkeypatch.setattr(scan_mod.coverage, "build", lambda **kw: {"stub": True})
    monkeypatch.setattr(scan_mod.coverage, "verdict_line", lambda b: "stub")
    root = Path(Path.cwd().anchor)
    r = scan_mod.scan_directory(str(root))    # used to fail: empty asset name
    assert r["target"] == str(root)


# --- 10. compare_coverage answers instead of crashing ---------------------------

def test_compare_on_incomplete_blocks_is_unestablished():
    from qrp_mcp.coverage import compare
    r = compare({}, {})
    assert r["verdict"] == "unestablished"
    assert {u["reason"] for u in r["unestablished"]} >= {"block_incomplete"}


# --- 12. the command line fails with a message, before the work ------------------

def test_cli_rejects_a_missing_path_without_a_traceback(tmp_path, capsys):
    from qrp_mcp.server import scan_to_file
    with pytest.raises(SystemExit) as e:
        scan_to_file([str(tmp_path / "nope")])
    assert e.value.code == 2
    assert "not a directory" in capsys.readouterr().err


def test_cli_checks_the_output_folder_before_scanning(tmp_path, capsys, monkeypatch):
    from qrp_mcp import server
    called = []
    monkeypatch.setattr(server, "scan_directory", lambda p: called.append(p) or {})
    with pytest.raises(SystemExit):
        server.scan_to_file([str(tmp_path), "--out", str(tmp_path / "missing" / "r.json")])
    assert not called
    assert "does not exist" in capsys.readouterr().err


def test_version_and_help_do_not_start_the_server(capsys, monkeypatch):
    from qrp_mcp import server, __version__
    monkeypatch.setattr(server.mcp, "run", lambda: pytest.fail("server started"))
    for arg, expect in (("--version", __version__), ("--help", "qrp-mcp scan PATH")):
        with pytest.raises(SystemExit) as e:
            server.main([arg])
        assert e.value.code == 0 and expect in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        server.main(["--bogus"])
    assert e.value.code == 2


# --- 6. things that look like cryptography and are not ---------------------------

def _families(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    return set(scan_directory(str(tmp_path))["detected_algorithms"])


def test_kyberswap_is_not_ml_kem(tmp_path):
    fam = _families(tmp_path, "swap.ts",
                    "import { KyberSwapClient } from '@kyberswap/sdk';\n")
    assert "ML-KEM" not in fam


def test_kyber_with_a_parameter_set_is_still_ml_kem(tmp_path):
    assert "ML-KEM" in _families(tmp_path, "k.c", "crypto_kem_keypair_kyber768(pk, sk);\n")


def test_release_candidate_suffix_is_not_rc4(tmp_path):
    fam = _families(tmp_path, "Cargo.toml", '[dependencies]\nhyper = "1.0.0-rc4"\n')
    assert "RC4" not in fam


def test_rc4_as_a_cipher_is_still_found(tmp_path):
    assert "RC4" in _families(tmp_path, "c.py", "cipher = ARC4.new(key)  # RC4\n")


def test_rc4_inside_a_cipher_suite_name_is_still_found(tmp_path):
    # The first version of the release-suffix fix dropped these (found on OpenSSL).
    assert "RC4" in _families(tmp_path, "tls1.h",
                              '#define SSL3_TXT_RSA_RC4_40_MD5 "EXP-RC4-MD5"\n')


def test_ppk_variable_in_source_is_not_a_preshared_key(tmp_path):
    fam = _families(tmp_path, "k.py", "ppk = paramiko.RSAKey.from_private_key_file(p)\n")
    assert "PPK" not in fam


def test_ppk_directive_in_configuration_is_still_found(tmp_path):
    assert "PPK" in _families(tmp_path, "swanctl.conf", "  ppk = my-ppk-id\n")


def test_dotnet_ecdh_is_ecdh_not_finite_field_dh(tmp_path):
    fam = _families(tmp_path, "k.cs", "using var e = ECDiffieHellman.Create();\n")
    assert "ECDH" in fam and "DH" not in fam


# --- 7. cryptography that was there and was missed ---------------------------------

def test_terraform_ed25519_and_ml_dsa_are_found(tmp_path):
    fam = _families(tmp_path, "main.tf",
                    'resource "tls_private_key" "k" { algorithm = "ED25519" }\n'
                    'customer_master_key_spec = "ML_DSA_65"\n')
    assert {"Ed25519", "ML-DSA"} <= fam


def test_kubernetes_manifest_with_tls_hybrid_group_is_found(tmp_path):
    fam = _families(tmp_path, "cm.yaml",
                    "apiVersion: v1\nkind: ConfigMap\ndata:\n"
                    "  nginx.conf: |\n    ssl_ecdh_curve X25519MLKEM768;\n")
    assert {"X25519", "ML-KEM"} <= fam


def test_algorithm_in_a_ci_pipeline_is_found(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "build.yml").write_text("steps:\n  - run: openssl req -newkey rsa:2048 -nodes\n")
    assert "RSA" in set(scan_directory(str(tmp_path))["detected_algorithms"])


def test_private_key_pasted_into_source_is_reported(tmp_path):
    (tmp_path / "k.py").write_text('KEY = """-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n"""\n')
    r = scan_directory(str(tmp_path))
    assert r["evidence"]["embedded_keys"]


def test_utf16_powershell_script_is_read(tmp_path):
    (tmp_path / "gen.ps1").write_bytes(
        "$rsa = [System.Security.Cryptography.RSA]::Create(2048)\n".encode("utf-16"))
    assert "RSA" in set(scan_directory(str(tmp_path))["detected_algorithms"])


def test_config_line_matched_by_both_rule_sets_is_one_occurrence(tmp_path):
    (tmp_path / "app.yaml").write_text("signing:\n  algorithm: ECDSA\n")
    r = scan_directory(str(tmp_path))
    located = [(e["path"], e["line"]) for kind in ("source_code", "iac")
               for e in r["evidence"][kind] if e["algorithm"] == "ECDSA"]
    assert located == [("app.yaml", 2)]


# --- 8. the CBOM carries what the scan found, and only that -----------------------

def _cbom(tmp_path):
    from qrp_mcp import cyclonedx
    return cyclonedx.build(scan_directory(str(tmp_path)))


def test_ppk_component_keeps_its_locations(tmp_path):
    (tmp_path / "swanctl.conf").write_text("  ppk_id = office\n")
    doc = _cbom(tmp_path)
    ppk = [c for c in doc["components"] if c["name"].startswith("PPK")][0]
    assert ppk["evidence"]["occurrences"][0]["location"] == "swanctl.conf"


def test_embedded_key_is_not_also_an_algorithm_component(tmp_path):
    (tmp_path / "k.tf").write_text('key = "-----BEGIN RSA PRIVATE KEY-----"\n')
    names = [c["name"] for c in _cbom(tmp_path)["components"]]
    assert "private_key" not in names and "signing_command" not in names
    assert names.count("Embedded private key material") == 1


def test_occurrence_carries_the_matched_line(tmp_path):
    (tmp_path / "a.py").write_text("h = hashlib.md5(data)\n")
    occ = [c for c in _cbom(tmp_path)["components"]
           if c["name"] == "MD5"][0]["evidence"]["occurrences"][0]
    assert "hashlib.md5" in occ["additionalContext"]


def test_unreadable_path_list_survives_a_comma_in_a_name():
    from qrp_mcp.cyclonedx import _flatten
    flat = dict(_flatten({"paths": ["a,b.c", "c.c"]}))
    assert flat == {"paths:0": "a,b.c", "paths:1": "c.c"}


def test_serial_changes_when_the_findings_change(tmp_path):
    (tmp_path / "a.py").write_text("h = hashlib.md5(data)\n")
    first = _cbom(tmp_path)["serialNumber"]
    assert _cbom(tmp_path)["serialNumber"] == first
    (tmp_path / "b.py").write_text("k = rsa.generate_private_key(65537, 2048)\n")
    assert _cbom(tmp_path)["serialNumber"] != first


def test_cbom_builds_when_keys_and_algorithms_are_both_present(tmp_path):
    # Found on certbot: embedded-key evidence has no 'algorithm', and sorting the
    # mixed evidence for the serial number raised TypeError.
    (tmp_path / "a.py").write_text("h = hashlib.md5(data)\n")
    (tmp_path / "b.py").write_text("h = hashlib.md5(data)\n")
    (tmp_path / "k.tf").write_text('key = "-----BEGIN RSA PRIVATE KEY-----"\n')
    (tmp_path / "k2.tf").write_text('key = "-----BEGIN EC PRIVATE KEY-----"\n')
    assert _cbom(tmp_path)["serialNumber"].startswith("urn:uuid:")
