"""National profiles for the suggested replacement: each one's words reach the output,
each says whom its document addresses, and none of them changes what is found."""

import json
import subprocess
import sys
import typing

import pytest

from qrp_mcp import profiles, remediation
from qrp_mcp.server import scan_repo

RSA = {"classification": "classical_vulnerable", "algorithm_family": "RSA"}
MD5 = {"classification": "deprecated_weak", "algorithm_family": "MD5"}


def _uses(out):
    return {o["for"].split()[0]: o["use"] for o in out["options"]}


@pytest.mark.parametrize("name", list(profiles.PROFILES))
def test_every_profile_names_its_source_and_whom_it_addresses(name):
    out = remediation.suggest(RSA, profile=name)
    block = out["profile"]
    assert block["name"] == name and block["addresses"] and block["hybrid"]
    assert block["source"]["url"].startswith("https://")
    assert block["source"]["read_on"] == profiles.READ_ON


def test_cnsa2_allows_one_parameter_set_and_single_tree_hash_signatures():
    uses = _uses(remediation.suggest(RSA, profile="us-cnsa2"))
    assert uses["key"].startswith("ML-KEM-1024")
    assert uses["signatures"].startswith("ML-DSA-87")
    assert "not approved" in uses["signatures"] and "SLH-DSA" in uses["signatures"]
    assert "HSS and XMSS^MT are not allowed" in uses["firmware"]


def test_a_role_the_authority_does_not_fill_is_left_out_not_filled_with_nist():
    uses = _uses(remediation.suggest(RSA, profile="au-ism"))
    assert set(uses) == {"key", "signatures"}
    assert "not be approved beyond 2030" in uses["key"]


@pytest.mark.parametrize("name", ["de-bsi", "fr-anssi"])
def test_hybrid_required_profiles_say_so_in_the_option_and_the_note(name):
    out = remediation.suggest(RSA, profile=name)
    assert "hybrid" in _uses(out)["key"]
    assert "Hybrid, under this profile" in out["note"]
    assert "accommodated" not in out["note"]  # NIST's hybrid sentence is replaced


def test_anssi_accepts_ml_kem_512_only_hybridised():
    assert "ML-KEM-512 is conformant" in _uses(remediation.suggest(RSA, profile="fr-anssi"))["key"]


def test_bulgaria_keeps_nist_options_and_says_why():
    nist = remediation.suggest(RSA)
    bg = remediation.suggest(RSA, profile="bg")
    assert _uses(bg) == _uses(nist)
    assert "No Bulgarian national guidance" in bg["profile"]["absent"]
    assert "2030" in bg["profile"]["dates"]


def test_weak_rows_stay_nist_and_carry_the_profile_minimum():
    out = remediation.suggest(MD5, profile="us-cnsa2")
    assert out["options"][0]["use"].startswith("SHA-256")
    assert out["profile"]["symmetric"] == "AES-256; SHA-384 or SHA-512."


def test_roles_still_filter_under_a_profile():
    out = remediation.suggest(RSA, {"signature": 2, "key_establishment": 0, "undetermined": 0},
                              profile="us-cnsa2")
    assert set(_uses(out)) == {"signatures", "firmware"}


def test_unknown_profile_is_an_error_not_nist():
    with pytest.raises(ValueError, match="known: nist"):
        remediation.suggest(RSA, profile="xx")
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", ".", "--profile", "xx"],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "invalid choice" in r.stderr


def test_the_tool_parameter_lists_exactly_the_profiles():
    hint = typing.get_type_hints(scan_repo.__wrapped__ if hasattr(scan_repo, "__wrapped__")
                                 else scan_repo, include_extras=True)["profile"]
    literal = typing.get_args(hint)[0]
    assert list(typing.get_args(literal)) == profiles.names()


def _scan(tmp_path, profile):
    tree = tmp_path / "tree"
    tree.mkdir(exist_ok=True)
    (tree / "a.py").write_text(
        "import hashlib\nhashlib.md5(b'x')\nk = rsa.generate_private_key(65537, 2048)\n")
    out = tmp_path / f"{profile}.json"
    subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree), "--out",
                    str(out), "--profile", profile], check=True, capture_output=True)
    return json.loads(out.read_text())


def test_detection_is_identical_under_every_profile(tmp_path):
    def strip(d):
        d = dict(d)
        d.pop("replacement_profile")
        d["findings"] = [{k: v for k, v in f.items() if k != "replacement"} for f in d["findings"]]
        d["coverage"] = {k: v for k, v in d["coverage"].items() if k != "window"}
        d.pop("files_left_out")
        return d
    base = strip(_scan(tmp_path, "nist"))
    for name in ("us-cnsa2", "de-bsi"):
        assert strip(_scan(tmp_path, name)) == base


def test_the_profile_reaches_the_file_and_the_tool(tmp_path):
    d = _scan(tmp_path, "de-bsi")
    assert d["replacement_profile"] == "de-bsi"
    rsa = [f for f in d["findings"] if f.get("algorithm_family") == "RSA"][0]
    assert rsa["replacement"]["profile"]["name"] == "de-bsi"
    t = scan_repo(str(tmp_path / "tree"), profile="fr-anssi")
    rsa = [f for f in t["findings"] if f.get("algorithm_family") == "RSA"][0]
    assert rsa["replacement"]["profile"]["name"] == "fr-anssi"


def test_the_cbom_has_no_profile_because_it_carries_no_replacement(tmp_path):
    (tmp_path / "a.py").write_text("k = rsa.generate_private_key(65537, 2048)\n")
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tmp_path),
                        "--profile", "us-cnsa2"], capture_output=True, text=True)
    assert r.returncode == 2
    from qrp_mcp.server import export_cbom
    fn = getattr(export_cbom, "__wrapped__", export_cbom)
    assert "profile" not in typing.get_type_hints(fn)
