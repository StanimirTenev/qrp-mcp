"""A classical SSH key exchange offered beside a hybrid is a finding of its own.

ZA-OPRAVYANE row 22 (2026-10-21): the defect of row 5, in OpenSSH. `KexAlgorithms
mlkem768x25519-sha256,curve25519-sha256` and `KexAlgorithms mlkem768x25519-sha256`
scanned the same -- ML-KEM and X25519 in both, nothing under `evidence` -- because the
X25519 inside the hybrid's name is the same family as curve25519-sha256 offered alone.
Removing the classical fallback from sshd, the step that ends the migration, closed
nothing in `closure`. The fixture pair in tests/fixtures/ssh-kex-fallback is that change.

The names are OpenSSH's (sshd_config.5 and kex-names.c at 7fe3b24, 2026-09-04): every
algorithm the table marks KEX_NOT_PQ. Nothing here is a claim about the wire: the client
chooses from what the server offers.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx
from qrp_mcp.assets import scan_ssh_kex
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

FIXTURES = Path(__file__).parent / "fixtures" / "ssh-kex-fallback"


def _tool(obj):
    return getattr(obj, "fn", obj)


def _alone(result):
    return [(g["group"], g["family"]) for g in result["evidence"]["ssh_kex"]]


def test_the_fallback_is_a_finding_before_and_not_after():
    assert _alone(scan_directory(FIXTURES / "before")) == [("curve25519-sha256", "X25519")]
    assert _alone(scan_directory(FIXTURES / "after")) == []


@pytest.mark.parametrize("line, expected", [
    ("KexAlgorithms mlkem768x25519-sha256,curve25519-sha256", ["curve25519-sha256"]),
    ("KexAlgorithms mlkem768x25519-sha256", []),
    ("KexAlgorithms sntrup761x25519-sha512@openssh.com,mlkem768nistp256-sha256", []),
    ("kexalgorithms=curve25519-sha256@libssh.org,ecdh-sha2-nistp256",
     ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256"]),
    ("  KexAlgorithms diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256",
     ["diffie-hellman-group14-sha256", "diffie-hellman-group-exchange-sha256"]),
    # '+' appends to the default and '^' puts the list at its head: still offered.
    ("KexAlgorithms +diffie-hellman-group1-sha1", ["diffie-hellman-group1-sha1"]),
    ("KexAlgorithms ^ecdh-sha2-nistp384,mlkem768x25519-sha256", ["ecdh-sha2-nistp384"]),
    # '-' removes everything the list names from the default: a removal is not an offer.
    ("KexAlgorithms -curve25519-sha256,ecdh-sha2-nistp256", []),
    ("ssh -o KexAlgorithms=curve25519-sha256 host", ["curve25519-sha256"]),
    ("# KexAlgorithms mlkem768x25519-sha256,curve25519-sha256", []),
    # Not a key exchange setting: the name here is the ordinary finding, not this one.
    ("Ciphers chacha20-poly1305@openssh.com", []),
    ("kex = curve25519-sha256", []),
    # Not a TLS group either: the TLS table does not apply to this setting.
    ("KexAlgorithms X25519", []),
])
def test_which_kex_count_as_offered_alone(line, expected):
    assert [g["group"] for g in scan_ssh_kex(line)] == expected


def test_families_are_named():
    found = {g["group"]: g["family"] for g in scan_ssh_kex(
        "KexAlgorithms curve25519-sha256,ecdh-sha2-nistp521,diffie-hellman-group16-sha512")}
    assert found == {"curve25519-sha256": "X25519", "ecdh-sha2-nistp521": "ECDH",
                     "diffie-hellman-group16-sha512": "DH"}


def test_an_sshd_config_is_not_a_tls_configuration():
    """The TLS statement is said only where TLS configuration was read."""
    assert scan_directory(FIXTURES / "before").get("tls_termination") is None
    assert scan_directory(FIXTURES / "before")["evidence"]["tls_groups"] == []


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _scan_cli(tree, out):
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads(out.read_text())
    # As in test_hybrid_fallback: the instrument is this working tree, dirty while it is
    # being changed; the comparison under test is of the corpus.
    data["coverage"]["instrument"]["source_commit"] = {
        "pinned": True, "commit": "instrument", "dirty": False}
    out.write_text(json.dumps(data))
    return out


def _pair(tmp_path, after_text=None):
    tree = tmp_path / "tree"
    shutil.copytree(FIXTURES / "before", tree)
    _git(tree, "init", "-q")
    _git(tree, "add", "-A")
    _git(tree, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "before")
    before = _scan_cli(tree, tmp_path / "before.json")
    if after_text is None:
        shutil.copy(FIXTURES / "after" / "sshd_config", tree / "sshd_config")
    else:
        (tree / "sshd_config").write_text(after_text)
    _git(tree, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "after")
    after = _scan_cli(tree, tmp_path / "after.json")
    out = tmp_path / "closure.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "closure", str(before),
                        str(after), "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(out.read_text())


def test_removing_the_fallback_is_closed(tmp_path):
    verdict = _pair(tmp_path)
    assert verdict["comparability"]["verdict"] == "comparable"
    closed = [c for c in verdict["closure"]["closed"] if c["category"] == "ssh_kex"]
    assert [(c["group"], c["offered"]) for c in closed] == [("curve25519-sha256", "alone")]
    assert verdict["closure"]["per_family_before_after"][
        "curve25519-sha256 offered alone"] == [1, 0]
    assert not [n for n in verdict["closure"]["new"] if n["category"] == "ssh_kex"]


def test_keeping_the_fallback_through_an_edit_is_still_open(tmp_path):
    verdict = _pair(tmp_path, after_text=(
        "Port 2222\nKexAlgorithms curve25519-sha256,mlkem768x25519-sha256\n"))
    assert not [c for c in verdict["closure"]["closed"] if c["category"] == "ssh_kex"]
    assert verdict["closure"]["per_family_before_after"][
        "curve25519-sha256 offered alone"] == [1, 1]


def test_it_reaches_the_tool_at_the_default_level():
    assert _alone(_tool(scan_repo)(str(FIXTURES / "before"))) == [
        ("curve25519-sha256", "X25519")]


def test_the_cbom_with_it_is_valid_cyclonedx_1_6():
    jsonschema = pytest.importorskip("jsonschema")
    schema_dir = Path(__file__).parent / "schema"
    schema = json.loads((schema_dir / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((schema_dir / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((schema_dir / "jsf-0.82.schema.json").read_text()),
    }
    validator = jsonschema.Draft7Validator(
        schema, resolver=jsonschema.RefResolver.from_schema(schema, store=store))
    doc = _tool(export_cbom)(str(FIXTURES / "before"))
    errors = sorted(validator.iter_errors(doc), key=str)
    assert not errors, errors[0].message


def test_it_reaches_the_cbom():
    before = _tool(export_cbom)(str(FIXTURES / "before"))
    after = _tool(export_cbom)(str(FIXTURES / "after"))
    name = "curve25519-sha256 (SSH key exchange offered alone)"
    assert name in [c["name"] for c in before["components"]]
    assert name not in [c["name"] for c in after["components"]]
    comp = next(c for c in before["components"] if c["name"] == name)
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qrp:basis"] == "configured_kex"
    assert props["qrp:offered"] == "alone"
    assert props["qrp:family"] == "X25519"
    assert comp["evidence"]["occurrences"][0]["location"] == "sshd_config"
    refs = [c["bom-ref"] for c in before["components"]]
    assert len(refs) == len(set(refs))


def test_the_same_kex_in_two_files_is_one_component(tmp_path):
    (tmp_path / "sshd_config").write_text("KexAlgorithms curve25519-sha256\n")
    (tmp_path / "ssh_config").write_text("KexAlgorithms=curve25519-sha256\n")
    doc = cyclonedx.build(scan_directory(tmp_path))
    comp = [c for c in doc["components"]
            if c["bom-ref"] == "ssh-kex:curve25519-sha256-offered-alone"]
    assert len(comp) == 1 and len(comp[0]["evidence"]["occurrences"]) == 2
