"""A classical group offered on its own beside a hybrid is a finding of its own.

Raised in public on 2026-10-03 (Addie LaMarr, "the exit question"): removing the
classical fallback from a hybrid group list was invisible. `ssl_ecdh_curve
X25519MLKEM768:X25519` and `ssl_ecdh_curve X25519MLKEM768` scanned the same --
ECDH, ML-KEM, X25519 -- because the X25519 inside the hybrid's name is the same
family as X25519 offered alone, and `closure` reported "3 closed, 3 new" on the one
line that changed. The fixture pair in tests/fixtures/hybrid-fallback is that
change, as found on 0.27.3.

Nothing here is a claim about the wire: what a connection negotiates is settled
where TLS terminates (see `assets.TLS_TERMINATION`), and that statement still holds.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import cyclonedx
from qrp_mcp.assets import scan_tls_groups
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import export_cbom, scan_repo

FIXTURES = Path(__file__).parent / "fixtures" / "hybrid-fallback"


def _tool(obj):
    return getattr(obj, "fn", obj)


def _alone(result):
    return [(g["group"], g["family"]) for g in result["evidence"]["tls_groups"]]


def test_the_fallback_is_a_finding_before_and_not_after():
    assert _alone(scan_directory(FIXTURES / "before")) == [("X25519", "X25519")]
    assert _alone(scan_directory(FIXTURES / "after")) == []


@pytest.mark.parametrize("line, expected", [
    ("ssl_ecdh_curve X25519MLKEM768:X25519;", ["X25519"]),
    ("ssl_ecdh_curve X25519MLKEM768;", []),
    ("ssl_ecdh_curve X25519:prime256v1:secp384r1;", ["X25519", "prime256v1", "secp384r1"]),
    ("Groups = X25519MLKEM768:X25519:P-256", ["X25519", "P-256"]),
    ("SSLOpenSSLConfCmd Curves SecP256r1MLKEM768:X448", ["X448"]),
    ("CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},",
     ["X25519", "CurveP256"]),
    ('System.setProperty("jdk.tls.namedGroups", "x25519,ffdhe2048");', ["x25519", "ffdhe2048"]),
    # OpenSSL 3.5 removes a group with a leading minus; a removal is not an offer.
    ("Groups = X25519MLKEM768:-X25519", []),
    ("# ssl_ecdh_curve X25519MLKEM768:X25519;", []),
    ("groups = admin, staff", []),
    ("ssl_ecdh_curve auto;", []),
    # Not a group setting: an X25519 here is the ordinary finding, not this one.
    ("key = x25519.generate()", []),
])
def test_which_groups_count_as_offered_alone(line, expected):
    assert [g["group"] for g in scan_tls_groups(line)] == expected


def test_families_are_named():
    found = {g["group"]: g["family"]
             for g in scan_tls_groups("Groups = X25519:X448:P-256:ffdhe3072")}
    assert found == {"X25519": "X25519", "X448": "X448", "P-256": "ECDH", "ffdhe3072": "DH"}


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _scan_cli(tree, out):
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    data = json.loads(out.read_text())
    # The instrument is this working tree, which is dirty while it is being changed;
    # the comparison under test is of the corpus, so both runs name the same clean
    # instrument. Everything else in the two results is what the command wrote.
    data["coverage"]["instrument"]["source_commit"] = {
        "pinned": True, "commit": "instrument", "dirty": False}
    out.write_text(json.dumps(data))
    return out


def _pair(tmp_path, after_text=None):
    """Scan the fixture's before, commit the after, scan again: a two-commit tree."""
    tree = tmp_path / "tree"
    shutil.copytree(FIXTURES / "before", tree)
    _git(tree, "init", "-q")
    _git(tree, "add", "-A")
    _git(tree, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "before")
    before = _scan_cli(tree, tmp_path / "before.json")
    if after_text is None:
        shutil.copy(FIXTURES / "after" / "nginx.conf", tree / "nginx.conf")
    else:
        (tree / "nginx.conf").write_text(after_text)
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
    closed = [c for c in verdict["closure"]["closed"] if c["category"] == "tls_groups"]
    assert [(c["group"], c["offered"]) for c in closed] == [("X25519", "alone")]
    assert verdict["closure"]["per_family_before_after"]["X25519 offered alone"] == [1, 0]
    assert not [n for n in verdict["closure"]["new"] if n["category"] == "tls_groups"]


def test_keeping_the_fallback_through_an_edit_is_still_open(tmp_path):
    """The line changes, the fallback stays: it must not read as closed."""
    verdict = _pair(tmp_path, after_text=(
        "server {\n    listen 443 ssl;\n    ssl_protocols TLSv1.3;\n"
        "    ssl_ecdh_curve X25519:X25519MLKEM768;\n}\n"))
    assert not [c for c in verdict["closure"]["closed"] if c["category"] == "tls_groups"]
    assert verdict["closure"]["per_family_before_after"]["X25519 offered alone"] == [1, 1]


def test_it_reaches_the_tool_at_the_default_level():
    assert _alone(_tool(scan_repo)(str(FIXTURES / "before"))) == [("X25519", "X25519")]


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


def _cbom_names(doc):
    return [c["name"] for c in doc["components"]]


def test_it_reaches_the_cbom():
    before = _tool(export_cbom)(str(FIXTURES / "before"))
    after = _tool(export_cbom)(str(FIXTURES / "after"))
    assert "X25519 (TLS group offered alone)" in _cbom_names(before)
    assert "X25519 (TLS group offered alone)" not in _cbom_names(after)
    comp = next(c for c in before["components"]
                if c["name"] == "X25519 (TLS group offered alone)")
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qrp:basis"] == "configured_group"
    assert props["qrp:offered"] == "alone"
    assert comp["evidence"]["occurrences"][0]["location"] == "nginx.conf"
    refs = [c["bom-ref"] for c in before["components"]]
    assert len(refs) == len(set(refs))


def test_two_spellings_of_one_group_are_one_component(tmp_path):
    (tmp_path / "a.conf").write_text("ssl_ecdh_curve X25519MLKEM768:X25519;\n")
    (tmp_path / "b.conf").write_text("Groups = x25519\n")
    doc = cyclonedx.build(scan_directory(tmp_path))
    refs = [c["bom-ref"] for c in doc["components"]]
    assert len(refs) == len(set(refs))
    comp = [c for c in doc["components"] if c["bom-ref"] == "tls-group:x25519-offered-alone"]
    assert len(comp) == 1 and len(comp[0]["evidence"]["occurrences"]) == 2
