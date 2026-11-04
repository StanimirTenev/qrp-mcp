"""`qrp-mcp control` -- the self-seeded control (ZA-OPRAVYANE row 433).

The harness is the one the L1 round of 04.11.2026 published (qrp-kachestvo/nov-podhod,
`L1/harness/plant.py`), moved into the package. Its figure is robustness on known patterns:
what this instrument does on lines its own harness planted. A control the instrument's author
plants is not independent, so the block must never become `claims.control.held` and must never
feed the CBOM's `compositions[].aggregate`. Those two are pinned here, beside the shape of the
block, which another tool reads.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import control, cyclonedx
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import main, mcp


def _tree(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.py").write_text("import os\n\n\ndef f():\n    return 1\n\n\nX = 2\n")
    (root / "src" / "b.py").write_text("import sys\n\nY = 3\n")
    (root / "src" / "c.go").write_text("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(1)\n}\n")
    (root / "src" / "D.java").write_text(
        "package x;\n\npublic class D {\n\n    private int a;\n\n    void m() {\n    }\n}\n")
    return root


def _digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        h.update(p.relative_to(root).as_posix().encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def _planted(tree: Path, seed: int, where: Path) -> dict:
    plan = control.make_plan(tree, seed)
    shutil.copytree(tree, where)
    control.apply_plan(plan, where)
    return plan


def test_the_same_seed_plants_the_same_items(tmp_path):
    tree = _tree(tmp_path / "t")
    a = _planted(tree, 5, tmp_path / "a")
    b = _planted(tree, 5, tmp_path / "b")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert control.plan_sha256(a) == control.plan_sha256(b)
    c = _planted(tree, 6, tmp_path / "c")
    assert [(i["path"], i["line"]) for i in a["items"]] != [(i["path"], i["line"]) for i in c["items"]]


def test_every_block_is_where_the_plan_says(tmp_path):
    tree = _tree(tmp_path / "t")
    plan = _planted(tree, 3, tmp_path / "w")
    for it in plan["items"]:
        lines = (tmp_path / "w" / it["path"]).read_bytes().decode(it.get("encoding", "utf-8")).split("\n")
        for o, line in enumerate(it["block"]):
            assert lines[it["line"] - 1 + o] == line, it["id"]
    assert set(plan["languages"]) == {"python", "java", "go"}
    utf16 = next(i for i in plan["items"] if i["style"] == "utf16_nobom")
    assert (tmp_path / "w" / utf16["path"]).read_bytes()[:2] != b"\xff\xfe"


def _item(kind, family, lines, **extra):
    d = {"id": "x", "kind": kind, "style": "s", "family": family, "lang": "python", "path": "f.py",
         "lines": lines, "name_lines": [], "name_offsets": [], "use_offsets": [0], "block": ["x"],
         "line": lines[0]}
    d.update(extra)
    return d


def _scan(rows, **extra):
    d = {"evidence": {"source_code": rows}, "files_read": ["f.py"],
         "coverage": {"not_examined": []}, "unreadable_files": [], "claimed_but_not_decoded": []}
    d.update(extra)
    return d


def test_scoring_of_uses_and_non_uses():
    plan = {"items": [
        _item("positive", "RSA", [10]), _item("positive", "ECDSA", [20]),
        _item("positive", "Ed25519", [30]), _item("positive", "RSA", [40], path="g.py"),
        _item("positive", "RSA", [50]), _item("positive", "ECDSA", [60]),
        _item("decoy", "RSA", [1]), _item("decoy", "RSA", [2]), _item("decoy", "RSA", [3]),
        _item("decoy", "RSA", [4], any_family=True),
    ]}
    scan = _scan([
        {"path": "f.py", "line": 10, "algorithm": "RSA", "evidence_kind": "call", "confidence": "high"},
        {"path": "f.py", "line": 20, "algorithm": "RSA", "evidence_kind": "call", "confidence": "high"},
        {"path": "f.py", "line": 50, "algorithm": "RSA", "evidence_kind": "comment", "confidence": "low"},
        # A generic EC row counts for ECDSA, as docs/measurement.md states for every tool.
        {"path": "f.py", "line": 60, "algorithm": "EC", "evidence_kind": "call", "confidence": "medium"},
        {"path": "f.py", "line": 1, "algorithm": "RSA", "evidence_kind": "ban", "confidence": "low"},
        {"path": "f.py", "line": 2, "algorithm": "RSA", "evidence_kind": "declaration", "confidence": "medium"},
        {"path": "f.py", "line": 4, "algorithm": "DSA", "evidence_kind": "reference", "confidence": "medium"},
    ], coverage={"not_examined": [{"reason": "type_not_claimed", "paths": ["g.py"]}]})
    control.score(plan, scan)
    assert [i["outcome"] for i in plan["items"]] == [
        "found", "wrong_family", "silent", "declared_not_read", "read_as_not_a_use", "found",
        "named_not_used", "reported_as_use", "silent", "reported_as_use"]


def test_the_block_has_its_published_shape(tmp_path):
    """docs/control.md publishes these keys; another tool reads them. Added to, never renamed."""
    block = control.run(_tree(tmp_path / "t"), 1)["self_seeded_control"]
    for key in ("ran", "name", "licenses", "feeds", "instrument", "seed", "harness_version",
                "harness_sha256", "plan_sha256", "tree", "languages", "families",
                "planted_uses", "found", "silent", "read_as_not_a_use", "wrong_family",
                "declared_not_read", "planted_non_uses", "reported_as_use", "named_not_used",
                "silent_on_decoys", "by_confidence", "by_style", "by_decoy_class", "styles",
                "decoy_classes", "key_size_on_another_line", "indirect_name_line", "sentence"):
        assert key in block, key
    assert block["ran"] is True and block["seed"] == 1
    assert block["name"] == "robustness on known patterns"
    assert block["planted_uses"] == (block["found"] + block["silent"] + block["read_as_not_a_use"]
                                     + block["wrong_family"] + block["declared_not_read"])
    assert block["planted_non_uses"] == (block["reported_as_use"] + block["named_not_used"]
                                         + block["silent_on_decoys"])
    assert set(block["by_confidence"]) == {"high", "medium", "low"}
    assert all(len(pair) == 2 for pair in block["by_confidence"].values())
    assert sum(v["planted"] for v in block["by_style"].values()) == block["planted_uses"]
    assert sum(v["planted"] for v in block["by_decoy_class"].values()) == block["planted_non_uses"]
    # Three languages, 5 code styles x 3 families each, 3 config styles x 3, UTF-16 x 3.
    assert block["planted_uses"] == 3 * 15 + 9 + 3
    assert block["planted_non_uses"] == 3 * 15 + 1 + 2


def test_the_words_it_does_not_license_are_not_in_it(tmp_path):
    block = control.run(_tree(tmp_path / "t"), 1)["self_seeded_control"]
    text = json.dumps(block).lower() + json.dumps(control.NOT_RUN).lower()
    for word in ("recall", "precision", "completeness", "complete"):
        assert not re.search(rf"\b{word}\b", text), word


def test_it_never_licenses_complete_and_never_holds_the_control(tmp_path):
    """The deciding question of the L1 round: `claims.control.held` stays false, and nothing in
    the new block feeds `compositions[].aggregate` -- even a block with every use found and no
    decoy reported, on a tree whose every file was read."""
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "a.py").write_text("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    scan = scan_directory(tree, settings=None)
    assert scan["coverage"]["scope"]["files_not_examined"] == 0
    claims = scan["coverage"]["claims"]
    assert claims["control"]["held"] is False
    assert claims["self_seeded_control"]["ran"] is False
    without = cyclonedx.build(json.loads(json.dumps(scan)))["compositions"][0]["aggregate"]
    perfect = json.loads(json.dumps(scan))
    block = control.run(tree, 1)["self_seeded_control"]
    block.update(found=block["planted_uses"], silent=0, reported_as_use=0)
    perfect["coverage"]["claims"]["self_seeded_control"] = block
    document = cyclonedx.build(perfect)
    assert document["compositions"][0]["aggregate"] == without == "unknown"
    assert perfect["coverage"]["claims"]["control"]["held"] is False
    props = {p["name"]: p["value"] for p in document["properties"]}
    assert props["qrp:coverage:claims:control:held"] == "false"
    assert props["qrp:coverage:claims:self_seeded_control:ran"] == "true"
    # The document that carries the block is still a valid CycloneDX 1.6 BOM.
    jsonschema = pytest.importorskip("jsonschema")
    schemas = Path(__file__).parent / "schema"
    schema = json.loads((schemas / "bom-1.6.schema.json").read_text())
    store = {"http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
             json.loads((schemas / "spdx.schema.json").read_text()),
             "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
             json.loads((schemas / "jsf-0.82.schema.json").read_text())}
    jsonschema.Draft7Validator(schema, resolver=jsonschema.RefResolver.from_schema(
        schema, store=store)).validate(document)


def test_the_command_writes_the_block_and_leaves_the_tree_alone(tmp_path):
    tree = _tree(tmp_path / "t")
    before = _digest(tree)
    out = tmp_path / "control.json"
    run = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "control", str(tree),
                          "--seed", "2", "--out", str(out)], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    assert _digest(tree) == before
    result = json.loads(out.read_text())
    assert result["self_seeded_control"]["seed"] == 2
    assert len(result["items"]) == (result["self_seeded_control"]["planted_uses"]
                                    + result["self_seeded_control"]["planted_non_uses"])
    again = tmp_path / "again.json"
    subprocess.run([sys.executable, "-m", "qrp_mcp.server", "control", str(tree), "--seed", "2",
                    "--out", str(again)], check=True, capture_output=True)
    assert json.loads(again.read_text()) == result
    # The seed is part of the claim: not given, the command refuses.
    assert subprocess.run([sys.executable, "-m", "qrp_mcp.server", "control", str(tree)],
                          capture_output=True).returncode == 2


def test_a_scan_carries_the_block_when_asked(tmp_path):
    tree = _tree(tmp_path / "t")
    out = tmp_path / "scan.json"
    with pytest.raises(SystemExit) as done:
        main(["scan", str(tree), "--no-config", "--control-seed", "1", "--out", str(out)])
    assert done.value.code == 0
    claims = json.loads(out.read_text())["coverage"]["claims"]
    assert claims["self_seeded_control"]["ran"] is True
    assert claims["self_seeded_control"]["seed"] == 1
    assert claims["control"]["held"] is False
    plain = tmp_path / "plain.json"
    with pytest.raises(SystemExit):
        main(["scan", str(tree), "--no-config", "--out", str(plain)])
    assert json.loads(plain.read_text())["coverage"]["claims"]["self_seeded_control"]["ran"] is False


def test_the_tool_is_read_only_and_names_its_boundary():
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    tool = tools["run_self_seeded_control"]
    a = tool.annotations
    assert a.read_only_hint is True and a.destructive_hint is False and a.open_world_hint is False
    assert "scan_repo" in (tool.description or "")
    assert "temporary directory" in (tool.description or "")
