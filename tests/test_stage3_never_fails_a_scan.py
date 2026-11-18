"""B1 of the 0.50.0 review (PREGLED.md, 18.11): a lead whose target is a pattern pathlib cannot
glob -- `**` inside a path component, which Python 3.10-3.12 refuse with ValueError -- ended the
whole scan: `qrp-mcp scan` exited 2 and `scan_repo` raised, where 0.49.0 scanned the same trees
and exited 0. Stage 3 is context; it must never change the exit code or raise.

Two defences, each pinned on its own: `adaptive._resolve` never globs a pattern it cannot glob
(the lead says `pattern_not_followed`), and `adaptive.annotate` as a whole cannot fail a scan
(a failure is named by its exception class, not its message, which may quote source text).

The expected findings are 0.49.0's (85b6271), taken from its scan of the same trees.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import adaptive
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

SRC = str(Path(__file__).resolve().parents[1] / "src")

# The three trees of the review (pregled/fixtures/v2-a, crash-sshd, crash-nginx) and what 0.49.0
# gives on each: exit code, findings as (family, raw_value), fingerprint.
EMPTY = "2329256b8d11486c73883a7288061fb1acda2d052456224d4b2ce2b631759b05"
TREES = {
    "yaml": ({"lint.yaml": 'exclude: "**.pem"\n'}, [], EMPTY),
    "sshd": ({"sshd_config": "Include ~/x/*.conf\nInclude a/**b/c\nHostKey ssh_host_rsa_key\n"},
             ["RSA"], "0cca1dd5cfb8e4fdc048aa1d2820f896edbea9b55152cc6c45e5bb6bc7cceb86"),
    "nginx": ({"nginx.conf": "server {\n include sites/**.conf;\n}\n"}, [], EMPTY),
}


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


@pytest.mark.parametrize("name", sorted(TREES))
def test_the_review_trees_scan_as_049_did_through_the_cli(tmp_path, name):
    files, families, fingerprint = TREES[name]
    root = _write(tmp_path / "t", files)
    out = tmp_path / "o.json"
    run = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                          str(root), "--out", str(out), "--no-config"],
                         capture_output=True, text=True, env={"PYTHONPATH": SRC, "PATH": "/usr/bin"})
    assert run.returncode == 0, run.stderr
    result = json.loads(out.read_text())
    assert sorted(f["algorithm_family"] for f in result["findings"]) == families
    assert result["findings_fingerprint"]["sha256"] == fingerprint


@pytest.mark.parametrize("name", sorted(TREES))
def test_the_review_trees_scan_as_049_did_through_scan_repo(tmp_path, name):
    files, families, fingerprint = TREES[name]
    root = _write(tmp_path / "t", files)
    for level in ("full", "masked", "trimmed"):
        result = scan_repo(path=str(root), level=level)
        assert sorted(f["algorithm_family"] for f in result["findings"]) == families
        assert result["findings_fingerprint"]["sha256"] == fingerprint


def test_a_pattern_that_cannot_be_globbed_is_a_lead_not_followed(tmp_path):
    root = _write(tmp_path, TREES["sshd"][0] | {"nginx.conf": TREES["nginx"][0]["nginx.conf"]})
    result = scan_directory(root)
    leads = {i["target"]: i["status"] for i in result["chosen_outside_files"]["leads"]["items"]}
    assert leads["a/**b/c"] == "pattern_not_followed"
    assert leads["sites/**.conf"] == "pattern_not_followed"
    assert "pattern_not_followed" in adaptive.LEADS_MEANING
    looked = [i for i in result["where_to_look"]["items"] if i.get("target") == "a/**b/c"]
    assert looked and looked[0]["status"] == "pattern_not_followed"


def test_a_pattern_that_matches_a_file_read_is_still_followed(tmp_path):
    # The review: `include conf.d/**.conf` with conf.d/a.conf present did not crash, and is followed.
    root = _write(tmp_path, {"nginx.conf": "http {\n include conf.d/**.conf;\n}\n",
                             "conf.d/a.conf": "server { listen 443 ssl; }\n"})
    leads = scan_directory(root)["chosen_outside_files"]["leads"]["items"]
    assert [(i["target"], i["status"], i["files"]) for i in leads] == [
        ("conf.d/**.conf", "followed", ["conf.d/a.conf"])]


# --- the second defence: no stage-3 section can fail the scan ----------------------------------

def test_a_stage3_section_that_raises_leaves_the_scan_and_says_so(tmp_path, monkeypatch):
    files, families, fingerprint = TREES["sshd"]
    root = _write(tmp_path, files)

    def boom(*_a, **_k):
        raise RuntimeError("secret zzleakboom path")

    monkeypatch.setattr(adaptive, "_where_to_look", boom)
    result = scan_directory(root)
    assert sorted(f["algorithm_family"] for f in result["findings"]) == families
    assert result["findings_fingerprint"]["sha256"] == fingerprint
    for key in ("ecosystems", "angles", "where_to_look"):
        assert key not in result
    assert "leads" not in result["chosen_outside_files"]
    assert result["adaptive_not_built"]["error"] == "RuntimeError"
    assert "zzleakboom" not in json.dumps(result)
    for level in ("full", "masked", "trimmed"):
        assert scan_repo(path=str(root), level=level)["findings_fingerprint"]["sha256"] == fingerprint


def test_a_stage3_section_that_raises_does_not_change_the_cli_exit_code(tmp_path):
    root = _write(tmp_path / "t", TREES["sshd"][0])
    out = tmp_path / "o.json"
    code = ("import sys; from qrp_mcp import adaptive\n"
            "def boom(*a, **k): raise ValueError('x')\n"
            "adaptive._leads = boom\n"
            "from qrp_mcp.server import main; main()")
    run = subprocess.run([sys.executable, "-c", code, "scan", str(root), "--out", str(out),
                          "--no-config"], capture_output=True, text=True,
                         env={"PYTHONPATH": SRC, "PATH": "/usr/bin"})
    assert run.returncode == 0, run.stderr
    assert json.loads(out.read_text())["adaptive_not_built"]["error"] == "ValueError"


# --- hostile strings: stage 3 never raises -----------------------------------------------------

FRAGMENTS = ["**", "*", "?", "[", "]", "[!", "{", "}", "\x00", "..", "../..", "/", "/etc/x",
             "C:\\x", "\\", "~", "$X", "%h", " ", "é", "**/", "a**b", "x" * 300, ".", "//",
             "\n", "\t", ":", ";", "#", "'", '"', "|", "\ud800"]


def _hostile(seed: int) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(FRAGMENTS) for _ in range(rng.randint(1, 8)))


@pytest.mark.parametrize("seed", range(300))
def test_resolve_never_raises_on_a_hostile_target(tmp_path, seed):
    target = _hostile(seed)
    for rel in ("nginx.conf", "a/b/sshd_config", "deep/er/x.yaml"):
        status = adaptive._resolve(target, rel, {"nginx.conf", "a/b/c.conf"}, tmp_path)["status"]
        assert status in {"followed", "followed_from_parent", "in_the_tree_not_read",
                          "outside_the_tree", "not_found", "templated", "pattern_not_followed"}


def test_resolve_never_raises_on_very_long_and_traversing_targets(tmp_path):
    for target in ("a" * 100_000, "*" * 5000, "**" * 2000 + ".conf", "../" * 500 + "x",
                   "a/" * 3000 + "**.pem", "/" + "x" * 5000, "a/**b/" * 200):
        adaptive._resolve(target, "nginx.conf", {"nginx.conf"}, tmp_path)


def test_a_tree_of_hostile_leads_in_every_rule_scans_with_every_section(tmp_path):
    lines = [_hostile(s).replace("\n", "").replace("\x00", "").replace("\ud800", "") for s in range(60)]
    files = {
        "nginx.conf": "http {\n" + "".join(f" include {t};\n" for t in lines) + "}\n",
        "sshd_config": "".join(f"Include {t.replace(' ', '')}\nHostKey {t.replace(' ', '')}\n"
                               for t in lines if t.strip()),
        "app.yaml": "".join(f"k{i}: {t.replace(' ', '')}.pem\n" for i, t in enumerate(lines)),
        "conf/app.ini": "".join(f"cert = {t.replace(' ', '')}.crt\n" for t in lines),
        "app/main.py": "".join(f"open('{t.replace(chr(39), '')}.pem')\n" for t in lines),
    }
    root = _write(tmp_path / "t", files)
    result = scan_directory(root)
    assert "adaptive_not_built" not in result
    assert result["chosen_outside_files"]["leads"]["count"] > 0
    for level in ("full", "masked", "trimmed"):
        scan_repo(path=str(root), level=level)
