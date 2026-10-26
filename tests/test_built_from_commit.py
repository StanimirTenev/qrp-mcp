"""An installed wheel names the commit it was built from.

Until 0.37.0 every installed qrp-mcp wrote `source_commit = {pinned: false, reason:
no_checkout}`: the CBOM did not say which revision produced it. A build from a git checkout
now records the commit (hatch_build.py -> qrp_mcp/_build_info.py), and the installed package
reports it as `basis: built_from` -- the commit the wheel was built from, not a checkout it is
running from. A build without git still says `no_checkout`.

The two build tests run the way a user gets the package: `python -m build` (an sdist, then the
wheel built from the unpacked sdist, where there is no git), installed into a fresh virtualenv,
and the `qrp-mcp` command of that environment run on a directory.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import sysconfig
import venv
from pathlib import Path

import pytest

from qrp_mcp import closure, coverage

ROOT = Path(__file__).resolve().parent.parent


def _checkout_head() -> str | None:
    if not shutil.which("git"):
        return None
    top = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != ROOT:
        return None
    return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()


def _can_build() -> bool:
    try:
        import build  # noqa: F401
        import hatchling  # noqa: F401
    except ImportError:
        return False
    return True


needs_build = pytest.mark.skipif(not _can_build(), reason="needs build and hatchling")


def _build_wheel(src: Path, out: Path) -> Path:
    # Without isolation, so the test runs offline with the hatchling already installed.
    subprocess.run([sys.executable, "-m", "build", "--no-isolation", "-o", str(out), str(src)],
                   check=True, capture_output=True, text=True, cwd=out.parent)
    (wheel,) = out.glob("qrp_mcp-*.whl")
    return wheel


def _install_and_scan(wheel: Path, tmp_path: Path) -> dict:
    env = tmp_path / "fresh"
    venv.EnvBuilder(with_pip=True).create(env)
    py = env / "bin" / "python"
    subprocess.run([str(py), "-m", "pip", "install", "-q", "--no-deps", "--no-index", str(wheel)],
                   check=True, capture_output=True, text=True)
    # The dependencies come from the interpreter running the tests, behind the fresh
    # environment's own site-packages (a path line in a .pth file is appended to sys.path;
    # the .pth files of that directory, the editable install among them, are not run).
    site = subprocess.run([str(py), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
                          capture_output=True, text=True, check=True).stdout.strip()
    Path(site, "zz_test_deps.pth").write_text(sysconfig.get_path("purelib") + "\n")
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                                   "k = rsa.generate_private_key(65537, 2048)\n")
    out = tmp_path / "scan.json"
    subprocess.run([str(env / "bin" / "qrp-mcp"), "scan", str(target), "--no-config",
                    "--out", str(out)], check=True, capture_output=True, text=True, cwd=tmp_path)
    instrument = json.loads(out.read_text())["coverage"]["instrument"]
    imported = subprocess.run([str(py), "-I", "-c", "import qrp_mcp; print(qrp_mcp.__file__)"],
                              capture_output=True, text=True, check=True, cwd=tmp_path)
    assert str(env) in imported.stdout, imported.stdout  # the installed copy ran
    return instrument


@needs_build
def test_a_wheel_built_from_a_checkout_names_its_commit(tmp_path):
    head = _checkout_head()
    if head is None:
        pytest.skip("not running from a git checkout")
    wheel = _build_wheel(ROOT, tmp_path / "dist")
    instrument = _install_and_scan(wheel, tmp_path)
    pin = instrument["source_commit"]
    assert pin["pinned"] is True and pin["basis"] == "built_from"
    assert pin["commit"] == head
    assert isinstance(pin["dirty"], bool)
    assert "built" in pin["meaning"] and "checked out" not in pin["meaning"]
    assert instrument["revision"].startswith(head + " (built from")


@needs_build
def test_a_build_without_git_still_says_no_checkout(tmp_path):
    src = tmp_path / "src-copy"
    shutil.copytree(ROOT, src, ignore=shutil.ignore_patterns(
        ".git", ".venv", "dist", "build", "target", "__pycache__", ".pytest_cache", "*.egg-info",
        ".claude"))
    assert not (src / "src" / "qrp_mcp" / "_build_info.py").exists()
    wheel = _build_wheel(src, tmp_path / "dist")
    instrument = _install_and_scan(wheel, tmp_path)
    pin = instrument["source_commit"]
    assert pin["pinned"] is False and pin["reason"] == "no_checkout"
    assert instrument["revision"] == "installed wheel, no VCS"


@needs_build
def test_an_sdist_unpacked_into_a_repository_of_its_own_keeps_its_commit(tmp_path):
    # Distribution packaging unpacks the sdist into a git repository of its own; that
    # repository's commit is not the one the package was built from.
    import tarfile
    import zipfile
    head = _checkout_head()
    if head is None:
        pytest.skip("not running from a git checkout")
    dist = tmp_path / "dist"
    subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--sdist", "-o", str(dist),
                    str(ROOT)], check=True, capture_output=True, text=True, cwd=tmp_path)
    (sdist,) = dist.glob("qrp_mcp-*.tar.gz")
    with tarfile.open(sdist) as tar:
        tar.extractall(tmp_path / "unpacked", filter="data")
    (src,) = (tmp_path / "unpacked").iterdir()
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "packaging"]):
        subprocess.run(["git", "-C", str(src), *args], check=True, capture_output=True)
    out = tmp_path / "wheel"
    subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--wheel", "-o", str(out),
                    str(src)], check=True, capture_output=True, text=True, cwd=tmp_path)
    (wheel,) = out.glob("qrp_mcp-*.whl")
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        info = z.read("qrp_mcp/_build_info.py").decode()
    assert names.count("qrp_mcp/_build_info.py") == 1
    assert f"COMMIT = {head!r}" in info


def test_built_from_reads_as_words():
    pin = {"pinned": True, "commit": "c" * 40, "dirty": False, "basis": "built_from"}
    assert coverage._revision(pin) == "c" * 40 + " (built from)"
    assert coverage._revision({**pin, "dirty": True}) == (
        "c" * 40 + " (built from, with uncommitted changes)")


def _result(items, tool_pin, commit="aaa"):
    return {
        "excerpt_level": "full",
        "coverage": {
            "instrument": {"version": "0.37.0", "source_commit": tool_pin,
                           "ruleset": {"algorithm_patterns": 48},
                           "claimed_types": {"source": [".py"]}, "excluded_dirs": [".git"]},
            "corpus": {"target": "/repo", "pinned_at": {"pinned": True, "kind": "git",
                                                        "commit": commit, "dirty": False}},
        },
        "evidence": {"source_code": items},
        "unreadable_files": [], "files_left_out": [], "unreadable_directories": [],
        "symlinks_not_followed": [],
        "files_read": sorted({"a.py"} | {i["path"] for i in items}),
    }


_RSA = {"path": "a.py", "line": 10, "algorithm": "RSA", "description": "RSA usage",
        "excerpt": "k = rsa.generate_private_key(65537, 2048)", "evidence_kind": "call",
        "in_test_code": False}


def _built(commit, dirty=False):
    return {"pinned": True, "commit": commit, "dirty": dirty, "basis": "built_from",
            "meaning": coverage.BUILT_FROM}


def test_closure_compares_two_built_wheels_by_their_commit():
    same = closure.prove_closure(_result([_RSA], _built("t1")), _result([], _built("t1"), "bbb"))
    assert same["comparability"]["verdict"] == "comparable"
    assert len(same["closure"]["closed"]) == 1
    other = closure.prove_closure(_result([_RSA], _built("t1")), _result([], _built("t2"), "bbb"))
    assert other["comparability"]["verdict"] == "not_comparable"
    assert other["closure"] is None


def test_closure_a_built_wheel_and_a_checkout_of_its_commit_compare():
    checkout = {"pinned": True, "commit": "t1", "dirty": False}
    out = closure.prove_closure(_result([_RSA], _built("t1")), _result([], checkout, "bbb"))
    assert out["comparability"]["verdict"] == "comparable"
