"""Third review of 0.50.0 (18.11), item 1 (blocker) and item 2.

1. setup.py was parsed with `ast.parse`, and on CPython 3.10 that segfaults (exit 139, the whole
   scan dies) on a deeply left-nested expression: `x = a+a+...` with 150 000 terms, 300 KB. A
   `try/except` cannot catch a segfault. Every input here runs in a subprocess, so a crash fails
   the test instead of killing pytest; the rows are checked too, so the test is red on 3.12 (where
   the parser raises and the file gave nothing) as well as on 3.10.
2. A setup.py Python cannot parse (Python 2 `print "x"`, a syntax error) gave no row, silently,
   and the verdict still said every file was read. It is read like any other file now.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import qrp_mcp
from qrp_mcp.assets import _setuptools_requests
from qrp_mcp.scan import scan_directory

H = "from setuptools import setup\n"
HOSTILE = {
    # The review's fixtures (review3/fx), generated here.
    "p_min": (H + 'setup(install_requires=["cryptography"])\nx = ' + "+".join(["a"] * 150000) + "\n",
              [("cryptography", 2)]),
    "p_binop": (H + "setup(install_requires=" + "+".join(['["cryptography"]'] * 200000) + ")\n",
                [("cryptography", 2)] * 200000),
    "p_unary": (H + "x = " + "-" * 200000 + '1\nsetup(install_requires=["cryptography"])\n',
                [("cryptography", 3)]),
    "p_lambda": (H + "x = " + "lambda: " * 3000 + '1\nsetup(install_requires=["cryptography"])\n',
                 [("cryptography", 3)]),
    "p_deep": (H + "setup(install_requires=" + "[" * 5000 + '"cryptography"' + "]" * 5000 + ")\n",
               [("cryptography", 2)]),
    # The other left-nested chains that crash 3.10's parser at about 150 000 levels.
    "attr": (H + 'setup(install_requires=["cryptography"])\nx = a' + ".b" * 200000 + "\n",
             [("cryptography", 2)]),
    "call": (H + 'setup(install_requires=["cryptography"])\nx = f' + "()" * 200000 + "\n",
             [("cryptography", 2)]),
    "subscript": (H + 'setup(install_requires=["cryptography"])\nx = a' + "[0]" * 200000 + "\n",
                  [("cryptography", 2)]),
}

_CHILD = """
import json, sys
from qrp_mcp.assets import _setuptools_requests
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
print(json.dumps([[p, n] for p, n, _ in _setuptools_requests("setup.py", lines)]))
"""


def _child_env() -> dict[str, str]:
    # The same qrp_mcp this test imported (src or the installed wheel).
    here = str(Path(qrp_mcp.__file__).resolve().parents[1])
    return {**os.environ, "PYTHONPATH": os.pathsep.join([here, os.environ.get("PYTHONPATH", "")])}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_a_hostile_setup_py_never_crashes_the_interpreter(tmp_path, name):
    text, expected = HOSTILE[name]
    (tmp_path / "setup.py").write_text(text)
    done = subprocess.run([sys.executable, "-c", _CHILD, str(tmp_path / "setup.py")],
                          capture_output=True, text=True, timeout=300, env=_child_env())
    assert done.returncode == 0, (done.returncode, done.stderr[-500:])
    assert [tuple(r) for r in json.loads(done.stdout)] == expected


def test_a_scan_of_the_review_fixture_ends(tmp_path):
    text, _ = HOSTILE["p_min"]
    (tmp_path / "setup.py").write_text(text)
    done = subprocess.run(
        [sys.executable, "-c",
         "import sys, json; from qrp_mcp.scan import scan_directory; "
         "r = scan_directory(sys.argv[1]); "
         "print(json.dumps(sorted(d['package'] for d in r['evidence']['dependencies'])))",
         str(tmp_path)],
        capture_output=True, text=True, timeout=300, env=_child_env())
    assert done.returncode == 0, (done.returncode, done.stderr[-500:])
    assert json.loads(done.stdout) == ["cryptography"]


def _names(text: str) -> list[tuple[str, int]]:
    return [(p, n) for p, n, _ in _setuptools_requests("setup.py", text.splitlines())]


@pytest.mark.parametrize("text, expected", [
    # The review's s_py2, s_syntax, s_py2print_but_valid_deps: fddec63 gave these rows.
    (H + 'print "hello"\nsetup(install_requires=["cryptography", "paramiko"])\n',
     [("cryptography", 3), ("paramiko", 3)]),
    (H + 'setup(install_requires=["cryptography", "paramiko"]\nprint "py2"\n',
     [("cryptography", 2), ("paramiko", 2)]),
    (H + 'exec "x"\nsetup(install_requires=["cryptography"])\n', [("cryptography", 3)]),
    # The second review's cases, in a file Python cannot parse: still right.
    ('print "x"\nsetup(\n    install_requires=["foo @ git+https://h.example/x.git#egg=foo"],\n'
     '    description="paramiko",\n    long_description="ecdsa",\n)', [("foo", 3)]),
    ('print "x"\nsetup(name="x", install_requires=["paramiko"] + ["ecdsa"], description="c")',
     [("paramiko", 2), ("ecdsa", 2)]),
    ('print "x"\nsetup(install_requires=["a"]  # "zzcomment"\n, description="b")', [("a", 2)]),
])
def test_a_setup_py_python_cannot_parse_is_still_read(tmp_path, text, expected):
    assert _names(text) == expected
    (tmp_path / "setup.py").write_text(text.replace('"foo @', '"cryptography @'))
    scan_directory(tmp_path)


def test_an_unterminated_string_or_bracket_ends_nothing():
    for text in ('setup(install_requires=["cryptography', 'setup(install_requires=["""a',
                 'setup(install_requires=[' * 3, 'install_requires = "a\\', "install_requires="):
        _names(text)
