"""A scanned tree must not be able to put code into the processes that read it.

Reported privately on 20.11.2026 against 0.52.0: a spawned reader is started with
`python -c ...`, which puts the working directory first on sys.path. When the server's
working directory is the scanned repository, a committed `multiprocessing/__init__.py`
is imported in place of the standard library and runs with the user's rights.

The test runs it the way a host does: the server over stdio, its working directory the
tree, `scan_repo(path=".")`. A `sitecustomize` outside the tree records every reader
process that starts, so the test also fails if the fix only works by no longer starting
readers.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _rpc(proc, i, method, params):
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method,
                                 "params": params}) + "\n")
    proc.stdin.flush()
    while True:
        line = proc.stdout.readline()
        assert line, "the server closed its output"
        message = json.loads(line)
        if message.get("id") == i:
            return message


def test_a_scanned_tree_cannot_shadow_a_module_in_the_readers(tmp_path):
    tree = tmp_path / "victim"
    (tree / "src").mkdir(parents=True)
    for i in range(260):
        (tree / "src" / f"m{i}.py").write_text(f"def f{i}():\n    return {i}\n")
    planted = tmp_path / "planted-ran"
    (tree / "multiprocessing").mkdir()
    (tree / "multiprocessing" / "__init__.py").write_text(
        f"open({str(planted)!r}, 'a').write('x')\n")

    hooks = tmp_path / "hooks"
    hooks.mkdir()
    readers = tmp_path / "readers"
    readers.mkdir()
    (hooks / "sitecustomize.py").write_text(
        "import os, sys\n"
        "if '--multiprocessing-fork' in getattr(sys, 'orig_argv', sys.argv):\n"
        f"    open(os.path.join({str(readers)!r}, str(os.getpid())), 'w').close()\n")
    launcher = tmp_path / "launch.py"                # outside the tree, as a console script is
    launcher.write_text("from qrp_mcp.server import main\nmain()\n")

    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONSAFEPATH", "PYTHONPATH")}
    env.update(QRP_MCP_JOBS="2", PYTHONPATH=os.pathsep.join([str(hooks), str(ROOT / "src")]))
    proc = subprocess.Popen([sys.executable, str(launcher)], cwd=tree, env=env, text=True,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    try:
        _rpc(proc, 1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "test", "version": "0"}})
        proc.stdin.write(json.dumps({"jsonrpc": "2.0",
                                     "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()
        answer = _rpc(proc, 2, "tools/call", {"name": "scan_repo", "arguments": {"path": "."}})
    finally:
        proc.stdin.close()
        proc.wait(timeout=60)

    assert "error" not in answer and not answer["result"].get("isError"), answer
    assert not planted.exists(), "the scanned tree's multiprocessing/ ran in a reader"
    assert len(list(readers.iterdir())) >= 2, "no reader process started: the test proves nothing"
