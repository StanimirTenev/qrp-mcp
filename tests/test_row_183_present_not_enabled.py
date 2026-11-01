"""ZA-OPRAVYANE row 183 (01.11.2026): XMSS in OpenSSH was counted as pqc_ready, but OpenSSH
compiles it only when WITH_XMSS is defined, and its build files never define it. Checked at
OpenSSH portable V_9_9_P1 (53a80ba): every XMSS file and the XMSS entries of `keyimpls[]` in
sshkey.c sit under `#ifdef WITH_XMSS`; configure.ac and Makefile.in do not name the macro.

Narrow on purpose: one gate, verified at the source. The flag is raised only where the tree
has preprocessor conditions on WITH_XMSS and no other line anywhere in it names the macro
(a `#define`, `-DWITH_XMSS`, `AC_DEFINE`, a CMake or meson line would). The classification
stays pqc_ready -- that is about the algorithm -- and the summary stops counting it."""

from __future__ import annotations

import json
import subprocess
import sys

from qrp_mcp.scan import scan_directory

XMSS_C = ("#include \"includes.h\"\n"
          "#ifdef WITH_XMSS\n"
          "int ssh_xmss_sign(struct sshkey *key) { return xmss_sign(key->xmss_sk); }\n"
          "#endif /* WITH_XMSS */\n")
KEY_H = "enum sshkey_types { KEY_RSA, KEY_ED25519, KEY_XMSS };\n"


def _tree(tmp_path, extra=None):
    t = tmp_path / "ossh"
    t.mkdir()
    (t / "ssh-xmss.c").write_text(XMSS_C)
    (t / "sshkey.h").write_text(KEY_H)
    (t / "configure.ac").write_text("AC_INIT([OpenSSH], [Portable])\n")
    for name, text in (extra or {}).items():
        (t / name).write_text(text)
    return t


def _xmss(result):
    return {f["algorithm_family"]: f for f in result["findings"]}["XMSS"]


def test_gated_and_undefined_is_flagged_and_not_counted(tmp_path):
    result = scan_directory(_tree(tmp_path))
    f = _xmss(result)
    assert f["classification"] == "pqc_ready"
    gate = f["not_enabled"]
    assert gate["gate"] == "WITH_XMSS"
    assert "no other line in any file" in gate["basis"]
    assert result["summary"]["pqc_ready_count"] == 0
    assert "XMSS" not in result["summary"]["by_role"]["signature"]["families"] or \
        result["summary"]["by_role"]["signature"]["pqc_readiness"] != "pqc_ready"


def test_defined_anywhere_is_not_flagged(tmp_path):
    for i, extra in enumerate(({"Makefile.in": "CFLAGS += -DWITH_XMSS\n"},
                               {"configure.ac": "AC_DEFINE([WITH_XMSS], [1], [xmss])\n"},
                               {"config.h": "#define WITH_XMSS 1\n"})):
        (tmp_path / str(i)).mkdir()
        result = scan_directory(_tree(tmp_path / str(i), extra))
        assert "not_enabled" not in _xmss(result), extra


def test_no_gate_at_all_is_not_flagged(tmp_path):
    t = tmp_path / "plain"
    t.mkdir()
    (t / "x.c").write_text("int f(void) { return xmss_sign(sk); }\n")
    assert "not_enabled" not in _xmss(scan_directory(t))


def test_flag_reaches_the_cbom(tmp_path):
    tree = _tree(tmp_path)
    out = tmp_path / "c.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    props = {}
    for c in json.loads(out.read_text())["components"]:
        if c["name"].startswith("XMSS"):
            props.update({p["name"]: p["value"] for p in c.get("properties", [])})
    assert "WITH_XMSS" in props["qrp:not_enabled"]
