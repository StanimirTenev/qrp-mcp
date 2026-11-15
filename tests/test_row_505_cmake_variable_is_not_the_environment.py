"""ZA-OPRAVYANE row 505, D10 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8
(MCUboot f30be48, 0.46.0).

`chosen_outside_files` held MCUboot `boot/zephyr/CMakeLists.txt:748` `set(key_size
"${boot_enc_key_size}")` and `:752` `math(EXPR key_size "${key_size} * 2")`: the byte length
of the encrypted-key TLV, worked out in the build from `set(boot_enc_key_size 16)` a few lines
above. In CMake `${name}` is a CMake variable; the environment is `$ENV{name}` ("Variable
References" and "Environment Variable References", cmake-language(7)). The `${NAME}` form of
a shell reference was read in CMake as if it were the shell's.
"""

import json

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

CMAKE = """if(CONFIG_BOOT_ENCRYPT_RSA OR CONFIG_BOOT_ENCRYPT_EC256)
  set(boot_enc_key_size 16)
  if(CONFIG_BOOT_SWAP_SAVE_ENCTLV)
    set(key_size 256)
  else()
    set(key_size "${boot_enc_key_size}")
  endif()
  math(EXPR key_size "${key_size} * 2")
endif()
set(TLS_CIPHERS $ENV{TLS_CIPHERS})
"""

SHELL = 'export TLS_CIPHERS="${TLS_CIPHERS}"\n'


def _tree(root):
    (root / "boot/zephyr").mkdir(parents=True)
    (root / "boot/zephyr/CMakeLists.txt").write_text(CMAKE)
    (root / "tools").mkdir()
    (root / "tools/env.sh").write_text(SHELL)
    return root


def _check(result):
    places = {(p["path"], p["line"]) for p in result["chosen_outside_files"]["places"]}
    assert places == {("boot/zephyr/CMakeLists.txt", 10), ("tools/env.sh", 1)}, places
    assert result["chosen_outside_files"]["count"] == 2


def test_cmake_variables_in_the_scan_json(tmp_path):
    tree = _tree(tmp_path / "repo")
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    _check(json.loads(out.read_text()))


def test_cmake_variables_in_the_mcp_tool(tmp_path):
    _check(server.scan_repo(str(_tree(tmp_path / "repo"))))


def test_cmake_variables_in_the_cbom(tmp_path):
    tree = _tree(tmp_path / "repo")
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        props = {p["name"]: p["value"] for p in doc["properties"]}
        assert props["qrp:chosen_outside_files:count"] == "2", props
        assert "CMakeLists.txt:6" not in props["qrp:chosen_outside_files:places"]
        assert "CMakeLists.txt:8" not in props["qrp:chosen_outside_files:places"]
