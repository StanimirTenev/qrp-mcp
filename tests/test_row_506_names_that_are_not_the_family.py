"""ZA-OPRAVYANE row 506, D12 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8
(MCUboot f30be48, U-Boot 6487c50, 0.46.0). Three names read as a family they are not:

* U-Boot `arch/sh/include/asm/cpu_sh7722.h:693` `#define MLDSA1R 0xFE940430`, a hardware
  register of the SH7722, was ML-DSA. ML-DSA's parameter sets are 44, 65 and 87 (FIPS 204); a
  digit right after the name that starts none of them is another name.
* tinycrypt's ECDSA file `ecc_dsa` (`#include <tinycrypt/ecc_dsa.h>`, `ecc_dsa.c` in CMake and
  in MCUboot's `sim/mcuboot-sys/build.rs`) was DSA, with severity high. ECC + DSA is ECDSA, as
  EC + DSA already was; so is tinycrypt's `ecc_dh` ECDH.
* `#define MBEDTLS_REMOVE_3DES_CIPHERSUITES` / `MBEDTLS_REMOVE_ARC4_CIPHERSUITES` (Mbed TLS 2.x:
  "Remove 3DES ciphersuites by default in SSL / TLS") were a declaration, a use. Defining the
  switch removes the suites: a removal, not a use.
"""

import json
from pathlib import Path

from qrp_mcp import cyclonedx, server
from qrp_mcp import detectors as d
from qrp_mcp.scan import scan_directory

REGISTERS = """/* SH7722 */
#define MLDSM1R     0xFE940428
#define MLDSA1R     0xFE940430
#define MLDSA2R     0xFE940434
"""

ECDSA_H = """#if defined(MCUBOOT_USE_TINYCRYPT)
    #include <tinycrypt/ecc_dsa.h>
    #include <tinycrypt/ecc_dh.h>
    #include <mbedtls/oid.h>
#endif
"""

CMAKE = """if(CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256)
  zephyr_library_sources(
      ${TINYCRYPT_DIR}/source/ecc.c
      ${TINYCRYPT_DIR}/source/ecc_dsa.c
  )
endif()
"""

BUILD_RS = """fn main() {
    let sig_ecdsa = env::var("CARGO_FEATURE_SIG_ECDSA").is_ok();
    if sig_ecdsa {
        conf.file("../../ext/tinycrypt/lib/source/ecc_dsa.c");
    }
}
"""

MBEDTLS_CONFIG = """/**
 * \\def MBEDTLS_REMOVE_ARC4_CIPHERSUITES
 *
 * Remove RC4 ciphersuites by default in SSL / TLS.
 */
#define MBEDTLS_REMOVE_ARC4_CIPHERSUITES

/**
 * \\def MBEDTLS_REMOVE_3DES_CIPHERSUITES
 *
 * Remove 3DES ciphersuites by default in SSL / TLS.
 */
#define MBEDTLS_REMOVE_3DES_CIPHERSUITES

#define MBEDTLS_ARC4_C
#define MBEDTLS_DES_C
"""


def _tree(root: Path) -> Path:
    files = {"arch/sh/include/asm/cpu_sh7722.h": REGISTERS,
             "boot/bootutil/include/bootutil/crypto/ecdsa.h": ECDSA_H,
             "boot/zephyr/CMakeLists.txt": CMAKE,
             "sim/mcuboot-sys/build.rs": BUILD_RS,
             "config/mcuboot_crypto_config.h": MBEDTLS_CONFIG}
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def _rows(result, path):
    return [(e["line"], e["algorithm"], e["evidence_kind"])
            for e in result["evidence"]["source_code"] if e["path"] == path]


def _check(result):
    assert not _rows(result, "arch/sh/include/asm/cpu_sh7722.h"), \
        _rows(result, "arch/sh/include/asm/cpu_sh7722.h")
    assert result["summary"]["pqc_ready_count"] == 0
    assert "ML-DSA" not in result["detected_algorithms"]
    assert "DSA" not in {e["algorithm"] for e in result["evidence"]["source_code"]}, [
        (e["path"], e["line"]) for e in result["evidence"]["source_code"] if e["algorithm"] == "DSA"]
    assert "DSA" not in result["detected_algorithms"]
    # ecc_dsa / ecc_dh now read as ec_dsa / ec_dh always did: one family word, ECDSA or ECDH,
    # which the identifier rule does not read alone. No DSA, no finite-field DH.
    header = _rows(result, "boot/bootutil/include/bootutil/crypto/ecdsa.h")
    assert not {alg for line, alg, _ in header if line in (2, 3)} & {"DSA", "DH"}, header
    used = {(line, alg) for line, alg, kind in _rows(result, "config/mcuboot_crypto_config.h")
            if kind not in ("comment", "ban", "identifier")}
    # The removal switches are not uses; the library switches beside them still are.
    assert not {u for u in used if u[0] in (6, 13)}, sorted(used)
    assert (15, "RC4") in used and (16, "DES") in used, sorted(used)
    config_rows = {(e["line"], e["algorithm"]): e for e in result["evidence"]["source_code"]
                   if e["path"] == "config/mcuboot_crypto_config.h"}
    assert config_rows[(6, "RC4")]["not_a_use_rule"] == "removal list", config_rows[(6, "RC4")]
    assert config_rows[(13, "3DES")]["not_a_use_rule"] == "removal list", config_rows[(13, "3DES")]


def test_names_in_the_scan_json(tmp_path):
    tree = _tree(tmp_path / "repo")
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    _check(json.loads(out.read_text()))


def test_names_in_the_mcp_tool(tmp_path):
    _check(server.scan_repo(str(_tree(tmp_path / "repo"))))


def test_names_in_the_cbom(tmp_path):
    tree = _tree(tmp_path / "repo")
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        names = {c["name"] for c in doc["components"]}
        assert not names & {"ML-DSA", "DSA"}, names


def test_ml_dsa_parameter_sets_are_still_ml_dsa():
    for text in ("MLDSA44", "mldsa65", "ML_DSA_87", "ml-dsa", "MLDSA65PrivateKey",
                 "ML-DSA-65", "mldsa_key"):
        rows = d.scan_source_file(Path("k.c"), "k.c", [f"#define X {text}"], hot=None)
        assert "ML-DSA" in {r["algorithm"] for r in rows}, text


def test_dsa_is_still_dsa_in_rust():
    rows = d.scan_source_file(Path("build.rs"), "build.rs",
                              ['conf.file("src/dsa.c");', "fn decode_dsa_openssh() {}"], hot=None)
    assert {r["line"] for r in rows if r["algorithm"] == "DSA"} == {1, 2}


def test_the_gate_and_the_full_read_agree():
    for name, text in (("cfg.h", MBEDTLS_CONFIG), ("ecdsa.h", ECDSA_H),
                       ("cpu_sh7722.h", REGISTERS), ("build.rs", BUILD_RS)):
        lines = text.split("\n")
        ext = Path(name).suffix
        assert (d.scan_source_file(Path(name), name, lines, hot=None)
                == d.scan_source_file(Path(name), name, lines, hot=d.hot_lines(lines, ext)))
