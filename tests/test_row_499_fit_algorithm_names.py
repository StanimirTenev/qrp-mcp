"""ZA-OPRAVYANE row 499 (D3 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8,
U-Boot 6487c50, 0.46.0).

U-Boot's FIT signature algorithm names, `<hash>,<signature>` (`"sha1,rsa2048"` in
tools/fdt_add_pubkey.c:7, `-a sha256,rsa4096` in tools/iot2050-sign-fw.sh:49), and U-Boot's own
RSA header `#include <u-boot/rsa.h>` with what it declares (`RSA_DEFAULT_PUBEXP`,
`struct rsa_public_key` in lib/rsa/rsa-mod-exp.c) gave no row: the files were read, and the
same names spelled `"rsa2048"` or `<openssl/rsa.h>` did. Each case is one file, as in the tree:
in a file with another RSA row the identifiers were already read, alone they were not.

Not claimed: the SHA-1 of `sha1,rsa2048` -- the hash half is not made a row here.
"""

import json

import pytest

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

FDT_ADD_PUBKEY = (
    "// SPDX-License-Identifier: GPL-2.0+\n"
    "#include <image.h>\n"
    "#include \"fit_common.h\"\n"
    "\n"
    "static const char *cmdname;\n"
    "\n"
    "static const char *algo_name = \"sha1,rsa2048\"; /* -a <algo> */\n"
    "static const char *keydir = \".\"; /* -k <keydir> */\n")

SIGN_SH = (
    "rm $TEMP_X509 $CERT_X509\n"
    "\n"
    "$TOOLS_DIR/binman/binman sign -i flash-pg1.bin -k $1 -a sha256,rsa4096 fit@380000\n")

RSA_MOD_EXP = (
    "// SPDX-License-Identifier: GPL-2.0+\n"
    "#include \"fdt_host.h\"\n"
    "#include <u-boot/rsa.h>\n"
    "#include <u-boot/rsa-mod-exp.h>\n"
    "\n"
    "/* Default public exponent for backward compatibility */\n"
    "#define RSA_DEFAULT_PUBEXP\t65537\n"
    "\n"
    "static void subtract_modulus(const struct rsa_public_key *key, uint32_t num[])\n"
    "{\n"
    "\tint64_t acc = 0;\n"
    "}\n")


def _one(tmp_path, name, text):
    t = tmp_path / "repo"
    t.mkdir()
    (t / name).write_text(text)
    return t


def _rsa(evidence, path):
    return {e["line"]: e for e in evidence["source_code"]
            if e["path"] == path and e["algorithm"] == "RSA"}


@pytest.mark.parametrize("name, text, line, size", [
    ("fdt_add_pubkey.c", FDT_ADD_PUBKEY, 7, 2048),
    ("iot2050-sign-fw.sh", SIGN_SH, 3, 4096),
])
def test_fit_algorithm_name_is_rsa_with_its_size(tmp_path, name, text, line, size):
    rows = _rsa(scan_directory(_one(tmp_path, name, text))["evidence"], name)
    assert line in rows, rows
    assert rows[line]["key_size"] == size, rows[line]
    assert rows[line]["evidence_kind"] not in ("comment", "ban"), rows[line]


def test_uboot_rsa_header_and_what_it_declares(tmp_path):
    rows = _rsa(scan_directory(_one(tmp_path, "rsa-mod-exp.c", RSA_MOD_EXP))["evidence"],
                "rsa-mod-exp.c")
    assert {3, 7, 9} <= set(rows), rows


@pytest.mark.parametrize("line", [
    # A hash and an RSA size that is no key's, or no FIT name at all.
    'x = "sha1,rsa"',
    'x = "sha256,rsassa"',
    'x = "crc32,sha256"',
])
def test_not_a_fit_rsa_name(tmp_path, line):
    rows = _rsa(scan_directory(_one(tmp_path, "a.c", line + "\n"))["evidence"], "a.c")
    assert not rows, rows


def test_fit_name_reaches_the_three_paths(tmp_path):
    t = _one(tmp_path, "fdt_add_pubkey.c", FDT_ADD_PUBKEY)
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(t), "--out", str(out)]) == 0
    assert _rsa(json.loads(out.read_text())["evidence"], "fdt_add_pubkey.c")[7]["key_size"] == 2048
    assert _rsa(server.scan_repo(str(t))["evidence"], "fdt_add_pubkey.c")[7]["key_size"] == 2048
    for doc in (server.export_cbom(str(t)), cyclonedx.build(scan_directory(t))):
        assert "RSA-2048" in {c["name"] for c in doc["components"]}
