"""ZA-OPRAVYANE row 498 (D2 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8,
U-Boot 6487c50, 0.46.0).

U-Boot keeps its FIT signing in image tree sources (`.its`), device trees (`.dts`, `.dtsi`,
`.dtso`) and board configurations (`configs/*_defconfig`, no extension): `algo =
"sha256,rsa3072"`, `key-name-hint`, `CONFIG_FIT_SIGNATURE=y`, `CONFIG_RSA=y`. All of them were
`type_not_claimed` (32 .its, 5053 .dts, 4437 .dtsi, 379 .dtso, 1599 defconfigs), so the files
that say how the firmware is signed were the ones not read. They are now read as configuration.

The probe's own repro (`repro/uboot-names/t/`): board.its, board.dtsi, board_defconfig.
Not claimed: `key-name-hint`, `required` and `keyfile` name a key, not an algorithm, and give no
row of their own; `CONFIG_FIT_SIGNATURE=y` names no family and gives none either.
"""

import json

import pytest

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

ITS = """/ {
\tconfigurations {
\t\tconf-1 {
\t\t\tsignature-1 {
\t\t\t\talgo = "sha256,rsa3072";
\t\t\t\tkey-name-hint = "bootloaders";
\t\t\t};
\t\t};
\t};
};
"""

DEFCONFIG = ("CONFIG_FIT_SIGNATURE=y\nCONFIG_RSA=y\nCONFIG_ECDSA_VERIFY=y\n# CONFIG_DSA is not set\n"
             # Error-correcting memory and the switch layer, not EC or DSA (U-Boot defconfigs).
             "CONFIG_DDR_ECC=y\nCONFIG_SPL_NAND_ECC=y\nCONFIG_DM_DSA=y\n")


@pytest.fixture
def tree(tmp_path):
    t = tmp_path / "repo"
    (t / "configs").mkdir(parents=True)
    for name in ("board.its", "board.dtsi", "board.dts", "board-overlay.dtso"):
        (t / name).write_text(ITS)
    (t / "configs" / "board_defconfig").write_text(DEFCONFIG)
    # None of the 20 U-Boot defconfigs with `CONFIG_RSA=y` gave an RSA row once claimed: the
    # identifier alone, with no other algorithm in the file, is not read.
    (t / "configs" / "rsa_only_defconfig").write_text(
        "CONFIG_FIT_SIGNATURE=y\nCONFIG_SPL_RSA=y\n# CONFIG_RSA_VERIFY is not set\n")
    return t


SIGNED = ("board.its", "board.dtsi", "board.dts", "board-overlay.dtso")


def _check(result):
    unclaimed = {p for n in result["coverage"]["not_examined"]
                 if n.get("reason") == "type_not_claimed" for p in n.get("paths", [])}
    assert not unclaimed & {*SIGNED, "configs/board_defconfig"}, unclaimed
    rows = result["evidence"]["source_code"]
    for name in SIGNED:
        rsa = [e for e in rows if e["path"] == name and e["algorithm"] == "RSA"]
        assert [(e["line"], e["key_size"]) for e in rsa] == [(5, 3072)], (name, rsa)
        # key-name-hint names a key, not an algorithm.
        assert not [e for e in rows if e["path"] == name and e["line"] == 6], rows
    config = {(e["line"], e["algorithm"]): e for e in rows if e["path"] == "configs/board_defconfig"}
    assert (2, "RSA") in config and (3, "ECDSA") in config, config
    # `CONFIG_FIT_SIGNATURE=y` names no family.
    assert not [k for k in config if k[0] == 1], config
    alone = {(e["line"], e["algorithm"]): e["evidence_kind"] for e in rows
             if e["path"] == "configs/rsa_only_defconfig"}
    assert alone.get((2, "RSA")) not in (None, "comment", "ban", "identifier"), alone
    assert alone.get((3, "RSA")) == "ban", alone
    assert not [k for k in config if k[0] >= 5], config
    # `# CONFIG_DSA is not set` is not a use.
    assert config.get((4, "DSA"), {}).get("evidence_kind") in (None, "comment", "ban"), config


def test_firmware_signing_files_in_the_scan_json(tree, tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--out", str(out)]) == 0
    _check(json.loads(out.read_text()))


def test_firmware_signing_files_in_the_mcp_tool(tree):
    _check(server.scan_repo(str(tree)))


def test_firmware_signing_files_reach_the_cbom(tree):
    for doc in (server.export_cbom(str(tree)), cyclonedx.build(scan_directory(tree))):
        assert "RSA-3072" in {c["name"] for c in doc["components"]}


@pytest.mark.parametrize("name", ["board_defconfig.txt", "notes.dtsx"])
def test_only_these_names(tmp_path, name):
    (tmp_path / name).write_text(DEFCONFIG)
    result = scan_directory(tmp_path)
    unclaimed = {p for n in result["coverage"]["not_examined"]
                 if n.get("reason") == "type_not_claimed" for p in n.get("paths", [])}
    assert name in unclaimed, unclaimed


def test_microcode_hex_is_not_x25519(tmp_path):
    # arch/x86/dts/microcode/m12306a9_0000001b.dtsi:110, read once .dtsi was claimed: a word
    # of an Intel microcode blob, `0x25519f22`, read as X25519.
    (tmp_path / "m12306a9_0000001b.dtsi").write_text(
        "\t0xe0a95d4e\t0x25519f22\t0x3ee1d340\t0x2ddc2ca8\n")
    (tmp_path / "kex.dtsi").write_text('kex = "x25519";\n')
    rows = scan_directory(tmp_path)["evidence"]["source_code"]
    assert {(e["path"], e["algorithm"]) for e in rows} == {("kex.dtsi", "X25519")}, rows
