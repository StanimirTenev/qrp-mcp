"""ZA-OPRAVYANE rows 203 and 196 (b) (LinkedIn, 03-04.11.2026; fixtures from the rooms' probes
`jp-rules` and `m-gw`).

A switch set off names the algorithm it would turn on: `USE_RSA = False`, Kconfig
`CONFIG_ECDSA=n`. Both were counted as a use -- `CONFIG_ECDSA=n` as "ECDSA usage" and in
`by_role.signature`. A list named LEGACY (`LEGACY_ALGS = ["RSA-PSS", "DSA"]`) put RSA in
`by_role.signature` at medium confidence beside the code's real ECDSA.

The switch set off is now a ban (not a use, as `!MD5` is); the legacy list is an identifier
row (low, never moving the headline or by_role). Switched on, both stay what they were."""

from __future__ import annotations

from pathlib import Path


def _rows(tmp_path: Path, name: str, text: str):
    from qrp_mcp.scan import scan_directory
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / name).write_text(text)
    result = scan_directory(tree)
    rows = {(e["line"], e["algorithm"]): e for e in result["evidence"]["source_code"]}
    return result, rows


SIGNER = ("from cryptography.hazmat.primitives.asymmetric import ed25519, ec\n"
          "\n"
          "USE_RSA = False\n"
          "LEGACY_ALGS = [\"RSA-PSS\", \"DSA\"]   # rejected at the API gateway\n"
          "\n"
          "def verify_partner(sig, data, pub):\n"
          "    pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))\n")


def test_python_switch_off_and_legacy_list_do_not_count(tmp_path):
    result, rows = _rows(tmp_path, "signer.py", SIGNER)
    assert rows[(3, "RSA")]["evidence_kind"] == "ban"
    assert rows[(4, "RSA")]["evidence_kind"] == "identifier"
    signature = result["summary"]["by_role"]["signature"]
    assert "RSA" not in signature["families"], signature
    assert "ECDSA" in signature["families"]


def test_python_switch_on_is_still_a_use(tmp_path):
    result, rows = _rows(tmp_path, "signer.py", SIGNER.replace("USE_RSA = False",
                                                                "USE_RSA = True"))
    assert rows[(3, "RSA")]["evidence_kind"] != "ban"


KCONFIG = ("CONFIG_FIT_SIGNATURE=y\n"
           "CONFIG_RSA=y\n"
           "CONFIG_RSA_VERIFY=y\n"
           "CONFIG_ECDSA=n\n")


def test_kconfig_option_set_to_n_is_not_a_use(tmp_path):
    result, rows = _rows(tmp_path, "u-boot.cfg", KCONFIG)
    assert rows[(4, "ECDSA")]["evidence_kind"] == "ban"
    assert rows[(3, "RSA")]["evidence_kind"] == "identifier"
    assert "RSA" in [f["algorithm_family"] for f in result["findings"]]
    assert "ECDSA" not in result["summary"]["by_role"]["signature"]["families"]


def test_kconfig_option_set_to_y_is_a_use(tmp_path):
    result, rows = _rows(tmp_path, "u-boot.cfg", KCONFIG.replace("CONFIG_ECDSA=n",
                                                                  "CONFIG_ECDSA=y"))
    assert rows[(4, "ECDSA")]["evidence_kind"] != "ban"
    assert "ECDSA" in result["summary"]["by_role"]["signature"]["families"]
