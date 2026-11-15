"""ZA-OPRAVYANE row 507, D14 of `linkedin-postove/2026-11-15/boot-proba/REZULTAT.md` §8
(U-Boot 6487c50, 0.46.0).

Every directory named `vendor` was excluded before counting, wherever it was. In U-Boot that
removed tools/binman/test/vendor/ -- 35 device trees, the binman tests of vendor image formats
(nxp_imx8_csf.dts, ti_secure.dts), not vendored code. A `vendor/` is now excluded at the root of
the tree, or beside a package manifest (go.mod, composer.json, Gemfile, Cargo.toml, package.json,
...), which is where a package manager puts what it vendors; elsewhere it is read.

Not claimed: `build/` is still excluded by name anywhere (U-Boot's doc/build/, 10 files).
"""

from qrp_mcp.scan import scan_directory


def _tree(tmp_path):
    t = tmp_path / "repo"
    files = {
        "tools/binman/test/vendor/nxp_imx8_csf.dts": '/ { csf { algo = "sha256,rsa4096"; }; };\n',
        "vendor/lib.py": "from Crypto.PublicKey import RSA\n",
        "app/go.mod": "module example.com/app\n\ngo 1.24\n",
        "app/vendor/golang.org/x/crypto/ssh/keys.go": "package ssh\nvar k = rsa.GenerateKey\n",
        "web/composer.json": "{}\n",
        "web/vendor/phpseclib/RSA.php": "<?php $k = RSA::createKey(1024);\n",
    }
    for rel, text in files.items():
        (t / rel).parent.mkdir(parents=True, exist_ok=True)
        (t / rel).write_text(text)
    return t


def test_vendor_only_at_the_root_or_beside_a_manifest(tmp_path):
    result = scan_directory(_tree(tmp_path))
    read = set(result["files_read"])
    assert "tools/binman/test/vendor/nxp_imx8_csf.dts" in read
    rows = [e for e in result["evidence"]["source_code"]
            if e["path"] == "tools/binman/test/vendor/nxp_imx8_csf.dts"]
    assert [(e["algorithm"], e["key_size"]) for e in rows] == [("RSA", 4096)], rows
    assert not read & {"vendor/lib.py", "app/vendor/golang.org/x/crypto/ssh/keys.go",
                       "web/vendor/phpseclib/RSA.php"}, read
    excluded = result["coverage"]["scope"]["files_excluded_before_counting"]
    assert excluded["by_directory"]["vendor"] == 3, excluded
    assert "tools/binman/test/vendor" not in str(excluded), excluded
    # The rule is declared where the excluded directories are, not only applied.
    instrument = result["coverage"]["instrument"]["excluded_dirs"]
    assert "vendor (at the root, or beside a package manifest)" in instrument, instrument
    assert "vendor" not in instrument, instrument
