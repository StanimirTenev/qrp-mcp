"""The verdict names what was left out before counting (ZA-OPRAVYANE row 49, raised in
public by Muhammad Atif, 22.10.2026).

An HSM client library in vendor/ was removed by the directory exclusions before anything
was counted, and the verdict said "read every one of the 3 files" of a 4-file tree; the
fourth appeared only in `coverage.scope.files_excluded_before_counting`. Moved to lib/, the
same run said 3 of 4. The verdict now says how many files each excluded directory removed.
`.git` is not named: git metadata is not part of the estate, and it is in every checkout.
"""

from qrp_mcp.scan import scan_directory

SIGN = ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "def sign(k: rsa.RSAPrivateKey, m): return k.sign(m)\n")


def _tree(tmp_path, files):
    for name, data in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_bytes(data)
    return scan_directory(tmp_path)


def test_verdict_names_the_vendored_file(tmp_path):
    result = _tree(tmp_path, {"payments/sign.py": SIGN.encode(),
                              "vendor/hsm-client.so": b"\x7fELF\x00\x01",
                              "node_modules/x/index.js": b"module.exports = 1;\n",
                              "node_modules/y/index.js": b"module.exports = 2;\n"})
    assert result["verdict"] == (
        "This scan read every one of the 1 files it was given. Left out before counting, "
        "by directory name: 2 files in node_modules/, 1 file in vendor/.")


def test_git_metadata_is_not_named(tmp_path):
    result = _tree(tmp_path, {"payments/sign.py": SIGN.encode(),
                              ".git/HEAD": b"ref: refs/heads/main\n"})
    assert result["verdict"] == "This scan read every one of the 1 files it was given."
