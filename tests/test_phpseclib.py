r"""phpseclib, the pure-PHP crypto library (ZA-OPRAVYANE row 303; fixture L1/f03-phpseclib).
Laravel Passport's `RSA::createKey(4096)` -- the command that makes `oauth-private.key` -- gave
0 findings on 0.41.0. Sources (read 04.11.2026): the README, "PSR-4 autoloading with namespace
rooted at `\phpseclib3`" (and `\phpseclib4`, 2.x `\phpseclib`),
https://github.com/phpseclib/phpseclib; phpseclib 3.0 phpseclib/Crypt/RSA.php,
https://github.com/phpseclib/phpseclib/blob/3.0/phpseclib/Crypt/RSA.php --
`namespace phpseclib3\Crypt;`, `public static function createKey($bits = 2048)`.
"""

from qrp_mcp.scan import scan_directory

KEYS = r"""<?php
namespace App\Console;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\DSA;
class KeysCommand {
    public function handle() {
        $key = RSA::createKey(4096);
        $ed  = EC::createKey('Ed25519');
        $dh  = \phpseclib4\Crypt\DH::createKey($params);
    }
}
"""


def test_phpseclib_classes_and_key_size(tmp_path):
    (tmp_path / "KeysCommand.php").write_text(KEYS)
    result = scan_directory(tmp_path)
    rows = sorted((f["line"], f["algorithm"], f.get("key_size")) for f in result["evidence"]["source_code"])
    assert rows == [(4, "DSA", "undetermined"), (7, "RSA", 4096), (8, "Ed25519", None),
                    (9, "DH", "undetermined")]


def test_other_rsa_class_names_are_not_phpseclib(tmp_path):
    (tmp_path / "a.php").write_text("<?php\n$x = MyRSA::createKey(1024);\n$y = Foo\\RSA::createKey(1);\n")
    result = scan_directory(tmp_path)
    assert [f for f in result["evidence"]["source_code"] if f["description"] == "RSA named by phpseclib"] == []
