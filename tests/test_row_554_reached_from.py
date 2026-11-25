"""Row 554 (25.11.2026, Madhukar Suluva, "which applications and services depend on it"; probe
`linkedin-postove/2026-11-25/stai/proba/madhukar`).

A shared `libs/cryptoutil/sign.py` (RSA-2048, sign) imported by `svc-payments/app.py` and
`svc-login/app.py`: the findings were on the wrapper's lines only, and the two services were only in
`files_read`. Now a Python occurrence inside a module of the tree carries `reached_from` -- the
places in other files read that import the top-level function or class it is in and call it (or,
where no call is seen, the import) -- with `reached_from_count` and `reached`, which says it is
static and incomplete. Beside the row and outside its identity, as `imported_in` is (row 157).

Read by import and name only, as the Python reference documents the import statement
(https://docs.python.org/3/reference/simple_stmts.html#the-import-statement): `from a.b import f`,
`from a.b import f as g`, `import a.b`, `import a.b as m`, `from a import b`, relative imports. A call
through another name, a re-export, `importlib`, or a module on a path the tree does not show is not
followed.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

SIGN = ("from cryptography.hazmat.primitives.asymmetric import rsa, padding\n"
        "from cryptography.hazmat.primitives import hashes\n\n"
        "def make_key():\n"
        "    return rsa.generate_private_key(public_exponent=65537, key_size=2048)\n\n"
        "def sign(key, data):\n"
        "    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())\n")
PROBE = {
    "libs/cryptoutil/sign.py": SIGN,
    "svc-payments/app.py": ("from libs.cryptoutil.sign import make_key, sign\nKEY = make_key()\n"
                            "def pay(msg):\n    return sign(KEY, msg)\n"),
    "svc-login/app.py": ("from libs.cryptoutil.sign import make_key, sign\ndef token(claims):\n"
                         "    return sign(make_key(), claims)\n"),
}


def _scan(root: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return scan_directory(root)


def _reached(result: dict, path: str = "libs/cryptoutil/sign.py") -> dict[int, list[str]]:
    return {i["line"]: i.get("reached_from") for i in result["evidence"]["source_code"]
            if i["path"] == path}


def test_the_probe_tree(tmp_path):
    result = _scan(tmp_path, PROBE)
    assert _reached(result) == {5: ["svc-login/app.py:3", "svc-payments/app.py:2"],
                                8: ["svc-login/app.py:3", "svc-payments/app.py:4"]}
    item = next(i for i in result["evidence"]["source_code"] if i["line"] == 5)
    assert item["reached_from_count"] == 2
    assert "static" in item["reached"] and "not followed" in item["reached"]


@pytest.mark.parametrize("importer", [
    "from libs.cryptoutil.sign import make_key as mk\nk = mk()\n",
    "import libs.cryptoutil.sign\nk = libs.cryptoutil.sign.make_key()\n",
    "import libs.cryptoutil.sign as s\nk = s.make_key()\n",
    "from libs.cryptoutil import sign\nk = sign.make_key()\n",
])
def test_each_import_form(tmp_path, importer):
    result = _scan(tmp_path, {"libs/cryptoutil/sign.py": SIGN, "svc/app.py": importer})
    assert _reached(result)[5] == ["svc/app.py:2"]
    assert _reached(result)[8] is None


def test_relative_imports(tmp_path):
    result = _scan(tmp_path, {
        "libs/__init__.py": "", "libs/cryptoutil/__init__.py": "",
        "libs/cryptoutil/sign.py": SIGN,
        "libs/cryptoutil/tokens.py": "from .sign import sign\ndef t(k, c):\n    return sign(k, c)\n",
        "libs/web/views.py": "from ..cryptoutil.sign import make_key\nK = make_key()\n"})
    assert _reached(result) == {5: ["libs/web/views.py:2"], 8: ["libs/cryptoutil/tokens.py:3"]}


def test_a_name_imported_and_not_called_is_the_import(tmp_path):
    result = _scan(tmp_path, {"libs/cryptoutil/sign.py": SIGN,
                              "svc/app.py": "from libs.cryptoutil.sign import sign\nHANDLER = sign\n"})
    assert _reached(result)[8] == ["svc/app.py:1"]


def test_a_method_is_reached_through_its_class(tmp_path):
    signer = ("from cryptography.hazmat.primitives.asymmetric import rsa\n\nclass Signer:\n"
              "    def key(self):\n"
              "        return rsa.generate_private_key(public_exponent=65537, key_size=3072)\n")
    result = _scan(tmp_path, {"lib/signer.py": signer,
                              "svc/app.py": "from lib.signer import Signer\ns = Signer()\n"})
    assert _reached(result, "lib/signer.py")[5] == ["svc/app.py:2"]


def test_an_ambiguous_module_links_nothing(tmp_path):
    result = _scan(tmp_path, {"a/crypto/sign.py": SIGN, "b/crypto/sign.py": SIGN,
                              "svc/app.py": "from crypto.sign import make_key\nK = make_key()\n"})
    assert _reached(result, "a/crypto/sign.py")[5] is None
    assert _reached(result, "b/crypto/sign.py")[5] is None


def test_a_suffix_of_the_path_resolves_when_it_is_the_only_one(tmp_path):
    # `src/` layouts: `from cryptoutil.sign import ...` with the module at src/cryptoutil/sign.py.
    result = _scan(tmp_path, {"src/cryptoutil/sign.py": SIGN,
                              "svc/app.py": "from cryptoutil.sign import make_key\nK = make_key()\n"})
    assert _reached(result, "src/cryptoutil/sign.py")[5] == ["svc/app.py:2"]


def test_the_fingerprint_and_closure_identity_do_not_move(tmp_path):
    from qrp_mcp import baseline, closure
    alone = _scan(tmp_path / "a", {"libs/cryptoutil/sign.py": SIGN})
    both = _scan(tmp_path / "b", {"libs/cryptoutil/sign.py": SIGN,
                                  "svc/app.py": "from libs.cryptoutil.sign import sign\n"})
    lib = lambda r: [i for i in r["evidence"]["source_code"] if i["path"].startswith("libs/")]  # noqa: E731
    assert ([closure._identity("source_code", i) for i in lib(alone)]
            == [closure._identity("source_code", i) for i in lib(both)])
    assert {"reached_from", "reached_from_count", "reached"} <= baseline._NOT_IDENTITY


def test_cli_mcp_and_cbom_carry_it(tmp_path):
    root = tmp_path / "tree"
    _scan(root, PROBE)
    out = tmp_path / "s.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(root), "--out", str(out)], check=True, capture_output=True,
                   env=dict(os.environ))
    for result in (json.loads(out.read_text()), scan_repo(str(root))):
        assert _reached(result)[5] == ["svc-login/app.py:3", "svc-payments/app.py:2"]
    cbom = build(scan_directory(root))
    values = [json.loads(p["value"]) for c in cbom["components"] for p in c.get("properties", [])
              if p["name"] == "qrp:reached_from"]
    assert {"libs/cryptoutil/sign.py:5": ["svc-login/app.py:3", "svc-payments/app.py:2"]} in [
        {k: v for k, v in val.items() if k.endswith(":5")} for val in values]


def test_a_local_file_with_an_imported_modules_name_is_linked_and_the_text_says_so(tmp_path):
    # Owner's decision 6 (25.11.2026): `import jwt` meant for PyJWT, beside a local jwt.py, links the
    # local file -- a one-part name resolves to the top of the tree or the importer's directory. The
    # place may be wrong, not only missing, and `reached` says that too.
    result = _scan(tmp_path, {"jwt.py": SIGN, "app.py": "import jwt\nt = jwt.sign(k, b'x')\n"})
    assert _reached(result, "jwt.py")[8] == ["app.py:2"]
    item = next(i for i in result["evidence"]["source_code"]
                if i["path"] == "jwt.py" and i["line"] == 8)
    assert "same name" in item["reached"] and "jwt.py" in item["reached"]
