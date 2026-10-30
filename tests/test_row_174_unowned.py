"""ZA-OPRAVYANE row 174 (Michael Wegger): with a CODEOWNERS file, an MD5 call in a path no line
covers came back with no owner and nothing said so -- no count, no list. Each such occurrence
now names the file that does not cover it (`unowned_by`), the codeowners block counts and lists
them, and the CBOM occurrence says `[owners: none per <file>]`."""

import json

from qrp_mcp import server
from qrp_mcp.scan import scan_directory


def _tree(tmp_path):
    t = tmp_path / "repo"
    (t / ".github").mkdir(parents=True)
    (t / "payments").mkdir()
    (t / ".github" / "CODEOWNERS").write_text("/payments/ @bank/payments-team\n")
    (t / "payments" / "sign.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
    (t / "util.py").write_text("import hashlib\nh = hashlib.md5(b'x').hexdigest()\n")
    return t


def test_unowned_occurrences_are_counted_and_named(tmp_path):
    r = scan_directory(_tree(tmp_path))
    block = r["codeowners"]["unowned"]
    assert block["count"] == 1 and block["paths"] == ["util.py"]
    md5 = [e for e in r["evidence"]["source_code"] if e["path"] == "util.py"][0]
    assert md5["unowned_by"] == ".github/CODEOWNERS" and "owners" not in md5
    rsa = [e for e in r["evidence"]["source_code"] if e["path"] == "payments/sign.py"][0]
    assert "unowned_by" not in rsa


def test_no_codeowners_no_claim(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "util.py").write_text("import hashlib\nh = hashlib.md5(b'x').hexdigest()\n")
    r = scan_directory(t)
    assert r["codeowners"] is None
    assert all("unowned_by" not in e for e in r["evidence"]["source_code"])


def test_the_cbom_says_none(tmp_path):
    out = tmp_path / "c.json"
    assert server.scan_to_file([str(_tree(tmp_path)), "--out", str(out)], cbom=True) == 0
    contexts = [o["additionalContext"] for c in json.loads(out.read_text())["components"]
                for o in c.get("evidence", {}).get("occurrences", []) if o["location"] == "util.py"]
    assert contexts and all("[owners: none per .github/CODEOWNERS]" in x for x in contexts)
