"""`--mandate cnsa-2.0|nist-ir-8547`: each occurrence gets the dated clause that applies to it.

NIST IR 8547 ipd (November 2024), section 4.1.1 Table 2 and section 4.1.2 Table 4: at 112 bits
of security strength deprecated after 2030 and disallowed after 2035; at 128 bits and more
disallowed after 2035. Lines 508-511 name "harvest now, decrypt later" for key establishment.

NSA CNSA 2.0 advisory (PP-22-1338, Sep 2022 Ver. 1.0), "Other requirements for NSS": software
and firmware signing and traditional networking equipment exclusively CNSA 2.0 by 2030; web
browsers/servers and cloud services, operating systems, niche equipment by 2033; custom
applications and legacy equipment updated or replaced by 2033.

`--lead-months N` makes the run exit 1 when a deadline falls within N months; a deadline
already passed exits 1 without it. Suppressed rows are listed and do not trip it.
"""

import json
from datetime import date

import pytest

from qrp_mcp import mandates, server
from qrp_mcp.scan import scan_directory

AS_OF = date(2026, 10, 25)
APP = ("from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, ed25519\n"
       "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
       "k3 = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
       "s = ec.generate_private_key(ec.SECP384R1()).exchange(ec.ECDH(), peer)\n"
       "x = x25519.X25519PrivateKey.generate()\n"
       "e = ed25519.Ed25519PrivateKey.generate()\n"
       "h = hashlib.md5(b\"x\")\n")


@pytest.fixture()
def tree(tmp_path):
    t = tmp_path / "repo"
    (t / ".github" / "workflows").mkdir(parents=True)
    (t / "etc" / "nginx").mkdir(parents=True)
    (t / "etc" / "ipsec").mkdir(parents=True)
    (t / "app.py").write_text(APP)
    (t / ".github" / "workflows" / "release.yml").write_text(
        "on: push\njobs:\n  sign:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: openssl dgst -sha256 -sign release-rsa.pem -out a.sig a.tgz\n")
    (t / "etc" / "nginx" / "nginx.conf").write_text(
        "server {\n    ssl_ecdh_curve secp384r1;\n}\n")
    (t / "etc" / "ipsec" / "swanctl.conf").write_text(
        "connections {\n  site {\n    proposals = aes256-sha384-ecp384\n  }\n}\n")
    return t


def _annotated(tree, *names):
    r = scan_directory(tree)
    mandates.apply(r, list(names), AS_OF, lead_months=0)
    return r


def _row(r, path, line, alg, kind="source_code"):
    return next(e for e in r["evidence"][kind]
                if e["path"] == path and e["line"] == line and e.get("algorithm") == alg)


def test_nist_ir_8547_by_security_strength(tree):
    r = _annotated(tree, "nist-ir-8547")
    rsa2048 = _row(r, "app.py", 2, "RSA")["mandates"]["nist-ir-8547"]
    assert rsa2048["deprecated_after"] == "2030-12-31"
    assert rsa2048["disallowed_after"] == rsa2048["deadline"] == "2035-12-31"
    assert rsa2048["strength"] == "112 bits"
    assert rsa2048["status"] == "due"
    assert "Table" in rsa2048["source"] and "8547" in rsa2048["source"]
    rsa3072 = _row(r, "app.py", 3, "RSA")["mandates"]["nist-ir-8547"]
    assert "deprecated_after" not in rsa3072 and rsa3072["deadline"] == "2035-12-31"
    ed = _row(r, "app.py", 6, "Ed25519")["mandates"]["nist-ir-8547"]
    assert ed["deadline"] == "2035-12-31" and "EdDSA" in ed["clause"]


def test_strength_not_read_is_said_to_be_conditional(tree):
    r = _annotated(tree, "nist-ir-8547")
    x = _row(r, "app.py", 5, "X25519")["mandates"]["nist-ir-8547"]
    assert x["strength"] == "not determined"
    assert x["deprecated_after"] == "2030-12-31" and x["conditional"]
    # A NIST curve named on the line gives the strength.
    ecdh = _row(r, "app.py", 4, "ECDH")["mandates"]["nist-ir-8547"]
    assert ecdh["strength"] == "128 bits or more" and "deprecated_after" not in ecdh


def test_cnsa_clause_follows_the_system_class(tree):
    r = _annotated(tree, "cnsa-2.0")
    sign = r["evidence"]["ci_pipeline"][0]["mandates"]["cnsa-2.0"]
    assert sign["deadline"] == "2030-12-31" and "signing" in sign["clause"]
    vpn = _row(r, "etc/ipsec/swanctl.conf", 3, "EC")["mandates"]["cnsa-2.0"]
    assert vpn["deadline"] == "2030-12-31" and "networking" in vpn["clause"]
    web = _row(r, "etc/nginx/nginx.conf", 2, "EC")["mandates"]["cnsa-2.0"]
    assert web["deadline"] == "2033-12-31" and "Web" in web["clause"]
    app = _row(r, "app.py", 2, "RSA")["mandates"]["cnsa-2.0"]
    assert app["deadline"] == "2033-12-31" and "Custom applications" in app["clause"]


def test_hndl_only_for_key_establishment(tree):
    r = _annotated(tree, "nist-ir-8547")
    assert _row(r, "app.py", 4, "ECDH")["hndl_exposed"] is True
    assert _row(r, "app.py", 5, "X25519")["hndl_exposed"] is True
    assert _row(r, "app.py", 6, "Ed25519")["hndl_exposed"] is False
    assert r["mandates"]["nist-ir-8547"]["hndl_exposed"] >= 2


def test_a_weak_hash_is_not_in_scope(tree):
    r = _annotated(tree, "nist-ir-8547")
    md5 = [e for e in r["evidence"]["source_code"] if e.get("algorithm") == "MD5"]
    assert md5 and all("mandates" not in e for e in md5)
    assert r["mandates"]["nist-ir-8547"]["not_in_scope"] >= 1


def test_summary_block(tree):
    r = _annotated(tree, "nist-ir-8547", "cnsa-2.0")
    m = r["mandates"]["cnsa-2.0"]
    assert m["as_of"] == "2026-10-25" and m["next_deadline"] == "2030-12-31"
    assert m["document"].startswith("NSA") and m["url"]
    assert m["new_products"]["from"] == "2027-01-01"
    assert r["mandates"]["nist-ir-8547"]["next_deadline"] == "2030-12-31"


def test_status_after_the_dates(tree):
    r = scan_directory(tree)
    mandates.apply(r, ["nist-ir-8547"], date(2031, 6, 1), lead_months=0)
    assert _row(r, "app.py", 2, "RSA")["mandates"]["nist-ir-8547"]["status"] == "deprecated"
    r = scan_directory(tree)
    mandates.apply(r, ["nist-ir-8547"], date(2036, 1, 1), lead_months=0)
    assert _row(r, "app.py", 2, "RSA")["mandates"]["nist-ir-8547"]["status"] == "disallowed"


@pytest.mark.parametrize("args, code", [
    (["--lead-months", "120"], 1),
    (["--lead-months", "1"], 0),
    ([], 0),
    (["--as-of", "2036-01-01"], 1),
])
def test_deadline_gate_exit_code(tree, tmp_path, args, code):
    out = tmp_path / "r.json"
    argv = [str(tree), "--mandate", "nist-ir-8547", "--as-of", "2026-10-25", *args,
            "--out", str(out)]
    assert server.scan_to_file(argv) == code
    r = json.loads(out.read_text())
    assert r["mandates"]["nist-ir-8547"]["gate"] == ("fail" if code else "pass")


def test_suppressed_rows_do_not_trip_the_gate(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)"
        "  # qrp:ignore RSA retired with the HSM in 2027\n")
    assert server.scan_to_file([str(t), "--mandate", "nist-ir-8547", "--lead-months", "200",
                                "--out", str(tmp_path / "r.json")]) == 0


def test_unknown_mandate_is_rejected(tree):
    with pytest.raises(SystemExit) as e:
        server.scan_to_file([str(tree), "--mandate", "fips-140"])
    assert e.value.code == 2
