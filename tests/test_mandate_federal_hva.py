"""ZA-OPRAVYANE row 493: the federal dates by role that NIST IR 8547 (final) restates from
EO 14412 / OMB M-26-15, beside the general dates and without moving them.

Probe `linkedin-postove/2026-11-15/ir8547-proba/` (0.46.0, `--mandate nist-ir-8547`): an RSA-3072
signature and a P-256 ECDH exchange both read "deprecated after 2030-12-31", which the final
text says (section 4.1.1, Table 2; section 4.1.2, Table 4). The same text, section 4, says
federal high value assets and high impact systems "must adopt post-quantum cryptography for key
establishment by December 31, 2030, and for digital signatures by December 31, 2031": a date by
role that was not in the result. It applies only to such systems, which a scan cannot see, so
it is said as a condition and the gate does not count it.
"""

import copy
import json
from datetime import date

from qrp_mcp import mandates, server
from qrp_mcp.scan import scan_directory

PROBE = ("from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding\n"
         "from cryptography.hazmat.primitives import hashes\n"
         "signing_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
         "sig = signing_key.sign(b\"doc\", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), "
         "salt_length=32), hashes.SHA256())\n"
         "kex = ec.generate_private_key(ec.SECP256R1())\n"
         "shared = kex.exchange(ec.ECDH(), ec.generate_private_key(ec.SECP256R1()).public_key())\n")
AS_OF = "2026-11-15"


def _tree(tmp_path):
    t = tmp_path / "repo"
    t.mkdir()
    (t / "app.py").write_text(PROBE)
    return t


def _clauses(r):
    return {(e["line"], e.get("role")): e["mandates"]["nist-ir-8547"]
            for kind in r["evidence"].values() for e in kind
            if isinstance(e, dict) and "nist-ir-8547" in (e.get("mandates") or {})}


def test_federal_date_by_role_through_the_cli(tmp_path):
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(_tree(tmp_path)), "--mandate", "nist-ir-8547",
                                "--as-of", AS_OF, "--out", str(out)]) == 0
    r = json.loads(out.read_text())
    clauses = _clauses(r)
    sign = next(c for (line, role), c in clauses.items() if line == 4 and role == "signature")
    kex = next(c for (line, role), c in clauses.items()
               if line == 6 and role == "key_establishment")
    for clause, by in ((sign, "2031-12-31"), (kex, "2030-12-31")):
        fed = clause["federal_high_value_assets"]
        assert fed["pqc_by"] == by
        assert "only if" in fed["applies"] and "high impact" in fed["applies"]
        assert "OMB M-26-15" in fed["source"] and "section 4" in fed["source"]
        # The general dates are unchanged.
        assert clause["deprecated_after"] == "2030-12-31"
        assert clause["disallowed_after"] == clause["deadline"] == "2035-12-31"
    block = r["mandates"]["nist-ir-8547"]["federal_high_value_assets"]
    assert block["key_establishment"] == "2030-12-31"
    assert block["signature"] == "2031-12-31"
    assert block["counted_by_gate"] is False


def test_role_not_determined_gives_both_dates(tmp_path):
    t = _tree(tmp_path)
    (t / "keys.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n"
                               "k = rsa.generate_private_key(public_exponent=65537, "
                               "key_size=3072)\n")
    r = scan_directory(t)
    mandates.apply(r, ["nist-ir-8547"], date.fromisoformat(AS_OF))
    und = [c for (line, role), c in _clauses(r).items() if role == "undetermined"]
    assert und
    for clause in und:
        fed = clause["federal_high_value_assets"]
        assert "pqc_by" not in fed
        assert fed["pqc_by_role"] == {"key_establishment": "2030-12-31",
                                      "signature": "2031-12-31"}


def test_the_gate_does_not_count_the_federal_dates(tmp_path):
    t = _tree(tmp_path)
    day = date.fromisoformat(AS_OF)
    for lead in (0, 49, 50, 200):
        r = scan_directory(t)
        failed = mandates.apply(r, ["nist-ir-8547"], day, lead_months=lead)
        block = copy.deepcopy(r["mandates"]["nist-ir-8547"])
        block.pop("federal_high_value_assets")
        assert block["next_gate_deadline"] == "2030-12-31"
        assert block["next_deadline"] == "2030-12-31"
        # 2030-12-31 is 49 months from 2026-11-15: the gate trips on the deprecation only.
        assert failed is (lead >= 50), (lead, block["within_lead"])
