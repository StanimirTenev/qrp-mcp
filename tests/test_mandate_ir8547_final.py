"""`--mandate nist-ir-8547` by the final NIST IR 8547 (October 2026), not the November 2024 draft.

ZA-OPRAVYANE row 168: the draft's Tables 2 and 4 deprecated only the 112-bit rows after 2030;
the final deprecates every quantum-vulnerable signature and key-establishment scheme after
2030 and disallows it after 2035, whatever its strength (section 4.1.1, Table 2; section
4.1.2, Table 4). RSA-3072, P-256 and Ed25519 got "disallowed after 2035" and nothing before.

Row 171: X25519's strength is fixed by its name (128 bits; X448 224), yet was "not determined".

Rows 170 + 177: section 3.2.1 allows a composite (hybrid) key establishment even when one input
comes from a disallowed algorithm. The classical half of `X25519MLKEM768` was dated and called
HNDL-exposed like a bare X25519. The fallback in `X25519MLKEM768:X25519` is a group offered on
its own and keeps its dates: each group in the list is dated, not the line.

Row 160: `next_deadline` said 2030-12-31 while the gate counted 2035-12-31 and passed. The block
now names the date the gate counts beside the earliest date.
"""

from datetime import date

import pytest

from qrp_mcp import mandates
from qrp_mcp.scan import scan_directory

AS_OF = date(2026, 10, 30)
KEYS = ("from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519\n"
        "a = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
        "b = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
        "c = ec.generate_private_key(ec.SECP256R1())\n"
        "d = ed25519.Ed25519PrivateKey.generate()\n")


def _scan(tmp_path, files, lead=0, day=AS_OF):
    t = tmp_path / "repo"
    t.mkdir()
    for name, text in files.items():
        (t / name).write_text(text)
    r = scan_directory(t)
    failed = mandates.apply(r, ["nist-ir-8547"], day, lead_months=lead)
    return r, failed


def _rows(r, path, line, family):
    return [e for kind in r["evidence"].values() for e in kind
            if isinstance(e, dict) and e.get("path") == path and e.get("line") == line
            and (e.get("algorithm") or e.get("family")) == family]


def test_every_vulnerable_key_is_deprecated_after_2030(tmp_path):
    r, _ = _scan(tmp_path, {"keys.py": KEYS})
    for line, family in ((2, "RSA"), (3, "RSA"), (4, "EC"), (5, "Ed25519")):
        clause = _rows(r, "keys.py", line, family)[0]["mandates"]["nist-ir-8547"]
        assert clause["deprecated_after"] == "2030-12-31", (line, family, clause)
        assert clause["disallowed_after"] == "2035-12-31"
        assert "conditional" not in clause
    block = r["mandates"]["nist-ir-8547"]
    assert "ipd" not in block["document"] and "Draft" not in block["document"]
    assert "October 2026" in block["document"]
    assert block["url"] == "https://doi.org/10.6028/NIST.IR.8547"


def test_x25519_strength_from_its_name(tmp_path):
    r, _ = _scan(tmp_path, {"tls.py": 'import ssl\nctx = ssl.create_default_context()\n'
                                      'ctx.set_ecdh_curve("X25519")\n'})
    clauses = [e["mandates"]["nist-ir-8547"] for e in _rows(r, "tls.py", 3, "X25519")]
    assert clauses and all(c["strength"] == "128 bits or more" for c in clauses)


def test_hybrid_half_is_a_composite_not_a_bare_x25519(tmp_path):
    r, _ = _scan(tmp_path, {"nginx.conf": "server {\n    listen 443 ssl;\n"
                                          "    ssl_ecdh_curve X25519MLKEM768;\n}\n"})
    halves = _rows(r, "nginx.conf", 3, "X25519")
    assert halves
    for row in halves:
        clause = row["mandates"]["nist-ir-8547"]
        assert clause["status"] == "composite_allowed"
        assert "3.2.1" in clause["source"] and "deadline" not in clause
        assert row["hndl_exposed"] is False
    block = r["mandates"]["nist-ir-8547"]
    assert block["composite"] >= 1 and block["hndl_exposed"] == 0


def test_fallback_group_beside_the_hybrid_keeps_its_dates(tmp_path):
    r, _ = _scan(tmp_path, {"nginx.conf": "server {\n    listen 443 ssl;\n"
                                          "    ssl_ecdh_curve X25519MLKEM768:X25519;\n}\n"})
    alone = [e for e in r["evidence"]["tls_groups"]
             if e["path"] == "nginx.conf" and e["line"] == 3 and e.get("offered") == "alone"]
    assert alone, "the standalone X25519 must stay a row of its own"
    clause = alone[0]["mandates"]["nist-ir-8547"]
    assert clause["deadline"] == "2035-12-31" and clause["status"] == "due"
    assert alone[0]["hndl_exposed"] is True
    assert r["mandates"]["nist-ir-8547"]["hndl_exposed"] >= 1


def test_block_names_the_date_the_gate_counts(tmp_path):
    r, failed = _scan(tmp_path, {"keys.py": KEYS}, lead=60, day=date(2026, 10, 28))
    block = r["mandates"]["nist-ir-8547"]
    assert block["next_deadline"] == "2030-12-31"
    assert block["gate_counts"] == "disallowed_after"
    assert block["next_gate_deadline"] == "2035-12-31"
    assert block["gate"] == "pass" and not failed


@pytest.mark.parametrize("lead, gate", [(110, "pass"), (111, "fail")])
def test_gate_still_counts_disallowance(tmp_path, lead, gate):
    # 2026-10-30 + 110 months = 2035-12-30 (before 2035-12-31); + 111 months reaches it.
    r, failed = _scan(tmp_path, {"keys.py": KEYS}, lead=lead)
    assert r["mandates"]["nist-ir-8547"]["gate"] == gate and failed == (gate == "fail")
