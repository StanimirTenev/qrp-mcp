"""`--mandate eu-pqc-roadmap|uk-ncsc|ca-cccs|au-ism|de-bsi` (0.48.0): the deadlines of other
jurisdictions, each quoted from its own document (profiles.DATED_MANDATES), and the warning
when the reading of a document is old.

- EU, NIS Cooperation Group roadmap v1.1 (11.06.2025): quantum-vulnerable public-key mechanisms
  not stand-alone after the end of 2035 for medium-risk use cases; high-risk ones by the end of
  2030 -- a class the scan cannot see, so said and not counted.
- UK, NCSC timelines v1.0 (20.03.2025): all systems by 2035; highest-priority by 2031 (said).
- Canada, ITSP.40.111 v5: each classical scheme without a post-quantum one phased out by the
  end of 2035; DSA, P-224 and RSA/FFC below 3072 bits by the end of 2030.
- Australia, ISM September 2026: DH, ECDH, ECDSA and RSA not approved beyond 2030; ML-KEM-768
  and ML-DSA-65 likewise; EdDSA not an approved algorithm at all (no date).
- Germany, BSI TR-02102-1 2026-01: classical key agreement alone until the end of 2031,
  classical signatures until the end of 2035.
"""

import json
import subprocess
import sys
from datetime import date

import pytest

from qrp_mcp import mandates, server
from qrp_mcp.scan import scan_directory

AS_OF = date(2026, 11, 17)
APP = ("from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, ed25519, dsa\n"
       "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
       "k3 = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
       "s = ec.generate_private_key(ec.SECP384R1()).exchange(ec.ECDH(), peer)\n"
       "x = x25519.X25519PrivateKey.generate()\n"
       "e = ed25519.Ed25519PrivateKey.generate()\n"
       "d = dsa.generate_private_key(key_size=3072)\n")
NEW = ("eu-pqc-roadmap", "uk-ncsc", "ca-cccs", "au-ism", "de-bsi", "nl-rqs", "se-ncsc",
       "jp-gov", "sg-csa-cii", "in-dst")


@pytest.fixture()
def tree(tmp_path):
    t = tmp_path / "repo"
    (t / ".github" / "workflows").mkdir(parents=True)
    t.mkdir(exist_ok=True)
    (t / "app.py").write_text(APP)
    (t / ".github" / "workflows" / "release.yml").write_text(
        "on: push\njobs:\n  sign:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: openssl dgst -sha256 -sign release-rsa.pem -out a.sig a.tgz\n")
    return t


def _annotated(tree, *names, day=AS_OF, lead=0):
    r = scan_directory(tree)
    mandates.apply(r, list(names), day, lead_months=lead)
    return r


def _row(r, line, alg, path="app.py"):
    return next(e for e in r["evidence"]["source_code"]
                if e["path"] == path and e["line"] == line and e.get("algorithm") == alg)


def test_every_new_mandate_is_offered_with_its_document():
    for name in NEW:
        m = mandates.MANDATES[name]
        assert m["url"].startswith("https://") and m["read_on"] and m["document"]
        for rule in m["rules"]:
            assert rule["deadline"] and rule["clause"] and rule["source"]


def test_eu_counts_2035_and_says_2030_for_high_risk(tree):
    r = _annotated(tree, "eu-pqc-roadmap")
    c = _row(r, 2, "RSA")["mandates"]["eu-pqc-roadmap"]
    assert c["deadline"] == "2035-12-31" and c["status"] == "due"
    assert "stand-alone" in c["clause"] and "medium-risk" in c["clause"]
    assert [e["date"] for e in c["earlier_if"]] == ["2030-12-31", "2030-12-31"]
    assert "high-risk" in c["earlier_if"][0]["if"]
    b = r["mandates"]["eu-pqc-roadmap"]
    assert b["gate_counts"] == "deadline" and b["next_gate_deadline"] == "2035-12-31"
    assert all(c["counted_by_gate"] is False for c in b["conditional"])
    assert b["milestones"][0]["date"] == "2026-12-31"
    # The firmware-upgrade date is for signatures, not for a key exchange.
    x = _row(r, 5, "X25519")["mandates"]["eu-pqc-roadmap"]
    assert [e["clause"] for e in x["earlier_if"]] == [
        "for high-risk use cases, quantum-vulnerable public-key mechanisms shall not be used "
        "stand-alone after the end of 2030"]


def test_eu_gate_does_not_count_the_high_risk_date(tree):
    # 49 months to 2030-12-31: a lead of 60 months would trip a gate that counted it.
    r = _annotated(tree, "eu-pqc-roadmap", lead=60)
    assert r["mandates"]["eu-pqc-roadmap"]["gate"] == "pass"
    r = _annotated(tree, "eu-pqc-roadmap", lead=110)
    assert r["mandates"]["eu-pqc-roadmap"]["gate"] == "fail"


def test_uk_2035_with_2031_said(tree):
    r = _annotated(tree, "uk-ncsc")
    c = _row(r, 6, "Ed25519")["mandates"]["uk-ncsc"]
    assert c["deadline"] == "2035-12-31" and "all your systems" in c["clause"]
    assert c["earlier_if"][0]["date"] == "2031-12-31"
    assert r["mandates"]["uk-ncsc"]["milestones"][0]["date"] == "2028-12-31"


def test_canada_by_algorithm_and_key_size(tree):
    r = _annotated(tree, "ca-cccs")
    rsa2048 = _row(r, 2, "RSA")["mandates"]["ca-cccs"]
    assert rsa2048["deadline"] == "2030-12-31" and "3072 bits" in rsa2048["clause"]
    assert [a["deadline"] for a in rsa2048["also"]] and all(
        a["deadline"] == "2035-12-31" for a in rsa2048["also"])
    rsa3072 = _row(r, 3, "RSA")["mandates"]["ca-cccs"]
    assert rsa3072["deadline"] == "2035-12-31" and "3072" not in rsa3072["clause"]
    assert "without a post-quantum" in rsa3072["clause"]
    ed = _row(r, 6, "Ed25519")["mandates"]["ca-cccs"]
    assert ed["deadline"] == "2035-12-31" and "EdDSA" in ed["clause"]
    assert "6.4" in ed["source"]
    # Section 5.3's curves are P-224 to P-521: X25519 is not among them.
    x = _row(r, 5, "X25519")["mandates"]["ca-cccs"]
    assert x["status"] == "not_in_document" and "deadline" not in x
    ecdh = _row(r, 4, "ECDH")["mandates"]["ca-cccs"]
    assert ecdh["deadline"] == "2035-12-31" and "ECC CDH" in ecdh["clause"]
    dsa = _row(r, 7, "DSA")["mandates"]["ca-cccs"]
    assert dsa["deadline"] == "2030-12-31" and "DSA" in dsa["clause"]
    b = r["mandates"]["ca-cccs"]
    assert len(b["sources"]) == 2 and b["conditional"][0]["date"] == "2031-12-31"


def test_australia_2030_and_edDSA_not_approved(tree):
    r = _annotated(tree, "au-ism")
    for line, alg in ((2, "RSA"), (4, "ECDH"), (5, "X25519")):
        c = _row(r, line, alg)["mandates"]["au-ism"]
        assert c["deadline"] == "2030-12-31" and "not be approved beyond 2030" in c["clause"]
    ed = _row(r, 6, "Ed25519")["mandates"]["au-ism"]
    assert ed["status"] == "not_in_document" and "deadline" not in ed
    assert r["mandates"]["au-ism"]["by_status"]["not_in_document"] >= 1


def test_australia_dates_ml_kem_768_and_the_gate_counts_it(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    (t / "kem.py").write_text('import oqs\nk = oqs.KeyEncapsulation("ML-KEM-768")\n')
    r = scan_directory(t)
    failed = mandates.apply(r, ["au-ism"], AS_OF, lead_months=60)
    row = next(e for e in r["evidence"]["source_code"] if e.get("algorithm") == "ML-KEM")
    c = row["mandates"]["au-ism"]
    assert c["deadline"] == "2030-12-31" and "ML-KEM-768" in c["clause"]
    assert failed and r["mandates"]["au-ism"]["gate"] == "fail"
    r = scan_directory(t)
    assert not mandates.apply(r, ["au-ism"], AS_OF, lead_months=12)


def test_germany_by_role(tree):
    r = _annotated(tree, "de-bsi")
    kex = _row(r, 5, "X25519")["mandates"]["de-bsi"]
    assert kex["deadline"] == "2031-12-31" and "key agreement" in kex["clause"]
    assert kex["earlier_if"][0]["date"] == "2030-12-31"
    sig = _row(r, 6, "Ed25519")["mandates"]["de-bsi"]
    assert sig["deadline"] == "2035-12-31" and "signature" in sig["clause"]
    # The very-high-protection date of TR-02102-1 is for key agreement only; the Leitlinie's
    # high-risk date is for every use case.
    assert [e["clause"][:28] for e in sig["earlier_if"]] == ["Anwendungsfälle mit hohem Ri"]
    assert r["mandates"]["de-bsi"]["milestones"][0]["date"] == "2026-12-31"
    assert len(r["mandates"]["de-bsi"]["sources"]) == 2


def test_a_signing_step_whose_key_is_not_read_is_not_dated(tree):
    # `openssl dgst -sign release-rsa.pem`: the key's family is not on the line. CNSA 2.0 dates
    # signing as a class; the dated documents date families, and "*" is any quantum-vulnerable
    # one -- not an unknown key, nor an ML-DSA one.
    r = _annotated(tree, "de-bsi", "eu-pqc-roadmap", "au-ism", "ca-cccs", "cnsa-2.0")
    sign = r["evidence"]["ci_pipeline"][0]
    assert set(sign["mandates"]) == {"cnsa-2.0"}
    assert r["mandates"]["au-ism"]["by_status"].get("not_in_document", 0) == 2  # Ed25519, DSA


def test_role_not_determined_takes_the_earlier_and_says_so(tree):
    r = _annotated(tree, "de-bsi")
    rsa = _row(r, 3, "RSA")
    assert rsa["hndl_exposed"] == "not determined"
    c = rsa["mandates"]["de-bsi"]
    assert c["deadline"] == "2031-12-31" and "both apply" in c["note"]
    assert [a["deadline"] for a in c["also"]] == ["2035-12-31"]


@pytest.mark.parametrize("name", ["eu-pqc-roadmap", "ca-cccs", "au-ism", "de-bsi", "in-dst"])
def test_classical_half_of_a_hybrid_is_not_dated(tmp_path, name):
    t = tmp_path / "t"
    t.mkdir()
    (t / "nginx.conf").write_text("server {\n    ssl_ecdh_curve X25519MLKEM768;\n}\n")
    (t / "app.c").write_text('const char *g = "X25519MLKEM768";\n')
    r = scan_directory(t)
    mandates.apply(r, [name], AS_OF, lead_months=0)
    clauses = [e["mandates"][name] for e in r["evidence"]["source_code"]
               if name in e.get("mandates", {})]
    halves = [c for c in clauses if c["status"] == "composite_allowed"]
    assert halves and all("deadline" not in c for c in halves)


def test_uk_says_it_does_not_address_the_classical_half(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    (t / "app.c").write_text('const char *g = "X25519MLKEM768";\n')
    r = scan_directory(t)
    mandates.apply(r, ["uk-ncsc"], AS_OF, lead_months=0)
    halves = [e["mandates"]["uk-ncsc"] for e in r["evidence"]["source_code"]
              if e.get("mandates", {}).get("uk-ncsc", {}).get("status")
              == "composite_not_addressed"]
    assert halves and all("deadline" not in c for c in halves)


# --- the staleness signal -------------------------------------------------------------------


def test_a_fresh_reading_is_not_stale(tree):
    r = _annotated(tree, *NEW, "nist-ir-8547", "cnsa-2.0")
    for name, b in r["mandates"].items():
        assert b["stale"] is False and "stale_because" not in b, name
        assert b["stale_after_days"] == mandates.STALE_AFTER_DAYS == 180


def test_an_old_reading_is_said_with_its_age(tree):
    day = date(2027, 6, 1)
    r = _annotated(tree, "uk-ncsc", "cnsa-2.0", day=day)
    uk = r["mandates"]["uk-ncsc"]
    age = (day - date.fromisoformat(mandates.MANDATES["uk-ncsc"]["read_on"])).days
    assert uk["read_on_age_days"] == age > 180 and uk["stale"] is True
    assert mandates.MANDATES["uk-ncsc"]["url"] in uk["stale_because"]
    assert r["mandates"]["cnsa-2.0"]["stale"] is True
    assert mandates.stale(r) == ["uk-ncsc", "cnsa-2.0"]


def test_the_threshold_is_exclusive(tree):
    read = date.fromisoformat(mandates.MANDATES["au-ism"]["read_on"])
    on = _annotated(tree, "au-ism", day=date.fromordinal(read.toordinal() + 180))
    assert on["mandates"]["au-ism"]["stale"] is False
    after = _annotated(tree, "au-ism", day=date.fromordinal(read.toordinal() + 181))
    assert after["mandates"]["au-ism"]["stale"] is True


def _cli(tree, tmp_path, *args):
    out = tmp_path / "r.json"
    p = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "scan", str(tree),
                        "--out", str(out), *args], capture_output=True, text=True)
    return p, out


def test_cli_warns_on_stderr_and_the_exit_code_is_unchanged(tree, tmp_path):
    p, out = _cli(tree, tmp_path, "--mandate", "eu-pqc-roadmap", "--as-of", "2027-12-01")
    assert p.returncode == 0
    assert "--mandate eu-pqc-roadmap" in p.stderr and "days before 2027-12-01" in p.stderr
    r = json.loads(out.read_text())
    assert r["mandates"]["eu-pqc-roadmap"]["stale"] is True
    assert r["mandates"]["eu-pqc-roadmap"]["gate"] in ("pass", "not_established")


def test_cli_fresh_reading_is_quiet(tree, tmp_path):
    p, out = _cli(tree, tmp_path, "--mandate", "eu-pqc-roadmap", "--mandate", "ca-cccs",
                  "--as-of", "2026-11-17")
    assert p.returncode == 0 and "--mandate" not in p.stderr
    r = json.loads(out.read_text())
    assert set(r["mandates"]) == {"eu-pqc-roadmap", "ca-cccs"}


@pytest.mark.parametrize("name, lead, code", [
    ("au-ism", 60, 1), ("au-ism", 12, 0),
    ("eu-pqc-roadmap", 60, 0), ("eu-pqc-roadmap", 120, 1),
    ("de-bsi", 62, 1), ("de-bsi", 60, 0),
])
def test_cli_gate_by_mandate(tree, tmp_path, name, lead, code):
    p, out = _cli(tree, tmp_path, "--mandate", name, "--as-of", "2026-11-17",
                  "--lead-months", str(lead))
    assert p.returncode == code, p.stderr
    r = json.loads(out.read_text())
    assert r["mandates"][name]["gate"] == ("fail" if code else "pass")


def test_sarif_carries_the_new_clause_and_the_staleness(tree, tmp_path):
    out = tmp_path / "r.sarif"
    assert server.scan_to_file([str(tree), "--mandate", "ca-cccs", "--as-of", "2027-12-01",
                                "--format", "sarif", "--out", str(out)]) == 0
    s = json.loads(out.read_text())
    run = s["runs"][0]
    text = json.dumps(run)
    assert "ITSP.40.111" in text and '"stale": true' in text


def test_config_file_accepts_a_new_mandate(tree, tmp_path):
    (tree / ".qrp.toml").write_text('mandate = ["de-bsi"]\n')
    out = tmp_path / "r.json"
    assert server.scan_to_file([str(tree), "--as-of", "2026-11-17", "--out", str(out)]) == 0
    assert "de-bsi" in json.loads(out.read_text())["mandates"]


def test_staleness_on_the_mandates_that_were_there(tree):
    # NIST IR 8547 was read on 2026-10-28: on 2027-06-01 that is 216 days.
    r = _annotated(tree, "nist-ir-8547", day=date(2027, 6, 1))
    b = r["mandates"]["nist-ir-8547"]
    assert b["read_on_age_days"] == 216 and b["stale"] is True
    r = _annotated(tree, "nist-ir-8547", day=date(2026, 11, 17))
    assert r["mandates"]["nist-ir-8547"]["stale"] is False


def test_netherlands_and_sweden_2035_with_2030_said(tree):
    r = _annotated(tree, "nl-rqs", "se-ncsc")
    nl = _row(r, 2, "RSA")["mandates"]["nl-rqs"]
    assert nl["deadline"] == "2035-12-31" and "gemiddeld risico" in nl["clause"]
    assert {e["date"] for e in nl["earlier_if"]} == {"2030-12-31"}
    assert [m["date"] for m in r["mandates"]["nl-rqs"]["milestones"]] == [
        "2026-12-31", "2027-12-31", "2028-12-31"]
    se = _row(r, 5, "X25519")["mandates"]["se-ncsc"]
    assert se["deadline"] == "2035-12-31" and "slutet av år 2035" in se["clause"]
    assert "tio år" in se["earlier_if"][0]["clause"]


def test_japan_singapore_india(tree):
    r = _annotated(tree, "jp-gov", "sg-csa-cii", "in-dst")
    row = _row(r, 2, "RSA")["mandates"]
    assert row["jp-gov"]["deadline"] == "2035-12-31" and "原則として" in row["jp-gov"]["clause"]
    assert row["sg-csa-cii"]["deadline"] == "2031-12-31"
    assert "CII" in r["mandates"]["sg-csa-cii"]["addresses"]
    assert row["in-dst"]["deadline"] == "2033-12-31"
    assert [e["date"] for e in row["in-dst"]["earlier_if"]] == ["2029-12-31", "2030-12-31"]
    assert r["mandates"]["in-dst"]["gate_counts"] == "deadline"


def test_p224_is_dated_2030_in_canada_and_p384_is_not(tmp_path):
    t = tmp_path / "t"
    t.mkdir()
    (t / "a.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "k = ec.generate_private_key(ec.SECP224R1())\n"
        "j = ec.generate_private_key(ec.SECP384R1())\n")
    r = scan_directory(t)
    mandates.apply(r, ["ca-cccs"], AS_OF, lead_months=0)
    by_line = {e["line"]: e["mandates"]["ca-cccs"] for e in r["evidence"]["source_code"]
               if "ca-cccs" in e.get("mandates", {})}
    assert by_line[2]["deadline"] == "2030-12-31" and "P-224" in by_line[2]["clause"]
    assert by_line[3]["deadline"] == "2035-12-31" and "P-224" not in by_line[3]["clause"]
