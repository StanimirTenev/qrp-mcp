"""An inline suppression can carry an expiry date and an owner (fix list row 221).

    # qrp:ignore-next-line RSA until=2027-06-30 owner=j.doe HSM firmware 4.2, no ML-DSA

`until=` and `owner=` may stand anywhere after the family; they are taken out of the reason.
Until the end of the `until` day the marker suppresses as before, and the suppression names
its date and owner. After it, the marker no longer suppresses: the occurrence is back in
`evidence` and the marker is in `markers_not_applied` with "expired on <date>". A `until=`
that is not a calendar date does not apply either, and says so.

A reason that calls itself temporary ("temporary", "for now", "interim") without a `until=`
date still applies, and is listed in `markers_flagged`: it cannot expire, so nothing will
ever bring it back.

Found by probing 0.40.1: `# qrp:ignore-next-line RSA temporary` was accepted with a one-word
reason, and the format had no way to give a date or an owner.
"""

import json

from qrp_mcp import cyclonedx, server
from qrp_mcp.scan import scan_directory

IMPORT = "from cryptography.hazmat.primitives.asymmetric import rsa\n"
KEYGEN = "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"


def _scan(tmp_path, marker):
    (tmp_path / "legacy_hsm.py").write_text(IMPORT + "\n" + marker + "\n" + KEYGEN)
    return scan_directory(tmp_path)


def _sarif_notes(tmp_path):
    """The way a CI run reads it: `qrp-mcp scan --format sarif`."""
    out = tmp_path.parent / (tmp_path.name + ".sarif")
    server.scan_to_file([str(tmp_path), "--no-config", "--format", "sarif", "--out", str(out)])
    return json.loads(out.read_text())["runs"][0]["invocations"][0]["toolExecutionNotifications"]


def _rsa_on_line_4(result):
    return any(e["path"] == "legacy_hsm.py" and e["line"] == 4 and e["algorithm"] == "RSA"
               for e in result["evidence"]["source_code"])


def test_a_date_to_come_suppresses_and_carries_date_and_owner(tmp_path):
    r = _scan(tmp_path, "# qrp:ignore-next-line RSA until=2999-12-31 owner=j.doe "
                        "HSM firmware 4.2 cannot do ML-DSA")
    assert not _rsa_on_line_4(r)
    item = r["suppressed"]["evidence"]["source_code"][0]
    assert item["suppression"] == {
        "family": "RSA", "reason": "HSM firmware 4.2 cannot do ML-DSA",
        "form": "qrp:ignore-next-line", "marker_line": 3,
        "until": "2999-12-31", "owner": "j.doe"}
    cov = r["coverage"]["suppressed"]["items"][0]
    assert cov["until"] == "2999-12-31" and cov["owner"] == "j.doe"
    props = {p["name"]: p["value"] for p in cyclonedx.build(r)["properties"]}
    assert props["qrp:coverage:suppressed:items:0:until"] == "2999-12-31"
    assert props["qrp:coverage:suppressed:items:0:owner"] == "j.doe"


def test_an_expired_marker_stops_suppressing_and_says_so(tmp_path):
    r = _scan(tmp_path, "# qrp:ignore-next-line RSA owner=j.doe until=2001-01-31 "
                        "replaced in Q3")
    assert _rsa_on_line_4(r)
    assert r["suppressed"]["count"] == 0
    assert r["suppressed"]["markers_not_applied"] == [{
        "path": "legacy_hsm.py", "line": 3, "form": "qrp:ignore-next-line", "family": "RSA",
        "until": "2001-01-31", "owner": "j.doe",
        "why": "expired on 2001-01-31: the occurrence is in evidence again"}]
    assert r["coverage"]["suppressed"]["markers_not_applied"]["count"] == 1
    notes = _sarif_notes(tmp_path)
    expired = [n for n in notes if "expired on 2001-01-31" in n["message"]["text"]]
    assert expired and expired[0]["locations"][0]["physicalLocation"]["region"][
        "startLine"] == 3


def test_a_date_that_is_not_a_date_does_not_apply(tmp_path):
    r = _scan(tmp_path, "# qrp:ignore-next-line RSA until=2027-02-30 vendor interop")
    assert _rsa_on_line_4(r)
    assert r["suppressed"]["markers_not_applied"][0]["why"] == (
        "until=2027-02-30 is not a date (YYYY-MM-DD)")


def test_temporary_without_a_date_is_flagged_as_unable_to_expire(tmp_path):
    # The probe's line: a one-word reason that promises an end it never gives.
    r = _scan(tmp_path, "# qrp:ignore-next-line RSA temporary")
    assert not _rsa_on_line_4(r)
    flagged = r["suppressed"]["markers_flagged"]
    assert flagged == [{"path": "legacy_hsm.py", "line": 3, "form": "qrp:ignore-next-line",
                        "family": "RSA", "why": "the reason says it is temporary and gives "
                        "no until= date: it cannot expire"}]
    assert r["coverage"]["suppressed"]["markers_flagged"]["count"] == 1
    notes = _sarif_notes(tmp_path)
    assert any("cannot expire" in n["message"]["text"] for n in notes)


def test_temporary_with_a_date_is_not_flagged(tmp_path):
    r = _scan(tmp_path, "# qrp:ignore-next-line RSA until=2999-01-01 temporary, ticket 41")
    assert r["suppressed"]["count"] == 1
    assert r["suppressed"]["markers_flagged"] == []


def test_an_expired_marker_over_nothing_does_not_claim_an_occurrence(tmp_path):
    (tmp_path / "a.py").write_text("# qrp:ignore-next-line RSA until=2001-01-31 old\nx = 1\n")
    r = scan_directory(tmp_path)
    assert r["suppressed"]["markers_not_applied"][0]["why"] == (
        "expired on 2001-01-31; no RSA occurrence on line 2")
