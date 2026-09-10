"""The emitted CBOM is checked against the real CycloneDX schema, not against a
reading of it. The schema files in tests/schema/ are the published ones, vendored
so the check runs offline and so the version it was checked against is pinned.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from qrp_mcp import coverage, cyclonedx
from qrp_mcp.scan import scan_directory

jsonschema = pytest.importorskip("jsonschema")

SCHEMA_DIR = Path(__file__).parent / "schema"


@pytest.fixture(scope="module")
def validator():
    schema = json.loads((SCHEMA_DIR / "bom-1.6.schema.json").read_text())
    store = {
        "http://cyclonedx.org/schema/spdx.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "spdx.schema.json").read_text()),
        "http://cyclonedx.org/schema/jsf-0.82.SNAPSHOT.schema.json":
            json.loads((SCHEMA_DIR / "jsf-0.82.schema.json").read_text()),
    }
    resolver = jsonschema.RefResolver.from_schema(schema, store=store)
    return jsonschema.Draft7Validator(schema, resolver=resolver)


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    """A small tree that is a real git checkout, so the pins have something to name."""
    root = tmp_path_factory.mktemp("corpus")
    (root / "app.py").write_text(
        "from Crypto.PublicKey import RSA\n"
        "import hashlib\n"
        "h = hashlib.md5(b'x')\n"
    )
    (root / "notes.md").write_text("not a claimed type\n")
    (root / "main.tf").write_text('resource "x" { algorithm = "ECDSA" }\n')
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"]):
        subprocess.run(["git", "-C", str(root), *args], check=True,
                       capture_output=True)
    return root


@pytest.fixture(scope="module")
def scan(corpus):
    return scan_directory(corpus)


@pytest.fixture(scope="module")
def document(scan):
    return cyclonedx.build(scan)


def test_document_validates_against_the_published_schema(validator, document):
    errors = sorted(validator.iter_errors(document), key=lambda e: e.path)
    assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)


def test_a_top_level_coverage_key_is_invalid(validator, document):
    """The reason the block travels in `properties`, asserted rather than assumed.

    If a future spec version admits a top-level key this test fails, which is the
    notification we want: the argument would have been answered.
    """
    with_key = dict(document, coverage={"files_present": 1})
    assert list(validator.iter_errors(with_key)), "root object accepted an unknown key"


def test_coverage_numbers_survive_the_flattening(scan, document):
    props = {p["name"]: p["value"] for p in document["properties"]}
    scope = scan["coverage"]["scope"]
    assert props["qrp:coverage:scope:files_present"] == str(scope["files_present"])
    assert props["qrp:coverage:scope:files_examined"] == str(scope["files_examined"])
    assert props["qrp:coverage:scope:files_not_examined"] == str(scope["files_not_examined"])
    assert props["qrp:coverage:scope:coverage_pct"] == str(scope["coverage_pct"])
    assert props["qrp:coverage:instrument:version"] == scan["coverage"]["instrument"]["version"]


def test_both_not_examined_reasons_stay_apart_including_the_empty_one(document):
    props = {p["name"]: p["value"] for p in document["properties"]}
    assert props["qrp:coverage:not_examined:0:reason"] == "type_not_claimed"
    assert props["qrp:coverage:not_examined:1:reason"] == "unreadable"
    # Zero is reported, not omitted: a reason with no instances is a checked
    # absence, and dropping it makes the document say less than the run knew.
    assert props["qrp:coverage:not_examined:1:count"] == "0"


def test_aggregate_is_incomplete_when_files_were_not_examined(scan, document):
    assert scan["coverage"]["scope"]["files_not_examined"] > 0
    assert document["compositions"][0]["aggregate"] == "incomplete"


def test_aggregate_is_complete_only_when_every_file_was_examined(scan):
    full = json.loads(json.dumps(scan))
    full["coverage"]["scope"]["files_not_examined"] = 0
    assert cyclonedx.build(full)["compositions"][0]["aggregate"] == "complete"


def test_aggregate_is_unknown_when_the_files_do_not_add_up(scan):
    broken = json.loads(json.dumps(scan))
    broken["coverage"]["accounts_for_every_file"] = False
    assert cyclonedx.build(broken)["compositions"][0]["aggregate"] == "unknown"


def test_assets_carry_file_and_line_evidence(document):
    located = [c for c in document["components"] if "evidence" in c]
    assert located, "no component carried an occurrence"
    for component in located:
        for occurrence in component["evidence"]["occurrences"]:
            assert occurrence["location"]
            assert occurrence["line"] >= 1


def test_rsa_is_a_public_key_primitive_and_md5_is_a_hash(document):
    primitive = {
        c["name"]: c["cryptoProperties"]["algorithmProperties"]["primitive"]
        for c in document["components"]
        if "algorithmProperties" in c["cryptoProperties"]
    }
    assert primitive["RSA"] == "pke"
    assert primitive["MD5"] == "hash"


def test_two_runs_of_the_same_code_over_the_same_corpus_share_a_serial(corpus):
    """The serial is a function of the run's conditions, not of the moment.

    Byte identity is deliberately not asserted: the window genuinely differs
    between two runs and a document claiming otherwise would be lying about when
    it read. What has to hold is that the identifier follows the instrument and
    the corpus, so a reader can tell two runs apart by their conditions rather
    than by their clocks.
    """
    first = cyclonedx.build(scan_directory(corpus))
    second = cyclonedx.build(scan_directory(corpus))
    assert first["serialNumber"] == second["serialNumber"]
    assert first["components"] == second["components"]
    assert first["compositions"] == second["compositions"]


def test_the_timestamp_comes_from_the_scan_window_not_from_the_clock(scan, document):
    assert document["metadata"]["timestamp"] == scan["coverage"]["window"]["started_at"]


def test_a_different_emitter_commit_changes_the_serial_number(scan):
    other = json.loads(json.dumps(scan))
    other["coverage"]["instrument"]["source_commit"]["commit"] = "0" * 40
    assert cyclonedx.build(other)["serialNumber"] != cyclonedx.build(scan)["serialNumber"]


def test_comparing_a_clean_run_with_itself_is_comparable(scan):
    block = json.loads(json.dumps(scan["coverage"]))
    block["corpus"]["pinned_at"]["dirty"] = False
    assert coverage.compare(block, block)["verdict"] == "comparable"


def test_a_changed_emitter_commit_is_not_comparable_at_the_same_version(scan):
    first = json.loads(json.dumps(scan["coverage"]))
    first["corpus"]["pinned_at"]["dirty"] = False
    second = json.loads(json.dumps(first))
    second["instrument"]["source_commit"]["commit"] = "0" * 40
    result = coverage.compare(first, second)
    assert result["verdict"] == "not_comparable"
    assert result["differences"][0]["reason"] == "instrument_commit_differs"
    assert first["instrument"]["version"] == second["instrument"]["version"]


def test_an_unpinned_emitter_leaves_comparability_unestablished(scan):
    first = json.loads(json.dumps(scan["coverage"]))
    first["corpus"]["pinned_at"]["dirty"] = False
    second = json.loads(json.dumps(first))
    second["instrument"]["source_commit"] = {
        "pinned": False, "reason": "no_checkout", "meaning": "installed",
    }
    result = coverage.compare(first, second)
    assert result["verdict"] == "unestablished"
    assert result["unestablished"][0]["reason"] == "instrument_unpinned"
    assert not result["differences"]


def test_the_verdict_line_follows_the_block_rather_than_the_counts(scan):
    block = json.loads(json.dumps(scan["coverage"]))
    assert str(block["scope"]["files_present"]) in coverage.verdict_line(block)
    block["accounts_for_every_file"] = False
    assert "cannot account" in coverage.verdict_line(block)


def test_every_absence_reason_is_in_the_closed_set():
    from qrp_mcp.coverage import PIN_ABSENT, UNESTABLISHED, INCOMPARABLE
    for table in (PIN_ABSENT, UNESTABLISHED, INCOMPARABLE):
        assert all(isinstance(v, str) and v for v in table.values())


def test_two_clones_of_one_commit_at_different_paths_are_comparable(scan):
    """A path is checkable and licenses nothing.

    The same commit checked out twice is the same corpus, and calling the pair
    incomparable because the directories differ was a pin that is true and does
    not support the conclusion -- in the table written to enumerate exactly that.
    """
    first = json.loads(json.dumps(scan["coverage"]))
    first["corpus"]["pinned_at"]["dirty"] = False
    second = json.loads(json.dumps(first))
    second["corpus"]["target"] = "/somewhere/else/same-repo"

    result = coverage.compare(first, second)
    assert result["verdict"] == "comparable"
    assert result["targets"] == [first["corpus"]["target"], "/somewhere/else/same-repo"]


def test_the_block_says_which_axis_its_figures_sit_on(scan):
    claims = scan["coverage"]["claims"]
    assert claims["axis"] == "reached"
    assert claims["control"]["held"] is False
    assert claims["control"]["reason"] in coverage.CONTROL_ABSENT


def test_the_axis_declaration_travels_in_the_cbom(document):
    """A declaration a reader cannot see in the document is not a declaration."""
    props = {p["name"]: p["value"] for p in document["properties"]}
    assert props["qrp:coverage:claims:axis"] == "reached"
    assert props["qrp:coverage:claims:control:held"] == "false"
    assert props["qrp:coverage:claims:control:reason"] == "none_held"


def test_a_missing_control_says_which_absence(scan):
    """Same discipline as the pins: an absent control names its absence.

    The three reasons take three different repairs -- build one, run it, re-run
    it against this instrument -- so the set is finished by the state-vocabulary
    test rather than by taste.
    """
    from qrp_mcp.coverage import CONTROL_ABSENT
    assert set(CONTROL_ABSENT) == {"none_held", "not_run", "stale"}
    assert all(v for v in CONTROL_ABSENT.values())


def test_the_denominator_carries_its_composition_not_only_its_size(scan):
    """Size makes a figure reproducible; composition makes it interpretable.

    The same scanner over a tree of Go and over a tree of Ruby reports different
    coverage with nothing in the scanner changing, so a reader holding only the
    total cannot tell which of the two a figure describes.
    """
    scope = scan["coverage"]["scope"]
    composition = scope["files_present_by_extension"]
    assert composition, "no composition emitted"
    assert sum(composition.values()) == scope["files_present"]
    counts = list(composition.values())
    assert counts == sorted(counts, reverse=True), "not ordered by size"


def test_the_composition_travels_in_the_cbom(document, scan):
    props = {p["name"]: p["value"] for p in document["properties"]}
    for ext, n in scan["coverage"]["scope"]["files_present_by_extension"].items():
        assert props[f"qrp:coverage:scope:files_present_by_extension:{ext}"] == str(n)


def test_the_denominator_reports_how_concentrated_it_is(scan):
    """Measured on the five published repositories, the two largest file kinds are
    between 43 and 55 per cent of the denominator, so a coverage figure over any
    of them is substantially a figure about two kinds of file."""
    c = scan["coverage"]["scope"]["concentration"]
    present = scan["coverage"]["scope"]["files_present"]
    assert c["distinct_kinds"] >= 1
    assert c["largest"]["files"] <= present
    assert c["largest_group"]["files"] >= c["largest"]["files"]
    assert 0 < c["largest_group"]["share_pct"] <= 100


def test_the_gap_reports_where_its_mass_sits(scan):
    """The reader's question is what was missed, so the concentration that
    changes the reading is of the misses rather than of the total. Measured:
    three kinds are 52 to 89 per cent of what was not read, across the five."""
    gap = next(r for r in scan["coverage"]["not_examined"]
               if r["reason"] == "type_not_claimed")
    c = gap["concentration"]
    assert sum(gap["by_extension"].values()) == gap["count"]
    assert c["largest_group"]["files"] <= gap["count"]
    assert 0 < c["largest_group"]["share_pct"] <= 100


def test_the_signers_sentence_names_where_the_gap_is(scan):
    """Govardhan Yadava's test: can it be lifted along with the number by someone
    who is not being careful. The clause sits in the same sentence as the count it
    qualifies, so stripping it removes something visible."""
    line = coverage.verdict_line(scan["coverage"])
    gap = next(r for r in scan["coverage"]["not_examined"]
               if r["reason"] == "type_not_claimed")
    g = gap["concentration"]["largest_group"]
    assert f"{g['share_pct']}%" in line
    assert str(gap["count"]) in line
    assert line.index(str(gap["count"])) < line.index(f"{g['share_pct']}%")
    assert ". " not in line and line.endswith("."), (
        "the clause must stay inside the sentence it qualifies, not become another")
