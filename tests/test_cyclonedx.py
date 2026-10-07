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


def test_reading_every_file_is_not_a_complete_component_list(scan):
    # Reading every file settles the denominator, not whether every asset present was
    # found. Comparing against other scanners showed us missing findings in files we
    # had read, while our own document said "complete".
    full = json.loads(json.dumps(scan))
    full["coverage"]["scope"]["files_not_examined"] = 0
    assert cyclonedx.build(full)["compositions"][0]["aggregate"] == "unknown"


def test_aggregate_is_complete_only_when_a_control_licenses_it(scan):
    full = json.loads(json.dumps(scan))
    full["coverage"]["scope"]["files_not_examined"] = 0
    full["coverage"]["claims"]["control"] = {"held": True, "corpus": "example"}
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


def pinned_block(scan):
    """A coverage block with both pins set, whatever the tool was installed from.

    The pins are supplied here instead of read from the environment. Three tests
    used to take them from the tool's own checkout and so passed from a git clone
    and failed from the published tarball -- found by an external audit of 0.9.0,
    which ran the suite from the ZIP and saw `unestablished` three times. What the
    comparison does when a pin is missing is a separate question, and the test
    below named for it is the one that asks it.
    """
    block = json.loads(json.dumps(scan["coverage"]))
    block["instrument"]["source_commit"] = {"pinned": True, "commit": "a" * 40,
                                            "dirty": False}
    block["corpus"]["pinned_at"] = {"pinned": True, "commit": "b" * 40,
                                    "dirty": False, "shallow": False}
    return block


def test_comparing_a_clean_run_with_itself_is_comparable(scan):
    block = pinned_block(scan)
    assert coverage.compare(block, block)["verdict"] == "comparable"


def test_a_changed_emitter_commit_is_not_comparable_at_the_same_version(scan):
    first = pinned_block(scan)
    second = json.loads(json.dumps(first))
    second["instrument"]["source_commit"]["commit"] = "0" * 40
    result = coverage.compare(first, second)
    assert result["verdict"] == "not_comparable"
    assert result["differences"][0]["reason"] == "instrument_commit_differs"
    assert first["instrument"]["version"] == second["instrument"]["version"]


def test_an_unpinned_emitter_leaves_comparability_unestablished(scan):
    first = pinned_block(scan)
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
    first = pinned_block(scan)
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
    # A share is a property of the aggregate crossed with the partition it was
    # measured over. Without the partition named, "two kinds are 50 per cent"
    # does not say what a kind is.
    assert c["partition"] == "files by extension"
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
    assert c["partition"] == "unread files by extension"
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
    # The cardinality travels too: a share cannot be read as high or low without
    # the number of kinds it is a share of.
    assert f"of {gap['concentration']['distinct_kinds']}, by extension" in line, (
        "the sentence must say what a kind is, not only how many there are")
    # Bracketed mid-sentence rather than trailing, so it cannot be dropped by
    # stopping early: the bracket opens before the clause that closes the sentence.
    listed = line.index("listed with a reason")
    bracket = line.index("(", line.index("%);"))
    assert bracket < listed, "the clause trails the sentence instead of sitting inside it"
    assert ". " not in line and line.endswith("."), (
        "the clause must stay inside the sentence it qualifies, not become another")


def test_an_unpinned_tool_is_unestablished_however_it_was_installed(scan):
    """The behaviour the fixture above deliberately steps around.

    Running from a wheel or a tarball there is no checkout to name, and the
    comparison must say so rather than pretend. This is the test that has to keep
    working from the published artefact, and it needs no pins to do it.
    """
    block = json.loads(json.dumps(scan["coverage"]))
    block["instrument"]["source_commit"] = {"pinned": False, "reason": "no_checkout",
                                            "meaning": "installed, not a checkout"}
    result = coverage.compare(block, json.loads(json.dumps(block)))
    assert result["verdict"] == "unestablished"
    assert any(u["reason"] == "instrument_unpinned" for u in result["unestablished"])


def test_an_occurrence_says_whether_its_evidence_is_a_comment(tmp_path):
    """The CBOM is the document that leaves the machine; it dropped the distinction.

    `scan_repo` grades every match with an `evidence_kind` -- call, declaration,
    import, reference, ban, comment -- and keeps comment evidence out of the
    inventory, for a measured reason: the nearest rival strips comments before
    matching and scored 0.542 precision against this scanner's 0.93.

    Measured on certbot 2026-09-26: **78 of 389 source findings (20%) are comment
    evidence**, and every one of them reached the exported CBOM as an occurrence
    indistinguishable from a call. An auditor reading the document could not tell
    that `ocsp.py:220` is a sentence about certificates rather than a signature.

    The schema has no field for it, so it is named in `additionalContext` -- the
    same answer this module already gives for classification and the PQC family:
    named, not silently dropped.
    """
    src = tmp_path / "svc.py"
    src.write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "\n"
        "def sign(key, msg):\n"
        "    # always present for RSA and ECDSA certificates\n"
        "    return key.sign(msg, ec.ECDSA(hashes.SHA256()))\n",
        encoding="utf-8")
    from qrp_mcp.server import export_cbom
    cbom = export_cbom(str(tmp_path), level="full")
    occurrences = [
        occurrence
        for component in cbom["components"]
        for occurrence in (component.get("evidence", {}) or {}).get("occurrences", []) or []
    ]
    assert occurrences, "the fixture must produce occurrences at all"
    comment_lines = [o for o in occurrences if o["line"] == 4]
    assert comment_lines, "the comment line is an occurrence of ECDSA"
    for occurrence in comment_lines:
        assert occurrence["additionalContext"].startswith("[comment]"), (
            "an occurrence whose only evidence is a comment must say so in the "
            f"document that leaves the machine, got: {occurrence['additionalContext']!r}")
    code_lines = [o for o in occurrences if o["line"] == 5]
    for occurrence in code_lines:
        assert not occurrence["additionalContext"].startswith("[comment]"), (
            "a call is not a comment")


def test_a_banned_algorithm_never_becomes_a_component_at_all(tmp_path):
    """Not marked downstream -- excluded upstream. Written after the opposite failed.

    The first version of this test expected `!RC4` to arrive marked `[ban]`, the way a
    comment arrives marked `[comment]`. It does not: a banned algorithm never becomes a
    component, which is stronger and is what the document should say. So `ban` is not in
    `_NOT_CODE`, because a branch for it could never run.
    """
    conf = tmp_path / "ssl.conf"
    conf.write_text('SSLCipherSuite ECDHE-RSA-AES256-GCM-SHA384:!aNULL:!RC4:!3DES\n',
                    encoding="utf-8")
    from qrp_mcp.server import export_cbom
    cbom = export_cbom(str(tmp_path), level="full")
    names = {component.get("name") for component in cbom["components"]}
    assert "RC4" not in names and "3DES" not in names, (
        f"a forbidden algorithm is not an asset, got: {sorted(n for n in names if n)}")
    assert {"RSA", "ECDH"} <= names, "what the line ENABLES is still inventory"


def test_the_test_code_marker_reaches_every_path_that_leaves_the_tool(tmp_path):
    """Three outputs leave qrp-mcp, and a field built in one of them reaches nobody.

    This is the defect that cost the most on 2026-09-21: a check was written, tested,
    and never called, because it was added to one exit and not the other two. So this
    test walks the exits -- `scan --out`, the MCP scan result, and the exported CBOM --
    rather than the function.
    """
    (tmp_path / "tests").mkdir()
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n",
        encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "FIXTURE = ec.generate_private_key(ec.SECP384R1())\n",
        encoding="utf-8")

    from qrp_mcp.server import export_cbom, scan_repo as scan_tool
    result = scan_tool(str(tmp_path))
    assert "test_code" in result, "the MCP scan result must declare it"
    assert result["test_code"]["findings_in_test_code"] >= 1
    assert "rule" in result["test_code"]

    cbom = export_cbom(str(tmp_path), level="full")
    contexts = {
        occurrence["location"]: occurrence["additionalContext"]
        for component in cbom["components"]
        for occurrence in (component.get("evidence", {}) or {}).get("occurrences", []) or []
    }
    assert any(path.startswith("tests/") for path in contexts), contexts
    for path, context in contexts.items():
        if path.startswith("tests/"):
            assert "[test]" in context, (
                f"a fixture must say so in the document that leaves the machine: "
                f"{path} -> {context!r}")
        else:
            assert "[test]" not in context, f"{path} is not test code: {context!r}"


def test_a_component_seen_only_in_test_code_carries_the_standard_scope(tmp_path):
    """The schema has had the field since 1.6, and we invented our own instead.

    `component.scope` enumerates required / optional / excluded, and 1.6 defines the
    third verbatim: "Components that are excluded provide the ability to document
    component usage for test and other non-runtime purposes." It is identical in 1.7
    and 2.0-dev. v0.18.0 shipped `[test]` in `additionalContext` and set no scope at
    all — a private spelling of a standard field, which is the thing this project
    criticises other tools for.

    `scope` is per component and the marker is per occurrence, so they say different
    things and both stay: a family seen ONLY in fixtures is `excluded`; one seen
    anywhere in production keeps the schema default, `required`.
    """
    (tmp_path / "tests").mkdir()
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n",
        encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "FIXTURE = ec.generate_private_key(ec.SECP384R1())\n",
        encoding="utf-8")
    from qrp_mcp.server import export_cbom
    cbom = export_cbom(str(tmp_path), level="full")
    scopes = {c.get("name"): c.get("scope") for c in cbom["components"]}
    ec_like = [name for name in scopes if name and name.startswith("EC")]
    assert ec_like, f"the fixture's EC family must be a component: {sorted(scopes)}"
    for name in ec_like:
        assert scopes[name] == "excluded", (
            f"{name} occurs only under tests/ and must carry the standard scope, "
            f"got {scopes[name]!r}")
    assert scopes.get("RSA") in (None, "required"), (
        f"RSA runs in production and must not be excluded, got {scopes.get('RSA')!r}")


def test_a_family_used_in_both_places_is_not_excluded(tmp_path):
    """Mutation caught this: `all` -> `any` broke nothing, because the first fixture
    had no family living in both places.

    Measured on certbot the same day: **not one of its 31 components** is confined to
    test code — every family that appears in a fixture also runs in production. So the
    mixed case is the normal case on real repositories, and getting it wrong would mark
    a production algorithm as non-runtime in the document an auditor reads.
    """
    (tmp_path / "tests").mkdir()
    (tmp_path / "app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n",
        encoding="utf-8")
    (tmp_path / "tests" / "test_app.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "FIXTURE = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n",
        encoding="utf-8")
    from qrp_mcp.server import export_cbom
    cbom = export_cbom(str(tmp_path), level="full")
    rsa_scope = {c.get("scope") for c in cbom["components"] if c.get("name") == "RSA"}
    assert rsa_scope, "RSA must be a component in this fixture"
    assert rsa_scope <= {None, "required"}, (
        f"RSA runs in production here and is only ALSO in a fixture; marking it "
        f"non-runtime would mislead, got {rsa_scope}")


def test_every_file_not_read_is_named(scan):
    """Joel Hillier's CAP-1 draft, R1: a count alone is not an accounting. On
    certbot at 0.27.2, 48 of the 427 files not read were named and 379 were a
    count by extension -- the remainder that reconciles only by arithmetic, and a
    CAP-1 verifier refuses it. Promised publicly on 2 Oct 2026 that they would be
    named. Every reason that carries a count now carries the paths it counts."""
    for entry in scan["coverage"]["not_examined"]:
        assert "paths" in entry, f"{entry['reason']} counts files it does not name"
        assert len(entry["paths"]) == entry["count"], entry["reason"]
        assert len(set(entry["paths"])) == len(entry["paths"])
    gap = next(r for r in scan["coverage"]["not_examined"]
               if r["reason"] == "type_not_claimed")
    assert gap["count"] > 0, "the fixture must exercise the type gap"
    by_ext: dict[str, int] = {}
    for p in gap["paths"]:
        from pathlib import PurePosixPath
        ext = PurePosixPath(p).suffix.lower() or "(no extension)"
        by_ext[ext] = by_ext.get(ext, 0) + 1
    assert by_ext == gap["by_extension"]


def test_the_names_travel_into_the_cbom(scan, document):
    """The second of the three ways a result leaves: the names must reach the
    exported document, not stop at the scan result."""
    props = {p["name"]: p["value"] for p in document["properties"]}
    gap_index = next(i for i, r in enumerate(scan["coverage"]["not_examined"])
                     if r["reason"] == "type_not_claimed")
    key = f"qrp:coverage:not_examined:{gap_index}:paths"
    gap = scan["coverage"]["not_examined"][gap_index]
    assert json.loads(props[key]) == gap["paths"]


def test_a_comma_in_a_file_name_does_not_change_where_the_names_are(tmp_path, validator):
    """Joel Hillier (CAP-1), 5 Oct 2026: the paths travelled joined by commas, and a
    path holding a comma breaks such a list. 0.27.3 did not lose it -- it switched to
    one indexed property per path -- but then a reader of `...:paths` found nothing
    there and had to know the rule. One shape now, the same for every name: a JSON
    array in the one property, through the command people run."""
    import sys
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "a,b.xyz").write_text("x\n")
    (tree / "c.xyz").write_text("y\n")
    (tree / "m.c").write_text("RSA_generate_key(2048);\n")
    out = tmp_path / "cbom.json"
    r = subprocess.run([sys.executable, "-m", "qrp_mcp.server", "cbom", str(tree),
                        "--out", str(out)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text())
    assert not list(validator.iter_errors(doc))
    props = {p["name"]: p["value"] for p in doc["properties"]}
    index = next(k.split(":")[3] for k, v in props.items()
                 if k.endswith(":reason") and v == "type_not_claimed")
    key = f"qrp:coverage:not_examined:{index}:paths"
    assert json.loads(props[key]) == ["a,b.xyz", "c.xyz"]
    assert not [k for k in props if k.startswith(key + ":")]


def test_policy_and_ike_components_validate(validator, tmp_path):
    """OPC UA policies, AWS TLS policies (configured and defaulted) and an IKE
    fragmentation state are protocol components; OPC UA has no CycloneDX protocol type
    of its own and must land on `other`, not on an invalid value."""
    (tmp_path / "Server.Config.xml").write_text(
        "<SecurityPolicyUri>http://opcfoundation.org/UA/SecurityPolicy#Basic256"
        "</SecurityPolicyUri>\n")
    (tmp_path / "main.tf").write_text(
        'resource "aws_lb_listener" "a" {\n  protocol = "HTTPS"\n}\n'
        'resource "aws_lb_listener" "b" {\n  protocol = "TLS"\n'
        '  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-PQ-2025-09"\n}\n')
    (tmp_path / "swanctl.conf").write_text(
        "connections {\n  c {\n    proposals = aes256-sha384-x25519-ke1_mlkem768\n  }\n}\n")
    document = cyclonedx.build(scan_directory(str(tmp_path)))
    errors = sorted(validator.iter_errors(document), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors[:5]]
    types = {c["cryptoProperties"]["protocolProperties"]["type"]
             for c in document["components"]
             if c.get("cryptoProperties", {}).get("assetType") == "protocol"}
    assert {"other", "tls", "ike"} <= types
    refs = [c["bom-ref"] for c in document["components"]]
    assert len(refs) == len(set(refs))
