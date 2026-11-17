"""Row 524 (17.11.2026, the thread with Meir Goldman, our reply: "only a re-read sees that").

`stale` measured our reading's age, not the document: a document replaced the day after it was
read looked as current as one untouched. Each mandate now keeps, beside `read_on`, the sha256 of
each document as it was downloaded when read (`documents`), where the address and the hash were
both recorded (srokove-v-skenera, REGISTAR.md and the SHA256SUMS files beside the copies). A
scan says `document_changed: "not_fetched"`: it makes no network call. `qrp-mcp mandate-check
NAME --document FILE ...` compares documents downloaded by the user (the block prints a `curl`
for each) with the recorded hashes: `document_changed` true, false or not_fetched, exit 1 when
one changed.

Limits, said in the output: the tool still makes no network call (the README's promise and
tests/test_scan.py hold), so the fetch is the user's; an HTML page changes its bytes without
any change to its text, so only PDFs are recorded; a mandate whose address or hash was not
recorded (uk-ncsc, au-ism, sg-csa-cii, cnsa-2.0, nist-ir-8547, ch-finma, hk-hkma) has none
and stays not_fetched.
"""

import hashlib
import json
import os
import subprocess
import sys
from datetime import date

import pytest

from qrp_mcp import mandates, profiles, server
from qrp_mcp.scan import scan_directory

HEX = set("0123456789abcdef")


def _cli(*args, cwd=None):
    return subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                           *args], capture_output=True, text=True, env=dict(os.environ), cwd=cwd)


def test_recorded_documents_carry_a_full_hash_and_their_address():
    recorded = {n: m.get("documents") or [] for n, m in mandates.MANDATES.items()}
    assert {n for n, d in recorded.items() if d} == {
        "eu-pqc-roadmap", "ca-cccs", "nl-rqs", "se-ncsc", "jp-gov", "in-dst", "de-bsi",
        "il-boi", "sg-mas"}
    for docs in recorded.values():
        for d in docs:
            assert len(d["sha256"]) == 64 and set(d["sha256"]) <= HEX
            assert d["url"].startswith("https://") and d["read_on"]
    assert [d["sha256"][:8] for d in recorded["de-bsi"]] == ["f601cdf2", "ad714afe"]


def test_a_scan_says_not_fetched(tmp_path):
    (tmp_path / "a.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")
    result = scan_directory(tmp_path)
    mandates.apply(result, ["de-bsi", "uk-ncsc", "il-boi"], date(2026, 11, 17))
    for name in ("de-bsi", "uk-ncsc", "il-boi"):
        assert result["mandates"][name]["document_changed"] == "not_fetched"
    assert len(result["mandates"]["de-bsi"]["documents"]) == 2
    assert result["mandates"]["uk-ncsc"]["documents"] == []


@pytest.fixture
def fake(monkeypatch, tmp_path):
    original = tmp_path / "doc.pdf"
    original.write_bytes(b"%PDF-1.7 the document as read\n")
    entry = {"name": "xx-test", "document": "a test document", "url": "https://example.test/d",
             "read_on": "2026-11-17", "documents": [
                 {"url": "https://example.test/d.pdf", "read_on": "2026-11-17",
                  "sha256": hashlib.sha256(original.read_bytes()).hexdigest()}]}
    monkeypatch.setitem(mandates.MANDATES, "xx-test", entry)
    return original


def _check(argv, capsys):
    with pytest.raises(SystemExit) as stop:
        server.main(argv)
    return stop.value.code, json.loads(capsys.readouterr().out)


def test_the_same_bytes_are_unchanged(fake, capsys):
    code, out = _check(["mandate-check", "xx-test", "--document", str(fake)], capsys)
    assert code == 0 and out["document_changed"] is False
    assert out["documents"][0]["document_changed"] is False


def test_other_bytes_are_changed_and_exit_1(fake, tmp_path, capsys):
    other = tmp_path / "new.pdf"
    other.write_bytes(b"%PDF-1.7 a newer version\n")
    code, out = _check(["mandate-check", "xx-test", "--document", str(other)], capsys)
    assert code == 1 and out["document_changed"] is True
    assert out["documents"][0]["sha256_now"] == hashlib.sha256(other.read_bytes()).hexdigest()


def test_no_file_is_not_fetched_and_says_how(fake, capsys):
    code, out = _check(["mandate-check", "xx-test"], capsys)
    assert code == 0 and out["document_changed"] == "not_fetched"
    assert "curl" in out["documents"][0]["how"] and "https://example.test/d.pdf" in out[
        "documents"][0]["how"]
    assert "no network call" in out["limits"]


def test_the_command_line_runs_without_the_network():
    r = _cli("mandate-check", "de-bsi")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["document_changed"] == "not_fetched" and len(out["documents"]) == 2


def test_a_mandate_with_nothing_recorded_says_so():
    r = _cli("mandate-check", "uk-ncsc")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["documents"] == [] and out["document_changed"] == "not_fetched"
    assert "not recorded" in out["why_not_fetched"]
