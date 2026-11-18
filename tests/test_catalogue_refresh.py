"""tools/catalogue_refresh.py, offline: a saved copy of one documentation page (the KexAlgorithms
entry of sshd_config(5), tests/fixtures/catalogue_refresh/) and a small catalogue written here.
Nothing is fetched."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "catalogue_refresh.py"
PAGE = Path(__file__).parent / "fixtures" / "catalogue_refresh" / "sshd_config-KexAlgorithms.html"
URL = "https://man.openbsd.org/sshd_config"
KEX = r"\b((?:curve25519|diffie-hellman|ecdh|mlkem\d+|sntrup\d+)[\w@.-]*)"


def _tool():
    spec = importlib.util.spec_from_file_location("catalogue_refresh", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _catalogue(tmp_path: Path, refresh: str, known=("curve25519-sha256", "ecdh-sha2-nistp256",
                                                     "mlkem768x25519-sha256"), extra_source="") -> Path:
    spellings = "".join(f'''
[[ecosystems.spellings]]
id = "kex-{k}"
spelling = "KexAlgorithms {k}"
source = "{URL}"
quote = "The supported algorithms are:"
file = "sshd_config"
snippet = """KexAlgorithms {k}
"""
expect = {{rows = [{{at = "evidence.ssh_kex", match = {{line = 1}}}}]}}
''' for k in known)
    if extra_source:
        spellings += f'''
[[ecosystems.spellings]]
id = "other"
spelling = "KexAlgorithms other"
source = "{extra_source}"
quote = "x"
file = "sshd_config"
snippet = "KexAlgorithms other"
expect = {{detected = ["DH"]}}
'''
    d = tmp_path / "operations"
    d.mkdir(parents=True)
    (d / "ssh.toml").write_text(f'operation = "ssh"\ncatalogue_version = "1"\n\n[[ecosystems]]\n'
                                f'ecosystem = "SSH"\nscope = "test"\n{spellings}\n{refresh}', encoding="utf-8")
    return d


def _refresh(pattern=KEX, extra=""):
    return (f"[[ecosystems.refresh]]\nsource = \"{URL}\"\npattern = '{pattern}'\n{extra}"
            f'file = "sshd_config"\nsnippet = "KexAlgorithms {{candidate}}\\n"\n'
            f'expect = {{rows = [{{at = "evidence.source_code", match = {{path = "sshd_config", line = 1}}}}]}}\n')


PAGES = {URL: PAGE}


def test_the_names_beside_the_known_ones_are_candidates(tmp_path):
    result = _tool().refresh(_catalogue(tmp_path, _refresh()), PAGES)
    (src,) = result["sources"]
    assert src["status"] == "saved copy" and len(src["sha256"]) == 64
    assert src["known_refound"] == src["known_cited"] == 3
    found = {c["candidate"] for c in result["candidates"]}
    # the page lists 16 names; 3 are in the catalogue
    assert len(found) == 13
    assert {"diffie-hellman-group1-sha1", "sntrup761x25519-sha512@openssh.com",
            "mlkem768nistp256-sha256"} <= found
    assert not found & {"curve25519-sha256", "ecdh-sha2-nistp256", "mlkem768x25519-sha256"}


def test_a_candidate_carries_its_page_its_line_and_a_snippet_to_try(tmp_path):
    result = _tool().refresh(_catalogue(tmp_path, _refresh()), PAGES)
    c = next(c for c in result["candidates"] if c["candidate"] == "diffie-hellman-group1-sha1")
    assert c["source"] == URL and c["context"] == "diffie-hellman-group1-sha1"
    assert c["snippet"] == "KexAlgorithms diffie-hellman-group1-sha1\n"
    assert c["expect"] == {"rows": [{"at": "evidence.source_code", "match": {"path": "sshd_config", "line": 1}}]}
    assert (c["operation"], c["ecosystem"], c["file"]) == ("ssh", "SSH", "sshd_config")


def test_ignore_and_window_narrow_the_candidates(tmp_path):
    tool = _tool()
    ignored = tool.refresh(_catalogue(tmp_path / "a", _refresh(extra='ignore = ["diffie-hellman-group1-sha1"]\n')), PAGES)
    assert "diffie-hellman-group1-sha1" not in {c["candidate"] for c in ignored["candidates"]}
    # within 40 characters of a known name: only the immediate neighbours in the list
    near = tool.refresh(_catalogue(tmp_path / "b", _refresh(extra="window = 40\n")), PAGES)
    all_ = tool.refresh(_catalogue(tmp_path / "c", _refresh()), PAGES)
    assert 0 < len(near["candidates"]) < len(all_["candidates"])
    assert "curve25519-sha256@libssh.org" in {c["candidate"] for c in near["candidates"]}


def test_an_unreachable_page_and_a_blind_pattern_are_said_not_counted_as_nothing_new(tmp_path):
    tool = _tool()
    gone = tool.refresh(_catalogue(tmp_path / "a", _refresh()), {})
    assert gone["sources"][0]["status"] == "unreachable" and gone["candidates"] == []
    blind = tool.refresh(_catalogue(tmp_path / "b", _refresh(pattern=r"\b(no-such-kex-\w+)")), PAGES)
    assert "blind pattern" in blind["sources"][0]["status"]
    assert blind["sources"][0]["known_refound"] == 0 and blind["sources"][0]["known_cited"] == 3


def test_a_cited_page_without_a_refresh_entry_is_listed_as_not_examined(tmp_path):
    other = "https://man.openbsd.org/ssh_config"
    result = _tool().refresh(_catalogue(tmp_path, _refresh(), extra_source=other), PAGES)
    assert result["not_examined"] == [{"operation": "ssh", "ecosystem": "SSH", "source": other, "spellings": 1}]
    assert "## Not examined" in _tool().report(result, "2026-11-18") and other in _tool().report(result, "2026-11-18")


def test_the_command_line_writes_the_report_and_the_candidates_and_is_repeatable(tmp_path):
    tool = _tool()
    cat = _catalogue(tmp_path, _refresh())
    pages = tmp_path / "pages"
    pages.mkdir()
    (pages / "kex.html").write_bytes(PAGE.read_bytes())
    (pages / "URLS.tsv").write_text(f"{URL}\tkex.html\n", encoding="utf-8")
    runs = []
    for n in (1, 2):
        out, rep = tmp_path / f"c{n}.json", tmp_path / f"r{n}.md"
        assert tool.main(["--catalogue", str(cat), "--pages", str(pages), "--report", str(rep),
                          "--candidates", str(out)]) == 0
        runs.append((json.loads(out.read_text()), rep.read_text()))
    assert runs[0] == runs[1]
    data, text = runs[0]
    assert data["by"] == "tools/catalogue_refresh.py" and len(data["candidates"]) == 13
    assert "candidates: 13" in text and "3/3" in text


@pytest.mark.parametrize("raw, lines", [
    (b"<html><body><ul><li>a-1</li><li>b-2</li></ul></body></html>", ["a-1", "b-2"]),
    (b"KexAlgorithms\n   x  y\n\n", ["KexAlgorithms", "x y"]),
])
def test_page_text_keeps_one_item_per_line(raw, lines):
    assert _tool().page_text(raw).splitlines() == lines


def test_a_candidate_of_several_words_is_known_when_a_spelling_holds_it(tmp_path):
    page = tmp_path / "labels.txt"
    page.write_text("-----BEGIN PRIVATE KEY-----\n-----BEGIN NEW LABEL-----\n", encoding="utf-8")
    d = tmp_path / "operations"
    d.mkdir()
    (d / "keyfile.toml").write_text('''operation = "keyfile"
catalogue_version = "1"

[[ecosystems]]
ecosystem = "PKI"
scope = "test"

[[ecosystems.spellings]]
id = "pkcs8"
spelling = "-----BEGIN PRIVATE KEY-----"
source = "https://example.org/labels"
quote = "x"
file = "k.pem"
material = "RSA2048_PKCS8_PEM"
expect = {detected = ["RSA"]}

[[ecosystems.refresh]]
source = "https://example.org/labels"
pattern = '-----BEGIN ([A-Z0-9 ]+)-----'
file = "k.pem"
snippet = "-----BEGIN {candidate}-----\\n"
expect = {detected = ["RSA"]}
''', encoding="utf-8")
    result = _tool().refresh(d, {"https://example.org/labels": page})
    assert [c["candidate"] for c in result["candidates"]] == ["NEW LABEL"]
    assert result["sources"][0]["known_refound"] == 1
