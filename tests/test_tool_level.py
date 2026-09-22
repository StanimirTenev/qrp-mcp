"""What the tools hand back, asked of the tools themselves.

The gap this closes: masking was added in 0.15.0 to `qrp-mcp scan --out`, the path
that writes a file for someone to inspect and send on. The tools had no level at
all. They are the path that runs on every agent call and returns its result to a
model -- which is a place the scanned line has not been before. The control had
been built for the path we thought left the machine rather than the one that
leaves on every call.

`export_cbom` made it plainer: its own description says to use it "when the result
has to leave the machine", and it carried every matched line verbatim into
`evidence.occurrences`.

So these tests go through the tool objects, and they check the whole serialised
result for the planted secret rather than one field. A per-field assertion is how
`evidence` -- a second place excerpts live -- would have been missed.
"""

from __future__ import annotations

import json

import pytest

from qrp_mcp.server import export_cbom, scan_repo

SECRET = "sk_live_9f3a2b7c8d1e"
CONFIG_SECRET = "tok_44448888"


def _tool(obj):
    """The underlying function of a registered tool, however the server wraps it."""
    return getattr(obj, "fn", obj)


@pytest.fixture
def tree(tmp_path):
    """A secret sharing its line with a finding, in the two file kinds that quote lines."""
    (tmp_path / "app.py").write_text(
        "import rsa\n"
        f'key = rsa.generate_private_key(key_size=1024, password="{SECRET}")\n',
        encoding="utf-8",
    )
    (tmp_path / "nginx.conf").write_text(
        f"ssl_ciphers ECDHE-RSA-AES128-SHA; # {CONFIG_SECRET}\n", encoding="utf-8")
    return tmp_path


def _leaks(document) -> list[str]:
    blob = json.dumps(document, ensure_ascii=False)
    return [token for token in (SECRET, CONFIG_SECRET) if token in blob]


def test_scan_repo_does_not_return_the_secret_by_default(tree):
    assert _leaks(_tool(scan_repo)(str(tree))) == []


def test_export_cbom_does_not_carry_the_secret_by_default(tree):
    """The document whose own description says it is the one that leaves."""
    assert _leaks(_tool(export_cbom)(str(tree))) == []


def test_full_is_still_available_and_still_full(tree):
    """Masking by default is not masking only. Someone examining the line itself
    has to be able to ask for it, or the default becomes a reason to distrust the
    tool rather than a reason to trust it."""
    assert SECRET in json.dumps(_tool(scan_repo)(str(tree), level="full"))


def test_the_finding_survives_masking(tree):
    """The point of masking rather than trimming: the answer is still there."""
    result = _tool(scan_repo)(str(tree))
    assert "RSA" in json.dumps(result).upper()
    excerpts = [item.get("excerpt", "")
                for items in result.get("evidence", {}).values() if isinstance(items, list)
                for item in items if isinstance(item, dict)]
    assert any("*" in text for text in excerpts), "nothing was masked at all"


def test_file_and_line_are_the_same_at_every_level(tree):
    """Masking hides the content of a line, never where it is. A reader who cannot
    find the finding again has been given less than nothing."""
    def places(level):
        result = _tool(scan_repo)(str(tree), level=level)
        return sorted(
            (item.get("file"), item.get("line"))
            for items in result.get("evidence", {}).values() if isinstance(items, list)
            for item in items if isinstance(item, dict)
        )

    assert places("masked") == places("full") == places("trimmed")


def test_trimmed_carries_no_line_at_all(tree):
    result = _tool(scan_repo)(str(tree), level="trimmed")
    assert _leaks(result) == []
    assert not any("excerpt" in item
                   for items in result.get("evidence", {}).values() if isinstance(items, list)
                   for item in items if isinstance(item, dict))


def test_counts_do_not_move_with_the_level(tree):
    """A privacy level must not change what was found, only how it is quoted.
    If coverage or the family list moved, two scans of one tree would disagree
    for a reason that has nothing to do with the tree.

    ⚠️ `coverage.window` is excluded on purpose, and the exclusion is the point:
    it holds `started_at`, `finished_at` and `seconds`, which differ between any
    two runs. The first version of this test compared the whole coverage block and
    passed by luck — two scans happened to land in the same fraction of a second.
    A test that fails at random is worse than no test, because it teaches everyone
    to disregard a red suite, and then the real failure goes unread too.
    """
    full = _tool(scan_repo)(str(tree), level="full")
    masked = _tool(scan_repo)(str(tree))
    for field in ("files_scanned", "files_present", "detected_algorithms",
                  "algorithm_key_sizes", "algorithm_key_sizes_observed", "verdict"):
        assert full[field] == masked[field], field
    for block in ("scope", "claims", "not_examined", "examined_without_result"):
        assert full["coverage"][block] == masked["coverage"][block], block
    assert (full["coverage"]["corpus"]["content_digest"]
            == masked["coverage"]["corpus"]["content_digest"])
