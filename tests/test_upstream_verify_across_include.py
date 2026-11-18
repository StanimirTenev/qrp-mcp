"""S2 of the 0.50.0 review (PREGLED.md, 18.11, fixture rules-n11): a false "upstream
verification off" across an include. nginx inherits `proxy_ssl_verify` from `http {}`; with
`nginx.conf` holding `http { proxy_ssl_verify on; include sites/*.conf; }` and `sites/a.conf`
holding `proxy_pass https://up;`, 0.50.0 wrote a `configured_verification` row
`peer_verification=off`, "proxy_ssl_verify not set", on `sites/a.conf` -- while `leads` marked
the include `followed` in the same result.

"Not set" is now said only where no file read that includes the file (directly or through
another include) sets that module's `*_ssl_verify`. Where one does, the value there decides:
`off` is its own row on its own line, `on` is not a finding. A file nothing read includes keeps
the single-file rule (nginx's default is off), which the closure tests pin.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

EMPTY = "2329256b8d11486c73883a7288061fb1acda2d052456224d4b2ce2b631759b05"
SITE = "server {\n location / {\n  proxy_pass https://up;\n }\n}\n"


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _verification(result: dict) -> list[tuple[str, int, str, str]]:
    return [(r["path"], r["line"], r["peer_verification"], r["verification_setting"])
            for r in result["evidence"]["protocols"]
            if r.get("basis") == "configured_verification"]


def test_the_review_tree_has_no_false_off(tmp_path):
    root = _write(tmp_path, {
        "nginx.conf": "http {\n proxy_ssl_verify on;\n proxy_ssl_trusted_certificate ca.pem;\n"
                      " include sites/*.conf;\n}\n",
        "sites/a.conf": SITE})
    result = scan_directory(root)
    assert _verification(result) == []
    assert result["findings_fingerprint"]["sha256"] == EMPTY      # 0.49.0's, on this tree
    lead = result["chosen_outside_files"]["leads"]["items"]
    assert [(l["target"], l["status"]) for l in lead if l["rule"] == "include"] == [
        ("sites/*.conf", "followed")]


def test_through_two_includes(tmp_path):
    root = _write(tmp_path, {
        "etc/nginx/nginx.conf": "http {\n grpc_ssl_verify on;\n include conf.d/*.conf;\n}\n",
        "etc/nginx/conf.d/app.conf": "server {\n include snippets/up.conf;\n}\n",
        "etc/nginx/snippets/up.conf": "location / {\n grpc_pass grpcs://up;\n}\n"})
    assert _verification(scan_directory(root)) == []


def test_off_in_the_including_file_is_reported_there_once(tmp_path):
    root = _write(tmp_path, {
        "nginx.conf": "http {\n proxy_ssl_verify off;\n include sites/*.conf;\n}\n",
        "sites/a.conf": SITE})
    assert _verification(scan_directory(root)) == [
        ("nginx.conf", 2, "off", "proxy_ssl_verify off")]


@pytest.mark.parametrize("files", [
    # Nothing read includes the file: the single-file rule, as the closure tests pin it.
    {"sites/a.conf": SITE},
    # An include of the file, but the including file sets another module's directive.
    {"nginx.conf": "http {\n grpc_ssl_verify on;\n include sites/*.conf;\n}\n",
     "sites/a.conf": SITE},
    # A file that sets the directive but does not include this one.
    {"other/nginx.conf": "http {\n proxy_ssl_verify on;\n include vhosts/*.conf;\n}\n",
     "sites/a.conf": SITE},
])
def test_not_set_stays_where_nothing_read_sets_it_above(tmp_path, files):
    rows = _verification(scan_directory(_write(tmp_path, files)))
    assert rows == [("sites/a.conf", 3, "off", "proxy_ssl_verify not set")]
