"""Stage 3, adaptive scanning by rules (adaptive.py): the ecosystems a tree uses and whether the
closure catalogue holds their operations, the angles that contradict each other (manifest, code,
key files), the leads a configuration or the code points to (include, a key file by path or by
environment variable), and one list of where a reviewer looks first.

All four are context. The same tree gives the same sections, and none of them moves the
findings, their fingerprint, the evidence, the summary, a mandate's gate or the exit code: the
last test scans one tree with the sections built and with them switched off.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp import adaptive, operations
from qrp_mcp.scan import findings_fingerprint, scan_directory
from qrp_mcp.server import main, scan_repo

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _eco(result: dict, name: str) -> dict:
    return next(e for e in result["ecosystems"]["present"] if e["ecosystem"] == name)


# --- 1. by ecosystem --------------------------------------------------------------------------

ECO_TREE = {
    "app/sign.py": "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                   "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
    "requirements.txt": "cryptography==47.0.0\n",
    "deploy/sshd_config": "KexAlgorithms curve25519-sha256\n",
    "deploy/nginx.conf": "events {}\n",
    "cmd/main.go": 'package main\nimport "crypto/rsa"\nfunc main() { _ = rsa.GenerateKey }\n',
    "tests/fixture.rs": "fn main() {}\n",
    "web/app.js": "const x = 1;\n",
}


def test_each_ecosystem_used_is_listed_with_the_rule_that_found_it(tmp_path):
    result = scan_directory(_write(tmp_path, ECO_TREE))
    names = {e["ecosystem"] for e in result["ecosystems"]["present"]}
    assert {"Py", "SSH", "nginx", "Go", "Rust"} <= names
    py = _eco(result, "Py")
    assert py["basis"]["code_suffix"] == 1 and py["basis"]["manifest"] == 1
    assert py["basis"]["crypto_dependency"] == 1
    assert _eco(result, "SSH")["basis"] == {"config_name": 1}
    assert _eco(result, "Rust")["only_in_test_code"] is True
    assert _eco(result, "Py")["only_in_test_code"] is False


def test_status_is_read_against_the_catalogue(tmp_path):
    result = scan_directory(_write(tmp_path, ECO_TREE))
    py = _eco(result, "Py")
    # external/Py is in the catalogue; keysize, sign ... of Python are not.
    assert py["status"] == "partially_closed"
    assert py["closed_operations"] == ["external"]
    assert "keysize" in py["open_operations"]
    assert "here we may miss" in py["may_miss"]
    # A tree without a VRF: vrf/Go is in the catalogue (row 535), but counts only where the scan
    # found a VRF (independent review of 0.51.0, 19.11: Vault read `partially_closed`).
    go = _eco(result, "Go")
    assert go["status"] == "not_closed" and go["closed_operations"] == []
    assert go["open_operations"] == ["external"] and "vrf" not in go["known_operations"]
    assert go["may_miss"].startswith("here we may miss")
    rust = _eco(result, "Rust")
    assert rust["status"] == "not_closed" and "vrf" not in rust["known_operations"]
    js = _eco(result, "JS")
    assert js["status"] == "not_closed" and js["closed_operations"] == []
    assert js["may_miss"].startswith("here we may miss")


def test_closed_when_every_operation_with_a_known_gap_is_in_the_catalogue(tmp_path, monkeypatch):
    monkeypatch.setitem(adaptive.KNOWN_OPERATIONS, "SSH", ("ssh",))
    result = scan_directory(_write(tmp_path, ECO_TREE))
    ssh = _eco(result, "SSH")
    assert ssh["status"] == "closed" and ssh["open_operations"] == []
    assert "may_miss" not in ssh


def test_an_empty_catalogue_says_so_rather_than_not_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(operations, "_load", lambda: ())
    result = scan_directory(_write(tmp_path, ECO_TREE))
    assert {e["status"] for e in result["ecosystems"]["present"]} == {"catalogue_not_loaded"}


# --- 2. angles --------------------------------------------------------------------------------

def test_declared_not_imported(tmp_path):
    result = scan_directory(_write(tmp_path, {
        "requirements.txt": "paramiko==3.4.0\n",
        "app/main.py": "print('hello')\n"}))
    rows = [c for c in result["angles"]["contradictions"] if c["rule"] == "declared_not_imported"]
    assert [(r["package"], r["path"], r["line"]) for r in rows] == [
        ("paramiko", "requirements.txt", 1)]
    assert rows[0]["kind"] == "declared, not seen"


def test_declared_and_imported_but_no_family_it_implements_in_the_code(tmp_path):
    result = scan_directory(_write(tmp_path, {
        "requirements.txt": "cryptography==47.0.0\n",
        "app/main.py": "from cryptography import x509\n"
                       "cert = x509.load_pem_x509_certificate(data)\n"}))
    rules = {(c["rule"], c.get("package")) for c in result["angles"]["contradictions"]}
    assert ("declared_no_family_in_code", "cryptography") in rules
    assert ("declared_not_imported", "cryptography") not in rules


def test_a_family_in_the_code_answers_the_declaration(tmp_path):
    result = scan_directory(_write(tmp_path, {
        "requirements.txt": "cryptography==47.0.0\n",
        "app/sign.py": "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                       "k = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"}))
    assert not [c for c in result["angles"]["contradictions"] if c.get("package") == "cryptography"]


def test_imported_not_declared(tmp_path):
    result = scan_directory(_write(tmp_path, {
        "requirements.txt": "requests==2.32.0\n",
        "app/token.py": "import jwt\nprint(jwt.decode(t, k, algorithms=['RS256']))\n"}))
    rows = [c for c in result["angles"]["contradictions"] if c["rule"] == "imported_not_declared"]
    assert [(r["package"], r["path"], r["line"]) for r in rows] == [("pyjwt", "app/token.py", 1)]
    assert rows[0]["kind"] == "seen, not declared"


def test_a_local_module_of_that_name_is_not_an_undeclared_package(tmp_path):
    result = scan_directory(_write(tmp_path, {
        "requirements.txt": "requests==2.32.0\n",
        "app/rsa.py": "x = 1\n",
        "app/main.py": "import rsa\n"}))
    assert not [c for c in result["angles"]["contradictions"]
                if c["rule"] == "imported_not_declared"]


def test_ecosystems_whose_imports_are_not_read_are_said_not_compared(tmp_path):
    result = scan_directory(_write(tmp_path, {
        "go.mod": "module x\n\nrequire golang.org/x/crypto v0.30.0\n",
        "main.go": 'package main\nimport "fmt"\nfunc main() { fmt.Println(1) }\n'}))
    assert [n["ecosystem"] for n in result["angles"]["not_compared"]] == ["go"]
    assert set(result["angles"]["not_compared"][0]["rules"]) == {
        "declared_not_imported", "imported_not_declared"}
    # The family rule still runs: nothing of what x/crypto implements is in the Go code.
    assert any(c["rule"] == "declared_no_family_in_code" and c["ecosystem"] == "go"
               for c in result["angles"]["contradictions"])


# --- 3. leads ---------------------------------------------------------------------------------

LEAD_TREE = {
    "nginx/nginx.conf": "http {\n  include conf.d/*.conf;\n  include /etc/nginx/mime.types;\n"
                        "  include missing/site.conf;\n  include {{ extra }}/x.conf;\n"
                        "  server {\n    listen 443 ssl;\n"
                        "    ssl_certificate /etc/ssl/srv.crt;\n"
                        "    ssl_trusted_certificate ca.pem;\n  }\n}\n",
    "nginx/conf.d/site.conf": "server_tokens off;\n",
    "app/serve.py": "import os, ssl\n"
                    "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
                    "ctx.load_cert_chain('certs/server.pem', 'certs/server.key')\n"
                    "cert = os.environ['TLS_CERT_FILE']\n",
    "certs/server.pem": "not a certificate\n",
    "deploy/sshd_config": "HostKey /etc/ssh/ssh_host_ed25519_key\n",
}


def _leads(result: dict) -> list[dict]:
    return result["chosen_outside_files"]["leads"]["items"]


def test_includes_are_followed_to_the_files_read_or_said_not_followed(tmp_path):
    result = scan_directory(_write(tmp_path, LEAD_TREE))
    includes = {l["target"]: l for l in _leads(result) if l["rule"] == "include"}
    assert includes["conf.d/*.conf"]["status"] == "followed"
    assert includes["conf.d/*.conf"]["files"] == ["nginx/conf.d/site.conf"]
    assert includes["/etc/nginx/mime.types"]["status"] == "outside_the_tree"
    assert includes["missing/site.conf"]["status"] == "not_found"
    assert includes["{{ extra }}/x.conf"]["status"] == "templated"


def test_key_and_certificate_paths_in_code_and_config(tmp_path):
    result = scan_directory(_write(tmp_path, LEAD_TREE))
    files = {(l["rule"], l["target"]): l["status"] for l in _leads(result)}
    assert files[("key_file_path", "certs/server.pem")] == "followed"
    assert files[("key_file_path", "certs/server.key")] == "not_found"
    assert files[("key_file_path", "/etc/ssh/ssh_host_ed25519_key")] == "outside_the_tree"
    assert files[("key_file_from_environment", "TLS_CERT_FILE")] == "read_at_run_time"


def test_what_other_sections_report_is_not_repeated(tmp_path):
    result = scan_directory(_write(tmp_path, LEAD_TREE))
    lines = {(l["path"], l["line"]) for l in _leads(result)}
    # ssl_certificate is tls_listeners' and tls_termination's; ssl_trusted_certificate is
    # trust_stores'.
    assert ("nginx/nginx.conf", 8) not in lines and ("nginx/nginx.conf", 9) not in lines
    elsewhere = result["chosen_outside_files"]["leads"]["reported_elsewhere"]
    assert elsewhere["trust_stores"] == 1


def test_the_places_and_their_count_stay_as_they_were(tmp_path):
    root = _write(tmp_path, {**LEAD_TREE,
                             "app/alg.py": 'import os\nalg = os.getenv("SIGN_ALG", "RSA-PSS")\n'})
    block = scan_directory(root)["chosen_outside_files"]
    assert block["count"] == len(block["places"]) == 1
    assert block["places"][0]["setting"].lower().startswith("sign")


# --- 4. where to look -------------------------------------------------------------------------

def test_where_to_look_orders_production_before_tests_and_kinds_by_rule(tmp_path):
    result = scan_directory(_write(tmp_path, {
        **LEAD_TREE, **ECO_TREE, "requirements.txt": "paramiko==3.4.0\ncryptography==47.0.0\n"}))
    items = result["where_to_look"]["items"]
    assert [i["rank"] for i in items] == list(range(1, len(items) + 1))
    kinds = [i["kind"] for i in items if not i["in_test_code"]]
    order = list(adaptive.KIND_ORDER)
    assert kinds == sorted(kinds, key=order.index)
    tested = [i["in_test_code"] for i in items]
    assert tested == sorted(tested)
    assert {"ecosystem_not_closed", "lead_not_followed", "contradiction"} <= set(kinds)
    assert result["where_to_look"]["count"] == len(items)
    assert "first" in result["where_to_look"]["order"]


# --- the invariant ----------------------------------------------------------------------------

INVARIANT_TREE = {**LEAD_TREE, **ECO_TREE,
                  "app/weak.py": "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                                 "k = rsa.generate_private_key(public_exponent=65537, "
                                 "key_size=1024)\n"}


def _cli(tmp_path, tag):
    out = tmp_path / f"{tag}.json"
    with pytest.raises(SystemExit) as code:
        main(["scan", str(tmp_path / "src"), "--out", str(out), "--no-config", "--level", "full",
              "--mandate", "cnsa-2.0", "--lead-months", "120", "--as-of", "2026-11-18"])
    return json.loads(out.read_text()), code.value.code


def test_every_exit_carries_the_sections(tmp_path):
    src = _write(tmp_path / "src", INVARIANT_TREE)
    direct = scan_directory(src)
    tool = getattr(scan_repo, "fn", scan_repo)(str(src), level="full")
    cli, _ = _cli(tmp_path, "cli")
    for key in ("ecosystems", "angles", "where_to_look"):
        assert direct[key] == tool[key] == cli[key], key
    assert direct["chosen_outside_files"]["leads"] == cli["chosen_outside_files"]["leads"]


def test_they_move_neither_findings_nor_fingerprint_nor_gate_nor_exit_code(tmp_path, monkeypatch):
    _write(tmp_path / "src", INVARIANT_TREE)
    with_sections, code_with = _cli(tmp_path, "with")
    monkeypatch.setattr(adaptive, "annotate", lambda result, root: None)
    without, code_without = _cli(tmp_path, "without")
    assert "where_to_look" in with_sections and "where_to_look" not in without
    for key in ("findings", "findings_fingerprint", "evidence", "summary", "mandates",
                "operation_closure", "trust_stores", "tls_listeners", "tls_termination"):
        assert with_sections[key] == without[key], key
    leads = with_sections["chosen_outside_files"].pop("leads")
    assert leads["items"]
    assert with_sections["chosen_outside_files"] == without["chosen_outside_files"]
    # RSA-1024 and CNSA 2.0 deadlines within ten years: the gate fails in both.
    assert code_with == code_without == 1
    altered = dict(with_sections, ecosystems={}, angles={}, where_to_look={"items": [1]})
    assert findings_fingerprint(altered) == findings_fingerprint(with_sections)


def test_the_same_tree_gives_the_same_sections_under_any_hash_seed(tmp_path):
    src = _write(tmp_path / "src", INVARIANT_TREE)
    script = ("import json,sys; from qrp_mcp.scan import scan_directory;"
              " r=scan_directory(sys.argv[1]);"
              "print(json.dumps([r['ecosystems'], r['angles'], r['where_to_look'],"
              " r['chosen_outside_files']['leads']], sort_keys=True))")
    outs = []
    for seed in ("1", "2"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": SRC}
        outs.append(subprocess.run([sys.executable, "-c", script, str(src)], env=env,
                                   capture_output=True, text=True, check=True).stdout)
    assert outs[0] == outs[1] and outs[0].strip()


# --- found on the positive control (certbot, Vault), pinned before the fix ----------------------

def test_an_environment_name_must_say_key_or_certificate_as_a_word(tmp_path):
    result = scan_directory(_write(tmp_path, {
        "app/a.py": "import os\np = os.environ.get('CERTBOT_PLUGIN_PATH')\n"
                    "q = os.environ.get('SSL_CERT_FILE')\n"}))
    assert [l["target"] for l in _leads(result)] == ["SSL_CERT_FILE"]


def test_a_command_before_a_key_path_is_not_a_setting(tmp_path):
    result = scan_directory(_write(tmp_path, {
        ".github/workflows/ci.yml":
            "steps:\n  - run: |\n      sha256sum ./support/private_key.pem\n",
        "vpn/client.conf": "client\nca ca.crt\n"}))
    assert [(l["path"], l["setting"]) for l in _leads(result)] == [("vpn/client.conf", "ca")]


def test_a_relative_path_is_followed_from_the_nearest_parent_that_has_it(tmp_path):
    result = scan_directory(_write(tmp_path, {
        "etc/nginx/fastcgi.conf": "fastcgi_param A b;\n",
        "etc/nginx/sites-available/site.conf": "server {\n  include fastcgi.conf;\n}\n"}))
    lead = next(l for l in _leads(result) if l["rule"] == "include")
    assert lead["status"] == "followed_from_parent"
    assert lead["files"] == ["etc/nginx/fastcgi.conf"]
    assert not result["angles"]["contradictions"]


def test_a_symlinked_target_is_in_the_tree_not_read(tmp_path):
    _write(tmp_path, {"conf/archive/cert1.pem": "x\n",
                      "conf/renewal/site.conf": "cert = live/cert.pem\n"})
    (tmp_path / "conf/live").mkdir()
    (tmp_path / "conf/live/cert.pem").symlink_to(tmp_path / "conf/archive/cert1.pem")
    result = scan_directory(tmp_path)
    lead = next(l for l in _leads(result) if l["target"] == "live/cert.pem")
    assert lead["status"] == "in_the_tree_not_read"
    assert not [c for c in result["angles"]["contradictions"]
                if c["rule"] == "named_key_file_absent"]


def test_a_placeholder_or_a_format_string_is_templated_not_absent(tmp_path):
    # The hand-judged sample of the control (etap3/izvadka-10.jsonl): certbot's MAGICDIR and
    # 'archive/{0}/privkey4.pem', Vault's /path/to/cacert.pem.
    result = scan_directory(_write(tmp_path, {
        "conf/renewal.conf": "privkey = MAGICDIR/live/x/privkey.pem\n",
        "agent.hcl": 'tls_cert_file = "/path/to/cacert.pem"\n',
        "app/t.py": "with open(join(d, 'archive/{0}/privkey4.pem').format(n)) as f:\n    pass\n"}))
    assert {l["target"]: l["status"] for l in _leads(result)} == {
        "MAGICDIR/live/x/privkey.pem": "templated", "/path/to/cacert.pem": "templated",
        "archive/{0}/privkey4.pem": "templated"}
    assert not result["angles"]["contradictions"]


def test_a_name_joined_to_a_directory_of_the_run_is_templated(tmp_path):
    # Vault's tests: os.ReadFile(filepath.Join(tempDir, "ca_cert.pem")), a file the test writes.
    result = scan_directory(_write(tmp_path, {
        "cert_test.go": 'package x\nfunc f() { b, _ := os.ReadFile(filepath.Join(tempDir, '
                        '"ca_cert.pem")); _ = b }\n',
        "t.py": "data = open(os.path.join(config_dir, 'live', 'cert.pem')).read()\n"}))
    assert {l["status"] for l in _leads(result)} == {"templated"}
    assert not result["angles"]["contradictions"]


# --- pins the mutation round found missing ----------------------------------------------------

def test_a_key_file_named_and_absent_is_a_contradiction(tmp_path):
    result = scan_directory(_write(tmp_path, LEAD_TREE))
    rows = [c for c in result["angles"]["contradictions"] if c["rule"] == "named_key_file_absent"]
    assert [(r["path"], r["line"], r["file"]) for r in rows] == [
        ("app/serve.py", 3, "certs/server.key")]
    assert rows[0]["kind"] == "declared, not seen"


def test_a_dangling_symlink_is_still_in_the_tree(tmp_path):
    _write(tmp_path, {"conf/renewal/site.conf": "cert = live/cert.pem\n"})
    (tmp_path / "conf/live").mkdir()
    (tmp_path / "conf/live/cert.pem").symlink_to("/etc/letsencrypt/archive/x/cert1.pem")
    result = scan_directory(tmp_path)
    lead = next(l for l in _leads(result) if l["target"] == "live/cert.pem")
    assert lead["status"] == "in_the_tree_not_read"


def test_vrf_counts_where_the_scan_found_a_vrf(tmp_path):
    tree = {**ECO_TREE, "cmd/elect.go": 'package main\nimport vrf "github.com/yahoo/coname/vrf"\n'
                                        "func e(s []byte, k *[64]byte) { vrf.Prove(s, k) }\n"}
    result = scan_directory(_write(tmp_path, tree))
    assert "vrf" in result["summary"]["by_role"]
    go = _eco(result, "Go")
    assert go["status"] == "partially_closed" and go["closed_operations"] == ["vrf"]
    assert go["open_operations"] == ["external"] and "vrf" in go["known_operations"]
    # The tree has no Rust VRF; Rust's status does not move with Go's.
    assert "vrf" not in _eco(result, "Rust")["closed_operations"]


def test_the_meaning_states_the_rule():
    from qrp_mcp.adaptive import ECOSYSTEMS_MEANING
    assert "only where the scan found" in ECOSYSTEMS_MEANING
    assert "18.11.2026)" not in ECOSYSTEMS_MEANING


def test_a_vrf_only_in_test_code_does_not_move_the_status(tmp_path):
    # Re-review of 0.51.0 (19.11): a VRF only in a _test.go file made Go `partially_closed`.
    tree = {**ECO_TREE, "cmd/elect_test.go": 'package main\nimport vrf "github.com/yahoo/coname/vrf"\n'
                                             "func e(s []byte, k *[64]byte) { vrf.Prove(s, k) }\n"}
    result = scan_directory(_write(tmp_path, tree))
    go = _eco(result, "Go")
    assert go["status"] == "not_closed" and "vrf" not in go["known_operations"]


# --- files read in no ecosystem (24.11.2026, Dong's ECH bench) -------------------------------

NA_TREE = {
    "cmd/main.go": 'package main\nimport "crypto/rsa"\nfunc main() { _ = rsa.GenerateKey }\n',
    "keys/ech-keys.json": '{"A": {"private_key_b64": "PjntTf1q+KbBhGczUxAis5BZQ1P0uLZyhLaOkFiuOdg="}}\n',
    "dns/https-rr.zone": "_8441._https.inner.example. 300 IN HTTPS 1 inner.example. port=8441 "
                         "ech=AEH+DQA9AQAgACDtAiDt\n",
    "dns/signed.zone": "example. 3600 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0d\n",
}


def test_a_file_read_in_no_ecosystem_is_said_so(tmp_path):
    result = scan_directory(_write(tmp_path, NA_TREE))
    na = result["ecosystems"]["not_attributed"]
    assert na["paths"] == ["dns/https-rr.zone", "keys/ech-keys.json"]
    assert na["count"] == 2 and na["meaning"].startswith("here we may miss")
    kinds = [i for i in result["where_to_look"]["items"] if i["kind"] == "files_not_attributed"]
    assert len(kinds) == 1 and kinds[0]["files"] == 2


def test_a_zone_is_dnssec_only_with_a_dnssec_record(tmp_path):
    result = scan_directory(_write(tmp_path, NA_TREE))
    assert _eco(result, "DNSSEC")["basis"] == {"config_content": 1}
    assert _eco(result, "DNSSEC")["example"] == "dns/signed.zone"


def test_not_attributed_leaves_by_every_exit(tmp_path):
    src = _write(tmp_path / "src", NA_TREE)
    direct = scan_directory(src)
    tool = getattr(scan_repo, "fn", scan_repo)(str(src), level="full")
    cli, _ = _cli(tmp_path, "na")
    assert (direct["ecosystems"]["not_attributed"] == tool["ecosystems"]["not_attributed"]
            == cli["ecosystems"]["not_attributed"])
    from qrp_mcp.cyclonedx import build
    props = {p["name"]: p["value"] for p in build(direct)["properties"]}
    assert props["qrp:ecosystems:not_attributed:count"] == "2"
    assert json.loads(props["qrp:ecosystems:not_attributed:paths"]) == [
        "dns/https-rr.zone", "keys/ech-keys.json"]


def test_not_attributed_reaches_the_cbom_of_the_command_and_of_the_tool(tmp_path):
    from qrp_mcp.server import export_cbom
    src = _write(tmp_path / "src", NA_TREE)
    out = tmp_path / "cbom.json"
    with pytest.raises(SystemExit):
        main(["cbom", str(src), "--out", str(out), "--no-config"])
    tool = getattr(export_cbom, "fn", export_cbom)(str(src))
    for cbom in (json.loads(out.read_text()), tool):
        props = {p["name"]: p["value"] for p in cbom["properties"]}
        assert props["qrp:ecosystems:not_attributed:count"] == "2"
