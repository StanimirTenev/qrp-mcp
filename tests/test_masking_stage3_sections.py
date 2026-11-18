"""The stage-3 sections quote at the level the rest of the result quotes (18.11.2026, before the
0.50.0 tag; `zadachi/qrp-mcp/izdanie-0.50.0/maskirane/NAHODKA.md`).

At `masked`, the default, and at `trimmed`, `where_to_look` wrote out the path of a trust store
that `trust_stores` masks (row 517), and `chosen_outside_files.leads` wrote out the target of an
include, a key file named by path and the name of an environment variable -- source text. The
same held for the path a TLS server loads its certificate from
(`tls_termination.authentication_not_read`, in the clear since 0.41.0), which `where_to_look`
repeats. Not changed here: `chosen_outside_files.places` keeps the name of a setting read from
the environment in `setting` and `read_from` at every level, as it has since before 0.50.0.

Below `full`, a path that is not a file read is masked as a line is, on every occurrence: a lead
that was followed keeps its target (it is files read), as a trust store read keeps its path.
`where_to_look` is built again from the masked sections, so it cannot disagree with them. At
`full` everything is written as before. CBOM and SARIF carry none of these sections.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory
from qrp_mcp.server import _at_level, scan_repo

SRC = str(Path(__file__).resolve().parents[1] / "src")
LEVELS = ("masked", "trimmed", "full")
SECTIONS = ("ecosystems", "angles", "chosen_outside_files.leads", "where_to_look",
            "operation_closure")

# NAHODKA.md, byte for byte.
NAHODKA = """http {
 server {
  ssl_client_certificate /etc/secret-ca/token-abc123.pem;
  include /etc/nginx/secret-xyz789.conf;
 }
}
"""
NAHODKA_NEEDLES = ("/etc/secret-ca/token-abc123.pem", "/etc/nginx/secret-xyz789.conf",
                   "token-abc123", "secret-xyz789", "secret-ca")

# A tree with sensitive-looking paths and environment names, none of them a file in the tree.
NGINX = """http {
 server {
  listen 443 ssl;
  ssl_protocols TLSv1.3;
  ssl_ecdh_curve X25519:prime256v1;
  ssl_certificate /etc/letsencrypt/live/hidden-host.example/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/hidden-host.example/privkey.pem;
  ssl_client_certificate /etc/secret-ca/token-abc123.pem;
  ssl_trusted_certificate private-trust/bundle-q7.pem;
  include /etc/nginx/secret-xyz789.conf;
  include snippets/missing-k4.conf;
 }
}
"""
SSHD = """HostKey /etc/ssh/hostkey-vault-77
Include /etc/ssh/sshd_config.d/hidden-55.conf
"""
PY = """import os, ssl
from cryptography.hazmat.primitives import serialization
ctx = ssl.create_default_context(cafile="/opt/corp-secret/ca-bundle-zz.pem")
key = open("/srv/keys/signing-key-qq.pem", "rb").read()
k2 = open(os.environ["PAYROLL_SIGNING_KEY_PATH"]).read()
priv = serialization.load_pem_private_key(open("keys/local-absent-r9.pem", "rb").read(), None)
"""
# Review B2 (PREGLED.md, 18.11): a YAML/INI key before a key file's path is source text too -- a
# host, a service, a customer -- whether the lead is followed (certs/c.pem is read) or not.
YAML = """zzhost.corp.example: certs/c.pem
zzhost2.corp: /opt/zzopt/c.pem
"""
TREE = {"conf/nginx.conf": NGINX, "conf/sshd_config": SSHD, "app/main.py": PY,
        "conf/app.yaml": YAML, "conf/certs/c.pem": "x\n"}
NEEDLES = ("hidden-host", "token-abc123", "secret-ca", "bundle-q7", "private-trust",
           "secret-xyz789", "missing-k4", "hostkey-vault-77", "hidden-55", "ca-bundle-zz",
           "corp-secret", "signing-key-qq", "srv/keys", "PAYROLL_SIGNING_KEY_PATH",
           "local-absent-r9", "zzhost", "zzopt")


def _write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


def _cli(root: Path, out: Path, *args: str) -> dict:
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", *args,
                    str(root), "--out", str(out), "--no-config"],
                   check=True, capture_output=True, env={"PYTHONPATH": SRC, "PATH": "/usr/bin"})
    return json.loads(out.read_text())


def _section(result: dict, name: str):
    node = result
    for part in name.split("."):
        node = (node or {}).get(part)
    return node


def _text(node) -> str:
    return json.dumps(node, ensure_ascii=False)


def _found(text: str, needles) -> list[str]:
    return [n for n in needles if n in text]


# --- the reproduction of NAHODKA.md, through both exits ---------------------------------------

@pytest.mark.parametrize("level", ("masked", "trimmed"))
def test_nahodka_scan_out_masks_the_trust_store_and_the_include(tmp_path, level):
    root = _write(tmp_path / "darvo", {"nginx.conf": NAHODKA})
    result = _cli(root, tmp_path / "out.json", "scan", "--level", level)
    assert result["excerpt_level"] == level
    assert _found(_text(result), NAHODKA_NEEDLES) == []
    masked = result["trust_stores"]["places"][0]["file"]
    assert masked == "/***/******-**/*****-******.***"
    # where_to_look says what trust_stores says, not something else.
    look = {i["rule"]: i for i in result["where_to_look"]["items"] if i.get("rule")}
    assert look["trust_stores"]["target"] == masked
    assert masked in look["trust_stores"]["statement"]
    lead = result["chosen_outside_files"]["leads"]["items"][0]
    assert lead["target"] == look["include"]["target"] != "/etc/nginx/secret-xyz789.conf"
    assert lead["target"] in look["include"]["statement"]


def test_nahodka_default_level_of_scan_out_is_masked(tmp_path):
    root = _write(tmp_path / "darvo", {"nginx.conf": NAHODKA})
    result = _cli(root, tmp_path / "out.json", "scan")
    assert result["excerpt_level"] == "masked"
    assert _found(_text(result), NAHODKA_NEEDLES) == []


def test_nahodka_full_still_writes_them(tmp_path):
    root = _write(tmp_path / "darvo", {"nginx.conf": NAHODKA})
    result = _cli(root, tmp_path / "out.json", "scan", "--level", "full")
    look = _text(result["where_to_look"])
    assert "/etc/secret-ca/token-abc123.pem" in look and "/etc/nginx/secret-xyz789.conf" in look
    assert (result["chosen_outside_files"]["leads"]["items"][0]["target"]
            == "/etc/nginx/secret-xyz789.conf")
    assert result["trust_stores"]["places"][0]["file"] == "/etc/secret-ca/token-abc123.pem"


@pytest.mark.parametrize("level", ("masked", "trimmed"))
def test_nahodka_scan_repo_tool(tmp_path, level):
    root = _write(tmp_path / "darvo", {"nginx.conf": NAHODKA})
    tool = getattr(scan_repo, "fn", scan_repo)
    assert _found(_text(tool(str(root), level=level)), NAHODKA_NEEDLES) == []
    assert _found(_text(tool(str(root))), NAHODKA_NEEDLES) == []
    assert "secret-xyz789" in _text(tool(str(root), level="full")["where_to_look"])


# --- each level, each stage-3 section ---------------------------------------------------------

@pytest.fixture(scope="module")
def scanned(tmp_path_factory):
    root = _write(tmp_path_factory.mktemp("tree"), TREE)
    return {level: _at_level(scan_directory(root), level) for level in LEVELS}


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("level", ("masked", "trimmed"))
def test_a_section_below_full_quotes_no_unread_path(scanned, level, section):
    node = _section(scanned[level], section)
    assert node is not None, section
    assert _found(_text(node), NEEDLES) == [], section


@pytest.mark.parametrize("section", ("angles", "chosen_outside_files.leads", "where_to_look"))
def test_the_needles_are_live_at_full(scanned, section):
    # The sections that carry the paths do carry them at full: the test above is not passing
    # because the fixture never reached them.
    assert _found(_text(_section(scanned["full"], section)), NEEDLES), section


def test_every_needle_is_somewhere_at_full(scanned):
    text = _text(scanned["full"])
    assert [n for n in NEEDLES if n not in text] == []


@pytest.mark.parametrize("level", ("masked", "trimmed"))
def test_where_to_look_agrees_with_the_sections_it_quotes(scanned, level):
    result = scanned[level]
    targets = {i["target"] for i in result["where_to_look"]["items"] if "target" in i}
    sources = ({p["file"] for p in result["trust_stores"]["places"]}
               | {p["file"] for p in result["tls_termination"]["authentication_not_read"]
                  ["places"]}
               | {l["target"] for l in result["chosen_outside_files"]["leads"]["items"]})
    assert targets and targets <= sources
    for item in result["where_to_look"]["items"]:
        if "target" in item:
            assert item["target"] in item["statement"]
    for c in result["angles"]["contradictions"]:
        if c.get("file"):
            assert c["file"] in c["statement"]


def test_a_followed_lead_keeps_its_target(tmp_path):
    root = _write(tmp_path, {"nginx/nginx.conf": "http {\n  include conf.d/*.conf;\n}\n",
                             "nginx/conf.d/site.conf": "server_tokens off;\n"})
    result = _at_level(scan_directory(root), "masked")
    lead = result["chosen_outside_files"]["leads"]["items"][0]
    assert lead["status"] == "followed" and lead["target"] == "conf.d/*.conf"


# --- tls_termination.authentication_not_read (since 0.41.0) ---------------------------------

@pytest.mark.parametrize("level", ("masked", "trimmed"))
def test_a_certificate_path_outside_the_files_read_is_masked_below_full(scanned, level):
    places = scanned[level]["tls_termination"]["authentication_not_read"]["places"]
    assert places and _found(_text(places), NEEDLES) == []
    assert places[0]["file"] == "/***/***********/****/******-****.*******/*********.***"
    full = scanned["full"]["tls_termination"]["authentication_not_read"]["places"]
    assert full[0]["file"] == "/etc/letsencrypt/live/hidden-host.example/fullchain.pem"


# --- the generic one: the whole output, every exit --------------------------------------------

def test_masked_output_quotes_no_unread_path_on_any_exit(tmp_path):
    root = _write(tmp_path / "tree", TREE)
    full = _cli(root, tmp_path / "full.json", "scan", "--level", "full")
    assert [n for n in NEEDLES if n not in _text(full)] == []
    for args in (("scan",), ("scan", "--level", "masked"), ("cbom",),
                 ("scan", "--format", "sarif")):
        out = _cli(root, tmp_path / "out.json", *args)
        assert _found(_text(out), NEEDLES) == [], args
    tool = getattr(scan_repo, "fn", scan_repo)(str(root))
    assert _found(_text(tool), NEEDLES) == []


@pytest.mark.parametrize("level", ("masked", "trimmed"))
def test_where_to_look_keeps_its_order_and_rows_below_full(scanned, level):
    def shape(result):
        return [(i["rank"], i["kind"], i.get("rule"), i.get("path"), i.get("line"),
                 i.get("status")) for i in result["where_to_look"]["items"]]
    assert shape(scanned[level]) == shape(scanned["full"])


# --- review B2: the key a key file is named under ---------------------------------------------

@pytest.mark.parametrize("level", ("masked", "trimmed"))
def test_a_config_key_before_a_key_path_is_masked_below_full(scanned, level):
    leads = scanned[level]["chosen_outside_files"]["leads"]["items"]
    yaml = {l["status"]: l for l in leads if l["path"] == "conf/app.yaml"}
    assert set(yaml) == {"followed", "outside_the_tree"}
    assert yaml["followed"]["setting"] == "******.****.*******"
    assert yaml["followed"]["target"] == "certs/c.pem"          # files read keep their path
    assert yaml["outside_the_tree"]["setting"] == "*******.****"
    look = [i for i in scanned[level]["where_to_look"]["items"] if i.get("path") == "conf/app.yaml"]
    assert look and all("zz" not in i["statement"] for i in look)
    full = {l["status"]: l["setting"] for l in scanned["full"]["chosen_outside_files"]["leads"]
            ["items"] if l["path"] == "conf/app.yaml"}
    assert full == {"followed": "zzhost.corp.example", "outside_the_tree": "zzhost2.corp"}


@pytest.mark.parametrize("level", ("masked", "trimmed"))
def test_the_fixed_vocabulary_of_a_lead_stays_readable(scanned, level):
    settings = {(l["rule"], l["setting"])
                for l in scanned[level]["chosen_outside_files"]["leads"]["items"]}
    assert {("include", "include"), ("include", "Include"), ("key_file_path", "HostKey"),
            ("key_file_path", "open"),
            ("key_file_from_environment", "environment variable")} <= settings


def test_b2_reproduction_through_scan_out(tmp_path):
    # pregled/fixtures/v2-e, as the review ran it.
    root = _write(tmp_path / "e", {"certs/c.pem": "x\n", "app.yaml": YAML})
    for args in (("scan",), ("scan", "--level", "trimmed")):
        assert "zzhost" not in _text(_cli(root, tmp_path / "m.json", *args)), args
    assert "zzhost.corp.example" in _text(_cli(root, tmp_path / "f.json", "scan", "--level",
                                               "full"))
