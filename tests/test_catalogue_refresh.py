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


# Stage 3b (18.11.2026): the 13 tightenings of obratna-proba/operacii/KANDIDATI-119.md §4, on the
# lines of the pages the noise came from. What a pattern (with its `ignore`) admits is read
# straight from the catalogue's own entry, not from Known, so a spelling that is confirmed later
# stays admitted here. Every exclusion is by shape ($, "(1)", ".a", *BYTES, a new line) or a
# named directive of another operation, never a list of the allowed names.
_PROXY = ("certificate", "certificate_cache", "certificate_key", "ciphers", "conf_command",
          "key_log", "name", "password_file", "server_name", "session_reuse", "verify_depth")
TIGHTENED = [
    ("tlsend", "nginx", "ngx_http_ssl_module.html",
     "$ssl_client_cert variable.\nssl_verify_depth number ;\nssl_verify_client on | off | optional ;\n"
     "ssl_client_certificate file ;\nssl_trusted_certificate file ;\n$ssl_client_verify variable.\n",
     {"ssl_client_cert", "ssl_verify_depth", "ssl_client_verify"},
     {"ssl_verify_client", "ssl_client_certificate", "ssl_trusted_certificate"}),
    *[("tlsend", "nginx", f"ngx_http_{m}_module.html",
       "".join(f"{m}_ssl_{d} x ;\n" for d in _PROXY + ("crl", "protocols", "verify", "trusted_certificate")),
       {f"{m}_ssl_{d}" for d in _PROXY},
       {f"{m}_ssl_{d}" for d in ("crl", "protocols", "verify", "trusted_certificate")})
      for m in ("proxy", "grpc", "uwsgi")],
    ("ssh", "SSH", "/sshd",
     "scp(1), sftp(1), ssh(1), ssh-add(1), ssh-agent(1),\nssh-keyscan(1) or by taking, for example,\n"
     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user\nsk-ssh-ed25519@openssh.com, rsa-sha2-512\n",
     {"ssh-add", "ssh-agent", "ssh-keyscan"}, {"ssh-ed25519", "sk-ssh-ed25519@openssh.com", "rsa-sha2-512"}),
    ("ssh", "SSH", "/sshd_config", "ssh-agent(1) sockets. Sockets may be created\nrsa-sha2-512,ssh-ed25519\n",
     {"ssh-agent"}, {"rsa-sha2-512", "ssh-ed25519"}),
    ("keysize", "NET", "new-selfsignedcertificate",
     "-KeyAlgorithm\nSpecifies the name of the algorithm\n-KeyAlgorithm RSA\nKeyAlgorithm = 'ECDSA_nistP256'\n",
     {"Specifies"}, {"RSA", "ECDSA_nistP256"}),
    *[("pqc", "C", page,
       f"{p}_alg_identifier (size_t i)\n{p}_alg_count (void)\n{p}_alg_is_enabled (const char *method_name)\n"
       f"#define {p}_alg_ml_x \"X\"\n",
       {f"{p}_alg_identifier", f"{p}_alg_count", f"{p}_alg_is_enabled"}, {f"{p}_alg_ml_x"})
      for p, page in (("OQS_KEM", "kem_8h.html"), ("OQS_SIG", "/sig_8h.html"), ("OQS_SIG_STFL", "sig__stfl_8h.html"))],
    ("pqc", "C", "read.me",
     "(and so -lpthread is required to link), and hss_verify.a, which just includes\n"
     "hss_generate_private_key and hss_validate_signature\n",
     {"hss_verify"}, {"hss_generate_private_key", "hss_validate_signature"}),
    ("external", "Py", "/os.html",
     "os.putenv()\nos.unsetenv\nos.getenv\nos.environ\n", {"os.putenv", "os.unsetenv"}, {"os.getenv", "os.environ"}),
    ("apiname", "C", "authenticated_encryption",
     "#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)\ncrypto_box_PUBLICKEYBYTES\ncrypto_box_easy\n"
     "crypto_box_keypair\n",
     {"crypto_box_MACBYTES", "crypto_box_PUBLICKEYBYTES"}, {"crypto_box_easy", "crypto_box_keypair"}),
    ("apiname", "C", "scalar_multiplication",
     "crypto_scalarmult_BYTES and crypto_scalarmult_SCALARBYTES\ncrypto_scalarmult_base\n",
     {"crypto_scalarmult_BYTES", "crypto_scalarmult_SCALARBYTES"}, {"crypto_scalarmult_base"}),
    ("apiname", "C", "public-key_signatures",
     "crypto_sign_verify()\ncrypto_sign_BYTES\ncrypto_sign_PUBLICKEYBYTES\ncrypto_sign_verify_detached\n"
     "crypto_sign_keypair\n",
     {"crypto_sign_verify", "crypto_sign_BYTES", "crypto_sign_PUBLICKEYBYTES"},
     {"crypto_sign_verify_detached", "crypto_sign_keypair"}),
    ("apiname", "C", "EVP_PKEY_set1_RSA.pod",
     "EVP_PKEY_get0_hmac, EVP_PKEY_get0_poly1305, EVP_PKEY_get0_siphash,\nEVP_PKEY_set1_engine, EVP_PKEY_get0_engine,\n"
     "L<EVP_PKEY_get0_type_name(3)> is more generally useful.\nEVP_PKEY_assign_POLY1305, EVP_PKEY_assign_SIPHASH,\n"
     "EVP_PKEY_get1_RSA, EVP_PKEY_set1_EC_KEY\n",
     {"EVP_PKEY_get0_hmac", "EVP_PKEY_get0_poly1305", "EVP_PKEY_get0_siphash", "EVP_PKEY_set1_engine",
      "EVP_PKEY_get0_engine", "EVP_PKEY_get0_type_name", "EVP_PKEY_assign_POLY1305", "EVP_PKEY_assign_SIPHASH"},
     {"EVP_PKEY_get1_RSA", "EVP_PKEY_set1_EC_KEY"}),
    ("apiname", "C", "EVP_PKEY_CTX_new.pod",
     "EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_new_from_name,\nEVP_PKEY_CTX_new_from_pkey, EVP_PKEY_CTX_dup,\n",
     {"EVP_PKEY_CTX_new", "EVP_PKEY_CTX_new_from_pkey"}, {"EVP_PKEY_CTX_new_id", "EVP_PKEY_CTX_new_from_name"}),
    ("apiname", "C", "gnutls-gnutls.html",
     "GNUTLS_PK_UNKNOWN\nGNUTLS_PK_RSA\nGNUTLS_PK_GOST_12_256\nGNUTLS_PK_MAX\nGNUTLS_PK_EXP_MAX\nGNUTLS_SIGN_GOST_94\n",
     {"GNUTLS_PK_UNKNOWN", "GNUTLS_PK_MAX", "GNUTLS_PK_EXP_MAX"},
     {"GNUTLS_PK_RSA", "GNUTLS_PK_GOST_12_256", "GNUTLS_SIGN_GOST_94"}),
    *[("keysize" if size else "keyfile", "PKI", "rfc7468.txt",
       "".join(f"-----BEGIN {label}-----\n" for label in ("X509 CRL", "ATTRIBUTE CERTIFICATE",
                                                          "ENCRYPTED PRIVATE KEY", "PKCS7", "CERTIFICATE")),
       {"X509 CRL", "ATTRIBUTE CERTIFICATE", "ENCRYPTED PRIVATE KEY"} if size else set(),
       {"PKCS7", "CERTIFICATE"} | (set() if size else {"X509 CRL", "ATTRIBUTE CERTIFICATE", "ENCRYPTED PRIVATE KEY"}))
      for size in (True, False)],
]


def _admitted(operation, ecosystem, page, text):
    """What the refresh entries of that page (by the end of its URL) admit on `text`."""
    import re
    from qrp_mcp import operations
    entries = [e for doc in operations.catalogue() if doc["operation"] == operation
               for eco in doc["ecosystems"] if eco["ecosystem"] == ecosystem
               for e in eco.get("refresh", []) if e["source"].endswith(page)]
    assert entries, page
    out = set()
    for entry in entries:
        pattern = re.compile(entry["pattern"])
        ignore = {i.lower() for i in entry.get("ignore", [])}
        hits = [m.group(1) if pattern.groups else m.group(0) for m in pattern.finditer(text)]
        out |= {h for h in hits if h.lower() not in ignore}
    return out


@pytest.mark.parametrize("operation, ecosystem, page, text, dropped, kept", TIGHTENED,
                         ids=[f"{t[0]}/{t[1]}/{t[2]}" for t in TIGHTENED])
def test_a_tightened_pattern_drops_the_noise_and_keeps_the_names(operation, ecosystem, page, text, dropped, kept):
    admitted = _admitted(operation, ecosystem, page, text)
    assert not admitted & dropped, sorted(admitted & dropped)
    assert kept <= admitted, sorted(kept - admitted)
