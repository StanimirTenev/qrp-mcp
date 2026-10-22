"""DNSSEC algorithms and the DNS size budget (ZA-OPRAVYANE row 33, 22.10.2026).

Georgi Ivanov's 1,232 bytes is the one number in the post-quantum DNSSEC trade-off that
sits in a file. On 0.31.0, a BIND dnssec-policy with `ecdsap256sha256` for the KSK and
`rsasha256` for the ZSK, `dnssec-keygen -a RSASHA256`, a signed zone and `max-udp-size
1232` gave: ECDSA only because the mnemonic has the letters, no curve; no RSA at all;
the .zone file not read; the size ignored.

The fixture is that test's tree. Mnemonics and numbers: IANA DNSSEC Algorithm Numbers
registry; mnemonics as BIND, Knot and PowerDNS write them (BIND 9 ARM dnssec-policy,
Knot DNS reference `algorithm:`, pdnsutil(1)); the sizes and their 1232 default: BIND 9
ARM `max-udp-size`, `edns-udp-size`.
"""

import json
import shutil
from pathlib import Path

import pytest

from qrp_mcp.cyclonedx import build
from qrp_mcp.scan import scan_directory

FIXTURE = Path(__file__).parent / "fixtures" / "dnssec"


def _tree(tmp_path, files=None):
    if files is None:
        shutil.copytree(FIXTURE, tmp_path / "t")
        return tmp_path / "t"
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def _found(result, path):
    return {(f["line"], f["algorithm"]) for f in result["evidence"]["source_code"]
            if f["path"] == path}


def test_the_test_tree_of_22_october(tmp_path):
    result = scan_directory(_tree(tmp_path))
    assert {(7, "ECDSA"), (8, "RSA")} <= _found(result, "named.conf")
    assert {(1, "ECDSA"), (2, "RSA")} <= _found(result, "keygen.sh")
    # The zone is read, and its DNSKEY algorithms 13 and 8 are named.
    assert "example.com.zone" in result["files_read"]
    assert {(3, "ECDSA"), (4, "RSA")} <= _found(result, "example.com.zone")
    ecdsa = [f for f in result["evidence"]["source_code"] if f["algorithm"] == "ECDSA"]
    assert ecdsa and all(f.get("curve") == "P-256" for f in ecdsa)
    rsa = {f["path"]: f.get("key_size") for f in result["evidence"]["source_code"]
           if f["algorithm"] == "RSA"}
    assert rsa["named.conf"] == 2048 and rsa["keygen.sh"] == 2048
    budget = {(a["udp_setting"], a["udp_size"]) for a in result["evidence"]["protocols"]
              if a["protocol"] == "dns"}
    assert budget == {("max-udp-size", 1232), ("edns-udp-size", 1232)}


@pytest.mark.parametrize("line,family", [
    ("    algorithm: rsasha512", "RSA"),                     # Knot
    ("default-ksk-algorithm=rsasha1-nsec3-sha1", "RSA"),     # PowerDNS
    ("pdnsutil add-zone-key example.com ksk active ecdsa384", "ECDSA"),
    ("dnssec-keygen -a RSAMD5 example.com", "RSA"),
    ("dnssec-keygen -a DSA-NSEC3-SHA1 example.com", "DSA"),
    ("dnssec-keygen -a ED448 example.com", "Ed448"),
])
def test_mnemonics(tmp_path, line, family):
    result = scan_directory(_tree(tmp_path, {"cfg.conf": line + "\n"}))
    assert family in {f["algorithm"] for f in result["evidence"]["source_code"]}


@pytest.mark.parametrize("line,family", [
    ("example.com. DS 12345 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE", "RSA"),
    ("example.com. 3600 IN RRSIG SOA 14 2 3600 20261101000000 20261001000000 1 example.com. abc", "ECDSA"),
    ('    "." static-key 257 3 15 "AwEAAagAIKlVZ";', "Ed25519"),
    ("example.com. IN DNSKEY 257 3 18 AAAA", "ML-DSA"),
    ("example.com. IN DNSKEY 257 3 5 AwEAAQ", "RSA"),
])
def test_record_numbers(tmp_path, line, family):
    result = scan_directory(_tree(tmp_path, {"a.zone": line + "\n"}))
    assert family in {f["algorithm"] for f in result["evidence"]["source_code"]}


def test_a_bare_number_is_not_an_algorithm(tmp_path):
    result = scan_directory(_tree(tmp_path, {"a.zone": "www IN A 192.0.2.8\nx IN TXT \"3 8\"\n",
                                             "b.conf": "keys 257 3 8 total\n"}))
    assert result["evidence"]["source_code"] == []


def test_bind_default_when_the_size_is_not_set(tmp_path):
    conf = 'dnssec-policy "p" {\n  keys { csk lifetime unlimited algorithm ecdsap256sha256; };\n};\n'
    result = scan_directory(_tree(tmp_path, {"named.conf": conf}))
    dns = [a for a in result["evidence"]["protocols"] if a["protocol"] == "dns"]
    assert [(a["udp_setting"], a["udp_size"], a.get("default_applied"), a["line"]) for a in dns] == [
        ("max-udp-size", 1232, True, 1)]
    cbom = build(result)
    props = [{p["name"]: p["value"] for p in c.get("properties", [])}
             for c in cbom["components"] if c["name"] == "DNS"]
    assert props and props[0]["qrp:udp_size"] == "1232" and props[0]["qrp:default_applied"] == "true"


def test_no_budget_without_dns(tmp_path):
    result = scan_directory(_tree(tmp_path, {"nginx.conf": "server { listen 443; }\n"}))
    assert not [a for a in result["evidence"]["protocols"] if a["protocol"] == "dns"]
