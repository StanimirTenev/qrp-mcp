"""ZA-OPRAVYANE row 536 (LinkedIn, 19.11.2026): an RFC 3161 time-stamp request is a place.

The reproduction (`linkedin-postove/2026-11-19/chernovi/raw/proba/fx/tsa`, qrp-mcp 0.50.0):
`rfc3161ng.RemoteTimestamper(...)` and `openssl ts -query` gave no row and no place;
`chosen_outside_files.places` was 0. The token is signed by the time-stamping authority with its
own key -- the algorithm is chosen there, outside the files, as with a KMS (`remote_signing`). It
is now a place, `kind: remote_timestamp`, with no family.

The hash of the request's messageImprint is chosen here, by the requester (Daniel J.'s answer,
19.11): `openssl ts -query -sha256`, `hashname="sha256"`. The place says it as `hash_choice`; where
no hash is written, the default of the library in use -- never a version's default assumed
(openssl-ts(1): SHA-256 in 3.0, SHA-1 in 1.1.1).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory
from qrp_mcp.server import scan_repo

STAMP_PY = '''from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import rfc3161ng

def stamp(data: bytes):
    tsa = rfc3161ng.RemoteTimestamper("https://freetsa.org/tsr", hashname="sha256")
    return tsa.timestamp(data=data)

def sign_record(data: bytes):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
'''
STAMP_SH = '''openssl ts -query -data record.pdf -sha256 -cert -out req.tsq
curl -s -H "Content-Type: application/timestamp-query" --data-binary @req.tsq https://freetsa.org/tsr -o resp.tsr
openssl ts -verify -in resp.tsr -queryfile req.tsq -CAfile cacert.pem
'''
REQUIREMENTS = "cryptography==43.0.1\nrfc3161ng==2.1.3\n"


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return root


def _places(result: dict) -> dict:
    return {(p["path"], p["line"]): p for p in result["chosen_outside_files"]["places"]}


def test_the_reproduction_names_both_places(tmp_path):
    result = scan_directory(str(_tree(tmp_path, {"stamp.py": STAMP_PY, "stamp.sh": STAMP_SH,
                                                 "requirements.txt": REQUIREMENTS})))
    places = _places(result)
    for at in (("stamp.py", 6), ("stamp.sh", 1)):
        place = places.get(at)
        assert place, (at, places)
        assert place["kind"] == "remote_timestamp"
        assert place["key_location"] == "tsa"
        assert place["hash_choice"] == "sha256"
        assert "family" not in place and "default_family" not in place
    # -verify chooses nothing; curl only carries the request.
    assert ("stamp.sh", 3) not in places and ("stamp.sh", 2) not in places
    assert result["chosen_outside_files"]["count"] == len(result["chosen_outside_files"]["places"])
    # The findings are what they were: the RSA key and its signature, nothing for the stamp.
    assert {f["algorithm_family"] for f in result["findings"]} == {"RSA"}


@pytest.mark.parametrize("line, hash_choice", [
    ("openssl ts -query -data f.bin -out q.tsq", "default of the OpenSSL in use"),
    ("openssl ts -query -data f.bin -sha512 -no_nonce -out q.tsq", "sha512"),
    ("openssl ts -query -data f.bin -sha3-256 -out q.tsq", "sha3-256"),
    ("openssl ts -query -data f.bin -sha1 -out q.tsq", "sha1"),
    ("  run: openssl  ts  -query -data dist/app.tar.gz -sha384 -cert -out app.tsq", "sha384"),
])
def test_openssl_ts_query_hash_choice(tmp_path, line, hash_choice):
    result = scan_directory(str(_tree(tmp_path, {"ci.sh": line + "\n"})))
    place = _places(result).get(("ci.sh", 1))
    assert place and place["kind"] == "remote_timestamp", _places(result)
    assert place["hash_choice"] == hash_choice


@pytest.mark.parametrize("line", [
    "openssl ts -reply -queryfile q.tsq -inkey tsakey.pem -signer tsacert.pem -out r.tsr",
    "openssl ts -verify -data f.bin -in r.tsr -CAfile ca.pem",
    "# openssl ts -query -data f.bin -sha256",
    "echo openssl tsx -query",
])
def test_reply_verify_and_comments_are_not_places(tmp_path, line):
    result = scan_directory(str(_tree(tmp_path, {"ci.sh": line + "\n"})))
    assert not [p for p in result["chosen_outside_files"]["places"]
                if p.get("kind") == "remote_timestamp"]


def test_rfc3161ng_without_a_hash_is_the_library_default(tmp_path):
    body = ("from rfc3161ng import RemoteTimestamper\n"
            "rt = RemoteTimestamper('http://time.certum.pl', certificate=certificate)\n")
    place = _places(scan_directory(str(_tree(tmp_path, {"t.py": body})))).get(("t.py", 2))
    assert place and place["kind"] == "remote_timestamp"
    assert place["hash_choice"] == "default of the rfc3161ng in use"


def test_rfc3161ng_hashname_on_the_next_line(tmp_path):
    body = ("import rfc3161ng\n"
            "rt = rfc3161ng.RemoteTimestamper(\n"
            "    'https://tsa.example/tsr',\n"
            "    hashname='sha512')\n")
    place = _places(scan_directory(str(_tree(tmp_path, {"t.py": body})))).get(("t.py", 2))
    assert place and place["hash_choice"] == "sha512"


def test_bouncy_castle_and_dotnet_requests(tmp_path):
    java = ("import org.bouncycastle.tsp.TimeStampRequestGenerator;\n"
            "class T { TimeStampRequest r(byte[] d) {\n"
            "  TimeStampRequestGenerator gen = new TimeStampRequestGenerator();\n"
            "  return gen.generate(TSPAlgorithms.SHA256, d);\n"
            "} }\n")
    cs = ("using System.Security.Cryptography.Pkcs;\n"
          "var req = Rfc3161TimestampRequest.CreateFromData(data, HashAlgorithmName.SHA384, "
          "requestSignerCertificates: true);\n")
    places = _places(scan_directory(str(_tree(tmp_path, {"T.java": java, "t.cs": cs}))))
    assert places[("T.java", 4)]["kind"] == "remote_timestamp"
    assert places[("T.java", 4)]["hash_choice"] == "TSPAlgorithms.SHA256"
    assert places[("t.cs", 2)]["kind"] == "remote_timestamp"
    assert places[("t.cs", 2)]["hash_choice"] == "HashAlgorithmName.SHA384"


def test_a_generate_call_without_the_tsp_generator_is_not_a_place(tmp_path):
    java = "class T { void f() { keyGen.generate(SHA256, d); } }\n"
    assert not _places(scan_directory(str(_tree(tmp_path, {"T.java": java}))))


def test_the_exits_carry_it(tmp_path):
    root = _tree(tmp_path / "t", {"stamp.py": STAMP_PY, "stamp.sh": STAMP_SH})
    out = tmp_path / "scan.json"
    run = subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()",
                          "scan", str(root), "--out", str(out)],
                         capture_output=True, text=True, timeout=300)
    assert out.exists(), run.stderr
    for result in (json.loads(out.read_text()), scan_repo(path=str(root))):
        kinds = [p.get("kind") for p in result["chosen_outside_files"]["places"]]
        assert kinds.count("remote_timestamp") == 2, kinds
        assert "remote_timestamp" in result["chosen_outside_files"]["meaning"]


# Independent review before the release (19.11): "default" only when the whole request was read
# and no hash is written; a hash written where the scan does not read it as a value is said so; and
# `hash_choice` never carries source text, which the masked levels would otherwise show.
NOT_A_VALUE = "set in the request, not read as a value"


@pytest.mark.parametrize("files, at, hash_choice", [
    ({"ci.sh": "openssl ts -query -data f.bin \\\n  -sha512 -cert -out q.tsq\n"}, ("ci.sh", 1), "sha512"),
    ({"ci.sh": "openssl ts -query -data f.bin -$DIGEST -out q.tsq\n"}, ("ci.sh", 1), NOT_A_VALUE),
    ({"ci.sh": "openssl ts -query -data f.bin -${HASH} -out q.tsq\n"}, ("ci.sh", 1), NOT_A_VALUE),
    ({"t.py": "import rfc3161ng\nrt = rfc3161ng.RemoteTimestamper(get_url(), hashname='sha512')\n"},
     ("t.py", 2), "sha512"),
    ({"t.py": "import rfc3161ng\nrt = rfc3161ng.RemoteTimestamper(URL, hashname=HASH)\n"},
     ("t.py", 2), NOT_A_VALUE),
    ({"T.java": "import org.bouncycastle.tsp.TimeStampRequestGenerator;\n"
                "class T { Object r(TimeStampRequestGenerator gen, byte[] d) { return gen.generate(hashAlg, d); } }\n"},
     ("T.java", 2), NOT_A_VALUE),
])
def test_a_hash_written_is_never_called_the_default(tmp_path, files, at, hash_choice):
    place = _places(scan_directory(str(_tree(tmp_path, files)))).get(at)
    assert place and place["kind"] == "remote_timestamp", at
    assert place["hash_choice"] == hash_choice


def test_a_call_that_goes_past_the_lines_read_is_not_the_default(tmp_path):
    body = "import rfc3161ng\nrt = rfc3161ng.RemoteTimestamper(\n" + "    x,\n" * 8 + "    hashname='sha512')\n"
    place = _places(scan_directory(str(_tree(tmp_path, {"t.py": body})))).get(("t.py", 2))
    assert place and not place["hash_choice"].startswith("default")


# Second independent review (19.11): a name in a known slot that is not a digest name --
# `hashname="zzneedlehash"`, `HashAlgorithmName.zzneedlealg`, `TSPAlgorithms.zzneedlebc` -- still
# carried its text. Only a digest name from a fixed list is said.
LEAKS = {
    "variable": ("T.java", "import org.bouncycastle.tsp.TimeStampRequestGenerator;\n"
                 "class T { Object r(TimeStampRequestGenerator gen, byte[] d) {\n"
                 "  return gen.generate(zzneedlealg, d); } }\n"),
    "hashname": ("t.py", 'import rfc3161ng\nt = rfc3161ng.RemoteTimestamper("u", hashname="zzneedlehash")\n'),
    "dotnet": ("L.cs", "using System.Security.Cryptography.Pkcs;\nclass L { void R(byte[] d) {\n"
               "  var q = Rfc3161TimestampRequest.CreateFromData(d, HashAlgorithmName.zzneedlealg); } }\n"),
    "bc-class": ("U.java", "import org.bouncycastle.tsp.TimeStampRequestGenerator;\n"
                 "class U { void r(TimeStampRequestGenerator g, byte[] d) {\n"
                 "  g.generate(TSPAlgorithms.zzneedlebc, d); } }\n"),
}


@pytest.mark.parametrize("level", ["masked", "trimmed"])
@pytest.mark.parametrize("form", sorted(LEAKS))
def test_hash_choice_carries_no_source_text(tmp_path, level, form):
    name, body = LEAKS[form]
    out = scan_repo(path=str(_tree(tmp_path, {name: body})), level=level)
    places = [p for p in out["chosen_outside_files"]["places"] if p.get("kind") == "remote_timestamp"]
    assert places, form
    assert places[0]["hash_choice"] == NOT_A_VALUE
    assert "zzneedle" not in json.dumps(out["chosen_outside_files"])


@pytest.mark.parametrize("written, said", [
    ('hashname="sha512"', "sha512"), ("hashname='SHA-256'", "sha-256"), ('hashname="sha3_256"', "sha3_256"),
])
def test_a_digest_name_is_still_said(tmp_path, written, said):
    body = f"import rfc3161ng\nt = rfc3161ng.RemoteTimestamper('u', {written})\n"
    place = _places(scan_directory(str(_tree(tmp_path, {"t.py": body})))).get(("t.py", 2))
    assert place["hash_choice"] == said


# Second independent review (19.11), the rest for row 536.
def test_dotnet_reads_the_hash_inside_the_call_only(tmp_path):
    cs = ("using System.Security.Cryptography;\nusing System.Security.Cryptography.Pkcs;\n"
          "class S { void Run(byte[] h, HashAlgorithmName alg) {\n"
          "    var req = Rfc3161TimestampRequest.CreateFromHash(h, alg, nonce: null);\n"
          "    var other = IncrementalHash.CreateHash(HashAlgorithmName.SHA1); } }\n")
    place = _places(scan_directory(str(_tree(tmp_path, {"S.cs": cs})))).get(("S.cs", 4))
    assert place and place["hash_choice"] == NOT_A_VALUE


def test_the_tsa_side_token_generator_is_not_a_request(tmp_path):
    java = ("import org.bouncycastle.tsp.TimeStampRequestGenerator;\n"
            "import org.bouncycastle.tsp.TimeStampTokenGenerator;\n"
            "class Tsa { void run(TimeStampTokenGenerator tokGen, TimeStampRequest req, byte[] d) {\n"
            "    TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();\n"
            "    TimeStampRequest r = reqGen.generate(TSPAlgorithms.SHA256, d);\n"
            "    TimeStampToken t = tokGen.generate(req, BigInteger.ONE, new Date()); } }\n")
    places = _places(scan_directory(str(_tree(tmp_path, {"Tsa.java": java}))))
    assert ("Tsa.java", 5) in places and ("Tsa.java", 6) not in places


def test_a_parenthesis_inside_a_string_does_not_end_the_call(tmp_path):
    body = 'import rfc3161ng\nt = rfc3161ng.RemoteTimestamper("https://tsa.example/x)", hashname="sha512")\n'
    place = _places(scan_directory(str(_tree(tmp_path, {"t.py": body})))).get(("t.py", 2))
    assert place and place["hash_choice"] == "sha512"


def test_printing_an_existing_request_is_not_a_request(tmp_path):
    sh = "#!/bin/sh\nopenssl ts -query -in req.tsq -text\nopenssl ts -query -data f.txt -sha1 -out r.tsq\n"
    places = _places(scan_directory(str(_tree(tmp_path, {"s.sh": sh}))))
    assert ("s.sh", 2) not in places and places[("s.sh", 3)]["hash_choice"] == "sha1"


def test_a_generator_assigned_without_its_type_is_read(tmp_path):
    # Re-review of 0.51.0 (19.11): `var g2 = new TimeStampRequestGenerator()` (Java 10+) and Kotlin's
    # `val g = TimeStampRequestGenerator()` name no type before the variable, and their generate(...)
    # was not read.
    java = ("import org.bouncycastle.tsp.*;\nclass A {\n"
            "  private final TimeStampRequestGenerator gen = new TimeStampRequestGenerator();\n"
            "  void a(byte[] d) throws Exception {\n"
            "    var g2 = new TimeStampRequestGenerator();\n"
            "    TimeStampRequest r1 = g2.generate(TSPAlgorithms.SHA256, d);\n"
            "    TimeStampRequest r3 = gen.generate(TSPAlgorithms.SHA3_256, d);\n  }\n}\n")
    kt = ("import org.bouncycastle.tsp.TimeStampRequestGenerator\n"
          "fun k(d: ByteArray) { val g = TimeStampRequestGenerator(); g.generate(TSPAlgorithms.SHA256, d) }\n")
    places = _places(scan_directory(str(_tree(tmp_path, {"A.java": java, "K.kt": kt}))))
    assert places[("A.java", 6)]["hash_choice"] == "TSPAlgorithms.SHA256"
    assert places[("A.java", 7)]["hash_choice"] == "TSPAlgorithms.SHA3_256"
    assert places[("K.kt", 2)]["hash_choice"] == "TSPAlgorithms.SHA256"
