"""Row 481 (15.11.2026): the de-bsi profile recommended a scheme the BSI has since withdrawn.

BSI, "Notes on recent developments concerning Classic McEliece", 29 September 2026: "Classic
McEliece should currently no longer be used in new developments or when planning new
cryptographic applications. For key agreement, it is advised to use FrodoKEM, ML-KEM or HQC
(once the corresponding standard has been published) in accordance with the recommendations of
TR-02102-1." The recommendation "is limited to hybrid use" and "will be revised in the next
version of TR-02102-1 ... expected to be published in early 2027".

Until 0.46.0 `--profile de-bsi` offered Classic McEliece as a replacement for RSA and called a
McEliece finding "recommended". Now the replacement names FrodoKEM, ML-KEM and HQC (once
published); a McEliece finding says it is under review, hybrid in existing use only; and the
note is cited beside TR-02102-1 2026-01. The CBOM carries no replacement or profile, so the
two exits are `scan --out --profile de-bsi` and the MCP `scan_repo` tool.
"""

import json
import subprocess
import sys

from qrp_mcp import profiles, remediation
from qrp_mcp.server import scan_repo

NOTE_URL = "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Crypto/Notes_Classic_McEliece.pdf"
RSA = {"classification": "classical_vulnerable", "algorithm_family": "RSA"}
PROBE = {"kem.py": 'import oqs\nkem = oqs.KeyEncapsulation("Classic-McEliece-460896")\n',
         "sign.py": "from cryptography.hazmat.primitives.asymmetric import rsa\n"
                    "k = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"}


def _results(tmp_path):
    for name, text in PROBE.items():
        (tmp_path / name).write_text(text)
    out = tmp_path.parent / f"{tmp_path.name}.json"
    subprocess.run([sys.executable, "-c", "from qrp_mcp.server import main; main()", "scan",
                    str(tmp_path), "--profile", "de-bsi", "--out", str(out)],
                   check=True, capture_output=True)
    return [json.loads(out.read_text()), scan_repo(str(tmp_path), profile="de-bsi")]


def test_the_replacement_no_longer_offers_classic_mceliece(tmp_path):
    for result in _results(tmp_path):
        rsa = next(f for f in result["findings"] if f["algorithm_family"] == "RSA")
        kem = next(o for o in rsa["replacement"]["options"]
                   if o["for"].startswith("key establishment"))
        assert "mceliece" not in kem["use"].lower()
        assert "FrodoKEM" in kem["use"] and "ML-KEM" in kem["use"] and "HQC" in kem["use"]
        assert NOTE_URL in json.dumps(kem["sources"])


def test_a_mceliece_finding_says_it_is_under_review(tmp_path):
    for result in _results(tmp_path):
        finding = next(f for f in result["findings"]
                       if f["algorithm_family"] == "Classic McEliece")
        said = finding["profile_standing"]["standing"]
        assert not said.startswith("recommended")
        assert "under review" in said and "hybrid" in said and "existing" in said
        assert "29 September 2026" in said
        assert NOTE_URL in json.dumps(finding["profile_standing"]["source"])


def test_the_note_is_cited_beside_the_guideline():
    source = profiles.source("de-bsi")
    assert source["what"].startswith("2026-01")
    (note,) = source["also"]
    assert note == {"standard": "BSI: Notes on recent developments concerning Classic McEliece",
                    "what": "29 September 2026", "url": NOTE_URL, "read_on": "2026-11-15"}
    block = remediation.suggest(RSA, None, "de-bsi")["profile"]
    assert NOTE_URL in json.dumps(block["source"])
