"""The coverage identity has four terms, not three (ZA-OPRAVYANE row 60, the summary probe
of 22.10.2026).

README and the scan_repo docstring said `files_scanned + unreadable_files +
files_skipped_by_type` always equals `files_present`. A linked file is in `files_present`
and in none of the three: it is in `symlinks_not_followed`. The statement now names it,
and this test holds the four-term identity and the docstring to each other. A linked file
also withholds a reassuring readiness, since it was not read (row 52).
"""

import os

from qrp_mcp import server
from qrp_mcp.scan import scan_directory


def test_four_term_identity_with_a_linked_file(tmp_path):
    tree = tmp_path / "repo"
    tree.mkdir()
    (tree / "kem.py").write_text("from pqcrypto.kem.ml_kem_768 import generate_keypair\n")
    outside = tmp_path / "outside_rsa.py"
    outside.write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n")
    os.symlink(outside, tree / "legacy.py")
    r = scan_directory(tree)
    linked = [e for e in r["symlinks_not_followed"] if e["kind"] == "file"]
    assert (sum(r["files_scanned"].values()) + len(r["unreadable_files"])
            + sum(r["files_skipped_by_type"].values()) + len(linked)) == r["files_present"] == 2
    assert r["summary"]["pqc_readiness"] == "not_established"


def test_the_docstring_states_the_fourth_term():
    doc = " ".join(server.scan_repo.__doc__.split())
    assert ("files_scanned + unreadable_files + files_skipped_by_type + the linked files in "
            "symlinks_not_followed == files_present") in doc
