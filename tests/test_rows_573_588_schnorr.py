"""Rows 573 and 588 (crypto-asset probe, 25.11.2026): BIP-340 Schnorr, MuSig2 and FROST are Schnorr,
not ECDSA.

On 0.53.0 libsecp256k1's `secp256k1_schnorrsig_sign32`, `secp256k1_schnorrsig_verify`,
`secp256k1_keypair_create` and `secp256k1_musig_*` were rows of ECDSA/secp256k1 (the curve's name in
the function's), and Rust `use frost_secp256k1` was ECDSA. Both are Shor-broken, but the scheme, its
replacement and its role (Taproot, MuSig, threshold signing) differ, and an inventory that says
ECDSA for a Schnorr signer is wrong about what is there.

Names from bitcoin-core/secp256k1's headers (include/secp256k1_schnorrsig.h, secp256k1_extrakeys.h,
secp256k1_musig.h, https://raw.githubusercontent.com/bitcoin-core/secp256k1/master/include/) and the
FROST book (https://raw.githubusercontent.com/ZcashFoundation/frost/main/book/src/tutorial/
importing.md, dkg.md, signing.md).
"""

from __future__ import annotations

import pytest

from qrp_mcp.scan import scan_directory

C = """#include <secp256k1.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
int run(const secp256k1_context *ctx, unsigned char *seckey, unsigned char *msg32) {
    ok = secp256k1_ecdsa_sign(ctx, &sig, msg32, seckey, NULL, NULL);
    ok = secp256k1_keypair_create(ctx, &kp, seckey);
    ok = secp256k1_schnorrsig_sign32(ctx, sig64, msg32, &kp, aux);
    ok = secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp);
    ok = secp256k1_schnorrsig_verify(ctx, sig64, msg32, 32, &xpk);
    ok = secp256k1_xonly_pubkey_parse(ctx, &xpk, in32);
    return secp256k1_musig_pubkey_agg(ctx, agg_pk, cache, pubkeys, n);
    return secp256k1_musig_partial_sign(ctx, ps, sn, kp, c, s);
}
"""
SCHNORR_LINES = (2, 3, 4, 7, 8, 9, 10, 11, 12, 13)


def _rows(tmp_path, name, body):
    (tmp_path / name).write_text(body)
    return scan_directory(tmp_path)["evidence"]["source_code"]


def test_schnorr_lines_are_schnorr_and_not_ecdsa(tmp_path):
    rows = _rows(tmp_path, "sign.c", C)
    by_line = {}
    for r in rows:
        by_line.setdefault(r["line"], set()).add(r["algorithm"])
    for n in SCHNORR_LINES:
        assert "Schnorr" in by_line.get(n, set()), (n, by_line.get(n))
        assert "ECDSA" not in by_line.get(n, set()), (n, by_line.get(n))
    # Unchanged controls: the ECDSA call and the base header.
    assert "ECDSA" in by_line[6] and "ECDSA" in by_line[1]


FROST = """use frost_secp256k1 as frost;
use frost_ed25519 as frost_ed;
fn main() {
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng).unwrap();
    let (r1_secret, r1_package) = frost::keys::dkg::part1(id, 3, 2, &mut rng).unwrap();
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
    let share = frost::round2::sign(&signing_package, &nonces, &key_package).unwrap();
    let group_sig = frost::aggregate(&signing_package, &shares_map, &pubkey_package).unwrap();
}
"""


@pytest.mark.parametrize("line", [4, 5, 6, 7, 8])  # the import row is covered by the calls
def test_frost_secp256k1_is_schnorr(tmp_path, line):
    rows = [r for r in _rows(tmp_path, "frost.rs", FROST) if r["line"] == line]
    families = {r["algorithm"] for r in rows}
    assert "Schnorr" in families and "ECDSA" not in families, rows


def test_frost_ed25519_stays_ed25519(tmp_path):
    rows = [r for r in _rows(tmp_path, "frost.rs", FROST) if r["line"] == 2]
    assert {r["algorithm"] for r in rows} == {"Ed25519"}
