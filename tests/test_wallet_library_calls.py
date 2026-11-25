"""Rows 561, 568-572, 574, 581, 583-588, 591-593 (crypto-asset probe, 25.11.2026): the signing and
key-generation calls of wallet libraries, read in a file that imports the library (libcalls.py).

On 0.53.0 these lines were read and gave nothing, or a row only on the import: go-ethereum
`crypto.GenerateKey()` / `crypto.Sign(h, key)` (row 561), ethers v6 with named imports, viem,
eth_account / eth_keys, alloy and ethers-rs, bitcoinjs' bip32 and tiny-secp256k1, rust-secp256k1,
the Solana SDKs, CometBFT's and cosmjs' signing methods, tss-lib. A call is read only where the file
imports the library, under the name it is bound to; a method only on a value the file got from it.

Each case is a line of the probe (qrp-kachestvo/roy-2026-11-25-kripto/probes-clean) or of the
library's own page (docs/, URLs in tools/urls.tsv); the expectation is the family and, where the
library has one curve only, the curve.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qrp_mcp.scan import scan_directory

GETH = """package main

import (
\t"github.com/ethereum/go-ethereum/crypto"
)

func run(hash []byte) {
\tkey, _ := crypto.GenerateKey()
\tsig, _ := crypto.Sign(hash, key)
\tpub, _ := crypto.SigToPub(hash, sig)
\tok := crypto.VerifySignature(crypto.FromECDSAPub(pub), hash, sig[:64])
\tk2, _ := crypto.HexToECDSA(hexKey)
\tk3, _ := crypto.LoadECDSA("node.key")
\taddr := crypto.PubkeyToAddress(key.PublicKey)
\t_, _, _, _ = ok, k2, k3, addr
}
"""
GETH_ALIAS = GETH.replace('\t"github.com/ethereum/go-ethereum/crypto"',
                          '\tethcrypto "github.com/ethereum/go-ethereum/crypto"').replace(
                              "crypto.", "ethcrypto.")
ETHERS6 = """import { ethers, Wallet, HDNodeWallet, SigningKey } from "ethers";
const w = Wallet.createRandom();
const w2 = new Wallet(process.env.PRIVATE_KEY);
const hd = HDNodeWallet.fromPhrase(phrase);
const child = hd.derivePath("m/44'/60'/0'/0/1");
const sig = await w.signMessage("hello");
const sigSync = w.signMessageSync("hello");
const sk = new SigningKey(privateKey);
const raw = sk.sign(digest);
const shared = sk.computeSharedSecret(otherPub);
const rec = SigningKey.recoverPublicKey(digest, raw);
"""
ETHERS5 = """const { ethers } = require("ethers");
const w = ethers.Wallet.createRandom();
const sig = await w.signMessage("hello");
const sk = new ethers.utils.SigningKey(privateKey);
const shared = sk.computeSharedSecret(otherPub);
"""
VIEM = """import { privateKeyToAccount, generatePrivateKey, mnemonicToAccount } from 'viem/accounts'
import { verifyMessage, recoverAddress, recoverMessageAddress } from 'viem'
const pk = generatePrivateKey()
const account = privateKeyToAccount(pk)
const hdAccount = mnemonicToAccount(phrase)
const signature = await account.signMessage({ message: 'hello world' })
const valid = await verifyMessage({ address: account.address, message: 'hello world', signature })
const who = await recoverAddress({ hash, signature })
const who2 = await recoverMessageAddress({ message: 'hello world', signature })
"""
ETH_ACCOUNT = """from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys
acct = Account.create()
acct2 = Account.from_key(private_key)
acct3 = Account.from_mnemonic(phrase, account_path="m/44'/60'/0'/0/0")
signed = Account.sign_message(encode_defunct(text="hi"), private_key)
signed_tx = Account.sign_transaction(tx, private_key)
who = Account.recover_message(encode_defunct(text="hi"), signature=signed.signature)
raw = Account.unsafe_sign_hash(msg_hash, private_key)
pk = keys.PrivateKey(private_key_bytes)
sig = pk.sign_msg(b"a message")
ok = pk.public_key.verify_msg(b"a message", sig)
s2 = acct.sign_message(encode_defunct(text="hi"))
"""
ALLOY = """use alloy_signer::{Signer, SignerSync};
use alloy_signer_local::PrivateKeySigner;
fn main() {
    let signer = PrivateKeySigner::random();
    let signature = signer.sign_message_sync(b"hello").unwrap();
    let sig2 = signer.sign_hash_sync(&hash).unwrap();
    let who = signature.recover_address_from_msg(b"hello").unwrap();
}
"""
ETHERS_RS = """use ethers_signers::{LocalWallet, Signer};
async fn run() {
    let wallet = LocalWallet::new(&mut rand::thread_rng());
    let signature = wallet.sign_message("hello world").await.unwrap();
    signature.verify("hello world", wallet.address()).unwrap();
}
"""
BITCOINJS = """const ecc = require('tiny-secp256k1');
const { BIP32Factory } = require('bip32');
const bitcoin = require('bitcoinjs-lib');
const bip32 = BIP32Factory(ecc);
const root = bip32.fromSeed(seed);
const child = root.derivePath("m/86'/0'/0'/0/0");
const sig = ecc.sign(hash, privateKey);
const schnorrSig = ecc.signSchnorr(hash, privateKey);
const okSchnorr = ecc.verifySchnorr(hash, xOnlyPub, schnorrSig);
const pub = ecc.pointFromScalar(privateKey);
const tweaked = ecc.xOnlyPointAddTweak(xOnlyPub, tweak);
const psbt = new bitcoin.Psbt({ network });
psbt.signInput(0, keyPair);
psbt.signAllInputs(keyPair);
const valid = psbt.validateSignaturesOfInput(0, validator);
"""
RUST_SECP = """use secp256k1::{Secp256k1, Message, SecretKey, PublicKey, Keypair};
use secp256k1::ecdh::SharedSecret;
fn main() {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut rand::rng());
    let message = Message::from_digest(digest);
    let sig = secp.sign_ecdsa(message, &secret_key);
    let ok = secp.verify_ecdsa(&sig, message, &public_key);
    let keypair = Keypair::new(&secp, &mut rand::rng());
    let ssig = secp.sign_schnorr(&digest, &keypair);
    let ok2 = secp.verify_schnorr(&ssig, &digest, &xonly);
    let shared = SharedSecret::new(&public_key, &secret_key);
}
"""
SOLANA_KIT = """import { generateKeyPair, createKeyPairFromBytes, signBytes, verifySignature } from '@solana/keys';
import { generateKeyPairSigner } from '@solana/kit';
const { privateKey, publicKey } = await generateKeyPair();
const kp2 = await createKeyPairFromBytes(keypairBytes);
const signer = await generateKeyPairSigner();
const sig = await signBytes(privateKey, data);
const ok = await verifySignature(publicKey, sig, data);
"""
SOLANA_WEB3 = """const { Keypair } = require('@solana/web3.js');
const kp = Keypair.generate();
const kp2 = Keypair.fromSecretKey(secretKey);
const kp3 = Keypair.fromSeed(seed);
"""
SOLANA_RS = """use solana_sdk::signature::{Keypair, Signer};
fn main() {
    let kp = Keypair::new();
    let kp2 = Keypair::from_base58_string(&s);
    let sig = kp.sign_message(b"hello");
}
"""
COMET = """package main

import (
\t"github.com/cometbft/cometbft/crypto/ed25519"
\t"github.com/cometbft/cometbft/crypto/secp256k1"
)

func run(msg []byte) bool {
\tpv := ed25519.GenPrivKey()
\tsig, _ := pv.Sign(msg)
\tok := pv.PubKey().VerifySignature(msg, sig)
\tsk := secp256k1.GenPrivKey()
\ts2, _ := sk.Sign(msg)
\t_ = s2
\treturn ok
}
"""
COSMJS = """import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
const wallet = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic, { prefix: "cosmos" });
const w2 = await DirectSecp256k1HdWallet.generate(24);
const resp = await wallet.signDirect(address, signDoc);
"""
WEB3JS = """const { Web3 } = require('web3');
const web3 = new Web3();
const acct = web3.eth.accounts.create();
const signed = web3.eth.accounts.sign('Some data', acct.privateKey);
"""
TSS = """package main

import (
\t"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
\t"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
)

func run() {
\tpreParams, _ := keygen.GeneratePreParams(1 * time.Minute)
\tparty := keygen.NewLocalParty(params, outCh, endCh, *preParams)
\tsparty := signing.NewLocalParty(message, params, ourKeyData, outCh, endCh)
\t_, _ = party, sparty
}
"""
BLST_RS = """use blst::min_pk::{SecretKey, PublicKey, Signature, AggregateSignature};
fn main() {
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();
    let sig = sk.sign(msg, dst, &[]);
    let err = sig.verify(true, msg, dst, &[], &pk, true);
}
"""
PY_ECC_BLS = """from py_ecc.bls import G2ProofOfPossession as bls_pop
sk = bls_pop.KeyGen(ikm)
pk = bls_pop.SkToPk(sk)
sig = bls_pop.Sign(sk, message)
ok = bls_pop.Verify(pk, message, sig)
agg = bls_pop.Aggregate([sig, sig2])
"""
NOBLE_BLS = """import { bls12_381 } from '@noble/curves/bls12-381.js';
const blsl = bls12_381.longSignatures;
const pk = blsl.getPublicKey(sk);
const sig = blsl.sign(msgp, sk);
const ok = blsl.verify(sig, msgp, pk);
"""

BITCOINLIB = """from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from bitcoin.signmessage import BitcoinMessage, VerifyMessage, SignMessage
secret = CBitcoinSecret(key)
signature = SignMessage(secret, message)
ok = VerifyMessage(address, message, signature)
"""

CASES = [
    # row 575: python-bitcoinlib (examples/sign-message.py)
    *[("signmsg.py", BITCOINLIB, n, "ECDSA", "secp256k1") for n in (3, 4, 5)],
    # row 561: go-ethereum crypto
    ("geth.go", GETH, 8, "ECDSA", "secp256k1"), ("geth.go", GETH, 9, "ECDSA", "secp256k1"),
    ("geth.go", GETH, 10, "ECDSA", "secp256k1"), ("geth.go", GETH, 11, "ECDSA", "secp256k1"),
    ("geth.go", GETH, 12, "ECDSA", "secp256k1"), ("geth.go", GETH, 13, "ECDSA", "secp256k1"),
    ("geth.go", GETH, 14, "ECDSA", "secp256k1"),
    ("geth_alias.go", GETH_ALIAS, 8, "ECDSA", "secp256k1"),
    ("geth_alias.go", GETH_ALIAS, 9, "ECDSA", "secp256k1"),
    # row 568: ethers v6 (named imports) and v5
    *[("ethers6.js", ETHERS6, n, "ECDSA", "secp256k1") for n in (2, 3, 4, 5, 6, 7, 8, 9, 11)],
    ("ethers6.js", ETHERS6, 10, "ECDH", "secp256k1"),
    ("ethers5.js", ETHERS5, 3, "ECDSA", "secp256k1"), ("ethers5.js", ETHERS5, 5, "ECDH", "secp256k1"),
    # row 569: viem
    *[("viem.ts", VIEM, n, "ECDSA", "secp256k1") for n in (3, 4, 5, 6, 7, 8, 9)],
    # row 570: eth_account, eth_keys
    *[("accounts.py", ETH_ACCOUNT, n, "ECDSA", "secp256k1") for n in range(4, 15)],
    # row 571: alloy, ethers-rs
    *[("alloy.rs", ALLOY, n, "ECDSA", "secp256k1") for n in (4, 5, 6, 7)],
    *[("ethers_rs.rs", ETHERS_RS, n, "ECDSA", "secp256k1") for n in (3, 4, 5)],
    # row 572: bip32, tiny-secp256k1, bitcoinjs Psbt
    *[("wallet.js", BITCOINJS, n, "ECDSA", "secp256k1") for n in (4, 5, 6, 7, 10, 13, 14, 15)],
    *[("wallet.js", BITCOINJS, n, "Schnorr", "secp256k1") for n in (8, 9, 11)],
    # row 574: rust-secp256k1
    *[("main.rs", RUST_SECP, n, "ECDSA", "secp256k1") for n in (5, 7, 8)],
    # Keypair::new is a secp256k1 key pair (read with the key types); the scheme is the method's.
    ("main.rs", RUST_SECP, 9, "ECDSA", "secp256k1"),
    *[("main.rs", RUST_SECP, n, "Schnorr", "secp256k1") for n in (10, 11)],
    ("main.rs", RUST_SECP, 12, "ECDH", "secp256k1"),
    # row 584: Solana kit / keys / web3.js
    *[("kit.ts", SOLANA_KIT, n, "Ed25519", None) for n in (3, 4, 5, 6, 7)],
    *[("solana.js", SOLANA_WEB3, n, "Ed25519", None) for n in (2, 3, 4)],
    # row 585: solana-sdk
    *[("solana.rs", SOLANA_RS, n, "Ed25519", None) for n in (3, 4, 5)],
    # row 586: CometBFT signing methods
    ("comet.go", COMET, 10, "Ed25519", None), ("comet.go", COMET, 11, "Ed25519", None),
    ("comet.go", COMET, 13, "ECDSA", "secp256k1"),
    # rows 591, 593: cosmjs and web3.js: the curve, and signDirect
    *[("cosmos.js", COSMJS, n, "ECDSA", "secp256k1") for n in (2, 3, 4)],
    *[("web3.js", WEB3JS, n, "ECDSA", "secp256k1") for n in (3, 4)],
    # row 587: tss-lib (threshold ECDSA)
    *[("tss.go", TSS, n, "ECDSA", None) for n in (9, 10, 11)],
    # rows 581, 583, 592: BLS signatures by their calls
    *[("blst.rs", BLST_RS, n, "BLS", "BLS12-381") for n in (3, 4, 5, 6)],
    *[("bls.py", PY_ECC_BLS, n, "BLS", "BLS12-381") for n in (2, 3, 4, 5, 6)],
    *[("noble.js", NOBLE_BLS, n, "BLS", "BLS12-381") for n in (3, 4, 5)],
]


def _scan(tmp_path: Path, name: str, body: str) -> dict:
    (tmp_path / name).write_text(body, encoding="utf-8")
    return scan_directory(tmp_path)


_CACHE: dict = {}


@pytest.mark.parametrize("name, body, line, family, curve", CASES,
                         ids=[f"{c[0]}:{c[2]}:{c[3]}" for c in CASES])
def test_the_call_has_a_row(tmp_path, name, body, line, family, curve):
    key = (name, body)
    if key not in _CACHE:
        _CACHE[key] = _scan(tmp_path, name, body)
    rows = [r for r in _CACHE[key]["evidence"]["source_code"]
            if r["path"] == name and r["line"] == line and r["algorithm"] == family]
    assert rows, (line, family, [(r["line"], r["algorithm"]) for r in _CACHE[key]["evidence"]["source_code"]])
    assert rows[0]["evidence_kind"] not in ("comment", "identifier")
    if curve:
        assert rows[0].get("curve") == curve, rows[0]


@pytest.mark.parametrize("name, body", [
    # Go's standard library is `crypto` too: crypto.Sign is not go-ethereum's without its import.
    ("std.go", "package main\n\nimport \"crypto/ed25519\"\n\nfunc f() {\n\th := crypto.SHA256\n"
               "\tsig, _ := crypto.Sign(h, key)\n}\n"),
    # A method name on a value the file did not get from the library.
    ("ethers_other.js", "import { ethers } from 'ethers';\nconst x = other.signMessage('hi');\n"),
    # The method names alone, with no wallet library imported.
    ("plain.js", "const w = makeWallet();\nconst s = w.signMessage('hi');\nconst k = new SigningKey(p);\n"),
    ("plain.py", "acct = Account.create()\nsig = acct.sign_message(m)\n"),
], ids=["go-stdlib", "unbound-receiver", "no-import-js", "no-import-py"])
def test_no_row_without_the_library(tmp_path, name, body):
    result = _scan(tmp_path, name, body)
    lines = {r["line"] for r in result["evidence"]["source_code"]
             if r["algorithm"] in ("ECDSA", "ECDH") and r["evidence_kind"] == "call"}
    if name == "ethers_other.js":
        assert 2 not in lines
    else:
        assert not lines, result["evidence"]["source_code"]


def test_solana_web3_is_not_ecdsa(tmp_path):
    """Row 584 (fp): `require('@solana/web3.js')` read `web3` as Ethereum's and gave ECDSA."""
    result = _scan(tmp_path, "s.js", "const { Keypair } = require('@solana/web3.js');\n")
    families = {r["algorithm"] for r in result["evidence"]["source_code"]}
    assert "Ed25519" in families and "ECDSA" not in families


BLST_GO = """package main

import blst "github.com/supranational/blst/bindings/go"

type PublicKey = blst.P1Affine
type Signature = blst.P2Affine

func run(ikm, msg, dst []byte) bool {
\tsk := blst.KeyGen(ikm)
\tpk := new(PublicKey).From(sk)
\tsig := new(Signature).Sign(sk, msg, dst)
\treturn sig.Verify(true, pk, true, msg, dst)
}
"""
HERUMI = """package main

import "github.com/herumi/bls-eth-go-binary/bls"

func run(msg []byte) bool {
\tbls.Init(bls.BLS12_381)
\tbls.SetETHmode(bls.EthModeDraft07)
\tvar sec bls.SecretKey
\tsec.SetByCSPRNG()
\tpub := sec.GetPublicKey()
\tsig := sec.SignByte(msg)
\treturn sig.VerifyByte(pub, msg)
}
"""


@pytest.mark.parametrize("name, body, lines", [
    ("blst.go", BLST_GO, (9, 10, 11, 12)), ("herumi.go", HERUMI, (7, 9, 10, 11, 12)),
], ids=["blst-go", "herumi"])
def test_row_582_bls_in_go(tmp_path, name, body, lines):
    rows = _scan(tmp_path, name, body)["evidence"]["source_code"]
    got = {r["line"] for r in rows if r["algorithm"] == "BLS" and r["evidence_kind"] == "call"}
    assert set(lines) <= got, sorted((r["line"], r["algorithm"], r["evidence_kind"]) for r in rows)


def test_a_second_family_of_a_library_adds_no_import_row(tmp_path):
    """Importing ethers is not key agreement, and importing noble's secp256k1 is not BLS
    (positive control on OpenZeppelin, 25.11.2026: 39 ECDH and 3 BLS import rows)."""
    rows = _scan(tmp_path, "t.js", "const { ethers } = require('ethers');\n"
                 "import { secp256k1 } from '@noble/curves/secp256k1';\n"
                 "const x = ethers.id('ROLE');\n")["evidence"]["source_code"]
    assert not [r for r in rows if r["algorithm"] in ("ECDH", "BLS")], rows


def test_a_rust_variable_named_secp256k1_keypair_is_not_schnorr(tmp_path):
    """lighthouse lcli: `let secp256k1_keypair = ...` -- a variable, not libsecp256k1's C API."""
    rows = _scan(tmp_path, "enr.rs", "fn f() {\n    let secret = secp256k1_keypair.secret().to_bytes();\n"
                 "    let k = k256::ecdsa::SigningKey::random(&mut rng);\n}\n")["evidence"]["source_code"]
    assert not [r for r in rows if r["algorithm"] == "Schnorr"], rows
