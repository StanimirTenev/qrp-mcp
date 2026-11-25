"""Calls into a cryptographic library, read only in a file that imports it (release 0.54.0).

The pattern table in detectors.py reads names that mean one thing wherever they stand:
`secp256k1`, `ecrecover`, `Groth16`. A wallet library's calls do not: `Wallet.createRandom()`,
`Account.sign_message(...)`, `crypto.Sign(h, key)`, `signer.sign_message_sync(...)` are ECDSA over
secp256k1 only because of what the file imports, and `crypto.Sign` is Go's standard library in a
file that does not import go-ethereum. So each library here is read as `_vrf_calls` reads a VRF
library (row 535): only in a file that imports it, under the name it is bound to there.

A library (`Lib`) gives:
  * `modules`: what the file imports -- a Python or JS module (a sub-path counts), a Go import
    path, a Rust crate path;
  * `classes`: names exported by it whose every constructor and member is the cryptography
    (`Wallet`, `Account`, `PrivateKeySigner`): `Wallet.createRandom()`, `new Wallet(k)`,
    `PrivateKeySigner::random()`;
  * `functions`: names exported by it that are the cryptography when called (`verifyMessage`,
    `GenerateKey`);
  * `methods`: names that are the cryptography when called on a value the file got from the
    library (`w.signMessage(...)` where `w = Wallet.createRandom()`). A method name alone, on a
    receiver the file did not bind from the library, is not read: `cert.Verify(...)` is not BLS.

The bound name is what the file binds: an alias (`import ckzg`, `const e = require("ethers")`, a Go
package name or its alias), a named import (`from eth_account import Account`, `import { Wallet }
from "ethers"`, `use alloy_signer_local::PrivateKeySigner`), and in Rust the crate's own name
(`solana_sdk::signature::Keypair::new()` needs no `use`). A receiver is a variable assigned from an
expression headed by a bound name or by another receiver (`hd = HDNodeWallet.fromPhrase(p)`,
`child = hd.derivePath(path)`).

Every library is listed with the page its names come from; a name not on that page is marked И
(inferred) beside it. The rows this module adds carry evidence_kind `call` (or `import` on the
import line), the library's family and, where the library has one curve only, that curve.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Lib:
    lang: str                      # "py", "js", "go", "rs"
    modules: tuple[str, ...]
    family: str
    curve: str | None
    what: str                      # the library, as the description names it
    classes: tuple[str, ...] = ()
    functions: tuple[str, ...] = ()
    methods: tuple[str, ...] = ()
    # Names that bind a receiver for `methods` without being read as a call themselves (a second
    # entry for the same library, of another family: ethers' computeSharedSecret is ECDH).
    binds: tuple[str, ...] = ()
    # Go: the package name a path is bound to when it is imported without an alias.
    go_names: dict[str, str] = field(default_factory=dict)


_EXT = {".py": "py", ".pyi": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".ts": "js",
        ".tsx": "js", ".jsx": "js", ".mts": "js", ".cts": "js", ".go": "go", ".rs": "rs"}

LIBRARIES: list[Lib] = []


def register(*libs: Lib) -> None:
    LIBRARIES.extend(libs)


# ---- imports ---------------------------------------------------------------------------------

def _module_re(modules: tuple[str, ...], sep: str) -> str:
    # The module itself or a sub-path of it.
    return "(?:" + "|".join(re.escape(m) for m in modules) + ")(?:" + re.escape(sep) + r"[\w.@/-]*)?"


def _split_names(text: str, as_word: str) -> dict[str, str]:
    """`a, b as c` / `a, b: c` -> {bound name: exported name}: {a: a, c: b}."""
    out = {}
    for part in text.replace("\n", " ").split(","):
        part = part.strip().strip("{}()").strip()
        if part.startswith("type "):
            part = part[5:].strip()
        if not part or part == "*":
            continue
        if as_word == ":" and ":" in part:
            orig, bound = (s.strip() for s in part.split(":", 1))
        elif re.search(rf"\s{as_word}\s", part):
            orig, bound = (s.strip() for s in part.split(f" {as_word} ", 1))
        else:
            orig = bound = part.split()[-1] if part.split() else part
        if re.fullmatch(r"[A-Za-z_$][\w$]*", bound) and re.fullmatch(r"[A-Za-z_$][\w$]*", orig):
            out[bound] = orig
    return out


def _imports(lib: Lib, text: str) -> tuple[set[str], dict[str, str], list[int]]:
    """(aliases, named, import line numbers) the file binds for `lib`."""
    aliases: set[str] = set()
    named: dict[str, str] = {}
    lines: list[int] = []

    def at(m: re.Match) -> None:
        lines.append(text.count("\n", 0, m.start()) + 1)

    if lib.lang == "py":
        mod = _module_re(lib.modules, ".")
        for m in re.finditer(rf"(?m)^[ \t]*import[ \t]+({mod})(?:[ \t]+as[ \t]+(\w+))?[ \t]*$", text):
            aliases.add(m.group(2) or m.group(1).split(".")[0])
            if not m.group(2):
                aliases.add(m.group(1))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*from[ \t]+({mod})[ \t]+import[ \t]+(\([^)]*\)|[^\n#]+)", text):
            named.update(_split_names(m.group(2), "as"))
            at(m)
    elif lib.lang == "js":
        mod = _module_re(lib.modules, "/")
        q = r"[\"']"
        for m in re.finditer(rf"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?require\(\s*{q}{mod}{q}\s*\)", text):
            aliases.add(m.group(1))
            at(m)
        for m in re.finditer(rf"\b(?:const|let|var)\s*\{{([^}}]*)\}}\s*=\s*(?:await\s+)?require\(\s*{q}{mod}{q}\s*\)", text):
            named.update(_split_names(m.group(1), ":"))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*import\s+([^;'\"]*?)\s+from\s+{q}{mod}{q}", text):
            clause = m.group(1)
            star = re.search(r"\*\s+as\s+(\w+)", clause)
            if star:
                aliases.add(star.group(1))
            braces = re.search(r"\{([^}]*)\}", clause)
            if braces:
                named.update(_split_names(braces.group(1), "as"))
            default = re.match(r"\s*(?:type\s+)?([A-Za-z_$][\w$]*)\s*(?:,|$)", clause)
            if default and default.group(1) != "type":
                aliases.add(default.group(1))
            at(m)
    elif lib.lang == "go":
        for path in lib.modules:
            for m in re.finditer(r"(?m)^[ \t]*(?:import[ \t]+)?(?:(\w+)[ \t]+)?\"" + re.escape(path)
                                 + r"\"", text):
                alias = m.group(1)
                if alias == "_":
                    continue
                aliases.add(alias or lib.go_names.get(path) or path.rstrip("/").split("/")[-1])
                at(m)
    elif lib.lang == "rs":
        crates = [m.split("::")[0] for m in lib.modules]
        aliases.update(crates)
        mod = "(?:" + "|".join(re.escape(m) for m in lib.modules) + r")(?:::\w+)*"
        for m in re.finditer(rf"(?m)^[ \t]*(?:pub[ \t]+)?use[ \t]+({mod})::\{{([^}}]*)\}}", text):
            named.update(_split_names(m.group(2), "as"))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*(?:pub[ \t]+)?use[ \t]+({mod})::(\w+)(?:[ \t]+as[ \t]+(\w+))?[ \t]*;", text):
            named[m.group(3) or m.group(2)] = m.group(2)
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*(?:pub[ \t]+)?use[ \t]+({mod})(?:[ \t]+as[ \t]+(\w+))?[ \t]*;", text):
            if m.group(2):
                aliases.add(m.group(2))
            at(m)
        for m in re.finditer(rf"(?m)^[ \t]*(?:pub[ \t]+)?use[ \t]+({mod})::\*[ \t]*;", text):
            named.update({n: n for n in lib.classes + lib.functions + lib.binds})
            at(m)
    return aliases, named, sorted(set(lines))


# ---- calls -----------------------------------------------------------------------------------

_COMMENT_START = {"py": ("#",), "js": ("//", "/*", "*"), "go": ("//", "/*", "*"), "rs": ("//", "/*", "*")}
_STRING = re.compile(r"\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`[^`]*`")


def _code(line: str, lang: str) -> str:
    text = _STRING.sub(lambda m: '""', line)
    marker = "#" if lang == "py" else "//"
    return text.split(marker, 1)[0]


def _alt(names) -> str:
    return "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))


def _call_patterns(lib: Lib, aliases: set[str], named: dict[str, str],
                   receivers: set[str]) -> list[re.Pattern]:
    sep = r"(?:\.|::)"
    pats: list[str] = []
    members = list(lib.classes) + list(lib.functions)
    if aliases and members:
        # alias.Class..., alias.function(...), with sub-modules between (`ethers.utils.SigningKey`).
        cls = _alt(lib.classes) if lib.classes else None
        fns = _alt(lib.functions) if lib.functions else None
        body = []
        if cls:
            body.append(rf"(?:{cls})\b")
        if fns:
            body.append(rf"(?:{fns})\s*(?:<[^>()]*>\s*)?\(")
        pats.append(rf"(?<![\w.$])(?:{_alt(aliases)})(?:{sep}\w+)*?{sep}(?:{'|'.join(body)})")
    named_classes = {b for b, o in named.items() if o in lib.classes}
    named_functions = {b for b, o in named.items() if o in lib.functions}
    if named_classes:
        pats.append(rf"(?<![\w.$])(?:new\s+)?(?:{_alt(named_classes)})(?:\s*{sep}\s*\w+|\s*(?:<[^>()]*>\s*)?\()")
        # Rust: `Groth16::<Bn254>::prove`
        pats.append(rf"(?<![\w.$])(?:{_alt(named_classes)})::<[^>]*>::\w+")
    if named_functions:
        pats.append(rf"(?<![\w.$])(?:{_alt(named_functions)})\s*(?:<[^>()]*>\s*)?\(")
    if receivers and lib.methods:
        pats.append(rf"(?<![\w.$])(?:{_alt(receivers)})(?:\s*\.\s*\w+(?:\(\s*\))?)*?\s*\.\s*(?:{_alt(lib.methods)})\s*(?:<[^>()]*>\s*)?\(")
    return [re.compile(p) for p in pats]


_ASSIGN = {
    "py": re.compile(r"^\s*(\w+)\s*(?::[^=]+)?=(?!=)\s*(?:await\s+)?(.+)$"),
    "js": re.compile(r"^\s*(?:(?:const|let|var)\s+)?(\w+)\s*(?::[^=]+)?=(?![=>])\s*(?:await\s+)?(?:new\s+)?(.+)$"),
    "go": re.compile(r"^\s*(?:var\s+)?(\w+)(?:\s*,\s*\w+)*\s*:?=(?!=)\s*(.+)$"),
    "rs": re.compile(r"^\s*let\s+(?:mut\s+)?\(?\s*(?:mut\s+)?(\w+)(?:\s*,[^)=]*)?\)?\s*(?::[^=]+)?=(?!=)\s*(.+)$"),
}


def _receivers(lib: Lib, lines: list[str], aliases: set[str], named: dict[str, str]) -> set[str]:
    """Variables assigned from the library: from a bound name, then from those, to a fixed point."""
    if not lib.methods:
        return set()
    heads = set(aliases) | {b for b, o in named.items()
                            if o in lib.classes or o in lib.functions or o in lib.binds}
    assigns = []
    for line in lines:
        m = _ASSIGN[lib.lang].match(_code(line, lib.lang))
        if m:
            head = re.match(r"\(?\s*(?:new\s+)?(\w+)", m.group(2))
            if head:
                assigns.append((m.group(1), head.group(1)))
    found: set[str] = set()
    while True:
        more = {var for var, head in assigns if (head in heads or head in found) and var not in found}
        if not more:
            return found - {"_"}
        found |= more


def calls(findings: list[dict[str, Any]], lines: list[str], rel_path: str, ext: str,
          in_test_code) -> list[dict[str, Any]]:
    lang = _EXT.get(ext)
    if lang is None or not lines:
        return findings
    text = "\n".join(lines)
    added: list[dict[str, Any]] = []
    for lib in LIBRARIES:
        if lib.lang != lang or not any(m.split("::")[0] in text for m in lib.modules):
            continue
        aliases, named, import_lines = _imports(lib, text)
        # A named import of the library's namespace (`const { ethers } = require("ethers")`).
        bases = {m.replace("::", "/").split("/")[-1].split(".")[-1] for m in lib.modules}
        aliases |= {b for b, o in named.items() if o in bases}
        if lang == "rs":
            # The crate's own name counts only where it is used as a path (`solana_sdk::...`).
            aliases = {a for a in aliases if re.search(rf"(?<![\w:]){re.escape(a)}::", text)}
        if not (aliases or named) and not import_lines:
            continue
        receivers = _receivers(lib, lines, aliases, named)
        patterns = _call_patterns(lib, aliases, named, receivers)
        if not patterns and not import_lines:
            continue
        here = {}
        for f in findings + added:
            if f["algorithm"] == lib.family:
                here.setdefault(f["line"], f)
        for n, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if not stripped or stripped.startswith(_COMMENT_START[lang]):
                continue
            if n in import_lines:
                kind = "import"
            elif any(p.search(_code(line, lang)) for p in patterns):
                kind = "call"
            else:
                continue
            held = here.get(n)
            if held is not None:
                if kind == "call" and held.get("evidence_kind") in ("import", "identifier",
                                                                   "declaration", "reference"):
                    held["evidence_kind"] = "call"
                if lib.curve and not held.get("curve"):
                    held["curve"] = lib.curve
                continue
            item = {"path": rel_path, "line": n, "algorithm": lib.family,
                    "description": (f"{lib.family} usage ({lib.what}, which this file imports)"
                                    if kind == "import" else
                                    f"{lib.family} usage (a call into {lib.what}, which this file "
                                    f"imports)"),
                    "excerpt": line.strip()[:200], "evidence_kind": kind,
                    "in_test_code": in_test_code(rel_path)}
            if lib.curve:
                item["curve"] = lib.curve
            added.append(item)
            here[n] = item
    return sorted(findings + added, key=lambda f: f["line"]) if added else findings


# ---- the libraries ---------------------------------------------------------------------------
# Rows 562, 563: pairing-based cryptography whose calls carry no curve or scheme word. Names that
# do (bn254, Groth16, KZG, snarkjs) are read by the pattern table wherever they stand.
register(
    # py_ecc: "Elliptic curve crypto in python including secp256k1, alt_bn128, and bls12_381"
    # (README). The modules are pairing curves; `pairing` is their pairing (И: the function is not
    # on the saved README page).
    Lib("py", ("py_ecc.optimized_bn128", "py_ecc.bn128"), "Pairing", "BN254",
        "py_ecc's alt_bn128 pairing", functions=("pairing", "final_exponentiate")),
    Lib("py", ("py_ecc.optimized_bls12_381", "py_ecc.bls12_381"), "Pairing", "BLS12-381",
        "py_ecc's BLS12-381 pairing", functions=("pairing", "final_exponentiate")),
    # gnark "currently supports: Groth16, PLONK" (README); the PLONK backend's package path and its
    # Setup/Prove/Verify are И (the README shows the Groth16 ones).
    Lib("go", ("github.com/consensys/gnark/backend/plonk",), "Pairing", None,
        "gnark's PLONK backend", functions=("Setup", "Prove", "Verify")),
)

# Rows 561, 568-572, 574, 581, 583-588, 591-593: wallet and chain libraries (pages in the docstring of
# tests/test_wallet_library_calls.py; a name not on its page is marked И).
_K1 = "secp256k1"
_ETHERS_SIGNERS = ("Wallet", "HDNodeWallet", "BaseWallet", "SigningKey", "HDNodeVoidWallet")
_ETHERS_METHODS = ("signMessage", "signMessageSync", "signTransaction", "signTypedData",
                   "_signTypedData", "authorize", "authorizeSync", "derivePath", "deriveChild",
                   "sign", "signDigest")
_BTC_SCHNORR = ("signSchnorr", "verifySchnorr", "xOnlyPointAddTweak", "xOnlyPointFromScalar",
                "xOnlyPointFromPoint", "tweak")
register(
    # go-ethereum/crypto (pkg.go.dev): secp256k1 keys and signatures.
    Lib("go", ("github.com/ethereum/go-ethereum/crypto",), "ECDSA", _K1, "go-ethereum's crypto",
        functions=("CompressPubkey", "DecompressPubkey", "Ecrecover", "FromECDSA", "FromECDSAPub",
                   "GenerateKey", "HexToECDSA", "LoadECDSA", "PubkeyToAddress", "S256",
                   "SaveECDSA", "Sign", "SigToPub", "ToECDSA", "ToECDSAUnsafe", "UnmarshalPubkey",
                   "ValidateSignatureValues", "VerifySignature")),
    # ethers v6 (docs.ethers.org/v6/api/wallet, /crypto) and v5 (/v5/api/signer, utils/signing-key).
    Lib("js", ("ethers",), "ECDSA", _K1, "ethers",
        classes=_ETHERS_SIGNERS,
        functions=("verifyMessage", "verifyTypedData", "recoverAddress", "computeAddress",
                   "recoverPublicKey", "computePublicKey"),
        methods=_ETHERS_METHODS),
    # SigningKey.computeSharedSecret: "Returns the ECDH shared secret between this private key and
    # the other key".
    Lib("js", ("ethers",), "ECDH", _K1, "ethers", binds=_ETHERS_SIGNERS,
        methods=("computeSharedSecret",)),
    # viem (site/pages/docs/accounts/local/*, utilities/*).
    Lib("js", ("viem",), "ECDSA", _K1, "viem",
        functions=("generatePrivateKey", "privateKeyToAccount", "mnemonicToAccount",
                   "hdKeyToAccount", "privateKeyToAddress", "verifyMessage", "verifyTypedData",
                   "verifyHash", "recoverAddress", "recoverMessageAddress", "recoverPublicKey",
                   "recoverTypedDataAddress", "signMessage", "signTypedData", "sign"),
        methods=("signMessage", "signTypedData", "signTransaction", "sign", "signAuthorization")),
    # web3.js v4 accounts (docs.web3js.org/libdocs/Accounts): the curve of its rows.
    Lib("js", ("web3", "web3-eth-accounts"), "ECDSA", _K1, "web3.js", classes=("Web3",),
        functions=("create", "privateKeyToAccount", "sign", "signTransaction", "recover",
                   "recoverTransaction", "privateKeyToAddress", "privateKeyToPublicKey"),
        methods=("create", "privateKeyToAccount", "sign", "signTransaction", "recover",
                 "recoverTransaction", "privateKeyToAddress", "privateKeyToPublicKey")),
    # eth_account (eth-account.readthedocs.io) and eth_keys (README).
    Lib("py", ("eth_account",), "ECDSA", _K1, "eth_account", classes=("Account",),
        methods=("sign_message", "sign_transaction", "sign_typed_data", "unsafe_sign_hash",
                 "sign_authorization")),
    Lib("py", ("eth_keys",), "ECDSA", _K1, "eth_keys", classes=("keys", "KeyAPI"),
        methods=("sign_msg", "sign_msg_hash", "verify_msg", "verify_msg_hash", "recover_from_msg",
                 "recover_from_msg_hash", "ecdsa_sign", "ecdsa_verify", "ecdsa_recover")),
    # alloy-signer-local / alloy-signer (docs.rs); ethers-signers (docs.rs).
    Lib("rs", ("alloy_signer_local", "alloy_signer", "alloy::signers"), "ECDSA", _K1, "alloy",
        classes=("PrivateKeySigner", "LocalSigner", "MnemonicBuilder"),
        methods=("sign_message", "sign_message_sync", "sign_hash", "sign_hash_sync",
                 "sign_typed_data", "sign_typed_data_sync", "sign_transaction",
                 "sign_transaction_sync", "recover_address_from_msg",
                 "recover_address_from_prehash")),
    Lib("rs", ("ethers_signers", "ethers::signers"), "ECDSA", _K1, "ethers-rs",
        classes=("LocalWallet", "Wallet", "MnemonicBuilder"),
        methods=("sign_message", "sign_transaction", "sign_typed_data", "sign_hash", "verify",
                 "recover")),
    # tiny-secp256k1 (README), bip32 (README), bitcoinjs-lib Psbt (README, ts_src/psbt.ts).
    Lib("js", ("tiny-secp256k1", "@bitcoinerlab/secp256k1"), "ECDSA", _K1, "tiny-secp256k1",
        functions=("sign", "signRecoverable", "verify", "recover", "pointFromScalar", "pointAdd",
                   "pointAddScalar", "pointCompress", "pointMultiply", "privateAdd", "privateSub",
                   "privateNegate")),
    Lib("js", ("tiny-secp256k1", "@bitcoinerlab/secp256k1"), "Schnorr", _K1, "tiny-secp256k1",
        functions=("signSchnorr", "verifySchnorr", "xOnlyPointAddTweak", "xOnlyPointFromScalar",
                   "xOnlyPointFromPoint")),
    Lib("js", ("bip32",), "ECDSA", _K1, "bip32", classes=("BIP32Factory",),
        methods=("fromSeed", "fromBase58", "fromPrivateKey", "fromPublicKey", "derivePath",
                 "derive", "deriveHardened", "sign", "verify")),
    Lib("js", ("bip32", "ecpair"), "Schnorr", _K1, "bip32", binds=("BIP32Factory", "ECPairFactory"),
        methods=("signSchnorr", "verifySchnorr", "tweak")),
    Lib("js", ("ecpair",), "ECDSA", _K1, "ecpair", classes=("ECPairFactory",),
        methods=("makeRandom", "fromWIF", "fromPrivateKey", "fromPublicKey", "sign", "verify")),
    Lib("js", ("bitcoinjs-lib",), "ECDSA", _K1, "bitcoinjs-lib", classes=("Psbt",),
        methods=("signInput", "signAllInputs", "signInputHD", "signAllInputsHD",
                 "signInputAsync", "signAllInputsAsync", "validateSignaturesOfInput",
                 "validateSignaturesOfAllInputs")),
    Lib("js", ("bitcoinjs-lib",), "Schnorr", _K1, "bitcoinjs-lib", functions=("p2tr",)),
    # rust-secp256k1 (src/lib.rs, src/schnorr.rs, src/ecdh.rs).
    Lib("rs", ("secp256k1",), "ECDSA", _K1, "rust-secp256k1",
        classes=("Secp256k1", "SecretKey", "PublicKey"),
        methods=("generate_keypair", "sign_ecdsa", "verify_ecdsa", "sign_ecdsa_recoverable",
                 "recover_ecdsa", "sign_ecdsa_low_r", "sign_ecdsa_with_noncedata")),
    Lib("rs", ("secp256k1",), "Schnorr", _K1, "rust-secp256k1",
        classes=("Keypair", "XOnlyPublicKey"), binds=("Secp256k1",),
        methods=("sign_schnorr", "verify_schnorr", "sign_schnorr_no_aux_rand",
                 "sign_schnorr_with_aux_rand", "x_only_public_key")),
    Lib("rs", ("secp256k1::ecdh",), "ECDH", _K1, "rust-secp256k1's ecdh",
        classes=("SharedSecret",), functions=("shared_secret_point",)),
    # python-bitcoinlib (README example sign-message.py).
    Lib("py", ("bitcoin.wallet", "bitcoin.signmessage", "bitcoin.core.key"), "ECDSA", _K1,
        "python-bitcoinlib", classes=("CBitcoinSecret", "CKey", "CECKey"),
        functions=("SignMessage", "VerifyMessage")),
    # Solana: @solana/keys, @solana/kit, @solana/signers (README); web3.js v1 Keypair.
    Lib("js", ("@solana/keys", "@solana/kit", "@solana/signers"), "Ed25519", None, "the Solana kit",
        functions=("generateKeyPair", "createKeyPairFromBytes", "createKeyPairFromPrivateKeyBytes",
                   "generateKeyPairSigner", "createKeyPairSignerFromBytes",
                   "createKeyPairSignerFromPrivateKeyBytes", "createSignerFromKeyPair",
                   "signBytes", "verifySignature")),
    Lib("js", ("@solana/web3.js",), "Ed25519", None, "@solana/web3.js",
        classes=("Keypair",), methods=("sign", "partialSign")),
    Lib("rs", ("solana_sdk", "solana_keypair", "solana_signer", "solana_signature"), "Ed25519",
        None, "the Solana SDK", classes=("Keypair",), functions=("read_keypair_file",),
        methods=("sign_message", "try_sign_message")),
    # CometBFT crypto/ed25519, crypto/secp256k1, cosmos-sdk crypto/keys/secp256k1 (pkg.go.dev).
    Lib("go", ("github.com/cometbft/cometbft/crypto/ed25519",
               "github.com/tendermint/tendermint/crypto/ed25519"), "Ed25519", None, "CometBFT's ed25519",
        functions=("GenPrivKey", "GenPrivKeyFromSecret"), methods=("Sign", "VerifySignature")),
    Lib("go", ("github.com/cometbft/cometbft/crypto/secp256k1",
               "github.com/tendermint/tendermint/crypto/secp256k1",
               "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"), "ECDSA", _K1,
        "CometBFT's secp256k1", functions=("GenPrivKey", "GenPrivKeyFromSecret"),
        methods=("Sign", "VerifySignature")),
    # cosmjs proto-signing / amino (README, directsecp256k1hdwallet.ts, secp256k1hdwallet.ts).
    Lib("js", ("@cosmjs/proto-signing", "@cosmjs/amino"), "ECDSA", _K1, "cosmjs",
        classes=("DirectSecp256k1HdWallet", "DirectSecp256k1Wallet", "Secp256k1HdWallet",
                 "Secp256k1Wallet"),
        methods=("signDirect", "signAmino")),
    # bnb-chain tss-lib (README): threshold ECDSA, keygen and signing parties.
    Lib("go", tuple(f"github.com/bnb-chain/tss-lib{v}/ecdsa/{p}" for v in ("", "/v2")
                    for p in ("keygen", "signing", "resharing")), "ECDSA", None,
        "tss-lib (threshold ECDSA)", functions=("NewLocalParty", "GeneratePreParams")),
    # blst Rust (bindings/rust/README): BLS12-381 signatures.
    Lib("rs", ("blst::min_pk", "blst::min_sig", "blst"), "BLS", "BLS12-381", "blst",
        classes=("SecretKey", "PublicKey", "Signature", "AggregateSignature", "AggregatePublicKey"),
        methods=("sk_to_pk", "sign", "verify", "aggregate_verify", "fast_aggregate_verify",
                 "aggregate", "key_gen")),
    # py_ecc.bls (README): G2Basic, G2MessageAugmentation, G2ProofOfPossession.
    Lib("py", ("py_ecc.bls",), "BLS", "BLS12-381", "py_ecc.bls",
        classes=("G2Basic", "G2MessageAugmentation", "G2ProofOfPossession")),
    # noble-curves bls12-381 (README): longSignatures / shortSignatures.
    Lib("js", ("@noble/curves",), "BLS", "BLS12-381", "noble-curves bls12-381",
        classes=("bls12_381",), methods=("getPublicKey", "sign", "verify", "aggregatePublicKeys",
                                         "aggregateSignatures", "verifyBatch")),
)

# FROST (ZcashFoundation/frost, book/src/tutorial: importing.md, dkg.md, signing.md): threshold
# Schnorr. Over secp256k1 it is Schnorr, not ECDSA (row 588); over Ed25519 it gives Ed25519 signatures.
_FROST = ("generate_with_dealer", "split", "part1", "part2", "part3", "commit", "sign", "aggregate")
register(
    Lib("rs", ("frost_secp256k1", "frost_secp256k1_tr"), "Schnorr", "secp256k1", "FROST",
        functions=_FROST),
    Lib("rs", ("frost_p256", "frost_ristretto255", "frost_ed448"), "Schnorr", None, "FROST",
        functions=_FROST),
    Lib("rs", ("frost_ed25519",), "Ed25519", None, "FROST", functions=_FROST),
)
