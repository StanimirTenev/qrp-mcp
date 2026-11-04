"""A self-seeded control: known lines planted into a copy of the tree, then scanned.

`qrp-mcp control PATH --seed N` copies the tree to a temporary directory, plants known
cryptographic uses in nine styles and known lines that name an algorithm without using it
(the decoys, in seven classes), scans the copy with this same instrument and scores every
planted line. The tree itself is never written to; the copy is removed afterwards.

What the figure is: **robustness on known patterns** -- what this version of the instrument
does on the planted styles, in this tree's languages and files. What it is not: a statement
about what the tree contains, how much of it was found, or how many of the tree's own findings
are right. The denominator is what was planted, and the styles and decoys are the harness's
own; a tool tuned on them would score better without being better on anything else.

So the block this produces never feeds `claims.control` or `compositions[].aggregate`.
`claims.control.held` is defined as a corpus with independently established contents, and a
control the instrument's author plants is not independent, whatever its scope. It travels
beside the coverage claims as `claims.self_seeded_control`, under its own name.

The harness is the one published with the method (the L1 round of 04.11.2026): the templates
come from library documentation, not from this scanner's rule tables, and were written before
the first planted run. The same seed on the same tree plants the same lines at the same
places; `plan_sha256` is the digest of that plan and `harness_sha256` the digest of the
templates and scoring tables, so two runs can be checked for being the same control.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from . import __version__

# Bumped when a template, a decoy or a scoring rule changes, so a figure is never compared
# with one produced by a different harness under the same name.
HARNESS_VERSION = "1"

NAME = "robustness on known patterns"
LICENSES = ("robustness on known patterns: what this instrument version does on the planted "
            "styles and decoy classes listed here, in this tree's languages. It says nothing "
            "about what the tree contains, how much of it was found, or how many of its own "
            "findings are right, and it does not carry to another version")
FEEDS = ("nothing: claims.control.held and the CBOM's compositions[].aggregate are not read "
         "from this block")
HOW = "qrp-mcp control PATH --seed N, or qrp-mcp scan PATH --control-seed N"

# ---------------------------------------------------------------- families and equivalence

# A row counts as the expected family when its `algorithm` is one of these spellings.
# A generic EC row counts for ECDSA (the rule docs/measurement.md states for every tool alike).
FAMILY_MATCH = {
    "RSA": {"RSA"},
    "ECDSA": {"ECDSA", "EC", "secp256r1", "P-256", "prime256v1"},
    "Ed25519": {"Ed25519", "EdDSA", "ED25519"},
}

# Which planted-row kinds count as "named, not used" (right on a decoy, not a hit on a use).
NOT_A_USE = {"comment", "ban"}

LANG_EXT = {
    "python": ".py", "ruby": ".rb", "rust": ".rs", "php": ".php",
    "typescript": ".ts", "java": ".java", "go": ".go",
}

# ---------------------------------------------------------------- positive templates
# Idioms come from library documentation (pyca/cryptography, Ruby OpenSSL, RustCrypto, PHP
# openssl/sodium, Node crypto, JCA, Go crypto) -- not from the scanner's rule tables.
# Each template: list of lines; `{id}` is replaced by a per-plant identifier.
# `use`: indexes (0-based inside the block) of the lines that carry the use; a hit on an
# import/constant line (`name`) is recorded separately.


def _wrap(lang: str, pid: str, body: list[str]) -> list[str]:
    """Wrap statements so the block is plausible at the chosen anchor (top-level or member)."""
    if lang == "go":
        return [f"func planted{pid}() {{"] + ["\t" + l for l in body] + ["\t_ = planted" + pid, "}"]
    if lang == "rust":
        return [f"fn planted_{pid}() {{"] + ["    " + l for l in body] + ["}"]
    if lang == "java":
        return [f"    static void planted{pid}() throws Exception {{"] + ["        " + l for l in body] + ["    }"]
    return body


POSITIVES: dict[str, dict[str, dict[str, dict]]] = {
    # lang -> style -> family -> {"lines": [...], "use": [idx...], "name": [idx...]}
    "python": {
        "direct_call": {
            "RSA": {"lines": ["key_{id} = rsa.generate_private_key(public_exponent=65537, key_size=2048)"], "use": [0]},
            "ECDSA": {"lines": ["key_{id} = ec.generate_private_key(ec.SECP256R1())"], "use": [0]},
            "Ed25519": {"lines": ["key_{id} = ed25519.Ed25519PrivateKey.generate()"], "use": [0]},
        },
        "indirect_name": {
            "RSA": {"lines": ["from cryptography.hazmat.primitives.asymmetric import rsa as asym_{id}",
                              "key_{id} = asym_{id}.generate_private_key(public_exponent=65537, key_size=2048)"], "use": [1], "name": [0]},
            "ECDSA": {"lines": ["from cryptography.hazmat.primitives.asymmetric import ec as curve_{id}", "CURVE_{id} = curve_{id}.SECP256R1()",
                                "key_{id} = curve_{id}.generate_private_key(CURVE_{id})"], "use": [2], "name": [0, 1]},
            "Ed25519": {"lines": ["from cryptography.hazmat.primitives.asymmetric import ed25519 as sig_{id}",
                                  "key_{id} = sig_{id}.Ed25519PrivateKey.generate()"], "use": [1], "name": [0]},
        },
        "string_built": {
            "RSA": {"lines": ["key_{id} = getattr(asymmetric, 'r' + 'sa').generate_private_key(public_exponent=65537, key_size=2048)"], "use": [0]},
            "ECDSA": {"lines": ["key_{id} = getattr(asymmetric, 'e' + 'c').generate_private_key(getattr(getattr(asymmetric, 'e' + 'c'), 'SECP' + '256R1')())"], "use": [0]},
            "Ed25519": {"lines": ["key_{id} = getattr(getattr(asymmetric, 'ed' + '25519'), 'Ed' + '25519PrivateKey').generate()"], "use": [0]},
        },
        "split_lines": {
            "RSA": {"lines": ["key_{id} = rsa.generate_private_key(", "    public_exponent=65537,", "    key_size=1024,", ")"], "use": [0, 1, 2, 3], "size": 1024},
            "ECDSA": {"lines": ["key_{id} = ec.generate_private_key(", "    ec.SECP256R1(),", ")"], "use": [0, 1, 2]},
            "Ed25519": {"lines": ["key_{id} = ed25519.Ed25519PrivateKey.from_private_bytes(", "    seed_{id},", ")"], "use": [0, 1, 2]},
        },
        "live_string": {
            "RSA": {"lines": ["script_{id} = \"#!/bin/sh\\nopenssl genrsa -out key_{id}.pem 2048\\n\"", "subprocess.run(['sh', '-c', script_{id}], check=True)"], "use": [0]},
            "ECDSA": {"lines": ["script_{id} = \"#!/bin/sh\\nopenssl ecparam -name prime256v1 -genkey -out key_{id}.pem\\n\"", "subprocess.run(['sh', '-c', script_{id}], check=True)"], "use": [0]},
            "Ed25519": {"lines": ["script_{id} = \"#!/bin/sh\\nssh-keygen -t ed25519 -f key_{id} -N ''\\n\"", "subprocess.run(['sh', '-c', script_{id}], check=True)"], "use": [0]},
        },
    },
    "ruby": {
        "direct_call": {
            "RSA": {"lines": ["key_{id} = OpenSSL::PKey::RSA.new(2048)"], "use": [0]},
            "ECDSA": {"lines": ["key_{id} = OpenSSL::PKey::EC.generate('prime256v1')"], "use": [0]},
            "Ed25519": {"lines": ["key_{id} = OpenSSL::PKey.generate_key('ED25519')"], "use": [0]},
        },
        "indirect_name": {
            "RSA": {"lines": ["ASYM_{id} = OpenSSL::PKey::RSA", "key_{id} = ASYM_{id}.new(2048)"], "use": [1], "name": [0]},
            "ECDSA": {"lines": ["CURVE_{id} = OpenSSL::PKey::EC", "CURVE_NAME_{id} = 'prime256v1'", "key_{id} = CURVE_{id}.generate(CURVE_NAME_{id})"], "use": [2], "name": [0, 1]},
            "Ed25519": {"lines": ["SIG_{id} = 'ED25519'", "key_{id} = OpenSSL::PKey.generate_key(SIG_{id})"], "use": [1], "name": [0]},
        },
        "string_built": {
            "RSA": {"lines": ["key_{id} = OpenSSL::PKey.const_get('R' + 'SA').new(2048)"], "use": [0]},
            "ECDSA": {"lines": ["key_{id} = OpenSSL::PKey.const_get('E' + 'C').generate('prime' + '256v1')"], "use": [0]},
            "Ed25519": {"lines": ["key_{id} = OpenSSL::PKey.generate_key('ED' + '25519')"], "use": [0]},
        },
        "split_lines": {
            "RSA": {"lines": ["key_{id} = OpenSSL::PKey::RSA.new(", "  1024", ")"], "use": [0, 1, 2], "size": 1024},
            "ECDSA": {"lines": ["key_{id} = OpenSSL::PKey::EC.generate(", "  'prime256v1'", ")"], "use": [0, 1, 2]},
            "Ed25519": {"lines": ["key_{id} = OpenSSL::PKey.generate_key(", "  'ED25519'", ")"], "use": [0, 1, 2]},
        },
        "live_string": {
            "RSA": {"lines": ["script_{id} = \"#!/bin/sh\\nopenssl genrsa -out key_{id}.pem 2048\\n\"", "system('sh', '-c', script_{id})"], "use": [0]},
            "ECDSA": {"lines": ["script_{id} = \"#!/bin/sh\\nopenssl ecparam -name prime256v1 -genkey -out key_{id}.pem\\n\"", "system('sh', '-c', script_{id})"], "use": [0]},
            "Ed25519": {"lines": ["script_{id} = \"#!/bin/sh\\nssh-keygen -t ed25519 -f key_{id} -N ''\\n\"", "system('sh', '-c', script_{id})"], "use": [0]},
        },
    },
    "rust": {
        "direct_call": {
            "RSA": {"lines": ["let key_{id} = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect(\"keygen\");"], "use": [0]},
            "ECDSA": {"lines": ["let key_{id} = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());"], "use": [0]},
            "Ed25519": {"lines": ["let key_{id} = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());"], "use": [0]},
        },
        "indirect_name": {
            "RSA": {"lines": ["use rsa::RsaPrivateKey as Asym{id};", "let key_{id} = Asym{id}::new(&mut rand::thread_rng(), 2048).expect(\"keygen\");"], "use": [1], "name": [0]},
            "ECDSA": {"lines": ["use p256::ecdsa::SigningKey as Curve{id};", "let key_{id} = Curve{id}::random(&mut rand::thread_rng());"], "use": [1], "name": [0]},
            "Ed25519": {"lines": ["use ed25519_dalek::SigningKey as Sig{id};", "let key_{id} = Sig{id}::generate(&mut rand::thread_rng());"], "use": [1], "name": [0]},
        },
        "string_built": {
            "RSA": {"lines": ["let key_{id} = openssl::pkey::PKey::generate_from_name(&format!(\"{{}}{{}}\", \"r\", \"sa\")).expect(\"keygen\");"], "use": [0]},
            "ECDSA": {"lines": ["let key_{id} = openssl::pkey::PKey::generate_from_name(&format!(\"{{}}{{}}\", \"e\", \"c\")).expect(\"keygen\");"], "use": [0]},
            "Ed25519": {"lines": ["let key_{id} = openssl::pkey::PKey::generate_from_name(&format!(\"{{}}{{}}\", \"ed\", \"25519\")).expect(\"keygen\");"], "use": [0]},
        },
        "split_lines": {
            "RSA": {"lines": ["let key_{id} = RsaPrivateKey::new(", "    &mut rand::thread_rng(),", "    1024,", ").expect(\"keygen\");"], "use": [0, 1, 2, 3], "size": 1024},
            "ECDSA": {"lines": ["let key_{id} = p256::ecdsa::SigningKey::random(", "    &mut rand::thread_rng(),", ");"], "use": [0, 1, 2]},
            "Ed25519": {"lines": ["let key_{id} = ed25519_dalek::SigningKey::generate(", "    &mut rand::thread_rng(),", ");"], "use": [0, 1, 2]},
        },
        "live_string": {
            "RSA": {"lines": ["let script_{id} = \"#!/bin/sh\\nopenssl genrsa -out key_{id}.pem 2048\\n\";", "std::process::Command::new(\"sh\").arg(\"-c\").arg(script_{id}).status().expect(\"sh\");"], "use": [0]},
            "ECDSA": {"lines": ["let script_{id} = \"#!/bin/sh\\nopenssl ecparam -name prime256v1 -genkey -out key_{id}.pem\\n\";", "std::process::Command::new(\"sh\").arg(\"-c\").arg(script_{id}).status().expect(\"sh\");"], "use": [0]},
            "Ed25519": {"lines": ["let script_{id} = \"#!/bin/sh\\nssh-keygen -t ed25519 -f key_{id} -N ''\\n\";", "std::process::Command::new(\"sh\").arg(\"-c\").arg(script_{id}).status().expect(\"sh\");"], "use": [0]},
        },
    },
    "php": {
        "direct_call": {
            "RSA": {"lines": ["$key_{id} = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);"], "use": [0]},
            "ECDSA": {"lines": ["$key_{id} = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);"], "use": [0]},
            "Ed25519": {"lines": ["$key_{id} = sodium_crypto_sign_keypair();"], "use": [0]},
        },
        "indirect_name": {
            "RSA": {"lines": ["$type_{id} = OPENSSL_KEYTYPE_RSA;", "$key_{id} = openssl_pkey_new(['private_key_type' => $type_{id}, 'private_key_bits' => 2048]);"], "use": [1], "name": [0]},
            "ECDSA": {"lines": ["$type_{id} = OPENSSL_KEYTYPE_EC;", "$curve_{id} = 'prime256v1';", "$key_{id} = openssl_pkey_new(['private_key_type' => $type_{id}, 'curve_name' => $curve_{id}]);"], "use": [2], "name": [0, 1]},
            "Ed25519": {"lines": ["$fn_{id} = 'sodium_crypto_sign_keypair';", "$key_{id} = $fn_{id}();"], "use": [1], "name": [0]},
        },
        "string_built": {
            "RSA": {"lines": ["$key_{id} = openssl_pkey_new(['private_key_type' => constant('OPENSSL_KEYTYPE_' . 'R' . 'SA'), 'private_key_bits' => 2048]);"], "use": [0]},
            "ECDSA": {"lines": ["$key_{id} = openssl_pkey_new(['private_key_type' => constant('OPENSSL_KEYTYPE_' . 'E' . 'C'), 'curve_name' => 'prime' . '256v1']);"], "use": [0]},
            "Ed25519": {"lines": ["$key_{id} = call_user_func('sodium_crypto_' . 'sign_keypair');"], "use": [0]},
        },
        "split_lines": {
            "RSA": {"lines": ["$key_{id} = openssl_pkey_new([", "    'private_key_type' => OPENSSL_KEYTYPE_RSA,", "    'private_key_bits' => 1024,", "]);"], "use": [0, 1, 2, 3], "size": 1024},
            "ECDSA": {"lines": ["$key_{id} = openssl_pkey_new([", "    'private_key_type' => OPENSSL_KEYTYPE_EC,", "    'curve_name' => 'prime256v1',", "]);"], "use": [0, 1, 2, 3]},
            "Ed25519": {"lines": ["$key_{id} = sodium_crypto_sign_seed_keypair(", "    $seed_{id}", ");"], "use": [0, 1, 2]},
        },
        "live_string": {
            "RSA": {"lines": ["$script_{id} = \"#!/bin/sh\\nopenssl genrsa -out key_{id}.pem 2048\\n\";", "shell_exec($script_{id});"], "use": [0]},
            "ECDSA": {"lines": ["$script_{id} = \"#!/bin/sh\\nopenssl ecparam -name prime256v1 -genkey -out key_{id}.pem\\n\";", "shell_exec($script_{id});"], "use": [0]},
            "Ed25519": {"lines": ["$script_{id} = \"#!/bin/sh\\nssh-keygen -t ed25519 -f key_{id} -N ''\\n\";", "shell_exec($script_{id});"], "use": [0]},
        },
    },
    "typescript": {
        "direct_call": {
            "RSA": {"lines": ["const key{id} = generateKeyPairSync('rsa', { modulusLength: 2048 });"], "use": [0]},
            "ECDSA": {"lines": ["const key{id} = generateKeyPairSync('ec', { namedCurve: 'P-256' });"], "use": [0]},
            "Ed25519": {"lines": ["const key{id} = generateKeyPairSync('ed25519');"], "use": [0]},
        },
        "indirect_name": {
            "RSA": {"lines": ["const ALG{id} = 'rsa';", "const key{id} = generateKeyPairSync(ALG{id}, { modulusLength: 2048 });"], "use": [1], "name": [0]},
            "ECDSA": {"lines": ["const ALG{id} = 'ec';", "const CURVE{id} = 'P-256';", "const key{id} = generateKeyPairSync(ALG{id}, { namedCurve: CURVE{id} });"], "use": [2], "name": [0, 1]},
            "Ed25519": {"lines": ["const ALG{id} = 'ed25519';", "const key{id} = generateKeyPairSync(ALG{id});"], "use": [1], "name": [0]},
        },
        "string_built": {
            "RSA": {"lines": ["const key{id} = generateKeyPairSync('r' + 'sa', { modulusLength: 2048 });"], "use": [0]},
            "ECDSA": {"lines": ["const key{id} = generateKeyPairSync('e' + 'c', { namedCurve: 'P-' + '256' });"], "use": [0]},
            "Ed25519": {"lines": ["const key{id} = generateKeyPairSync('ed' + '25519');"], "use": [0]},
        },
        "split_lines": {
            "RSA": {"lines": ["const key{id} = generateKeyPairSync(", "  'rsa',", "  { modulusLength: 1024 },", ");"], "use": [0, 1, 2, 3], "size": 1024},
            "ECDSA": {"lines": ["const key{id} = generateKeyPairSync(", "  'ec',", "  { namedCurve: 'P-256' },", ");"], "use": [0, 1, 2, 3]},
            "Ed25519": {"lines": ["const key{id} = generateKeyPairSync(", "  'ed25519',", ");"], "use": [0, 1, 2]},
        },
        "live_string": {
            "RSA": {"lines": ["const script{id} = '#!/bin/sh\\nopenssl genrsa -out key{id}.pem 2048\\n';", "execSync(script{id});"], "use": [0]},
            "ECDSA": {"lines": ["const script{id} = '#!/bin/sh\\nopenssl ecparam -name prime256v1 -genkey -out key{id}.pem\\n';", "execSync(script{id});"], "use": [0]},
            "Ed25519": {"lines": ["const script{id} = '#!/bin/sh\\nssh-keygen -t ed25519 -f key{id} -N \"\"\\n';", "execSync(script{id});"], "use": [0]},
        },
    },
    "java": {
        "direct_call": {
            "RSA": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(\"RSA\"); kpg{id}.initialize(2048);"], "use": [0]},
            "ECDSA": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(\"EC\"); kpg{id}.initialize(new ECGenParameterSpec(\"secp256r1\"));"], "use": [0]},
            "Ed25519": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(\"Ed25519\");"], "use": [0]},
        },
        "indirect_name": {
            "RSA": {"lines": ["final String alg{id} = \"RSA\";", "KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(alg{id}); kpg{id}.initialize(2048);"], "use": [1], "name": [0]},
            "ECDSA": {"lines": ["final String alg{id} = \"EC\";", "final String curve{id} = \"secp256r1\";", "KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(alg{id}); kpg{id}.initialize(new ECGenParameterSpec(curve{id}));"], "use": [2], "name": [0, 1]},
            "Ed25519": {"lines": ["final String alg{id} = \"Ed25519\";", "KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(alg{id});"], "use": [1], "name": [0]},
        },
        "string_built": {
            "RSA": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(\"R\" + \"SA\"); kpg{id}.initialize(2048);"], "use": [0]},
            "ECDSA": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(\"E\" + \"C\"); kpg{id}.initialize(new ECGenParameterSpec(\"secp\" + \"256r1\"));"], "use": [0]},
            "Ed25519": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(\"Ed\" + \"25519\");"], "use": [0]},
        },
        "split_lines": {
            "RSA": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(", "        \"RSA\");", "kpg{id}.initialize(", "        1024);"], "use": [0, 1, 2, 3], "size": 1024},
            "ECDSA": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(", "        \"EC\");", "kpg{id}.initialize(", "        new ECGenParameterSpec(\"secp256r1\"));"], "use": [0, 1, 2, 3]},
            "Ed25519": {"lines": ["KeyPairGenerator kpg{id} = KeyPairGenerator.getInstance(", "        \"Ed25519\");"], "use": [0, 1]},
        },
        "live_string": {
            "RSA": {"lines": ["String script{id} = \"#!/bin/sh\\nopenssl genrsa -out key{id}.pem 2048\\n\";", "new ProcessBuilder(\"sh\", \"-c\", script{id}).start().waitFor();"], "use": [0]},
            "ECDSA": {"lines": ["String script{id} = \"#!/bin/sh\\nopenssl ecparam -name prime256v1 -genkey -out key{id}.pem\\n\";", "new ProcessBuilder(\"sh\", \"-c\", script{id}).start().waitFor();"], "use": [0]},
            "Ed25519": {"lines": ["String script{id} = \"#!/bin/sh\\nssh-keygen -t ed25519 -f key{id} -N ''\\n\";", "new ProcessBuilder(\"sh\", \"-c\", script{id}).start().waitFor();"], "use": [0]},
        },
    },
    "go": {
        "direct_call": {
            "RSA": {"lines": ["key{id}, _ := rsa.GenerateKey(rand.Reader, 2048)"], "use": [0]},
            "ECDSA": {"lines": ["key{id}, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)"], "use": [0]},
            "Ed25519": {"lines": ["_, key{id}, _ := ed25519.GenerateKey(rand.Reader)"], "use": [0]},
        },
        "indirect_name": {
            # Go has no aliased family-carrying import at call level that hides the package name
            # in a realistic way except an import alias; the alias line sits in the import block,
            # so the block is: alias import written as a separate import statement at top level.
            "RSA": {"lines": ["import asym{id} \"crypto/rsa\"", "var key{id}, _ = asym{id}.GenerateKey(rand.Reader, 2048)"], "use": [1], "name": [0], "toplevel": True},
            "ECDSA": {"lines": ["import curve{id} \"crypto/ecdsa\"", "var curveParams{id} = elliptic.P256()", "var key{id}, _ = curve{id}.GenerateKey(curveParams{id}, rand.Reader)"], "use": [2], "name": [0, 1], "toplevel": True},
            "Ed25519": {"lines": ["import sig{id} \"crypto/ed25519\"", "var _, key{id}, _ = sig{id}.GenerateKey(rand.Reader)"], "use": [1], "name": [0], "toplevel": True},
        },
        "string_built": {
            "RSA": {"lines": ["alg{id} := \"r\" + \"sa\"", "key{id}, _ := keygen.ByName(alg{id}, 2048)"], "use": [0, 1]},
            "ECDSA": {"lines": ["alg{id} := \"ec\" + \"dsa\"", "key{id}, _ := keygen.ByName(alg{id}, 256)"], "use": [0, 1]},
            "Ed25519": {"lines": ["alg{id} := \"ed\" + \"25519\"", "key{id}, _ := keygen.ByName(alg{id}, 0)"], "use": [0, 1]},
        },
        "split_lines": {
            "RSA": {"lines": ["key{id}, _ := rsa.GenerateKey(", "\trand.Reader,", "\t1024,", ")"], "use": [0, 1, 2, 3], "size": 1024},
            "ECDSA": {"lines": ["key{id}, _ := ecdsa.GenerateKey(", "\telliptic.P256(),", "\trand.Reader,", ")"], "use": [0, 1, 2, 3]},
            "Ed25519": {"lines": ["_, key{id}, _ := ed25519.GenerateKey(", "\trand.Reader,", ")"], "use": [0, 1, 2]},
        },
        "live_string": {
            "RSA": {"lines": ["script{id} := \"#!/bin/sh\\nopenssl genrsa -out key{id}.pem 2048\\n\"", "_ = exec.Command(\"sh\", \"-c\", script{id}).Run()"], "use": [0]},
            "ECDSA": {"lines": ["script{id} := \"#!/bin/sh\\nopenssl ecparam -name prime256v1 -genkey -out key{id}.pem\\n\"", "_ = exec.Command(\"sh\", \"-c\", script{id}).Run()"], "use": [0]},
            "Ed25519": {"lines": ["script{id} := \"#!/bin/sh\\nssh-keygen -t ed25519 -f key{id} -N ''\\n\"", "_ = exec.Command(\"sh\", \"-c\", script{id}).Run()"], "use": [0]},
        },
    },
}

# Config-value positives: new files, language independent. Documented formats:
# cert-manager Certificate (privateKey.algorithm/size), Terraform tls_private_key, Java properties.
CONFIG_POSITIVES = {
    "cert_manager_yaml": {
        "RSA": {"path": "deploy/planted-{id}-certificate.yaml",
                "lines": ["apiVersion: cert-manager.io/v1", "kind: Certificate", "metadata:", "  name: planted-{id}", "spec:",
                          "  secretName: planted-{id}-tls", "  privateKey:", "    algorithm: RSA", "    size: 2048",
                          "  dnsNames:", "    - planted-{id}.example.internal", "  issuerRef:", "    name: internal-ca", "    kind: ClusterIssuer"],
                "use": [7, 8]},
        "ECDSA": {"path": "deploy/planted-{id}-certificate.yaml",
                  "lines": ["apiVersion: cert-manager.io/v1", "kind: Certificate", "metadata:", "  name: planted-{id}", "spec:",
                            "  secretName: planted-{id}-tls", "  privateKey:", "    algorithm: ECDSA", "    size: 256",
                            "  dnsNames:", "    - planted-{id}.example.internal", "  issuerRef:", "    name: internal-ca", "    kind: ClusterIssuer"],
                  "use": [7, 8]},
        "Ed25519": {"path": "deploy/planted-{id}-certificate.yaml",
                    "lines": ["apiVersion: cert-manager.io/v1", "kind: Certificate", "metadata:", "  name: planted-{id}", "spec:",
                              "  secretName: planted-{id}-tls", "  privateKey:", "    algorithm: Ed25519",
                              "  dnsNames:", "    - planted-{id}.example.internal", "  issuerRef:", "    name: internal-ca", "    kind: ClusterIssuer"],
                    "use": [7]},
    },
    "terraform_tls_key": {
        "RSA": {"path": "infra/planted-{id}.tf",
                "lines": ["resource \"tls_private_key\" \"planted_{id}\" {", "  algorithm = \"RSA\"", "  rsa_bits  = 2048", "}"], "use": [1, 2]},
        "ECDSA": {"path": "infra/planted-{id}.tf",
                  "lines": ["resource \"tls_private_key\" \"planted_{id}\" {", "  algorithm   = \"ECDSA\"", "  ecdsa_curve = \"P256\"", "}"], "use": [1, 2]},
        "Ed25519": {"path": "infra/planted-{id}.tf",
                    "lines": ["resource \"tls_private_key\" \"planted_{id}\" {", "  algorithm = \"ED25519\"", "}"], "use": [1]},
    },
    "java_properties": {
        "RSA": {"path": "config/planted-{id}.properties", "lines": ["# token signing", "planted.{id}.jwt.algorithm=RS256", "planted.{id}.jwt.key-size=2048"], "use": [1]},
        "ECDSA": {"path": "config/planted-{id}.properties", "lines": ["# token signing", "planted.{id}.jwt.algorithm=ES256"], "use": [1]},
        "Ed25519": {"path": "config/planted-{id}.properties", "lines": ["# token signing", "planted.{id}.jwt.algorithm=EdDSA", "planted.{id}.jwt.curve=Ed25519"], "use": [1, 2]},
    },
}

# ---------------------------------------------------------------- decoy templates
# A decoy names the family and is not a use. The correct outputs: nothing, or a row whose
# evidence_kind is comment or ban. Anything else is a false alarm.
DECOYS: dict[str, dict[str, dict[str, list[str]]]] = {
    "python": {
        "disabled_flag": {"RSA": ["RSA_ENABLED_{id} = False"], "ECDSA": ["ECDSA_ENABLED_{id} = False"], "Ed25519": ["ED25519_ENABLED_{id} = False"]},
        "deny_list": {"RSA": ["DISALLOWED_{id} = frozenset({{'RSA', 'DSA'}})"], "ECDSA": ["DISALLOWED_{id} = frozenset({{'ECDSA', 'DSA'}})"], "Ed25519": ["DISALLOWED_{id} = frozenset({{'Ed25519', 'DSA'}})"]},
        "log_string": {"RSA": ["logger.info('rotating RSA signing key for tenant %s', tenant_{id})"], "ECDSA": ["logger.info('ECDSA verifier not configured for %s', tenant_{id})"], "Ed25519": ["logger.info('Ed25519 key for %s expires soon', tenant_{id})"]},
        "variable_name": {"RSA": ["rsa_migration_done_{id} = True"], "ECDSA": ["ecdsa_fallback_count_{id} = 0"], "Ed25519": ["ed25519_rollout_pct_{id} = 100"]},
        "comment": {"RSA": ["# RSA signing was removed in 3.0; do not reintroduce it here ({id})"], "ECDSA": ["# ECDSA verification moved to the gateway ({id})"], "Ed25519": ["# Ed25519 keys are issued by the platform team ({id})"]},
    },
    "ruby": {
        "disabled_flag": {"RSA": ["RSA_ENABLED_{id} = false"], "ECDSA": ["ECDSA_ENABLED_{id} = false"], "Ed25519": ["ED25519_ENABLED_{id} = false"]},
        "deny_list": {"RSA": ["DISALLOWED_{id} = %w[RSA DSA].freeze"], "ECDSA": ["DISALLOWED_{id} = %w[ECDSA DSA].freeze"], "Ed25519": ["DISALLOWED_{id} = %w[Ed25519 DSA].freeze"]},
        "log_string": {"RSA": ["logger.info(\"rotating RSA signing key for tenant #{{tenant_{id}}}\")"], "ECDSA": ["logger.info(\"ECDSA verifier not configured for #{{tenant_{id}}}\")"], "Ed25519": ["logger.info(\"Ed25519 key for #{{tenant_{id}}} expires soon\")"]},
        "variable_name": {"RSA": ["rsa_migration_done_{id} = true"], "ECDSA": ["ecdsa_fallback_count_{id} = 0"], "Ed25519": ["ed25519_rollout_pct_{id} = 100"]},
        "comment": {"RSA": ["# RSA signing was removed in 3.0; do not reintroduce it here ({id})"], "ECDSA": ["# ECDSA verification moved to the gateway ({id})"], "Ed25519": ["# Ed25519 keys are issued by the platform team ({id})"]},
    },
    "rust": {
        "disabled_flag": {"RSA": ["const RSA_ENABLED_{id}: bool = false;"], "ECDSA": ["const ECDSA_ENABLED_{id}: bool = false;"], "Ed25519": ["const ED25519_ENABLED_{id}: bool = false;"]},
        "deny_list": {"RSA": ["const DISALLOWED_{id}: &[&str] = &[\"RSA\", \"DSA\"];"], "ECDSA": ["const DISALLOWED_{id}: &[&str] = &[\"ECDSA\", \"DSA\"];"], "Ed25519": ["const DISALLOWED_{id}: &[&str] = &[\"Ed25519\", \"DSA\"];"]},
        "log_string": {"RSA": ["fn log_{id}() {{ log::info!(\"rotating RSA signing key for tenant\"); }}"], "ECDSA": ["fn log_{id}() {{ log::info!(\"ECDSA verifier not configured\"); }}"], "Ed25519": ["fn log_{id}() {{ log::info!(\"Ed25519 key expires soon\"); }}"]},
        "variable_name": {"RSA": ["const RSA_MIGRATION_DONE_{id}: bool = true;"], "ECDSA": ["const ECDSA_FALLBACK_COUNT_{id}: u32 = 0;"], "Ed25519": ["const ED25519_ROLLOUT_PCT_{id}: u32 = 100;"]},
        "comment": {"RSA": ["// RSA signing was removed in 3.0; do not reintroduce it here ({id})"], "ECDSA": ["// ECDSA verification moved to the gateway ({id})"], "Ed25519": ["// Ed25519 keys are issued by the platform team ({id})"]},
    },
    "php": {
        "disabled_flag": {"RSA": ["$rsaEnabled_{id} = false;"], "ECDSA": ["$ecdsaEnabled_{id} = false;"], "Ed25519": ["$ed25519Enabled_{id} = false;"]},
        "deny_list": {"RSA": ["$disallowed_{id} = ['RSA', 'DSA'];"], "ECDSA": ["$disallowed_{id} = ['ECDSA', 'DSA'];"], "Ed25519": ["$disallowed_{id} = ['Ed25519', 'DSA'];"]},
        "log_string": {"RSA": ["$log->info(\"rotating RSA signing key for tenant {{$tenant_{id}}}\");"], "ECDSA": ["$log->info(\"ECDSA verifier not configured for {{$tenant_{id}}}\");"], "Ed25519": ["$log->info(\"Ed25519 key for {{$tenant_{id}}} expires soon\");"]},
        "variable_name": {"RSA": ["$rsaMigrationDone_{id} = true;"], "ECDSA": ["$ecdsaFallbackCount_{id} = 0;"], "Ed25519": ["$ed25519RolloutPct_{id} = 100;"]},
        "comment": {"RSA": ["// RSA signing was removed in 3.0; do not reintroduce it here ({id})"], "ECDSA": ["// ECDSA verification moved to the gateway ({id})"], "Ed25519": ["// Ed25519 keys are issued by the platform team ({id})"]},
    },
    "typescript": {
        "disabled_flag": {"RSA": ["const RSA_ENABLED_{id} = false;"], "ECDSA": ["const ECDSA_ENABLED_{id} = false;"], "Ed25519": ["const ED25519_ENABLED_{id} = false;"]},
        "deny_list": {"RSA": ["const DISALLOWED_{id} = new Set(['RSA', 'DSA']);"], "ECDSA": ["const DISALLOWED_{id} = new Set(['ECDSA', 'DSA']);"], "Ed25519": ["const DISALLOWED_{id} = new Set(['Ed25519', 'DSA']);"]},
        "log_string": {"RSA": ["console.info(`rotating RSA signing key for tenant ${{tenant{id}}}`);"], "ECDSA": ["console.info(`ECDSA verifier not configured for ${{tenant{id}}}`);"], "Ed25519": ["console.info(`Ed25519 key for ${{tenant{id}}} expires soon`);"]},
        "variable_name": {"RSA": ["const rsaMigrationDone{id} = true;"], "ECDSA": ["const ecdsaFallbackCount{id} = 0;"], "Ed25519": ["const ed25519RolloutPct{id} = 100;"]},
        "comment": {"RSA": ["// RSA signing was removed in 3.0; do not reintroduce it here ({id})"], "ECDSA": ["// ECDSA verification moved to the gateway ({id})"], "Ed25519": ["// Ed25519 keys are issued by the platform team ({id})"]},
    },
    "java": {
        "disabled_flag": {"RSA": ["    static final boolean RSA_ENABLED_{id} = false;"], "ECDSA": ["    static final boolean ECDSA_ENABLED_{id} = false;"], "Ed25519": ["    static final boolean ED25519_ENABLED_{id} = false;"]},
        "deny_list": {"RSA": ["    static final java.util.Set<String> DISALLOWED_{id} = java.util.Set.of(\"RSA\", \"DSA\");"], "ECDSA": ["    static final java.util.Set<String> DISALLOWED_{id} = java.util.Set.of(\"ECDSA\", \"DSA\");"], "Ed25519": ["    static final java.util.Set<String> DISALLOWED_{id} = java.util.Set.of(\"Ed25519\", \"DSA\");"]},
        "log_string": {"RSA": ["    static void log{id}(String t) {{ LOG.info(\"rotating RSA signing key for tenant {{}}\", t); }}"], "ECDSA": ["    static void log{id}(String t) {{ LOG.info(\"ECDSA verifier not configured for {{}}\", t); }}"], "Ed25519": ["    static void log{id}(String t) {{ LOG.info(\"Ed25519 key for {{}} expires soon\", t); }}"]},
        "variable_name": {"RSA": ["    static final boolean rsaMigrationDone{id} = true;"], "ECDSA": ["    static final int ecdsaFallbackCount{id} = 0;"], "Ed25519": ["    static final int ed25519RolloutPct{id} = 100;"]},
        "comment": {"RSA": ["    // RSA signing was removed in 3.0; do not reintroduce it here ({id})"], "ECDSA": ["    // ECDSA verification moved to the gateway ({id})"], "Ed25519": ["    // Ed25519 keys are issued by the platform team ({id})"]},
    },
    "go": {
        "disabled_flag": {"RSA": ["const rsaEnabled{id} = false"], "ECDSA": ["const ecdsaEnabled{id} = false"], "Ed25519": ["const ed25519Enabled{id} = false"]},
        "deny_list": {"RSA": ["var disallowed{id} = []string{{\"RSA\", \"DSA\"}}"], "ECDSA": ["var disallowed{id} = []string{{\"ECDSA\", \"DSA\"}}"], "Ed25519": ["var disallowed{id} = []string{{\"Ed25519\", \"DSA\"}}"]},
        "log_string": {"RSA": ["func log{id}(t string) {{ log.Printf(\"rotating RSA signing key for tenant %s\", t) }}"], "ECDSA": ["func log{id}(t string) {{ log.Printf(\"ECDSA verifier not configured for %s\", t) }}"], "Ed25519": ["func log{id}(t string) {{ log.Printf(\"Ed25519 key for %s expires soon\", t) }}"]},
        "variable_name": {"RSA": ["const rsaMigrationDone{id} = true"], "ECDSA": ["const ecdsaFallbackCount{id} = 0"], "Ed25519": ["const ed25519RolloutPct{id} = 100"]},
        "comment": {"RSA": ["// RSA signing was removed in 3.0; do not reintroduce it here ({id})"], "ECDSA": ["// ECDSA verification moved to the gateway ({id})"], "Ed25519": ["// Ed25519 keys are issued by the platform team ({id})"]},
    },
}

# Language-independent decoys, planted as new files.
FILE_DECOYS = {
    # A JWKS whose only key is EC P-256 and whose kid label says rsa4096. Any RSA row is false.
    "kid_label": {
        "RSA": {"path": "config/planted-{id}-jwks.json", "decoy_line": 4, "family": "RSA", "any_family": True,
                "lines": ["{{", "  \"keys\": [", "    {{", "      \"kid\": \"rsa4096-{id}\",", "      \"kty\": \"EC\",", "      \"crv\": \"P-256\"," ,
                          "      \"use\": \"sig\",", "      \"alg\": \"ES256\",",
                          "      \"x\": \"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",", "      \"y\": \"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"",
                          "    }}", "  ]", "}}"]},
    },
    # sshd_config that removes ssh-rsa and the SHA-1 DH group from the defaults ("-" prefix,
    # sshd_config(5): "If the specified list begins with a '-' character, then the specified
    # algorithms (including wildcards) will be removed from the default set").
    "switched_off_setting": {
        "RSA": {"path": "deploy/planted-{id}/sshd_config", "decoy_line": 1, "family": "RSA", "any_family": True,
                "lines": ["HostKeyAlgorithms -ssh-rsa,ssh-dss", "PubkeyAcceptedAlgorithms -ssh-rsa,ssh-dss"]},
        "DH": {"path": "deploy/planted-{id}/sshd_config", "decoy_line": 1, "family": "DH", "any_family": True,
               "lines": ["KexAlgorithms -diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"]},
    },
}

FAMILIES = ["RSA", "ECDSA", "Ed25519"]

# ---------------------------------------------------------------- tree helpers

_JAVA_TYPE = re.compile(r"^(?:public |final |abstract |sealed |static )*(?:class|interface|enum|record) \w", re.M)


def _skipped_dirs() -> set[str]:
    # The directories the scan itself leaves out: nothing planted there would be read.
    from .detectors import EXCLUDED_DIRS
    return set(EXCLUDED_DIRS)


def language_files(root: Path) -> dict[str, list[Path]]:
    """The files of each language a block may be planted into, in a fixed order."""
    out: dict[str, list[Path]] = {l: [] for l in LANG_EXT}
    ext_to_lang = {v: k for k, v in LANG_EXT.items()}
    skip = _skipped_dirs()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for f in sorted(filenames):
            p = Path(dirpath) / f
            lang = ext_to_lang.get(p.suffix)
            if lang is None or p.is_symlink():
                continue
            if f.endswith(".d.ts") or p.stat().st_size > 400_000:
                continue
            try:
                text = p.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                continue
            if lang == "java" and not _JAVA_TYPE.search(text):
                continue  # package-info, module-info: no class body to plant into
            out[lang].append(p)
    return out


def anchors(lines: list[str], lang: str, member: bool) -> list[int]:
    """0-based indexes after which a block may be inserted.

    Top-level anchor: a blank line whose next non-blank line starts at column 0 (or EOF).
    Member anchor (Java): a blank line whose next non-blank line is indented and not a closing
    brace, inside the first class body.
    """
    n = len(lines)
    out: list[int] = []
    first_code = 0
    if lang == "php":
        for i, l in enumerate(lines):
            if l.lstrip().startswith("<?php"):
                first_code = i + 1
                break
    if lang == "java":
        for i, l in enumerate(lines):
            if _JAVA_TYPE.match(l):
                first_code = i + 1
                while first_code < n and not lines[first_code - 1].rstrip().endswith("{"):
                    first_code += 1
                break
        else:
            return []
    for i in range(first_code, n):
        if lines[i].strip() != "":
            continue
        j = i + 1
        while j < n and lines[j].strip() == "":
            j += 1
        if j >= n:
            if not member:
                out.append(i)
            continue
        nxt = lines[j]
        if member:
            if nxt[:1] in (" ", "\t") and nxt.strip() not in ("}", "};") and not nxt.lstrip().startswith(("*", "@", "}")):
                out.append(i)
        else:
            if nxt[:1] not in (" ", "\t", "}", ")", "]") and not nxt.startswith(("import ", "use ", "package ", "from ", "require")):
                out.append(i)
    if not member and not out:
        out.append(n - 1)
    return out


# ---------------------------------------------------------------- planting


def make_plan(tree: Path, seed: int, families: list[str] | None = None) -> dict[str, Any]:
    """Every item to plant, chosen with the seed alone: the same seed gives the same plan."""
    families = families or FAMILIES
    rng = random.Random(seed)
    files = language_files(tree)
    langs = [l for l in LANG_EXT if files[l]]
    items: list[dict[str, Any]] = []
    counter = 0

    def pid() -> str:
        nonlocal counter
        counter += 1
        return f"p{seed}x{counter:03d}"

    def pick_file(lang: str) -> Path:
        return files[lang][rng.randrange(len(files[lang]))]

    # code positives: every (lang present, style, family)
    for lang in langs:
        for style, byfam in POSITIVES[lang].items():
            for fam in families:
                t = byfam[fam]
                i = pid()
                lines = [l.replace("{id}", i) for l in t["lines"]]
                if lang in ("go", "rust", "java") and not t.get("toplevel"):
                    wrapped, offset = _wrap(lang, i, lines), 1
                else:
                    wrapped, offset = lines, 0
                f = pick_file(lang)
                items.append({
                    "id": i, "kind": "positive", "style": style, "family": fam, "lang": lang,
                    "path": f.relative_to(tree).as_posix(), "new_file": False,
                    "member": lang == "java", "block": wrapped,
                    "use_offsets": [u + offset for u in t["use"]],
                    "name_offsets": [u + offset for u in t.get("name", [])],
                    "expected_size": t.get("size"),
                })
        for cls, byfam in DECOYS[lang].items():
            for fam in families:
                i = pid()
                lines = [l.replace("{id}", i) for l in byfam[fam]]
                f = pick_file(lang)
                items.append({
                    "id": i, "kind": "decoy", "style": cls, "family": fam, "lang": lang,
                    "path": f.relative_to(tree).as_posix(), "new_file": False,
                    "member": lang == "java", "block": lines,
                    "use_offsets": list(range(len(lines))), "name_offsets": [],
                })
    # config positives (new files)
    for style, byfam in CONFIG_POSITIVES.items():
        for fam in families:
            t = byfam[fam]
            i = pid()
            items.append({
                "id": i, "kind": "positive", "style": style, "family": fam, "lang": "config",
                "path": t["path"].replace("{id}", i), "new_file": True, "member": False,
                "block": [l.replace("{id}", i) for l in t["lines"]],
                "use_offsets": t["use"], "name_offsets": [],
            })
    # UTF-16 positives (new files): the direct call of the first language present, UTF-16LE
    # without a BOM, with a Cyrillic comment line first.
    if langs:
        lang = langs[0]
        for fam in families:
            t = POSITIVES[lang]["direct_call"][fam]
            i = pid()
            comment = {"python": "#", "ruby": "#", "php": "#"}.get(lang, "//")
            lines = [f"{comment} ключ за подписване, засаден {i}"] + [l.replace("{id}", i) for l in t["lines"]]
            if lang in ("go", "rust", "java"):
                lines = [lines[0]] + _wrap(lang, i, lines[1:])
                use = [u + 2 for u in t["use"]]
            else:
                use = [u + 1 for u in t["use"]]
            items.append({
                "id": i, "kind": "positive", "style": "utf16_nobom", "family": fam, "lang": lang,
                "path": f"planted/{i}{LANG_EXT[lang]}", "new_file": True, "member": False,
                "encoding": "utf-16-le", "block": lines, "use_offsets": use, "name_offsets": [],
            })
    # file decoys
    for cls, byfam in FILE_DECOYS.items():
        for fam, t in byfam.items():
            i = pid()
            items.append({
                "id": i, "kind": "decoy", "style": cls, "family": t["family"], "lang": "config",
                "path": t["path"].replace("{id}", i), "new_file": True, "member": False,
                "block": [l.replace("{id}", i) for l in t["lines"]],
                "use_offsets": [t["decoy_line"] - 1], "name_offsets": [],
                "any_family": t.get("any_family", False),
            })
    return {"seed": seed, "languages": langs, "items": items}


def apply_plan(plan: dict[str, Any], work: Path) -> None:
    """Insert every block, record its final line numbers, and verify by re-reading."""
    rng = random.Random(plan["seed"] * 7919 + 1)
    by_file: dict[str, list[dict[str, Any]]] = {}
    for it in plan["items"]:
        if it["new_file"]:
            p = work / it["path"]
            p.parent.mkdir(parents=True, exist_ok=True)
            text = "\n".join(it["block"]) + "\n"
            if it.get("encoding") == "utf-16-le":
                p.write_bytes(text.encode("utf-16-le"))
            else:
                p.write_bytes(text.encode("utf-8"))
            it["line"] = 1
            it["lines"] = [1 + o for o in it["use_offsets"]]
            it["name_lines"] = [1 + o for o in it["name_offsets"]]
            continue
        by_file.setdefault(it["path"], []).append(it)
    for rel, its in by_file.items():
        p = work / rel
        raw = p.read_bytes().decode("utf-8")
        nl = "\r\n" if "\r\n" in raw else "\n"
        lines = raw.split("\n")
        trailing_nl = raw.endswith("\n")
        if trailing_nl:
            lines = lines[:-1]
        lines = [l.rstrip("\r") for l in lines]
        lang, member = its[0]["lang"], its[0]["member"]
        cands = anchors(lines, lang, member)
        if not cands:
            cands = anchors(lines, lang, False) or [len(lines) - 1]
        # one anchor per item, chosen with the seed; items at the same anchor stack in id order
        for it in its:
            it["anchor"] = cands[rng.randrange(len(cands))]
        its.sort(key=lambda d: (d["anchor"], d["id"]))
        out: list[str] = []
        k = 0
        for idx, l in enumerate(lines):
            out.append(l)
            while k < len(its) and its[k]["anchor"] == idx:
                it = its[k]
                start = len(out) + 1  # 1-based line of block[0]
                out.extend(it["block"])
                out.append("")
                it["line"] = start
                it["lines"] = [start + o for o in it["use_offsets"]]
                it["name_lines"] = [start + o for o in it["name_offsets"]]
                k += 1
        if k != len(its):
            raise RuntimeError(f"planting failed in {rel}: {k} of {len(its)} blocks placed")
        p.write_bytes((nl.join(out) + (nl if trailing_nl else "")).encode("utf-8"))
    for it in plan["items"]:
        p = work / it["path"]
        got = p.read_bytes().decode(it.get("encoding", "utf-8")).split("\n")
        for o, l in enumerate(it["block"]):
            have = got[it["line"] - 1 + o].rstrip("\r")
            if have != l:
                raise RuntimeError(f"planting verification failed at {it['path']}:{it['line'] + o}")


# ---------------------------------------------------------------- scoring


def _rows_by_path(scan: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Every evidence row with a path and a line, from every evidence list."""
    out: dict[str, list[dict[str, Any]]] = {}
    for rows in (scan.get("evidence") or {}).values():
        if not isinstance(rows, list):
            continue
        for r in rows:
            if isinstance(r, dict) and "path" in r:
                out.setdefault(r["path"], []).append(r)
    return out


def _row_family(r: dict[str, Any]) -> str | None:
    for k in ("algorithm", "family", "algorithm_family", "group", "kex"):
        v = r.get(k)
        if isinstance(v, str):
            return v
    return None


def _family_matches(expected: str, name: str | None) -> bool:
    return name is not None and name in FAMILY_MATCH.get(expected, {expected})


def _not_read_reason(scan: dict[str, Any], path: str) -> str | None:
    cov = scan.get("coverage") or {}
    for r in cov.get("not_examined") or []:
        if path in (r.get("paths") or []):
            return f"not_examined:{r.get('reason')}"
    for key in ("unreadable_files", "claimed_but_not_decoded"):
        for p in scan.get(key) or []:
            if (p.get("path") if isinstance(p, dict) else p) == path:
                return key
    for r in cov.get("examined_partly") or []:
        if (r.get("path") if isinstance(r, dict) else r) == path:
            return "examined_partly"
    return None


_CONF_ORDER = {"high": 3, "medium": 2, "low": 1}


def _best_conf(rows: list[dict[str, Any]]) -> str:
    return max((r.get("confidence", "none") for r in rows), key=lambda c: _CONF_ORDER.get(c, 0))


def score(plan: dict[str, Any], scan: dict[str, Any]) -> None:
    """Give every planted item its outcome, from the rows the scan put on its lines."""
    by_path = _rows_by_path(scan)
    files_read = set(scan.get("files_read") or [])
    for it in plan["items"]:
        rows = by_path.get(it["path"], [])
        on_use = [r for r in rows if r.get("line") in it["lines"]]
        on_name = [r for r in rows if r.get("line") in it.get("name_lines", [])]
        if it["kind"] == "positive":
            fam = [r for r in on_use if _family_matches(it["family"], _row_family(r))]
            use_hits = [r for r in fam if r.get("evidence_kind") not in NOT_A_USE]
            downgraded = [r for r in fam if r.get("evidence_kind") in NOT_A_USE]
            wrong = [r for r in on_use if not _family_matches(it["family"], _row_family(r))]
            if use_hits:
                it["outcome"], it["confidence"] = "found", _best_conf(use_hits)
                it["evidence_kind"] = use_hits[0].get("evidence_kind")
            elif downgraded:
                it["outcome"], it["confidence"] = "read_as_not_a_use", _best_conf(downgraded)
                it["evidence_kind"] = downgraded[0].get("evidence_kind")
            elif wrong:
                it["outcome"], it["confidence"] = "wrong_family", _best_conf(wrong)
            else:
                reason = _not_read_reason(scan, it["path"])
                if reason is None and it["path"] not in files_read:
                    reason = "not in files_read"
                if reason:
                    it["outcome"], it["reason"] = "declared_not_read", reason
                else:
                    it["outcome"] = "silent"
            it["found_on_name_line"] = any(_family_matches(it["family"], _row_family(r)) for r in on_name)
            if it.get("expected_size"):
                it["size_read"] = it["expected_size"] in {r.get("key_size") for r in on_use}
        else:
            # For the two file decoys the whole line is a removal or a label, so any family
            # on it counts.
            fam = [r for r in on_use if (it.get("any_family") and _row_family(r))
                   or _family_matches(it["family"], _row_family(r))]
            uses = [r for r in fam if r.get("evidence_kind") not in NOT_A_USE]
            if uses:
                it["outcome"], it["confidence"] = "reported_as_use", _best_conf(uses)
                it["evidence_kind"] = uses[0].get("evidence_kind")
            elif fam:
                it["outcome"], it["confidence"] = "named_not_used", _best_conf(fam)
                it["evidence_kind"] = fam[0].get("evidence_kind")
            else:
                it["outcome"] = "silent"


def _tally(items: list[dict[str, Any]], outcomes: tuple[str, ...]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for it in items:
        d = out.setdefault(it["style"], {"planted": 0, **{o: 0 for o in outcomes}})
        d["planted"] += 1
        d[it["outcome"]] += 1
    return out


POSITIVE_OUTCOMES = ("found", "silent", "read_as_not_a_use", "wrong_family", "declared_not_read")
DECOY_OUTCOMES = ("reported_as_use", "named_not_used", "silent")


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _named_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{n} {k}" for k, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def sentence(block: dict[str, Any]) -> str:
    """The sentence a report carries with the figure, built from the block alone."""
    u, d = block["planted_uses"], block["planted_non_uses"]
    silent = {s: v["silent"] for s, v in block["by_style"].items() if v["silent"]}
    alarms = {c: v["reported_as_use"] for c, v in block["by_decoy_class"].items()
              if v["reported_as_use"]}
    other = u - block["found"] - block["silent"]
    return (
        f"A control planted into a copy of this tree -- "
        f"{_plural(u, 'cryptographic use', 'cryptographic uses')} in "
        f"{_plural(len(block['by_style']), 'style', 'styles')} and "
        f"{_plural(d, 'line', 'lines')} that name an algorithm without using it -- was scanned "
        f"with this instrument ({block['instrument']['tool']} {block['instrument']['version']}), "
        f"seed {block['seed']}. It found {block['found']} of the {u} uses"
        + (f" (silent on {block['silent']}: {_named_counts(silent)})" if silent else "")
        + (f"; {other} more were read but not as a use of the planted family" if other else "")
        + f", and reported {block['reported_as_use']} of the {d} non-uses as uses"
        + (f" ({_named_counts(alarms)})" if alarms else "")
        + ". This says what the instrument does on those styles. It does not say what this "
          "tree contains, how much of it was found, or that the inventory lists everything, "
          "and it is for this version only."
    )


def harness_sha256() -> str:
    """The digest of what decides the planted lines and their scoring: the templates, the
    decoys, the family equivalences and the harness version. Over the tables, not over this
    file, so it does not change with how the package was installed."""
    material = json.dumps([HARNESS_VERSION, POSITIVES, CONFIG_POSITIVES, DECOYS, FILE_DECOYS,
                           {k: sorted(v) for k, v in FAMILY_MATCH.items()}, sorted(NOT_A_USE)],
                          sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def plan_sha256(plan: dict[str, Any]) -> str:
    """The digest of where every block went and what it says."""
    material = json.dumps([{k: it.get(k) for k in ("id", "kind", "style", "family", "lang",
                                                     "path", "line", "lines", "block")}
                           for it in plan["items"]], sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def block_from(plan: dict[str, Any], instrument: dict[str, Any],
               git_head: str | None) -> dict[str, Any]:
    """The `claims.self_seeded_control` block. Its keys are a published shape
    (docs/control.md): added to, never renamed."""
    pos = [i for i in plan["items"] if i["kind"] == "positive"]
    dec = [i for i in plan["items"] if i["kind"] == "decoy"]

    def n(items: list[dict[str, Any]], outcome: str) -> int:
        return sum(1 for i in items if i["outcome"] == outcome)

    by_confidence = {lvl: [sum(1 for i in pos if i["outcome"] == "found" and i.get("confidence") == lvl),
                           sum(1 for i in dec if i["outcome"] == "reported_as_use" and i.get("confidence") == lvl)]
                     for lvl in ("high", "medium", "low")}
    sized = [i for i in pos if "size_read" in i]
    named = [i for i in pos if i["name_offsets"]]
    block: dict[str, Any] = {
        "ran": True,
        "name": NAME,
        "licenses": LICENSES,
        "feeds": FEEDS,
        "instrument": instrument,
        "seed": plan["seed"],
        "harness_version": HARNESS_VERSION,
        "harness_sha256": harness_sha256(),
        "plan_sha256": plan_sha256(plan),
        "tree": {"git_head": git_head},
        "languages": plan["languages"],
        "families": FAMILIES,
        "planted_uses": len(pos),
        "found": n(pos, "found"),
        "silent": n(pos, "silent"),
        "read_as_not_a_use": n(pos, "read_as_not_a_use"),
        "wrong_family": n(pos, "wrong_family"),
        "declared_not_read": n(pos, "declared_not_read"),
        "planted_non_uses": len(dec),
        "reported_as_use": n(dec, "reported_as_use"),
        "named_not_used": n(dec, "named_not_used"),
        "silent_on_decoys": n(dec, "silent"),
        # [found on planted uses, reported as a use on planted non-uses], by the highest
        # confidence the scan gave the planted line.
        "by_confidence": by_confidence,
        "by_style": _tally(pos, POSITIVE_OUTCOMES),
        "by_decoy_class": _tally(dec, DECOY_OUTCOMES),
        "styles": list(dict.fromkeys(i["style"] for i in pos)),
        "decoy_classes": list(dict.fromkeys(i["style"] for i in dec)),
        "key_size_on_another_line": {"planted": len(sized),
                                     "read": sum(1 for i in sized if i["size_read"])},
        "indirect_name_line": {"planted": len(named),
                               "found": sum(1 for i in named if i["found_on_name_line"])},
    }
    block["sentence"] = sentence(block)
    return block


NOT_RUN = {"ran": False, "name": NAME, "feeds": FEEDS, "how": HOW}


def not_run() -> dict[str, Any]:
    return dict(NOT_RUN)


_ITEM_KEYS = ("id", "kind", "style", "family", "lang", "path", "line", "lines", "outcome",
              "confidence", "evidence_kind", "reason")


def run(path: str | Path, seed: int) -> dict[str, Any]:
    """Plant into a temporary copy of `path`, scan it with this instrument, score it.

    Returns `{"self_seeded_control": block, "items": [...]}`; the items say, for every
    planted line, where it went and what the scan did with it."""
    from . import coverage
    from .scan import scan_directory
    tree = Path(path).expanduser().resolve()
    if not tree.is_dir():
        raise NotADirectoryError(f"not a directory: {tree}")
    plan = make_plan(tree, seed)
    skip = _skipped_dirs()
    tmp = Path(tempfile.mkdtemp(prefix="qrp-control-"))
    try:
        work = tmp / tree.name
        shutil.copytree(tree, work, symlinks=True,
                        ignore=lambda _d, names: [n for n in names if n in skip])
        apply_plan(plan, work)
        # The instrument, not the owner's settings: a control under a config that excludes
        # half the tree would measure the config.
        scan = scan_directory(work, settings=None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    score(plan, scan)
    inst = (scan.get("coverage") or {}).get("instrument") or {}
    instrument = {"tool": inst.get("tool", "qrp-mcp"), "version": inst.get("version", __version__),
                  "revision": inst.get("revision")}
    git_head = coverage._git_pin(tree).get("commit")
    return {"self_seeded_control": block_from(plan, instrument, git_head),
            "items": [{k: it[k] for k in _ITEM_KEYS if k in it} for it in plan["items"]]}
