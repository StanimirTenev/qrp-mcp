"""Differential test: the extracted classifier must behave identically to the original
crypto-fingerprint-service, apart from the deliberately removed HNDL fields.

This is the check that proves the extraction did not silently drop a branch. It is skipped
when the original service source is not present (i.e. everywhere except the author's machine).
"""

from __future__ import annotations

import importlib.util
import itertools
import os
import sys
from pathlib import Path

import pytest

from qrp_mcp import classifier as new

ORIGINAL_PATH = Path(
    os.environ.get(
        "QRP_FINGERPRINT_SERVICE_PATH",
        Path.home() / "Quantum-Readiness-Platform/services/crypto-fingerprint-service/app/main.py",
    )
)

HNDL_SENTENCE = " Recorded traffic is exposed to harvest-now-decrypt-later."


def _load_original():
    if not ORIGINAL_PATH.is_file():
        pytest.skip(f"original service not available at {ORIGINAL_PATH}")
    name = "_original_fingerprint"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ORIGINAL_PATH)
    module = importlib.util.module_from_spec(spec)
    # Registered before exec so pydantic can resolve the models' annotations against
    # the module namespace; without this its forward references stay unresolved.
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except ImportError as exc:  # fastapi/pydantic missing
        del sys.modules[name]
        pytest.skip(f"cannot import original service: {exc}")
    return module


ALGORITHMS = [
    # post-quantum
    "ML-KEM-768", "Kyber512", "ML-DSA-65", "Dilithium3", "SLH-DSA-SHA2-128s",
    "SPHINCS+-SHA2-128s", "Falcon-512", "FrodoKEM-640",
    # classical public key
    "ECDSA", "ecdsa-with-SHA256", "EdDSA", "Ed25519", "Ed448", "X25519", "X448",
    "ECDH", "id-ecPublicKey", "RSASSA-PSS", "RSA-PSS", "rsaEncryption", "RSA",
    "DSA", "Diffie-Hellman", "DHE-RSA", "DH", "EC",
    # weak / deprecated
    "md5WithRSAEncryption", "sha1WithRSAEncryption", "MD5", "SHA1", "RC4",
    "TripleDES", "3DES", "DES-CBC",
    # symmetric / hash / unknown
    "ChaCha20-Poly1305", "AES-256-GCM", "SHA-512", "SHA-384", "SHA-256", "SHA-224",
    "SHA3-256", "", "not-a-real-algorithm", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
]

USAGES = ["signature", "public_key", "key_exchange", "cipher", "explicit"]
KEY_SIZES = [None, 512, 1024, 2048, 4096, 0]


def _comparable(finding) -> dict:
    data = finding.model_dump()
    data.pop("harvest_now_decrypt_later", None)
    data["reason"] = data["reason"].replace(HNDL_SENTENCE, "")
    return data


def test_classify_algorithm_matches_original_across_the_matrix() -> None:
    original = _load_original()
    combinations = list(itertools.product(ALGORITHMS, USAGES, KEY_SIZES))
    assert len(combinations) > 1000, "corpus too small to be a meaningful differential test"

    for raw_value, usage, key_size in combinations:
        old_finding = original.classify_algorithm(
            raw_value, usage, source="s", location="l", key_size=key_size
        )
        new_finding = new.classify_algorithm(
            raw_value, usage, source="s", location="l", key_size=key_size
        )
        assert _comparable(old_finding) == _comparable(new_finding), (
            f"divergence for raw_value={raw_value!r} usage={usage} key_size={key_size}"
        )


EVIDENCE_DOCUMENTS = [
    {"asset_name": "empty"},
    {"asset_name": "explicit", "algorithms": ["RSA", "ML-KEM-768", "MD5"]},
    {
        "asset_name": "tls-nested",
        "tls_metadata": {
            "certificate": {
                "algorithms": {"signature": "sha1WithRSAEncryption", "public_key": "rsaEncryption"},
                "key": {"size_bits": 1024},
            },
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        },
    },
    {
        "asset_name": "tls-flat",
        "tls_metadata": {
            "certificate": {
                "signature_algorithm": "ecdsa-with-SHA256",
                "public_key_algorithm": "id-ecPublicKey",
                "public_key_size": 256,
            }
        },
    },
    {
        "asset_name": "repo",
        "crypto_evidence": {
            "package_metadata": {"packages": [{"name": "RSA"}, {"name": "ECDSA"}]},
            "repo_scan": {
                "ci_pipeline_findings": [
                    {"path": ".github/workflows/ci.yml", "line": 12, "command_type": "cosign_sign"}
                ],
                "embedded_key_findings": [
                    {"path": "main.tf", "line": 3, "description": "Embedded private key material"}
                ],
            },
        },
    },
]


def test_full_fingerprint_matches_original() -> None:
    original = _load_original()

    for document in EVIDENCE_DOCUMENTS:
        old_response = original.fingerprint(original.FingerprintRequest(**document))
        new_response = new.fingerprint(new.FingerprintRequest(**document))

        assert [_comparable(f) for f in old_response.findings] == [
            _comparable(f) for f in new_response.findings
        ], f"findings diverge for {document['asset_name']}"

        old_summary = old_response.summary.model_dump()
        old_summary.pop("hndl_exposure", None)
        assert old_summary == new_response.summary.model_dump(), (
            f"summary diverges for {document['asset_name']}"
        )
        assert old_response.contract_version == new_response.contract_version


# Families added after extraction for the blockchain audience. Everything the original
# knew must survive unchanged; these are additions on top.
ADDED_FAMILIES = {"Schnorr", "BLS"}


def test_known_algorithms_extends_original_without_changing_it() -> None:
    original = _load_original()
    old = [
        {k: v for k, v in entry.items() if k != "hndl_capable"}
        for entry in original.algorithms()["algorithms"]
    ]
    current = new.known_algorithms()

    added = [entry for entry in current if entry["family"] in ADDED_FAMILIES]
    assert {entry["family"] for entry in added} == ADDED_FAMILIES

    kept = [entry for entry in current if entry["family"] not in ADDED_FAMILIES]
    assert kept == old, "an existing algorithm family changed or disappeared"
