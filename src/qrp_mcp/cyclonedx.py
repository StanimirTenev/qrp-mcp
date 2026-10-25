"""A CycloneDX 1.6 CBOM that carries its own coverage.

Every scanner computes coverage. The measured gap is that the number dies at the
export boundary: it lives in the tool's native report, which an engineer reads,
and is absent from the CBOM, which is the document that gets signed and handed to
an auditor. At least one competing scanner emits `filesScanned`, `analyzedFiles`
and an unreadable counter natively and drops all three on the way into CycloneDX,
while using `properties` freely in the same document for other things.

So the argument here is not that the schema forbids it. The schema has no home for
it -- the root object is `additionalProperties: false`, so a top-level `coverage`
key is invalid -- and `properties` is the escape hatch the format supplies for
exactly this. This emitter uses it, deliberately and visibly. A document that has
to flatten a structured measurement into dotted name-value strings is the evidence
that the field is missing; a tidier document would hide the argument.

Three things travel that a bare component list cannot say:

  compositions   how complete the component list is, in the schema's own vocabulary.
                 `complete` only when every file present was examined. Anything else
                 is `incomplete`, which is a word the format has had since 1.3 and
                 which the reference emitter never writes: checked on the
                 sonar-cryptography tree, no code path constructs a Composition and
                 the sample CBOM in its own README carries none. So the vocabulary
                 for saying "this list is not everything" already exists and goes
                 unused, which is a count anyone can repeat rather than an opinion
                 about a gap.
  properties     the whole coverage block, flattened. Instrument, corpus, window,
                 scope, and every file not examined with its reason.
  evidence       where each asset was found: file, line and matched text, matching
                 the shape the reference emitter already publishes.

Determinism is a requirement rather than a nicety, because the comparison tool in
`coverage.compare` reads these documents. Two runs of the same instrument over the
same corpus that find the same things get the same serial number: it is derived from
the target, the two pins and a digest of the findings and counts rather than drawn at
random. Since release A the whole document is byte-identical across such runs: the
timestamp is the tree's commit time (or SOURCE_DATE_EPOCH, or absent), and the read
window stays in the scan result, named in the CBOM rather than carried. Two runs whose
instrument differs get different serial numbers, which is the pin argument stated in one
field.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .assets import TLS_SETTING_NOTE
from .detectors import in_test_code
from .classifier import known_algorithms

SPEC_VERSION = "1.6"

# CycloneDX namespaces `properties` by convention rather than by schema, so the
# prefix is what keeps these from colliding with another tool's keys.
NS = "qrp:"

# A cryptographic asset's primitive, in the schema's enum. Derived from the
# classifier's own `kind` where it says enough, and named per family where it does
# not: `kind` calls both a KEM and a Diffie-Hellman exchange `key_exchange`, and
# those are different primitives. Anything not covered here is `unknown`, which is
# the schema's word and is honest -- but a family arriving here regularly means it
# belongs in one of the tables instead.
_PRIMITIVE_BY_KIND = {
    "signature": "signature",
    "key_exchange": "key-agree",
    "public_key": "pke",
}
_KEM_FAMILIES = {
    "ML-KEM", "Kyber", "FrodoKEM", "Classic McEliece", "NTRU", "BIKE", "HQC", "SIKE",
    "SMAUG-T",      # ZA-OPRAVYANE row 139
}
_PRIMITIVE_BY_FAMILY = {
    "MD5": "hash",
    "SHA1": "hash",
    "DES": "block-cipher",
    "3DES": "block-cipher",
    "RC4": "stream-cipher",
    "RC2": "block-cipher",
    "MD2": "hash",      # MD2 and MD4: row 139
    "MD4": "hash",
    "SHA-224": "hash",
    "SHA3-224": "hash",
    "AES-ECB": "block-cipher",
    "PPK (RFC 8784)": "other",
    # Not an algorithm: a certificate format whose strength is the CA's and cosigners'.
    "MTC": "other",
}


# -- M4: the standard fields, each from a table with a source (release A) -----------------
#
# Filled only where the scan read what the table needs; otherwise absent, never guessed.
#
# `oid`: the algorithm's own identifier, only where the family is one algorithm and not a
# combination with a hash (ECDSA's OIDs all name one, so ECDSA gets none). The same
# entries, from the same RFCs, as oids.OIDS: RFC 8017 App. C (rsaEncryption), RFC 3279
# (id-dsa, dhpublicnumber, md5, sha1), RFC 5480 (id-ecPublicKey), RFC 8410 (X25519, X448,
# Ed25519, Ed448). A test holds the two tables together.
_OID_BY_FAMILY = {
    "RSA": "1.2.840.113549.1.1.1",
    "DSA": "1.2.840.10040.4.1",
    "DH": "1.2.840.10046.2.1",
    "EC": "1.2.840.10045.2.1",
    "X25519": "1.3.101.110",
    "X448": "1.3.101.111",
    "Ed25519": "1.3.101.112",
    "Ed448": "1.3.101.113",
    "MD5": "1.2.840.113549.2.5",
    "SHA1": "1.3.14.3.2.26",
}
# A post-quantum OID names a parameter set, so it is stated only where one set was read.
# NIST CSOR (Computer Security Objects Register), as classifier._OID_FAMILIES:
# kems 2.16.840.1.101.3.4.4.{1,2,3} = ML-KEM-512/768/1024 (FIPS 203); sigAlgs
# 2.16.840.1.101.3.4.3.{17,18,19} = ML-DSA-44/65/87 (FIPS 204, RFC 9881) and .20-.31 = the
# twelve pure SLH-DSA sets in FIPS 205 order (RFC 9909).
_PQC_OID = {
    ("ML-KEM", "512"): "2.16.840.1.101.3.4.4.1",
    ("ML-KEM", "768"): "2.16.840.1.101.3.4.4.2",
    ("ML-KEM", "1024"): "2.16.840.1.101.3.4.4.3",
    ("ML-DSA", "44"): "2.16.840.1.101.3.4.3.17",
    ("ML-DSA", "65"): "2.16.840.1.101.3.4.3.18",
    ("ML-DSA", "87"): "2.16.840.1.101.3.4.3.19",
    **{("SLH-DSA", f"{h}-{n}{v}"): f"2.16.840.1.101.3.4.3.{20 + i}"
       for i, (h, n, v) in enumerate((h, n, v) for h in ("SHA2", "SHAKE")
                                     for n in (128, 192, 256) for v in "sf")},
}
# `nistQuantumSecurityLevel`: the category the standard assigns to the parameter set.
# FIPS 203 §8 (ML-KEM-512/768/1024: 1/3/5), FIPS 204 §4 Table 1 (ML-DSA-44/65/87: 2/3/5),
# FIPS 205 §11 Table 2 (SLH-DSA-*-128/192/256: 1/3/5).
_PQC_CATEGORY = {
    ("ML-KEM", "512"): 1, ("ML-KEM", "768"): 3, ("ML-KEM", "1024"): 5,
    ("ML-DSA", "44"): 2, ("ML-DSA", "65"): 3, ("ML-DSA", "87"): 5,
    **{("SLH-DSA", f"{h}-{n}{v}"): {128: 1, 192: 3, 256: 5}[n]
       for h in ("SHA2", "SHAKE") for n in (128, 192, 256) for v in "sf"},
}
# ...and 0 -- "none of the categories are met", the schema's own words -- for the classical
# public-key families Shor's algorithm breaks (NIST IR 8547 ipd lists RSA, ECDSA, EdDSA,
# DH, ECDH and DSA as quantum-vulnerable; the rest are the same integer-factorisation and
# discrete-log problems).
_SHOR_BROKEN = {
    "RSA", "DSA", "DH", "EC", "ECDSA", "ECDH", "EdDSA", "Ed25519", "Ed448", "X25519", "X448",
    "Schnorr", "BLS", "GOST R 34.10", "SM2", "ElGamal",
}
# `classicalSecurityLevel` (bits). NIST SP 800-57 Part 1 Rev. 5, Table 2: IFC/FFC by the
# modulus size exactly as tabulated (4096 is not in the table, so it gets none); ECC by
# the size of n in ranges. Table 3 for hash collision resistance (SHA-224: 112; MD5 and
# SHA-1 are "<80" there, not a number, so they get none). NIST SP 800-186 for the
# Montgomery and Edwards curves (Curve25519/Edwards25519: 128, Curve448/Edwards448: 224).
_IFC_FFC_STRENGTH = {1024: 80, 2048: 112, 3072: 128, 7680: 192, 15360: 256}
_IFC_FFC = {"RSA", "DSA", "DH", "ElGamal"}
_ECC = {"EC", "ECDSA", "ECDH"}
_ECC_STRENGTH = ((512, 256), (384, 192), (256, 128), (224, 112), (160, 80))
_FIXED_STRENGTH = {"X25519": 128, "Ed25519": 128, "X448": 224, "Ed448": 224,
                   "SHA-224": 112, "SHA3-224": 112}
# `curve`: where the family fixes it, in the names the schema recommends
# (neuromancer.sk/std, "other" category); otherwise only a curve read from the file.
_FIXED_CURVE = {"X25519": "Curve25519", "X448": "Curve448",
                "Ed25519": "Ed25519", "Ed448": "Ed448"}
# `cryptoFunctions`: what the algorithm implements, by primitive (schema enum). Key
# agreement derives the shared key (NIST SP 800-56A Rev. 3 §5.8: key derivation is part of
# every key-agreement scheme). `pke` is said per family: an "EC" key is not an algorithm.
_FUNCTIONS_BY_PRIMITIVE = {
    "signature": ["keygen", "sign", "verify"],
    "kem": ["keygen", "encapsulate", "decapsulate"],
    "key-agree": ["keygen", "keyderive"],
    "hash": ["digest"],
    "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"],
}
_FUNCTIONS_BY_FAMILY = {
    "RSA": ["keygen", "encrypt", "decrypt", "sign", "verify"],
    "ElGamal": ["keygen", "encrypt", "decrypt"],
}


def _classical_strength(family: str, sizes: list[int]) -> int | None:
    if family in _FIXED_STRENGTH:
        return _FIXED_STRENGTH[family]
    if len(sizes) != 1:
        return None
    if family in _IFC_FFC:
        return _IFC_FFC_STRENGTH.get(sizes[0])
    if family in _ECC:
        return next((bits for floor, bits in _ECC_STRENGTH if sizes[0] >= floor), None)
    return None


def _m4_fields(family: str, primitive: str, sizes: list[int],
               in_use: list[dict[str, Any]]) -> tuple[dict[str, Any], str | None, list[str]]:
    """The M4 fields for one family: algorithmProperties additions, the OID, and every
    parameter set read when there was more than one (named, none chosen)."""
    sets = sorted({i["parameter_set"] for i in in_use if i.get("parameter_set")})
    curves = sorted({c.strip() for i in in_use if i.get("curve")
                     for c in str(i["curve"]).split(",") if c.strip()})
    one_set = sets[0] if len(sets) == 1 else None
    fields: dict[str, Any] = {}
    # A key size wins where one was read (the existing rule); otherwise one parameter set.
    if len(sizes) != 1 and one_set:
        fields["parameterSetIdentifier"] = one_set
    curve = _FIXED_CURVE.get(family) or (curves[0] if len(curves) == 1 else None)
    if curve:
        fields["curve"] = curve
    functions = _FUNCTIONS_BY_FAMILY.get(family) or _FUNCTIONS_BY_PRIMITIVE.get(primitive)
    if functions:
        fields["cryptoFunctions"] = list(functions)
    strength = _classical_strength(family, sizes)
    if strength is not None:
        fields["classicalSecurityLevel"] = strength
    if family in _SHOR_BROKEN:
        fields["nistQuantumSecurityLevel"] = 0
    elif (family, one_set) in _PQC_CATEGORY:
        fields["nistQuantumSecurityLevel"] = _PQC_CATEGORY[(family, one_set)]
    oid = _OID_BY_FAMILY.get(family) or _PQC_OID.get((family, one_set))
    return fields, oid, sets if len(sets) > 1 else []


# What a protocol asset says beyond its version, carried as properties. The default a
# listener got because nothing was written, the standing of an OPC UA policy, and the
# fragmentation of an IKE configuration all have to reach the document that is sent,
# and an excerpt -- masked by default -- cannot carry them.
_PROTOCOL_FIELDS = ("security_policy", "policy_status", "policy", "allows_versions",
                    "post_quantum", "default_applied", "product", "fragmentation",
                    "fragmentation_default", "udp_setting", "udp_size", "included_by",
                    "listener", "library_defaults", "peer_verification",
                    "verification_setting", "dnssec_algorithm", "dnssec_mnemonic")
_CDX_PROTOCOLS = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa"}


def _protocol_label(asset: dict[str, Any]) -> str:
    if asset.get("listener"):
        return f"TLS listener ({asset['listener']})"
    if asset.get("peer_verification"):
        return f"TLS peer verification off ({asset['verification_setting']})"
    if asset.get("security_policy"):
        return f"OPC UA SecurityPolicy {asset['security_policy']}"
    if asset.get("policy"):
        return asset["policy"] + (" (default: ssl_policy absent)"
                                  if asset.get("default_applied") else "")
    if asset.get("product"):
        return f"{asset.get('version') or 'IKE'} ({asset['product']})"
    if asset.get("dnssec_algorithm") is not None:
        return f"DNSSEC algorithm {asset['dnssec_algorithm']} (not named by this scan)"
    return asset.get("version") or asset["protocol"].upper()


# Said beside every provider, so the name is not read as more than it is.
PROVIDER_VALIDATION = (
    "not claimed: the provider is named from the API in the file, not from the build, "
    "and whether that module is CMVP-validated (FIPS 140-3) has to be checked against "
    "the CMVP list for the version actually deployed")


def _primitive(family: str) -> str:
    if family in _PRIMITIVE_BY_FAMILY:
        return _PRIMITIVE_BY_FAMILY[family]
    if family in _KEM_FAMILIES:
        return "kem"
    kind = _kinds().get(family)
    return _PRIMITIVE_BY_KIND.get(kind or "", "unknown")


def _kinds() -> dict[str, str]:
    """Family to kind, from the same table the classifier answers from.

    Read here rather than taken off the finding: a finding carries the
    classification, not the kind, and inferring one from the other would put a
    guess where the table already has the answer.
    """
    return {a["family"]: a["kind"] for a in known_algorithms()}


def _ref(prefix: str, name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return f"{prefix}:{slug}"


def _flatten(value: Any, path: str = "") -> list[tuple[str, str]]:
    """Coverage block to dotted name-value pairs.

    Lossless for the numbers, which is what a reader has to be able to
    reconstruct. Lists of scalars are joined rather than indexed because the
    claimed extensions are a set and the order carries nothing; lists of objects
    keep their index because `not_examined[0]` and `not_examined[1]` are
    different reasons and collapsing them is the defect this block exists against.
    """
    if isinstance(value, dict):
        out: list[tuple[str, str]] = []
        for key, sub in value.items():
            out.extend(_flatten(sub, f"{path}:{key}" if path else key))
        return out
    if isinstance(value, list):
        # File names are data, and data can hold any separator. Until 0.28.0 they were
        # joined by commas unless a name held one, and then indexed -- lossless, but
        # where the names sat depended on what they were called (Joel Hillier, CAP-1,
        # 5 Oct 2026). Now one shape for every list of names: a JSON array, `[]` empty.
        # A list of objects (linked entries) stays indexed, field by field, as before.
        if (path.rsplit(":", 1)[-1] == "paths"
                and all(not isinstance(item, (dict, list)) for item in value)):
            return [(path, json.dumps([str(item) for item in value], ensure_ascii=False))]
        if not value:
            return [(path, "")]
        # A set of scalars is joined, unless an item itself contains the separator
        # (a file called "a,b.c"); then it is indexed, so the list reads back exactly.
        if (all(not isinstance(item, (dict, list)) for item in value)
                and not any("," in str(item) for item in value)):
            return [(path, ",".join(str(item) for item in value))]
        out = []
        for index, item in enumerate(value):
            out.extend(_flatten(item, f"{path}:{index}"))
        return out
    if isinstance(value, bool):
        return [(path, "true" if value else "false")]
    if value is None:
        return [(path, "")]
    return [(path, str(value))]


def _serial(coverage: dict[str, Any], findings_digest: str = "") -> str:
    """A serial number that is a function of the run, not of the moment.

    Same instrument over the same corpus gives the same document; a different
    emitter commit gives a different one even at the same version. That is the
    version-does-not-pin-the-emitter finding expressed where a reader trips over
    it rather than in prose.
    """
    corpus = coverage["corpus"]
    instrument = coverage["instrument"]
    corpus_pin = corpus.get("pinned_at") or {}
    tool_pin = instrument.get("source_commit") or {}
    seed = "|".join([
        corpus["target"],
        str(corpus_pin.get("commit") or corpus_pin.get("reason") or ""),
        instrument["version"],
        str(tool_pin.get("commit") or tool_pin.get("reason") or ""),
        # What was found and how much was read: a directory that is not under git
        # can change without any pin changing, and a different result must not
        # share a serial with the old one.
        findings_digest,
    ])
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


# Where the read time lives, said in the CBOM in place of the times themselves.
WINDOW_NOT_CARRIED = (
    "not carried in the CBOM: the read time differs on every run and would make two "
    "documents of one unchanged tree differ; it is in the scan result's coverage.window")


def _timestamp(coverage: dict[str, Any]) -> tuple[str | None, str]:
    """A timestamp that is a function of the tree, and what it is.

    SOURCE_DATE_EPOCH first (the reproducible-builds convention), then the commit time
    of a clean checkout. Otherwise none: the schema makes the field optional, and a
    clock reading would be the one thing in the document the tree did not decide.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch.isdigit():
        stamp = datetime.fromtimestamp(int(epoch), timezone.utc).isoformat(timespec="seconds")
        return stamp, "SOURCE_DATE_EPOCH, set by whoever ran the scan"
    pin = coverage["corpus"].get("pinned_at") or {}
    if pin.get("pinned") and pin.get("dirty") is False and pin.get("committed_at"):
        return pin["committed_at"], ("the commit time of the scanned tree's commit "
                                     "(a clean checkout), not the time of the run")
    return None, ("not stated: the tree is not a clean checkout and SOURCE_DATE_EPOCH is "
                  "not set, so nothing but the clock could give one")


def _occurrences(located: list[dict[str, Any]], family: str,
                 family_of: dict[str, str]) -> list[dict[str, Any]]:
    """Where a family was found. The detector names what it matched ("PPK"); the
    classifier names the family ("PPK (RFC 8784)"), so the evidence is joined
    through the findings' own raw_value -> family pairs rather than by string
    equality, which silently dropped every PPK location."""
    return [
        {
            "location": item["path"],
            "line": item["line"],
            # The matched line when the scan kept it (a 'trimmed' scan does not),
            # otherwise what the rule looks for -- prefixed with the kind of evidence
            # when it is not code.
            "additionalContext": _context(item),
        }
        for item in located
        if family_of.get(item.get("algorithm"), item.get("algorithm")) == family
    ]


def _scope(located: list[dict[str, Any]], family: str,
           family_of: dict[str, str]) -> str | None:
    """`excluded` when every sighting of this family is test code, otherwise nothing.

    The schema has carried this since 1.6 and says it verbatim: "Components that are
    excluded provide the ability to document component usage for test and other
    non-runtime purposes." Identical in 1.7 and 2.0-dev.

    ⚠️ v0.18.0 shipped `[test]` in `additionalContext` and set no scope at all -- a
    private spelling of a standard field, which is the thing this project criticises
    other tools for. The marker stays, because the two say different things: `scope` is
    a property of the component, the marker is a property of one sighting, and a family
    that runs in production and also appears in a fixture needs both facts.
    
    Nothing is emitted for the mixed case: the schema's default is already `required`,
    and writing it out would claim a judgement where the default carries it.
    """
    mine = [item for item in located
            if family_of.get(item.get("algorithm"), item.get("algorithm")) == family]
    if not mine:
        return None
    return "excluded" if all(item.get("in_test_code") for item in mine) else None


# Evidence kinds that are NOT the code doing the thing. `scan_repo` already grades
# every match and keeps these out of the inventory; the exported document dropped the
# grade, so a sentence about certificates arrived at an auditor looking exactly like a
# signature. Measured on certbot 2026-09-26: 78 of 389 source findings (20%) are
# comment evidence, and all 78 travelled unmarked.
#
# The schema has no field for it, so it is named in `additionalContext` for the same
# reason classification and the PQC family travel as properties: named, not silently
# dropped. A reader who filters on `[comment]` gets the inventory the scan itself used.
#
# ⚠️ `ban` is deliberately NOT here. A banned algorithm never becomes a component at
# all -- `!RC4` in a cipher list is excluded upstream, not marked downstream -- so a
# branch for it would be a line that can never run. Measured, not assumed: a fixture
# whose only mention of RC4 is `!RC4` produces no RC4 component.
_NOT_CODE = {"comment"}


def _context(item: dict[str, Any]) -> str:
    """The matched text, prefixed with what kind of place it sits in.

    Composable, because a mention can be both: a comment inside a test fixture gets
    `[comment][test]`. Anything that is plain code in plain code gets no prefix, so an
    unprefixed occurrence means exactly what it used to mean.
    """
    text = item.get("excerpt") or item.get("description", "")
    tags = []
    if item.get("evidence_kind") in _NOT_CODE:
        tags.append(f"[{item['evidence_kind']}]")
    if item.get("in_test_code"):
        tags.append("[test]")
    # The owner of this place, by CODEOWNERS (ZA-OPRAVYANE row 94). Per occurrence, because
    # a component is an algorithm and one algorithm sits in many teams' code; with the line
    # that said it, because it is the file's assumption and not a fact.
    if item.get("owners"):
        tags.append(f"[owners: {' '.join(item['owners'])} per {item['owners_source']}]")
    return f"{''.join(tags)} {text}" if tags else text


# Findings that are not algorithms. Signing commands are counted in the document
# properties; embedded keys become related-crypto-material below.
_NOT_ALGORITHMS = {"signing_command", "private_key"}


def _findings_digest(scan_result: dict[str, Any]) -> str:
    import hashlib
    import json
    material = {
        "findings": sorted((f["algorithm_family"], f["classification"])
                           for f in scan_result["findings"]),
        # Embedded-key items carry neither an algorithm nor a command type; every
        # part is made a string so mixed items sort.
        "evidence": sorted((str(e.get("path")), str(e.get("line")),
                            str(e.get("algorithm") or e.get("command_type") or e.get("description")))
                           for items in scan_result["evidence"].values() for e in items),
        "scope": {k: scan_result["coverage"]["scope"].get(k)
                  for k in ("files_present", "files_examined", "files_not_examined")},
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True, default=str).encode()).hexdigest()


def build(scan_result: dict[str, Any]) -> dict[str, Any]:
    """A CycloneDX 1.6 document from one scan, with the coverage block inside it."""
    coverage = scan_result["coverage"]
    scope = coverage["scope"]
    instrument = coverage["instrument"]

    located = list(scan_result["evidence"]["source_code"]) + list(scan_result["evidence"]["iac"])
    by_family = {f["algorithm_family"]: f for f in scan_result["findings"]
                 if f["algorithm_family"] not in _NOT_ALGORITHMS}
    # Measured on the line and, until 0.17.0, dropped on the way out: the document
    # named the family and said nothing about the modulus.
    observed_sizes: dict[str, list[int]] = scan_result.get("algorithm_key_sizes_observed", {})
    family_of = {f["raw_value"]: f["algorithm_family"] for f in scan_result["findings"]
                 if f.get("raw_value") and f.get("algorithm_family")}

    components: list[dict[str, Any]] = []
    for family in sorted(by_family):
        finding = by_family[family]
        # The sightings the inventory itself uses: a comment or a ban cannot set a field.
        in_use = [item for item in located
                  if family_of.get(item.get("algorithm"), item.get("algorithm")) == family
                  and item.get("evidence_kind") not in {"comment", "ban"}]
        m4, oid, several_sets = _m4_fields(family, _primitive(family),
                                           observed_sizes.get(family, []), in_use)
        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": _ref("crypto", family),
            "name": family,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": _primitive(family),
                    # The schema's own example for this field is the key length:
                    # "in AES128, '128' identifies the key length in bits".
                    #
                    # Stated only where ONE size was observed. Where several were,
                    # the field is left out and every size is named in a property
                    # instead: choosing one of them would publish a number that
                    # looks measured and is not, and a reader cannot tell the
                    # difference. A string, because the schema says string.
                    **({"parameterSetIdentifier": str(observed_sizes[family][0])}
                       if len(observed_sizes.get(family, [])) == 1 else {}),
                    **m4,
                },
                **({"oid": oid} if oid else {}),
            },
            # The classification and the post-quantum family have no field in the
            # schema, so they travel as properties for the same reason coverage
            # does. Named, not silently dropped.
            "properties": [
                {"name": f"{NS}classification", "value": finding["classification"]},
                {"name": f"{NS}quantum_vulnerable",
                 "value": "true" if finding["quantum_vulnerable"] else "false"},
            ],
        }
        # More than one size for the same family: all of them, none chosen.
        if len(observed_sizes.get(family, [])) > 1:
            component["properties"].append({
                "name": f"{NS}observedKeySizes",
                "value": ", ".join(str(s) for s in observed_sizes[family]),
            })
        # More than one parameter set read: all of them, none chosen (as for sizes).
        if several_sets:
            component["properties"].append({
                "name": f"{NS}observedParameterSets", "value": ", ".join(several_sets)})
        for key in ("pqc_family", "pqc_status"):
            if finding.get(key):
                component["properties"].append({"name": f"{NS}{key}", "value": finding[key]})
        # The modules the evidence names, one JSON array like every other list here.
        # Not `certificationLevel`: that field states a validation, and nothing in a
        # file establishes one. Not `implementationPlatform`: that is a CPU.
        if finding.get("providers"):
            component["properties"].append({
                "name": f"{NS}providers",
                "value": json.dumps(finding["providers"], ensure_ascii=False)})
            component["properties"].append({
                "name": f"{NS}provider_validation", "value": PROVIDER_VALIDATION})
        # The version a manifest pins for the provider, and where an openssl.cnf
        # activates the FIPS provider -- both read from files, neither a validation.
        if finding.get("provider_pins"):
            component["properties"].append({
                "name": f"{NS}provider_pins",
                "value": json.dumps(finding["provider_pins"], ensure_ascii=False)})
        if finding.get("fips_provider_configured_in"):
            component["properties"].append({
                "name": f"{NS}provider_configuration",
                "value": ("FIPS provider activated in "
                          + ", ".join(finding["fips_provider_configured_in"])
                          + "; whether the process running this code loads that "
                            "configuration is not in the files")})
        # A pinned image that cannot negotiate the group at every place it is used: the
        # scan's summary does not count it as ready, and the component says why.
        if finding.get("not_negotiable_by"):
            component["properties"].append({
                "name": f"{NS}not_negotiable_by",
                "value": json.dumps(finding["not_negotiable_by"], ensure_ascii=False)})
        occurrences = _occurrences(located, family, family_of)
        if occurrences:
            component["evidence"] = {"occurrences": occurrences}
        # ⚠️ NOT `scope` -- this function already binds that name to the coverage
        # block, and shadowing it made `scope["files_not_examined"]` read None.
        component_scope = _scope(located, family, family_of)
        if component_scope:
            component["scope"] = component_scope
        components.append(component)

    keys = scan_result["evidence"]["embedded_keys"]
    if keys:
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": "crypto:embedded-private-key-material",
            "name": "Embedded private key material",
            "cryptoProperties": {"assetType": "related-crypto-material"},
            "evidence": {"occurrences": [
                {"location": k["path"], "line": k["line"],
                 "additionalContext": k.get("excerpt") or k.get("description", "")}
                for k in keys
            ]},
        })

    # Protocols. CycloneDX has assetType "protocol" for exactly this, and a
    # version pin is the one thing it can honestly carry: which algorithms get
    # negotiated is not in the line that pins the version.
    protocols = scan_result["evidence"].get("protocols", [])
    # Banned and configured are kept apart: `-SSLv3` and `ssl_protocols SSLv3`
    # are opposite facts, and merging them would report a ban as a use.
    # A named policy (OPC UA, AWS) or an IKE configuration is one component per policy
    # and per state: what it says is in the fields below, and two files that say
    # different things about the same policy are two facts.
    by_protocol: dict[tuple[str, str | None, bool, str], list[dict[str, Any]]] = {}
    for asset in protocols:
        said = json.dumps({k: asset[k] for k in _PROTOCOL_FIELDS if k in asset},
                          sort_keys=True)
        by_protocol.setdefault(
            (asset["protocol"], asset.get("version"), bool(asset.get("banned")), said),
            []).append(asset)
    for (name, version, banned, said), group in sorted(by_protocol.items(),
                                                       key=lambda kv: str(kv[0])):
        label = _protocol_label(group[0]) + (" (forbidden)" if banned else "")
        properties = [
            {"name": f"{NS}basis", "value": group[0].get("basis", "configured_protocol")},
            {"name": f"{NS}deprecated",
             "value": "true" if any(a.get("deprecated") for a in group) else "false"},
            # A version listed to forbid it is evidence of hardening, not of use.
            {"name": f"{NS}forbidden", "value": "true" if banned else "false"},
        ]
        # The pointer beside every TLS setting (row 25), on the components the scan marked
        # as a TLS place (a commented-out pin is not one); the statement stays out.
        if any(a.get("tls_termination") for a in group):
            properties.append({"name": f"{NS}tls_termination",
                               "value": TLS_SETTING_NOTE})
        for key, value in json.loads(said).items():
            properties.append({"name": f"{NS}{key}", "value": (
                json.dumps(value) if isinstance(value, (list, dict))
                else ("true" if value is True else "false" if value is False else str(value)))})
        components.append({
            "type": "cryptographic-asset",
            # Stable across runs: the same policy in the same state gets the same ref.
            "bom-ref": _ref("protocol", label + (
                "-" + hashlib.sha256(said.encode()).hexdigest()[:8] if said != "{}" else "")),
            "name": label,
            "cryptoProperties": {
                "assetType": "protocol",
                # CycloneDX's protocol types are a closed list: OPC UA is `other`, and
                # the property above names it.
                "protocolProperties": {"type": name if name in _CDX_PROTOCOLS else "other",
                                       **({"version": version} if version else {})},
            },
            "properties": properties,
            "evidence": {"occurrences": [
                {"location": a["path"], "line": a["line"],
                 "additionalContext": a.get("excerpt", "")}
                for a in group
            ]},
        })

    # A classical TLS group offered as a group of its own, beside or instead of a hybrid.
    # Its own component, so a document from before the fallback was removed and one from
    # after differ by a component rather than by nothing. One per group, however it is
    # spelled: `X25519` and `x25519` would otherwise repeat a bom-ref.
    by_group: dict[str, list[dict[str, Any]]] = {}
    for item in scan_result["evidence"].get("tls_groups", []):
        by_group.setdefault(_ref("tls-group", f"{item['group']}-offered-alone"),
                            []).append(item)
    for ref, group in sorted(by_group.items()):
        component = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": f"{group[0]['group']} (TLS group offered alone)",
            "cryptoProperties": {"assetType": "algorithm",
                                 "algorithmProperties": {"primitive": "key-agree"}},
            "properties": [
                {"name": f"{NS}basis", "value": "configured_group"},
                {"name": f"{NS}offered", "value": "alone"},
                {"name": f"{NS}family", "value": group[0]["family"]},
                {"name": f"{NS}tls_termination", "value": TLS_SETTING_NOTE},
            ],
            "evidence": {"occurrences": [
                {"location": g["path"], "line": g["line"],
                 "additionalContext": _context(g)}
                for g in group
            ]},
        }
        if all(g.get("in_test_code") for g in group):
            component["scope"] = "excluded"
        components.append(component)

    # RSA key exchange enabled by a cipher-suite setting (ZA-OPRAVYANE row 43): one
    # component, whichever suites name it; the suites travel as a property.
    static_rsa = scan_result["evidence"].get("static_rsa_kex", [])
    if static_rsa:
        suites: list[str] = []
        for item in static_rsa:
            suites.extend(s for s in item["suites"] if s not in suites)
        component = {
            "type": "cryptographic-asset",
            "bom-ref": _ref("tls-kex", "RSA-static"),
            "name": "RSA key exchange (static RSA cipher suites)",
            "cryptoProperties": {"assetType": "algorithm",
                                 "algorithmProperties": {"primitive": "pke"}},
            "properties": [
                {"name": f"{NS}basis", "value": "configured_cipher_suite"},
                {"name": f"{NS}family", "value": "RSA"},
                {"name": f"{NS}key_exchange", "value": "RSA"},
                {"name": f"{NS}suites", "value": ", ".join(suites)},
                {"name": f"{NS}tls_termination", "value": TLS_SETTING_NOTE},
            ],
            "evidence": {"occurrences": [
                {"location": g["path"], "line": g["line"],
                 "additionalContext": _context(g)}
                for g in static_rsa
            ]},
        }
        if all(g.get("in_test_code") for g in static_rsa):
            component["scope"] = "excluded"
        components.append(component)

    # A TLS server image pinned beside the hybrid groups the tree configures
    # (ZA-OPRAVYANE row 41): whether its library can negotiate them, where established.
    by_image: dict[str, list[dict[str, Any]]] = {}
    for item in scan_result["evidence"].get("library_support", []):
        by_image.setdefault(item["image"], []).append(item)
    for image, group in sorted(by_image.items()):
        first = group[0]
        properties = [
            {"name": f"{NS}basis", "value": "pinned_image"},
            {"name": f"{NS}support", "value": first["support"]},
            {"name": f"{NS}groups", "value": ", ".join(first["groups"])},
        ]
        if first.get("tls_library"):
            properties.append({"name": f"{NS}tls_library", "value": first["tls_library"]})
            properties.append({"name": f"{NS}not_negotiable",
                               "value": ", ".join(first.get("not_negotiable") or [])})
        components.append({
            "type": "container",
            "bom-ref": _ref("image", image),
            "name": image,
            "properties": properties,
            "evidence": {"occurrences": [
                {"location": g["path"], "line": g["line"], "additionalContext": g["description"]}
                for g in group
            ]},
        })

    # The same for SSH: a classical algorithm in a KexAlgorithms list, beside or instead
    # of a hybrid (ZA-OPRAVYANE row 22). OpenSSH's names are case-sensitive on the wire
    # but not in this table, so one component per name however it is spelled.
    by_kex: dict[str, list[dict[str, Any]]] = {}
    for item in scan_result["evidence"].get("ssh_kex", []):
        by_kex.setdefault(_ref("ssh-kex", f"{item['group']}-offered-alone"), []).append(item)
    for ref, group in sorted(by_kex.items()):
        component = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": f"{group[0]['group']} (SSH key exchange offered alone)",
            "cryptoProperties": {"assetType": "algorithm",
                                 "algorithmProperties": {"primitive": "key-agree"}},
            "properties": [
                {"name": f"{NS}basis", "value": "configured_kex"},
                {"name": f"{NS}offered", "value": "alone"},
                {"name": f"{NS}family", "value": group[0]["family"]},
            ],
            "evidence": {"occurrences": [
                {"location": g["path"], "line": g["line"],
                 "additionalContext": _context(g)}
                for g in group
            ]},
        }
        if all(g.get("in_test_code") for g in group):
            component["scope"] = "excluded"
        components.append(component)

    # An EC key whose private scalar is small enough to read off the public key
    # (ZA-OPRAVYANE row 32). Related key material, one component per curve and scalar:
    # the same weak key in two files is one key.
    by_weak: dict[str, list[dict[str, Any]]] = {}
    for item in scan_result["evidence"].get("weak_keys", []):
        by_weak.setdefault(_ref("weak-key", f"{item['curve']}-k{item['scalar']}"),
                           []).append(item)
    for ref, group in sorted(by_weak.items()):
        component = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": f"EC key on {group[0]['curve']} with private scalar {group[0]['scalar']}",
            "cryptoProperties": {"assetType": "related-crypto-material",
                                 "relatedCryptoMaterialProperties": {"type": "public-key"}},
            "properties": [
                {"name": f"{NS}basis", "value": group[0]["basis"]},
                {"name": f"{NS}curve", "value": group[0]["curve"]},
                {"name": f"{NS}scalar", "value": str(group[0]["scalar"])},
                {"name": f"{NS}bound", "value": str(group[0]["bound"])},
            ],
            "evidence": {"occurrences": [
                {"location": g["path"], "line": g["line"],
                 "additionalContext": g["description"]}
                for g in group
            ]},
        }
        if all(g.get("in_test_code") for g in group):
            component["scope"] = "excluded"
        components.append(component)

    # A hybrid is one asset made of two (release A, M4h): its own component, and a
    # `dependencies` entry from it to each half the inventory holds. Kept only where a
    # half is in use on the same line, so a hybrid named in a comment is not an asset.
    # A half the inventory does not hold is named, not pointed at: a ref to a component
    # that is not in the document would be a link to nothing.
    in_use_at = {(item.get("path"), item.get("line"),
                  family_of.get(item.get("algorithm"), item.get("algorithm")))
                 for item in located if item.get("evidence_kind") not in {"comment", "ban"}}
    family_refs = {_ref("crypto", family) for family in by_family}
    by_hybrid: dict[str, list[dict[str, Any]]] = {}
    for item in scan_result.get("hybrid_names", []):
        if any((item["path"], item["line"], family) in in_use_at
               for family, _ in item["halves"]):
            by_hybrid.setdefault(item["name"], []).append(item)
    hybrid_dependencies: list[dict[str, Any]] = []
    for name, group in sorted(by_hybrid.items()):
        halves = group[0]["halves"]
        ref = _ref("hybrid", name)
        held = [_ref("crypto", family) for family, _ in halves
                if _ref("crypto", family) in family_refs]
        missing = [family for family, _ in halves if _ref("crypto", family) not in family_refs]
        properties = [
            {"name": f"{NS}basis", "value": "named_hybrid"},
            {"name": f"{NS}halves", "value": " + ".join(
                f"{family}-{pset}" if pset and family in {"ML-KEM", "Kyber"} else
                f"{family} ({pset})" if pset else family for family, pset in halves)},
        ]
        if missing:
            properties.append({"name": f"{NS}half_not_in_inventory",
                               "value": ", ".join(missing)})
        component = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {
                "primitive": "combiner",
                "cryptoFunctions": ["keygen", "encapsulate", "decapsulate"]}},
            "properties": properties,
            "evidence": {"occurrences": [
                {"location": g["path"], "line": g["line"],
                 "additionalContext": f"{name}: hybrid of "
                                      + " and ".join(f for f, _ in halves)}
                for g in group]},
        }
        if all(in_test_code(g["path"]) for g in group):
            component["scope"] = "excluded"
        components.append(component)
        if held:
            hybrid_dependencies.append({"ref": ref, "dependsOn": sorted(held)})

    # Dependencies are libraries, not cryptographic assets: what is installed is
    # not what is called. They travel as `library` components carrying the
    # families they implement, and the basis says the difference out loud.
    # One component per library, however many manifests declare it: a monorepo
    # names the same dependency in every module, and a repeated bom-ref breaks
    # the uniqueness the schema requires of compositions.assemblies.
    by_library: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for dependency in scan_result["evidence"].get("dependencies", []):
        by_library.setdefault((dependency["ecosystem"], dependency["package"]),
                              []).append(dependency)
    for (ecosystem, package), group in sorted(by_library.items()):
        families: list[str] = []
        for dependency in group:
            for family in dependency["families"]:
                if family not in families:
                    families.append(family)
        components.append({
            "type": "library",
            "bom-ref": _ref("dependency", f"{ecosystem}:{package}"),
            "name": package,
            "properties": [
                {"name": f"{NS}basis", "value": "declared_dependency"},
                {"name": f"{NS}ecosystem", "value": ecosystem},
                {"name": f"{NS}implements", "value": ", ".join(families)},
            ],
            "evidence": {"occurrences": [
                {"location": dependency["path"], "line": dependency["line"],
                 "additionalContext": dependency["description"]}
                for dependency in group
            ]},
        })

    # Each file an occurrence cites, with the SHA-256 of the bytes that were read
    # (release A, 05-novi-merki T2). Occurrences have no hash field in 1.6, so a `file`
    # component named exactly as the occurrence's location carries the schema's own
    # `hashes`. Not inventory: left out of the composition below.
    digests: dict[str, str] = scan_result.get("evidence_file_sha256") or {}
    cited = sorted({o["location"] for c in components
                    for o in c.get("evidence", {}).get("occurrences", [])
                    if o.get("location") in digests})
    evidence_files = [{
        "type": "file",
        "bom-ref": f"file:{path}",
        "name": path,
        "hashes": [{"alg": "SHA-256", "content": digests[path]}],
        "properties": [{"name": f"{NS}basis", "value": "evidence_file"}],
    } for path in cited]

    # `complete` is a claim about the component list, so it is tied to the file
    # count rather than to the run finishing without error. Anything short of
    # every present file examined is `incomplete` -- a word the schema has had
    # since 1.3 and which almost nothing populates from a measurement.
    # `complete` is a claim on the second axis -- that every asset present was found --
    # and nothing in a reading figure licenses it. Reading every file says the
    # denominator is whole, not that the list of components is. So a held control is
    # what makes `complete` sayable; without one the honest word is `unknown`.
    control_held = bool((coverage.get("claims", {}).get("control") or {}).get("held"))
    # A recognised report (row 144) holds no asset this list could be missing.
    unread = scope["files_not_examined"] - sum(
        r["count"] for r in coverage["not_examined"] if r["reason"] == "report_document")
    if unread == 0:
        aggregate = "complete" if control_held else "unknown"
    else:
        aggregate = "incomplete"
    if not coverage["accounts_for_every_file"]:
        # The identity present == examined + not examined failed, so the tool
        # cannot say how complete the list is. `unknown` is the honest value and
        # it is different from `incomplete`, which asserts a known shortfall.
        aggregate = "unknown"

    timestamp, timestamp_basis = _timestamp(coverage)
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial(coverage, _findings_digest(scan_result)),
        "version": 1,
        "metadata": {
            **({"timestamp": timestamp} if timestamp else {}),
            "tools": {"components": [{
                "type": "application",
                "name": instrument["tool"],
                "version": instrument["version"],
            }]},
            "component": {
                "type": "application",
                "bom-ref": _ref("target", coverage["corpus"]["target"]),
                "name": coverage["corpus"]["target"],
            },
        },
        "components": components + evidence_files,
        **({"dependencies": hybrid_dependencies} if hybrid_dependencies else {}),
        "compositions": [{
            "aggregate": aggregate,
            "assemblies": [c["bom-ref"] for c in components],
        }],
        # The read window is the one part of the block that changes when the tree does
        # not; it is named in its place rather than dropped.
        "properties": [
            {"name": f"{NS}coverage:{name}", "value": value}
            for name, value in _flatten({**coverage, "window": WINDOW_NOT_CARRIED})
        ] + [{"name": f"{NS}timestamp_basis", "value": timestamp_basis}],
    }

    # Signing commands found in CI are evidence of cryptography being used without
    # being a cryptographic asset the schema can hold. Counted here rather than
    # dropped: a tool that quietly discards a category of its own findings on
    # export is the behaviour this emitter was written to argue against.
    ci = scan_result["evidence"]["ci_pipeline"]
    document["properties"].append(
        {"name": f"{NS}evidence:ci_signing_commands", "value": str(len(ci))}
    )
    return document
