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
same corpus produce byte-identical output: the timestamp comes from the coverage
window rather than from the clock, and the serial number is derived from the target
and the two pins rather than drawn at random. Two runs whose instrument differs get
different serial numbers, which is the pin argument stated in one field.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

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
    "ML-KEM", "FrodoKEM", "Classic McEliece", "NTRU", "BIKE", "HQC", "SIKE",
}
_PRIMITIVE_BY_FAMILY = {
    "MD5": "hash",
    "SHA1": "hash",
    "DES": "block-cipher",
    "3DES": "block-cipher",
    "RC4": "stream-cipher",
    "PPK (RFC 8784)": "other",
}


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
        if not value:
            return [(path, "")]
        if all(not isinstance(item, (dict, list)) for item in value):
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


def _serial(coverage: dict[str, Any]) -> str:
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
    ])
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def _occurrences(findings: list[dict[str, Any]], family: str) -> list[dict[str, Any]]:
    return [
        {
            "location": item["path"],
            "line": item["line"],
            # The call site or matched text. The reference emitter carries the
            # same field for the same purpose, so a reader comparing the two
            # documents is comparing like with like.
            "additionalContext": item.get("description") or item.get("excerpt", ""),
        }
        for item in findings
        if item.get("algorithm") == family
    ]


def build(scan_result: dict[str, Any]) -> dict[str, Any]:
    """A CycloneDX 1.6 document from one scan, with the coverage block inside it."""
    coverage = scan_result["coverage"]
    scope = coverage["scope"]
    instrument = coverage["instrument"]

    located = list(scan_result["evidence"]["source_code"]) + list(scan_result["evidence"]["iac"])
    by_family = {f["algorithm_family"]: f for f in scan_result["findings"]}

    components: list[dict[str, Any]] = []
    for family in sorted(by_family):
        finding = by_family[family]
        component: dict[str, Any] = {
            "type": "cryptographic-asset",
            "bom-ref": _ref("crypto", family),
            "name": family,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {"primitive": _primitive(family)},
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
        for key in ("pqc_family", "pqc_status"):
            if finding.get(key):
                component["properties"].append({"name": f"{NS}{key}", "value": finding[key]})
        occurrences = _occurrences(located, family)
        if occurrences:
            component["evidence"] = {"occurrences": occurrences}
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
                 "additionalContext": k.get("description", "")}
                for k in keys
            ]},
        })

    # `complete` is a claim about the component list, so it is tied to the file
    # count rather than to the run finishing without error. Anything short of
    # every present file examined is `incomplete` -- a word the schema has had
    # since 1.3 and which almost nothing populates from a measurement.
    aggregate = "complete" if scope["files_not_examined"] == 0 else "incomplete"
    if not coverage["accounts_for_every_file"]:
        # The identity present == examined + not examined failed, so the tool
        # cannot say how complete the list is. `unknown` is the honest value and
        # it is different from `incomplete`, which asserts a known shortfall.
        aggregate = "unknown"

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": _serial(coverage),
        "version": 1,
        "metadata": {
            "timestamp": coverage["window"]["started_at"],
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
        "components": components,
        "compositions": [{
            "aggregate": aggregate,
            "assemblies": [c["bom-ref"] for c in components],
        }],
        "properties": [
            {"name": f"{NS}coverage:{name}", "value": value}
            for name, value in _flatten(coverage)
        ],
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
