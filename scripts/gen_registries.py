"""Build src/qrp_mcp/data/registry_names.json from the registries themselves (release 3b).

Usage: python -I scripts/gen_registries.py SOURCE_DIR

SOURCE_DIR holds the files this reads, fetched or produced on the date below:

  ssh-parameters.xml   https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xml
  tls-parameters.xml   https://www.iana.org/assignments/tls-parameters/tls-parameters.xml
  jose.xml             https://www.iana.org/assignments/jose/jose.xml
  cose.xml             https://www.iana.org/assignments/cose/cose.xml
  ssh-Q-*.txt          `ssh -Q key|key-cert|key-sig|sig|kex|kex-gss|cipher|mac` (OpenSSH 9.6p1):
                       the names OpenSSH implements beyond the IANA lists (*-cert-v01@openssh.com,
                       sk-*, *-etm@openssh.com)
  openssl-*.txt        `openssl list -commands|-digest-commands`, `openssl ecparam -list_curves`
                       (OpenSSL 3.0.13)
  pem-strings.txt      the PEM_STRING_* labels of OpenSSL 3.0.13 include/openssl/pem.h

Every name of each registry is kept, with family null where the scan reports no family for it
(AES, ChaCha20, HMAC-SHA2, ...): the table is the registry, the findings are what is in scope.
The family of each name is set by the rules in `_family`, which read the name's own parts and,
where the name alone does not say it, the registry's description (RFC 4253 groups, HPKE suites).
"""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RETRIEVED = "2026-10-25"
NS = {"i": "http://www.iana.org/assignments"}
OUT = Path(__file__).resolve().parent.parent / "src" / "qrp_mcp" / "data" / "registry_names.json"

# RFC 4253 section 8 / RFC 8268: the MODP groups the SSH names carry by number.
_SSH_GROUP_BITS = {"1": 1024, "14": 2048, "15": 3072, "16": 4096, "17": 6144, "18": 8192}
_NIST = {"192": "P-192", "224": "P-224", "256": "P-256", "384": "P-384", "521": "P-521"}
# Post-quantum and hybrid names are read by their own rules (detectors.HYBRIDS, the ML-KEM /
# ML-DSA / SLH-DSA patterns): kept here with family null so no name of the table can map a
# post-quantum scheme to a classical family.
_PQ = re.compile(r"mlkem|ml-kem|mldsa|ml-dsa|slhdsa|slh-dsa|sntrup|kyber|xwing|x-wing", re.I)


def _curve(name: str) -> dict | None:
    low = name.lower()
    m = re.search(r"nistp(192|224|256|384|521)|secp(192|224|256|384|521)r1|prime(192|256)v1", low)
    if m:
        bits = next(g for g in m.groups() if g)
        return {"curve": _NIST[bits], "key_size": int(bits)}
    m = re.search(r"(brainpoolp(\d{3})[rt]1|secp(\d{3})[kr]\d|sect(\d{3})[kr]\d|prime(\d{3})v\d|"
                  r"c2[pt]nb(\d{3})\w*|wap-wsg-idm-ecid-wtls\d+)", low)
    if m:
        bits = next((g for g in m.groups()[1:] if g), None)
        out: dict = {"curve": m.group(1).replace("brainpoolp", "brainpoolP")}
        if bits:
            out["key_size"] = int(bits)
        return out
    return None


def _ssh_family(name: str) -> tuple[str | None, dict | None, str | None]:
    """(family, parameters, use) for an SSH algorithm name (RFC 4250-4253, 4432, 5656, 8332,
    8709, 8731, OpenSSH PROTOCOL.certkeys / PROTOCOL.u2f)."""
    low = name.lower()
    if _PQ.search(low) or "mldsa" in low:
        return None, None, None
    m = re.match(r"(?:gss-)?diffie-hellman-group(\d+)-|gss-group(\d+)-", low)
    if m:
        number = m.group(1) or m.group(2)
        bits = _SSH_GROUP_BITS.get(number)
        return "DH", ({"key_size": bits} if bits else None), None
    if low.startswith(("diffie-hellman-group-exchange-", "gss-gex-")):
        return "DH", None, None
    if low.startswith(("ecdh-sha2-", "ecmqv-", "gss-nistp")):
        return "ECDH", _curve(low), None
    if "curve25519" in low:
        return "X25519", None, None
    if "curve448" in low:
        return "X448", None, None
    m = re.match(r"(?:x509v3-)?rsa(1024|2048)-sha", low)
    if m:
        return "RSA", {"key_size": int(m.group(1))}, None
    if re.search(r"(?:^|-)(?:ssh-rsa|rsa-sha2|sign-rsa)", low) or low == "x509v3-ssh-rsa":
        return "RSA", None, None
    if re.search(r"(?:^|-)(?:ssh-dss|sign-dss)", low):
        return "DSA", None, None
    if "ecdsa-sha2-" in low:
        return "ECDSA", _curve(low), None
    if "ed25519" in low:
        return "Ed25519", None, None
    if "ed448" in low:
        return "Ed448", None, None
    if low.startswith("3des-"):
        return "3DES", None, None
    if low.startswith("des-"):
        return "DES", None, None
    if low.startswith("arcfour"):
        return "RC4", None, None
    if low.startswith("hmac-md5"):
        return "MD5", None, "MAC"
    if low.startswith("hmac-sha1"):
        return "SHA1", None, "MAC"
    return None, None, None


def _tls_scheme_family(name: str) -> tuple[str | None, dict | None, str | None]:
    """TLS SignatureScheme (RFC 8446 4.2.3) and Supported Groups (RFC 8422, 7919, 8446)."""
    low = name.lower()
    if _PQ.search(low):
        return None, None, None
    if low.startswith("rsa_"):
        return "RSA", None, None
    if low.startswith("ecdsa_"):
        return "ECDSA", _curve(low), None
    if low.startswith("ffdhe"):
        return "DH", {"key_size": int(low[5:])}, None
    if low.startswith("sm2") or low == "curvesm2":
        return "SM2", None, None
    if low.startswith("gostr3410"):
        return "GOST R 34.10", None, None
    if low == "secp256k1":
        return "ECDSA", {"curve": "secp256k1", "key_size": 256}, None
    if re.match(r"secp|sect|brainpool", low):
        return "EC", _curve(low), None
    return None, None, None


def _jose_family(name: str, description: str) -> tuple[str | None, dict | None, str | None]:
    """JWA (RFC 7518, 8037, 8812, 9864) and COSE (RFC 9053, 8812, 9864) algorithm names."""
    if _PQ.search(name):
        return None, None, None
    m = re.fullmatch(r"(?:RS|PS)(1|256|384|512)", name)
    if m or name.startswith(("RSA1_5", "RSA-OAEP", "RSAES-OAEP")):
        return "RSA", None, None
    m = re.fullmatch(r"ESP?(256|384|512)", name)
    if m:
        bits = {"256": "256", "384": "384", "512": "521"}[m.group(1)]
        return "ECDSA", {"curve": _NIST[bits], "key_size": int(bits)}, None
    if name == "ES256K":
        return "ECDSA", {"curve": "secp256k1", "key_size": 256}, None
    m = re.fullmatch(r"ESB(256|320|384|512)", name)
    if m:
        return "ECDSA", {"curve": f"brainpoolP{m.group(1)}r1", "key_size": int(m.group(1))}, None
    if name.startswith(("ECDH-ES", "ECDH-SS")):
        return "ECDH", None, None
    if name == "EdDSA":
        return "EdDSA", None, None
    if name in ("Ed25519", "Ed448"):
        return name, None, None
    if name.startswith("HPKE-"):
        for curve, bits in (("P-256", 256), ("P-384", 384), ("P-521", 521)):
            if curve in description:
                return "ECDH", {"curve": curve, "key_size": bits}, None
        if "X25519" in description:
            return "X25519", None, None
        if "X448" in description:
            return "X448", None, None
    if name == "HSS-LMS":
        return "HSS/LMS", None, None
    if name == "SHA-1":
        return "SHA1", None, None
    if name in ("RS1",):
        return "RSA", None, None
    # WalnutDSA is a braid-group signature, not DSA.
    return None, None, None


def _records(path: Path, registry: str):
    root = ET.parse(path).getroot()
    for r in root.iter("{http://www.iana.org/assignments}registry"):
        if r.get("id") == registry:
            for rec in r.findall("i:record", NS):
                yield {c.tag.split("}")[1]: (c.text or "").strip() for c in rec}


def _updated(path: Path) -> str:
    m = re.search(r"<updated>([^<]+)</updated>", path.read_text())
    return m.group(1) if m else ""


def main(src: Path) -> None:
    names: dict[str, list] = {}       # lower-cased name -> [name, family, params, use, source]
    prefixes: dict[str, list] = {}
    quoted: dict[str, list] = {}      # exact-case short names, read only as a whole value
    sources: dict[str, dict] = {}

    def add(table: dict, name: str, fam, params, use, source: str, key: str | None = None):
        key = key or name.lower()
        if key not in table:
            table[key] = [name, fam, params, use, source]

    f = src / "ssh-parameters.xml"
    sources["iana-ssh"] = {"url": "https://www.iana.org/assignments/ssh-parameters/",
                           "registries": "16 Key Exchange Method Names, 17 Encryption Algorithm "
                                         "Names, 18 MAC Algorithm Names, 19 Public Key "
                                         "Algorithm Names",
                           "registry_updated": _updated(f), "retrieved": RETRIEVED}
    for reg in ("ssh-parameters-16", "ssh-parameters-17", "ssh-parameters-18",
                "ssh-parameters-19"):
        for rec in _records(f, reg):
            name = rec.get("value", "")
            if not name or name in ("none", "null") or " " in name:
                continue
            fam, params, use = _ssh_family(name)
            if name.endswith("-*"):
                add(prefixes, name[:-1], fam, params, use, "iana-ssh")
            elif name.endswith("-") and name.startswith("gss-"):
                add(prefixes, name, fam, params, use, "iana-ssh")
            else:
                add(names, name, fam, params, use, "iana-ssh")
    sources["openssh"] = {"url": "OpenSSH 9.6p1 `ssh -Q` (PROTOCOL.certkeys, PROTOCOL.u2f)",
                          "retrieved": RETRIEVED}
    for q in ("key", "key-cert", "key-sig", "sig", "kex", "cipher", "mac", "kex-gss"):
        for name in (src / f"ssh-Q-{q}.txt").read_text().split():
            fam, params, use = _ssh_family(name)
            if name.endswith("-"):
                add(prefixes, name, fam, params, use, "openssh")
            else:
                add(names, name, fam, params, use, "openssh")
    # RFC 5656 6.1/10: the ecdsa-sha2-* / ecdh-sha2-* family is instantiated with these
    # curve names; the IANA list carries only the wildcard.
    for kind in ("ecdsa-sha2-", "ecdh-sha2-", "x509v3-ecdsa-sha2-"):
        for curve in ("nistp256", "nistp384", "nistp521"):
            fam, params, use = _ssh_family(kind + curve)
            add(names, kind + curve, fam, params, use, "iana-ssh")

    f = src / "tls-parameters.xml"
    sources["iana-tls"] = {"url": "https://www.iana.org/assignments/tls-parameters/",
                           "registries": "TLS Supported Groups, TLS SignatureScheme (the cipher "
                                         "suites are read by detectors.scan_cipher_suites, whose "
                                         "grammar is the registry's TLS_*_WITH_* form)",
                           "registry_updated": _updated(f), "retrieved": RETRIEVED}
    for reg in ("tls-parameters-8", "tls-signaturescheme"):
        for rec in _records(f, reg):
            name = rec.get("description", "").split(" ")[0]
            if (not name or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]+", name)
                    or name.startswith(("Reserved", "Unassigned", "arbitrary", "private"))):
                continue
            fam, params, use = _tls_scheme_family(name)
            if len(name) < 7:
                # x25519, x448, ed448, mldsa44: read by their own rules.
                continue
            add(names, name, fam, params, use, "iana-tls")

    f = src / "jose.xml"
    sources["iana-jose"] = {"url": "https://www.iana.org/assignments/jose/",
                            "registries": "JSON Web Signature and Encryption Algorithms, "
                                          "JSON Web Key Elliptic Curve",
                            "registry_updated": _updated(f), "retrieved": RETRIEVED}
    for rec in _records(f, "web-signature-encryption-algorithms"):
        name = rec.get("value", "")
        fam, params, use = _jose_family(name, rec.get("description", ""))
        add(quoted, name, fam, params, use, "iana-jose", key=name)
    for rec in _records(f, "web-key-elliptic-curve"):
        name = rec.get("value", "")
        if name.startswith("P-"):
            bits = int(name[2:])
            add(quoted, name, "EC", {"curve": name, "key_size": bits}, None, "iana-jose", key=name)

    f = src / "cose.xml"
    sources["iana-cose"] = {"url": "https://www.iana.org/assignments/cose/",
                            "registries": "COSE Algorithms (names; the numbers are "
                                          "detectors.COSE_ALGORITHMS)",
                            "registry_updated": _updated(f), "retrieved": RETRIEVED}
    for rec in _records(f, "algorithms"):
        name = rec.get("name", "")
        if not name or " " in name or name.startswith(("Reserved", "Unassigned")):
            continue
        fam, params, use = _jose_family(name, rec.get("description", ""))
        add(quoted, name, fam, params, use, "iana-cose", key=name)

    sources["openssl"] = {"url": "OpenSSL 3.0.13 `openssl list -commands`, "
                                 "`-digest-commands`, `ecparam -list_curves`, "
                                 "include/openssl/pem.h", "retrieved": RETRIEVED}
    commands = set((src / "openssl-commands.txt").read_text().split())
    command_family = {"rsa": "RSA", "genrsa": "RSA", "rsautl": "RSA", "dsa": "DSA",
                      "dsaparam": "DSA", "gendsa": "DSA", "ec": "EC", "ecparam": "EC",
                      "dhparam": "DH"}
    openssl_commands = {c: command_family[c] for c in sorted(commands) if c in command_family}
    digests = set((src / "openssl-digest-commands.txt").read_text().split())
    digest_family = {"md5": "MD5", "sha1": "SHA1", "sha224": "SHA224", "sha3-224": "SHA3-224",
                     "md4": "MD4", "md2": "MD2"}
    openssl_digests = {d: digest_family[d] for d in sorted(digests | {"md4", "md2"})
                       if d in digest_family}
    curves = {}
    for line in (src / "openssl-curves.txt").read_text().splitlines():
        m = re.match(r"\s+([A-Za-z][A-Za-z0-9-]*)\s*:", line)
        if not m:
            continue
        name = m.group(1)
        params = _curve(name)
        fam = "ECDSA" if name == "secp256k1" else "EC"
        if name == "secp256k1":
            params = {"curve": "secp256k1", "key_size": 256}
        if len(name) >= 7:
            add(names, name, fam, params, None, "openssl")
        curves[name] = [fam, params]
    pem = {}
    for line in (src / "pem-strings.txt").read_text().splitlines():
        m = re.search(r'"([^"]+)"', line)
        if not m:
            continue
        label = m.group(1)
        head = label.split(" ")[0]
        fam = {"RSA": "RSA", "DSA": "DSA", "EC": "EC", "ECDSA": "ECDSA", "DH": "DH",
               "X9.42": "DH"}.get(head)
        if fam:
            pem[label] = fam

    sources["ssh-keygen"] = {"url": "OpenSSH 9.6p1 ssh-keygen(1), -t", "retrieved": RETRIEVED}
    keygen = {"dsa": "DSA", "ecdsa": "ECDSA", "ecdsa-sk": "ECDSA", "ed25519": "Ed25519",
              "ed25519-sk": "Ed25519", "rsa": "RSA", "rsa1": "RSA"}

    out = {
        "about": "Algorithm names from their registries, each with the family it names; "
                 "built by scripts/gen_registries.py. Family null: in the registry, out of "
                 "the scan's scope (or read by another rule: post-quantum and hybrid names).",
        "sources": sources,
        "names": sorted(names.values(), key=lambda r: r[0].lower()),
        "prefixes": sorted(prefixes.values(), key=lambda r: r[0].lower()),
        "quoted": sorted(quoted.values(), key=lambda r: r[0]),
        "openssl_commands": openssl_commands,
        "openssl_digests": openssl_digests,
        "openssl_genpkey": {"RSA": "RSA", "RSA-PSS": "RSA", "DSA": "DSA", "DH": "DH",
                            "DHX": "DH", "EC": "EC", "X25519": "X25519", "X448": "X448",
                            "ED25519": "Ed25519", "ED448": "Ed448", "SM2": "SM2"},
        "ssh_keygen_types": keygen,
        "pem_labels": pem,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    print(OUT, len(out["names"]), "names", len(out["prefixes"]), "prefixes",
          len(out["quoted"]), "quoted")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
