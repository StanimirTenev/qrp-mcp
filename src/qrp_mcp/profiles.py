"""What a national authority says to replace a quantum-vulnerable algorithm with.

The default answer in `remediation` follows NIST. Other authorities disagree with it, and
with each other, on the parameter set, on whether a post-quantum algorithm may stand alone,
and on dates: the NSA allows ML-KEM-1024 only and forbids SLH-DSA; the BSI and ANSSI accept
ML-KEM and ML-DSA only in hybrid form; ASD stops approving ML-KEM-768 after 2030. One
"replace RSA with X" is wrong somewhere, so the reader chooses whose rules apply.

Every string here was checked on 2026-09-27 against the text of the document it cites.
Each profile also says whom the document addresses. None of these is law for everyone who
picks it: CNSA 2.0 is written for US National Security Systems, the ECCG list for EU product
certification. A profile is the reading of one document, not a legal finding.
"""

from __future__ import annotations

from typing import Any

READ_ON = "2026-09-27"

PROFILES: dict[str, dict[str, Any]] = {
    "us-cnsa2": {
        "authority": "NSA (United States)",
        "document": "The Commercial National Security Algorithm Suite 2.0 and Quantum Computing FAQ",
        "version": "Ver. 2.1, December 2024; the date from CNSS Policy 15, March 2025 (that "
                   "copy was fetched without TLS verification; its table matches the FAQ)",
        "url": "https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF",
        "addresses": "National Security System (NSS) owners and operators, and their vendors",
        "key_establishment": "ML-KEM-1024 (the only parameter set in CNSA 2.0)",
        "signatures": "ML-DSA-87 (the only parameter set in CNSA 2.0); SLH-DSA is not "
                      "approved for any use in NSS",
        "firmware": "LMS or XMSS, single-tree only; HSS and XMSS^MT are not allowed",
        "hybrid": "Not required: NSA 'will not require NSS developers to use hybrid "
                  "certified products'; accepted where a protocol or interoperability needs it.",
        "dates": "From 1 January 2027, unless excepted, CNSA 2.0 algorithms 'will be required "
                 "in all new products and services that provide cryptographic protection' "
                 "(CNSS Policy 15).",
        "symmetric": "AES-256; SHA-384 or SHA-512.",
        # Replaces NIST's row for the weak algorithms: the FAQ's table says 'Use SHA-384
        # or SHA-512 for all classification levels' and AES 'Use 256-bit keys for all
        # classification levels', so NIST's SHA-256 would not be CNSA 2.0 at all.
        "weak_hash": "SHA-384 or SHA-512 (CNSA 2.0, all classification levels)",
        "weak_cipher": "AES-256 (CNSA 2.0, all classification levels)",
        # `--mandate cnsa-2.0` (mandates.py): the dated clauses, by class of system. Text of
        # NSA's advisory "Announcing the Commercial National Security Algorithm Suite 2.0",
        # PP-22-1338, SEP 2022 Ver. 1.0, section "Other requirements for NSS" (p. 6):
        #   "Software and firmware signing: begin transitioning immediately, support and
        #    prefer CNSA 2.0 by 2025, and exclusively use CNSA 2.0 by 2030."
        #   "Web browsers/servers and cloud services: support and prefer CNSA 2.0 by 2025,
        #    and exclusively use CNSA 2.0 by 2033."
        #   "Traditional networking equipment (e.g., virtual private networks, routers):
        #    support and prefer CNSA 2.0 by 2026, and exclusively use CNSA 2.0 by 2030."
        #   "Operating systems: support and prefer CNSA 2.0 by 2027, and exclusively use
        #    CNSA 2.0 by 2033."
        #   "Custom applications and legacy equipment: update or replace by 2033."
        # and "Timing" (p. 4): "NSA expects the transition to QR algorithms for NSS to be
        # complete by 2035 in line with NSM-10."
        # Read 25.10.2026 from the copy fetched for this module on 27.09 (the advisory at
        # media.defense.gov/2025/May/30/2003728741/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS.PDF, the
        # same Sep 2022 v1.0 text; qrp-mcp/razuznavane/profili, US-1). A live fetch on
        # 25.10.2026 was refused (HTTP 403); secondary summaries found the same day give
        # the same years. "By 2030" is read as the end of 2030: the advisory gives years.
        "mandate": {
            "name": "cnsa-2.0",
            "document": "NSA, Announcing the Commercial National Security Algorithm Suite 2.0 "
                        "(Cybersecurity Advisory PP-22-1338, Sep 2022 Ver. 1.0)",
            "url": "https://media.defense.gov/2025/May/30/2003728741/-1/-1/0/"
                   "CSA_CNSA_2.0_ALGORITHMS.PDF",
            "read_on": "2026-10-25",
            "classes": {
                "signing": ("Software and firmware signing: exclusively use CNSA 2.0 by 2030",
                            "2030-12-31"),
                "networking": ("Traditional networking equipment (e.g., virtual private "
                               "networks, routers): exclusively use CNSA 2.0 by 2030",
                               "2030-12-31"),
                "web": ("Web browsers/servers and cloud services: exclusively use CNSA 2.0 "
                        "by 2033", "2033-12-31"),
                "custom": ("Custom applications and legacy equipment: update or replace by "
                           "2033", "2033-12-31"),
            },
            "section": "section 'Other requirements for NSS'",
            "complete_by": ("2035-12-31", "NSA expects the transition to QR algorithms for "
                                          "NSS to be complete by 2035 in line with NSM-10 "
                                          "(section 'Timing')"),
            # The profile's own date above, from CNSS Policy 15 (March 2025).
            "new_products": {"from": "2027-01-01",
                             "clause": "CNSA 2.0 algorithms 'will be required in all new "
                                       "products and services that provide cryptographic "
                                       "protection', unless excepted (CNSS Policy 15)"},
        },
    },
    "uk-ncsc": {
        "authority": "NCSC (United Kingdom)",
        "document": "Next steps in preparing for post-quantum cryptography; Timelines for "
                    "migration to post-quantum cryptography",
        "version": "Version 2.0, 14 August 2024; timelines Version 1.0, 20 March 2025",
        "url": "https://www.ncsc.gov.uk/whitepaper/next-steps-preparing-for-post-quantum-cryptography",
        "addresses": "personal, enterprise and OFFICIAL-tier government information",
        "key_establishment": "ML-KEM-768 (NCSC's recommendation; the other ML-KEM sets are "
                             "also acceptable)",
        "signatures": "ML-DSA-65 (NCSC's recommendation; the other ML-DSA sets are also "
                      "acceptable)",
        "firmware": "LMS or XMSS, which 'can only be used in a subset of use cases'",
        "hybrid": "Allowed, at a cost in complexity and efficiency; sometimes needed for "
                  "interoperability or implementation security.",
        "dates": "By 2028 discovery and a plan; by 2031 the highest-priority migrations; by "
                 "2035 migration of all systems, services and products.",
    },
    "au-ism": {
        "authority": "ASD (Australia)",
        "document": "Information security manual, Guidelines for cryptography",
        "version": "September 2026",
        "url": "https://www.cyber.gov.au/sites/default/files/2026-08/Information%20security%20"
               "manual%20%28September%202026%29.pdf",
        "addresses": "organisations applying the ISM's cyber security framework",
        "key_establishment": "ML-KEM-1024; ML-KEM-768 is approved but 'will not be approved "
                             "beyond 2030'; ML-KEM-512 is not among the approved sets",
        "signatures": "ML-DSA-87; ML-DSA-65 is approved but 'will not be approved beyond "
                      "2030'; ML-DSA-44 is not among the approved sets",
        "firmware": None,
        "hybrid": "'Not recommended; however, it is not prohibited.'",
        "dates": "ECDSA 'will not be approved beyond 2030'; new equipment and libraries to "
                 "support ML-DSA-87, ML-KEM-1024, SHA-384, SHA-512 and AES-256 by 2030.",
        "absent": "SLH-DSA, LMS and XMSS do not appear in the ISM.",
        "weak_hash": "SHA-384 or SHA-512 (SHA-224 and SHA-256 'will not be approved beyond 2030')",
        "weak_cipher": "AES-128, AES-192 or AES-256, preferably AES-256 (AES-192 or AES-256 for TOP "
                       "SECRET)",
        "weak_rsa": "at least 2048 bits, preferably 3072; RSA 'will not be approved beyond 2030'",
    },
    "ca-cccs": {
        "authority": "Canadian Centre for Cyber Security",
        "document": "Cryptographic algorithms for UNCLASSIFIED, PROTECTED A and PROTECTED B "
                    "information (ITSP.40.111)",
        "version": "Version 5, in effect 29 May 2026",
        "url": "https://www.cyber.gc.ca/sites/default/files/itsp40111-cryptographic-algorithms-e.pdf",
        "addresses": "UNCLASSIFIED, PROTECTED A and PROTECTED B information",
        "key_establishment": "ML-KEM-512, ML-KEM-768 or ML-KEM-1024",
        "signatures": "ML-DSA-44, ML-DSA-65 or ML-DSA-87; or SLH-DSA",
        "firmware": "LMS, HSS, XMSS or XMSS^MT",
        "hybrid": "Not addressed: the document does not mention hybrids.",
        "dates": "RSA 'without a post-quantum key establishment scheme should be phased out "
                 "by the end of 2035'.",
        "weak_rsa": "at least 2048 bits, increased to at least 3072 bits by the end of 2030",
    },
    "de-bsi": {
        "authority": "BSI (Germany)",
        "document": "Technical Guideline TR-02102-1, Cryptographic Mechanisms: "
                    "Recommendations and Key Lengths",
        "version": "2026-01, 23 January 2026",
        "url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/"
               "TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile",
        "addresses": "recommendations of a BSI Technical Guideline",
        # key_establishment, dates and recommends re-read 23.10.2026 (ZA-OPRAVYANE row 101):
        # the 2026-01 edition added FrodoKEM and Classic McEliece ("Recommendation of
        # FrodoKEM and Classic McEliece with appropriate security parameters for PQC
        # applications in conjunction with a previously recommended asymmetric mechanism";
        # sections 2.4.1 and 2.4.2, Tables 2.5 and 2.6), which the reading of 27.09 missed.
        "key_establishment": "ML-KEM-768 or ML-KEM-1024; FrodoKEM-976 or FrodoKEM-1344; or "
                             "Classic McEliece (mceliece460896, mceliece6688128, "
                             "mceliece8192128, or their 'f' variants) -- each in hybrid with a "
                             "classical key agreement",
        "signatures": "ML-DSA-65 or ML-DSA-87 in the 'hedged' variant, in hybrid with a "
                      "classical signature; or a hash-based signature alone",
        "firmware": "hash-based signatures: SLH-DSA, or stateful LMS/HSS or XMSS/XMSS^MT, which "
                    "'can ... also be used alone (i.e. not in hybrid form)'",
        "hybrid": "Lattice schemes are recommended only in hybrid form: the guideline 'currently "
                  "only recommends the hybrid use' of quantum-safe methods. Hash-based signatures "
                  "may stand alone.",
        "dates": "Classical key agreement alone is recommended only until the end of 2031 "
                 "(the end of 2030 for very high protection requirements). The joint "
                 "guideline of BMDS, BMI and BSI (Leitlinie zur Umstellung auf PQC, 11 "
                 "September 2026): the initial cryptographic inventory should be complete by "
                 "the end of 2026 (section 4.3); high-risk use cases quantum-safe by the end of "
                 "2030 and medium-risk ones by the end of 2035 (section 3).",
        "also_reads": "Leitlinie zur Umstellung auf PQC, joint guideline of BMDS, BMI and BSI, "
                      "11 September 2026 (sections 3 and 4.3)",
        # Families the document recommends that NIST did not standardise: their finding
        # still says `candidate` (that is NIST's standing), and says this beside it.
        "recommends": {
            "FrodoKEM": "recommended (FrodoKEM-976, FrodoKEM-1344) in hybrid with a "
                        "classical key agreement, TR-02102-1 2026-01 section 2.4.1",
            "Classic McEliece": "recommended (mceliece460896, mceliece6688128, "
                                "mceliece8192128 and the 'f' variants) in hybrid with a "
                                "classical key agreement, TR-02102-1 2026-01 section 2.4.2",
        },
        "weak_hash": "SHA-256, SHA-512/256, SHA-384 or SHA-512; or SHA3-256, SHA3-384 or SHA3-512 "
                     "(TR-02102-1, Table 4.1)",
        "weak_rsa": "at least 3000 bits, the guideline's 'recommended minimum bit length'",
    },
    "fr-anssi": {
        "authority": "ANSSI (France)",
        "document": "PG-083, Règles et recommandations concernant le choix et le "
                    "dimensionnement des mécanismes cryptographiques",
        "version": "v3.00, 20 March 2026",
        "url": "https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf",
        "addresses": "ANSSI's rules and recommendations for choosing cryptographic mechanisms",
        "key_establishment": "ML-KEM-768 (preferred; ML-KEM-512 is conformant), only hybridised "
                             "with a classical mechanism",
        "signatures": "ML-DSA only hybridised with a classical signature (alone it is not "
                      "conformant, whatever the parameter set); or SLH-DSA alone",
        "firmware": None,
        "hybrid": "Required for ML-KEM and ML-DSA; SLH-DSA 'peut donc être utilisé tel quel'.",
        "weak_hash": "a hash with at least 256-bit output (SHA2-256, SHA3-256); at least 384 bits "
                     "where post-quantum security is the goal (RecoPQHachage), e.g. SHA3-384",
        "weak_cipher": "AES-128 is conformant; AES-192 or AES-256 where post-quantum security is "
                       "the goal (RecoPQTailleCléSym: keys of at least 192 bits)",
        "weak_rsa": "at least 2048 bits for use ending by 2030, at least 3072 bits from 2031; 3072 "
                    "is recommended even before 2031",
    },
    "nl-ncsc": {
        "authority": "AIVD, CWI and TNO (Netherlands)",
        "document": "The PQC Migration Handbook",
        "version": "Revised and extended 2nd edition, December 2024",
        "url": "https://english.aivd.nl/site/binaries/site-content/collections/documents/2024/12/3/"
               "the-pqc-migration-handbook/The+PQC+Migration+Handbook+.pdf",
        "addresses": "guidance for organisations planning a migration",
        "key_establishment": "ML-KEM-1024 or ML-KEM-768 (NIST level 5 or 3), recommended in "
                             "hybrid with ECDH",
        "signatures": "ML-DSA-87 or ML-DSA-65 (NIST level 5 or 3), recommended in hybrid with "
                      "ECDSA or EdDSA",
        "firmware": None,
        "hybrid": "Recommended.",
    },
    "eu-eccg": {
        "authority": "European Cybersecurity Certification Group, Sub-group on Cryptography",
        "document": "Agreed Cryptographic Mechanisms",
        "version": "Version 2.0, April 2025",
        "url": "https://certification.enisa.europa.eu/document/download/a845662b-aee0-484e-9191-"
               "890c4cfa7aaa_en?filename=ECCG%20Agreed%20Cryptographic%20Mechanisms%20version%202.pdf",
        "addresses": "EU cybersecurity certification of products",
        "key_establishment": "ML-KEM-1024 or ML-KEM-768 (the highest possible), combined with a "
                             "classical mechanism",
        "signatures": "ML-DSA-87 or ML-DSA-65 (the highest possible), combined with a classical "
                      "mechanism; or SLH-DSA, LMS or XMSS, which may stand alone",
        "firmware": None,
        "hybrid": "Lattice schemes 'shouldn't be used in a standalone way'; hash-based ones "
                  "'may however also be used in a standalone way'.",
    },
    "bg": {
        "authority": "Bulgaria",
        "document": "no national post-quantum guidance found",
        "version": f"searched {READ_ON}",
        "url": "https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-"
               "roadmap-transition-post-quantum-cryptography",
        "addresses": "no Bulgarian document; the EU roadmap is shown instead",
        "key_establishment": None,
        "signatures": None,
        "firmware": None,
        "hybrid": "Not addressed by any Bulgarian document found. The EU roadmap names no "
                  "algorithms; the replacements shown are NIST's.",
        "dates": "EU coordinated roadmap (NIS Cooperation Group, v1.1, 11 June 2025): a national "
                 "transition strategy by the end of 2026; high-risk use cases no later than the "
                 "end of 2030; as many systems as practically feasible by 2035.",
        "absent": "No Bulgarian national guidance on post-quantum cryptography was found in web "
                  f"searches in Bulgarian and English on {READ_ON}. "
                  "A national plan for quantum communication infrastructure exists; that is "
                  "quantum key distribution, not post-quantum cryptography.",
    },
}


# `--mandate nist-ir-8547` (mandates.py). The `nist` profile has no entry above -- it is the
# default in remediation -- so its dated document is here. NIST IR 8547 ipd, "Transition to
# Post-Quantum Cryptography Standards", Initial Public Draft, November 2024: section 4.1.1
# Table 2 (quantum-vulnerable digital signatures) and section 4.1.2 Table 4 (quantum-vulnerable
# key establishment). Every row reads the same: at 112 bits of security strength "Deprecated
# after 2030 / Disallowed after 2035"; at "≥ 128 bits of security strength" "Disallowed after
# 2035". EdDSA has only the >= 128-bit row. Lines 508-511 (section 4.1.2): "in order to
# mitigate the risk of 'harvest now, decrypt later' attacks on network communications,
# application-specific guidance ... may require or recommend migration to quantum-resistant
# key establishment schemes before the classical schemes are generally disallowed."
# Fetched live 25.10.2026 from nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf (sha256
# 6b551b4f...0ed6, identical to the copy of 27.09); csrc.nist.gov/pubs/ir/8547/ipd lists no
# later draft or final on 25.10.2026. Security strength of a key size from SP 800-57 Part 1
# Rev. 5, Table 2 (fetched 25.10.2026): IFC (RSA) k = 2048 and FFC L = 2048 give 112 bits,
# k = 3072 / L = 3072 give 128; ECC f = 224-255 gives 112, f = 256-383 gives 128; k = 1024
# and f = 160-223 give at most 80.
NIST_IR_8547: dict[str, Any] = {
    "name": "nist-ir-8547",
    "document": "NIST IR 8547 ipd, Transition to Post-Quantum Cryptography Standards "
                "(Initial Public Draft, November 2024)",
    "url": "https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf",
    "read_on": "2026-10-25",
    "deprecated_after": "2030-12-31",
    "disallowed_after": "2035-12-31",
    "tables": {
        "signature": "section 4.1.1, Table 2: Quantum-vulnerable digital signature algorithms",
        "key_establishment": "section 4.1.2, Table 4: Quantum-vulnerable key-establishment "
                             "schemes",
    },
    "hndl": "section 4.1.2, lines 508-511: 'harvest now, decrypt later' attacks on network "
            "communications may require migration of key establishment before the classical "
            "schemes are generally disallowed",
}


def names() -> list[str]:
    return ["nist", *PROFILES]


def source(profile: str) -> dict[str, str]:
    p = PROFILES[profile]
    return {"standard": f"{p['authority']}: {p['document']}", "what": p["version"],
            "url": p["url"], "read_on": READ_ON}


def standing(profile: str, family: str) -> dict[str, Any] | None:
    """What the profile's document says of a family it recommends beyond NIST's standards."""
    said = PROFILES.get(profile, {}).get("recommends", {}).get(family)
    if not said:
        return None
    return {"profile": profile, "standing": said, "source": source(profile)}
