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
        # Row 210: from the key_establishment and signatures lines above.
        "parameter_sets": {
            "ML-KEM-512": "not in CNSA 2.0: ML-KEM-1024 is the only parameter set",
            "ML-KEM-768": "not in CNSA 2.0: ML-KEM-1024 is the only parameter set",
            "ML-DSA-44": "not in CNSA 2.0: ML-DSA-87 is the only parameter set",
            "ML-DSA-65": "not in CNSA 2.0: ML-DSA-87 is the only parameter set",
        },
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
        # What the document says of a post-quantum parameter set short of its first choice
        # (ZA-OPRAVYANE row 210), from the key_establishment and signatures lines above.
        "parameter_sets": {
            "ML-KEM-768": "approved but 'will not be approved beyond 2030'",
            "ML-KEM-512": "not among the approved sets",
            "ML-DSA-65": "approved but 'will not be approved beyond 2030'",
            "ML-DSA-44": "not among the approved sets",
        },
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
        # Row 481: Classic McEliece is no longer offered. BSI, "Notes on recent developments
        # concerning Classic McEliece", 29 September 2026: it "should currently no longer be
        # used in new developments or when planning new cryptographic applications. For key
        # agreement, it is advised to use FrodoKEM, ML-KEM or HQC (once the corresponding
        # standard has been published) in accordance with the recommendations of TR-02102-1."
        "key_establishment": "ML-KEM-768 or ML-KEM-1024; or FrodoKEM-976 or FrodoKEM-1344 -- "
                             "each in hybrid with a classical key agreement; HQC once its "
                             "standard is published (BSI note of 29 September 2026)",
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
                      "11 September 2026 (sections 3 and 4.3); BSI, Notes on recent "
                      "developments concerning Classic McEliece, 29 September 2026",
        # Cited beside the guideline wherever its source is (row 481).
        "also_sources": [{
            "standard": "BSI: Notes on recent developments concerning Classic McEliece",
            "what": "29 September 2026",
            "url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Crypto/"
                   "Notes_Classic_McEliece.pdf",
            "read_on": "2026-11-15"}],
        # Families the document recommends that NIST did not standardise: their finding
        # still says `candidate` (that is NIST's standing), and says this beside it.
        "recommends": {
            "FrodoKEM": "recommended (FrodoKEM-976, FrodoKEM-1344) in hybrid with a "
                        "classical key agreement, TR-02102-1 2026-01 section 2.4.1",
            # Row 481: TR-02102-1 2026-01 section 2.4.2 recommended it in hybrid; the BSI note
            # of 29 September 2026 withdraws it from new developments until the next edition.
            "Classic McEliece": "under review: hybrid use in existing deployments only, not "
                                "for new developments (BSI, Notes on recent developments "
                                "concerning Classic McEliece, 29 September 2026), until the "
                                "next TR-02102-1, expected early 2027; TR-02102-1 2026-01 "
                                "section 2.4.2 had recommended it in hybrid with a classical "
                                "key agreement",
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
# default in remediation -- so its dated document is here. NIST IR 8547, "Transition to
# Post-Quantum Cryptography Standards", final, October 2026 (doi.org/10.6028/NIST.IR.8547;
# the PDF read 28.10.2026, sha256 1cd01067...0f7f). Section 4.1.1 Table 2 (quantum-vulnerable
# digital signatures: ECDSA and RSA at >= 112 bits, EdDSA at >= 128 bits) and section 4.1.2
# Table 4 (quantum-vulnerable key establishment: finite-field DH and MQV, elliptic-curve DH and
# MQV, RSA, each at >= 112 bits): every row reads "Deprecated after 2030 / Disallowed after
# 2035". The text below each table: "NIST will deprecate all quantum-vulnerable cryptography
# after 2030 and disallow its use under NIST standards and guidelines after 2035."
# ZA-OPRAVYANE row 168: until 0.38.0 this was the initial public draft of November 2024, whose
# 128-bit rows were "Disallowed after 2035" only, so RSA-3072, P-256 and Ed25519 had no 2030 date.
# Section 4.1.2, below Table 4: "in order to mitigate the risk of 'harvest now, decrypt later'
# attacks on network communications, application-specific guidance, as described in Sec. 4.2,
# may require or recommend migration to quantum-resistant key-establishment schemes before the
# classical schemes are generally disallowed." Section 3.2.1: "The generic composite
# key-establishment technique is allowed, even if T is derived from an unapproved source
# (including a disallowed algorithm)" -- the classical half of a hybrid (rows 170, 177).
# Security strength of a key size from SP 800-57 Part 1 Rev. 5, Table 2 (fetched 25.10.2026):
# IFC (RSA) k = 2048 and FFC L = 2048 give 112 bits, k = 3072 / L = 3072 give 128; ECC f =
# 224-255 gives 112, f = 256-383 gives 128; k = 1024 and f = 160-223 give at most 80.
# X25519 (f = 255) and X448 (f = 448) are named by their curve: 128 and 224 bits (RFC 7748).
NIST_IR_8547: dict[str, Any] = {
    "name": "nist-ir-8547",
    "document": "NIST IR 8547, Transition to Post-Quantum Cryptography Standards "
                "(final, October 2026)",
    "url": "https://doi.org/10.6028/NIST.IR.8547",
    "read_on": "2026-10-28",
    "deprecated_after": "2030-12-31",
    "disallowed_after": "2035-12-31",
    "tables": {
        "signature": "section 4.1.1, Table 2: Quantum-vulnerable digital signature algorithms",
        "key_establishment": "section 4.1.2, Table 4: Quantum-vulnerable key-establishment "
                             "schemes",
    },
    "hndl": "section 4.1.2, below Table 4: to mitigate 'harvest now, decrypt later' attacks on "
            "network communications, application-specific guidance may require or recommend "
            "migration of key establishment before the classical schemes are generally "
            "disallowed",
    "composite": "section 3.2.1, Hybrid Key-Establishment Techniques: the generic composite "
                 "key-establishment technique of SP 800-56C is allowed even if one input is "
                 "derived from a disallowed algorithm",
    # Row 493. Section 4 (final text, read 2026-11-15, lines 734-737; also 251-254, 843-846,
    # 944-946): "federal agencies must transition high value assets and high impact systems
    # (i.e., systems for which at least one FIPS 199 security objective is assigned a
    # potential impact value of 'high') on an accelerated schedule. These systems must adopt
    # post-quantum cryptography for key establishment by December 31, 2030, and for digital
    # signatures by December 31, 2031." Lines 747-748: the 2030-2035 window "does not alter"
    # these. As IR 8547 states them; OMB M-26-15 itself was not read.
    "federal_high_value_assets": {
        "key_establishment": "2030-12-31",
        "signature": "2031-12-31",
        "applies": "only if the system is a federal high value asset or high impact system "
                   "(FIPS 199: at least one security objective high), or another system "
                   "prioritised under OMB M-26-15; the scan cannot tell which systems are",
        "source": "NIST IR 8547 (final, October 2026), section 4 and sections 4.1.1, 4.1.2, "
                  "restating EO 14412 and OMB M-26-15: post-quantum cryptography for key "
                  "establishment by December 31, 2030, and for digital signatures by "
                  "December 31, 2031",
    },
}


# `--mandate eu-pqc-roadmap|uk-ncsc|ca-cccs|au-ism|nl-rqs|se-ncsc|jp-gov|sg-csa-cii|in-dst|
# de-bsi` (mandates.py, 0.48.0): the dated clauses of other jurisdictions, each quoted from its
# own document, quoted below. Only dates checked against the primary text are here; documents
# whose dates no line of code carries (a plan, a class of information) are not.
#
# Each entry: `rules` are the dates an occurrence carries by itself -- by family (RSA, DH, ECDH,
# ECDSA, EdDSA, DSA; "*" is any quantum-vulnerable family) and by role, where the document
# separates them. `conditional` are dates that apply only to a class of system the scan cannot
# see (high-risk, highest priority): said beside the clause as `earlier_if` and on the block,
# never counted by the gate (the precedent of row 493). `milestones` are organisational dates
# (a plan, an inventory) that no line of code carries; on the block only. `composite` is the
# document's text that leaves the classical half of a hybrid out of the date. A rule's `except`
# names families the document's own list leaves out of it. `unlisted` is
# what is said of a quantum-vulnerable family the document does not name. "By 2030" is read as
# the end of 2030, as for cnsa-2.0: the documents give years.
DATED_MANDATES: dict[str, dict[str, Any]] = {
    # NIS Cooperation Group, "A Coordinated Implementation Roadmap for the Transition to
    # Post-Quantum Cryptography", Part 1, Version 1.1, 11.06.2025. Section 4.1: "For high-risk
    # use cases, quantum-vulnerable public-key mechanisms shall not be used stand-alone after
    # the end of 2030, analogously after the end of 2035 for medium-risk use cases." The box
    # "Timeline for the transition to PQC": "3. By 31.12.2035: The PQC transition for
    # medium-risk use cases has been completed. The PQC transition for low-risk use cases has
    # been completed as much as feasible." "2. By 31.12.2030: ... The PQC transition for
    # high-risk use cases has been completed. ... Quantum-safe software and firmware upgrades
    # are enabled by default." "1. By 31.12.2026: ... Initial national PQC transition roadmaps
    # have been established by all Member States." High-risk (section 4.2 item 2): "if
    # compromising confidentiality after 10 years or more would still cause significant
    # damage"; section 5 adds high transition effort with high impact, "for example for
    # securing software updates". The scan sees neither, so 2035 -- the date for every use case
    # that is not low-risk, and the end of the roadmap for those that are -- is the one counted.
    "eu-pqc-roadmap": {
        "name": "eu-pqc-roadmap",
        "document": "NIS Cooperation Group, A Coordinated Implementation Roadmap for the "
                    "Transition to Post-Quantum Cryptography (Part 1, Version 1.1, 11.06.2025)",
        "url": "https://digital-strategy.ec.europa.eu/en/library/coordinated-implementation-"
               "roadmap-transition-post-quantum-cryptography",
        "read_on": "2026-11-17",
        "addresses": "EU Member States, recommended (not law); NIS2 entities through their "
                     "national plans",
        "rules": [
            {"families": "*", "deadline": "2035-12-31",
             "clause": "quantum-vulnerable public-key mechanisms shall not be used stand-alone "
                       "after the end of 2035 for medium-risk use cases; the transition for "
                       "low-risk use cases completed as much as feasible by 31.12.2035",
             "source": "section 4.1 and the box 'Timeline for the transition to PQC', item 3"},
        ],
        "conditional": [
            {"date": "2030-12-31",
             "clause": "for high-risk use cases, quantum-vulnerable public-key mechanisms shall "
                       "not be used stand-alone after the end of 2030",
             "applies": "only if the use case is high-risk: confidentiality that would still "
                        "matter after 10 years or more, or a high transition effort with a "
                        "high impact such as securing software updates (sections 4.2, 5); the "
                        "scan cannot tell which use cases are",
             "source": "section 4.1; the box 'Timeline for the transition to PQC', item 2"},
            {"date": "2030-12-31",
             "clause": "quantum-safe software and firmware upgrades are enabled by default",
             "applies": "only if this signs software or firmware upgrades; the scan cannot "
                        "tell what a key signs",
             "roles": ["signature", "undetermined"],
             "source": "the box 'Timeline for the transition to PQC', item 2"},
        ],
        "milestones": [
            {"date": "2026-12-31",
             "clause": "at least the First Steps implemented and initial national PQC "
                       "transition roadmaps established by all Member States",
             "source": "the box 'Timeline for the transition to PQC', item 1"},
        ],
        "composite": "section 4.1: the dates are for quantum-vulnerable mechanisms used "
                     "'stand-alone'; the roadmap recommends 'standardised and tested hybrid "
                     "solutions'",
    },
    # NCSC, "Timelines for migration to post-quantum cryptography", Version 1.0, published and
    # reviewed 20 March 2025: "By 2028 ... Carry out a full discovery exercise ... Build an
    # initial plan for migration"; "By 2031 Carry out your early, highest-priority PQC
    # migration activities"; "By 2035 Complete migration to PQC of all your systems, services
    # and products". "This leads to a target date of 2035 for completing migration to
    # post-quantum cryptography." Guidance, not law: "indicative timelines that UK industry,
    # government and regulators can follow".
    "uk-ncsc": {
        "name": "uk-ncsc",
        "document": "NCSC, Timelines for migration to post-quantum cryptography (Version 1.0, "
                    "20 March 2025)",
        "url": "https://www.ncsc.gov.uk/guidance/pqc-migration-timelines",
        "read_on": "2026-11-17",
        "addresses": "UK organisations; 'indicative timelines that UK industry, government and "
                     "regulators can follow' (guidance, not law)",
        "rules": [
            {"families": "*", "deadline": "2035-12-31",
             "clause": "By 2035: Complete migration to PQC of all your systems, services and "
                       "products",
             "source": "Executive summary, key milestones"},
        ],
        "conditional": [
            {"date": "2031-12-31",
             "clause": "By 2031: Carry out your early, highest-priority PQC migration "
                       "activities",
             "applies": "only if this system is among the owner's highest-priority "
                        "migrations; the scan cannot tell",
             "source": "Executive summary, key milestones"},
        ],
        "milestones": [
            {"date": "2028-12-31",
             "clause": "By 2028: Define your migration goals; carry out a full discovery "
                       "exercise; build an initial plan for migration",
             "source": "Executive summary, key milestones"},
        ],
    },
    # Canadian Centre for Cyber Security. ITSP.40.111, "Cryptographic algorithms for
    # UNCLASSIFIED, PROTECTED A, and PROTECTED B information", Version 5, in effect May 29,
    # 2026. Section 5.1: "The RSA modulus length should be increased to at least 3072 bits by
    # the end of 2030. The use of RSA without a post-quantum key establishment scheme should be
    # phased out by the end of 2035." 5.2: "The FFC field size should be increased to at least
    # 3072 bits by the end of 2030. The use of FFC DH and FFC MQV without a post-quantum key
    # establishment scheme should be phased out by the end of 2035." 5.3: "Curve P-224 should be
    # phased out by the end of 2030." "The use of ECC CDH and ECC MQV without a post-quantum key
    # establishment scheme should be phased out by the end of 2035." 6.1: "The RSA modulus
    # length should be increased to at least 3072 bits by the end of 2030. The use of RSA
    # without a post-quantum digital signature scheme should be phased out by the end of
    # 2035." 6.2: "The use of Digital Signature Algorithm (DSA) should be phased out by the end
    # of 2030." 6.3: "Curve P-224 should be phased out by the end of 2030." "The use of ECDSA
    # without a post-quantum digital signature scheme should be phased out by the end of 2035."
    # 6.4: "The use of EdDSA without a post-quantum digital signature scheme should be phased
    # out by the end of 2035." ITSM.40.001, "Roadmap for the migration to post-quantum
    # cryptography for the Government of Canada", in effect June 23, 2025, section 4: "April
    # 2026: Develop an initial departmental PQC migration plan"; "End of 2031: Completion of
    # PQC migration of high priority systems"; "End of 2035: Completion of PQC migration of
    # remaining systems" -- for "non-classified IT systems" of federal departments.
    "ca-cccs": {
        "name": "ca-cccs",
        "document": "Canadian Centre for Cyber Security, ITSP.40.111 Cryptographic algorithms "
                    "for UNCLASSIFIED, PROTECTED A, and PROTECTED B information (Version 5, "
                    "in effect May 29, 2026); ITSM.40.001 Roadmap for the migration to "
                    "post-quantum cryptography for the Government of Canada (June 23, 2025)",
        "url": "https://www.cyber.gc.ca/sites/default/files/itsp40111-cryptographic-"
               "algorithms-e.pdf",
        "read_on": "2026-11-17",
        "sources": [
            {"document": "ITSP.40.111, Version 5", "read_on": "2026-11-17",
             "url": "https://www.cyber.gc.ca/sites/default/files/itsp40111-cryptographic-"
                    "algorithms-e.pdf"},
            {"document": "ITSM.40.001", "read_on": "2026-11-17",
             "url": "https://www.cyber.gc.ca/sites/default/files/itsm.40.001-migration-post-"
                    "quantum-cryptography-government-canada-e.pdf"},
        ],
        "addresses": "UNCLASSIFIED, PROTECTED A and PROTECTED B information (ITSP.40.111); "
                     "non-classified IT systems of Government of Canada departments "
                     "(ITSM.40.001)",
        "rules": [
            {"families": ["RSA"], "role": "key_establishment", "deadline": "2035-12-31",
             "clause": "The use of RSA without a post-quantum key establishment scheme should "
                       "be phased out by the end of 2035",
             "source": "ITSP.40.111 section 5.1"},
            {"families": ["RSA"], "role": "key_establishment", "deadline": "2030-12-31",
             "key_size_below": 3072,
             "clause": "The RSA modulus length should be increased to at least 3072 bits by "
                       "the end of 2030",
             "source": "ITSP.40.111 section 5.1"},
            {"families": ["DH"], "deadline": "2035-12-31",
             "clause": "The use of FFC DH and FFC MQV without a post-quantum key establishment "
                       "scheme should be phased out by the end of 2035",
             "source": "ITSP.40.111 section 5.2"},
            {"families": ["DH"], "deadline": "2030-12-31", "key_size_below": 3072,
             "clause": "The FFC field size should be increased to at least 3072 bits by the "
                       "end of 2030",
             "source": "ITSP.40.111 section 5.2"},
            # Section 5.3 recommends ECC CDH on P-224, P-256, P-384 and P-521 only: X25519 and
            # X448 are not among its curves, so they are `unlisted`, not dated.
            {"families": ["ECDH"], "deadline": "2035-12-31", "except": ["X25519", "X448"],
             "clause": "The use of ECC CDH and ECC MQV without a post-quantum key establishment "
                       "scheme should be phased out by the end of 2035",
             "source": "ITSP.40.111 section 5.3"},
            {"families": ["ECDH", "ECDSA"], "deadline": "2030-12-31", "curve": "224",
             "clause": "Curve P-224 should be phased out by the end of 2030",
             "source": "ITSP.40.111 sections 5.3 and 6.3"},
            {"families": ["RSA"], "role": "signature", "deadline": "2035-12-31",
             "clause": "The use of RSA without a post-quantum digital signature scheme should "
                       "be phased out by the end of 2035",
             "source": "ITSP.40.111 section 6.1"},
            {"families": ["RSA"], "role": "signature", "deadline": "2030-12-31",
             "key_size_below": 3072,
             "clause": "The RSA modulus length should be increased to at least 3072 bits by "
                       "the end of 2030",
             "source": "ITSP.40.111 section 6.1"},
            {"families": ["DSA"], "deadline": "2030-12-31",
             "clause": "The use of Digital Signature Algorithm (DSA) should be phased out by "
                       "the end of 2030",
             "source": "ITSP.40.111 section 6.2"},
            {"families": ["ECDSA"], "deadline": "2035-12-31",
             "clause": "The use of ECDSA without a post-quantum digital signature scheme should "
                       "be phased out by the end of 2035",
             "source": "ITSP.40.111 section 6.3"},
            {"families": ["EdDSA"], "deadline": "2035-12-31",
             "clause": "The use of EdDSA without a post-quantum digital signature scheme should "
                       "be phased out by the end of 2035",
             "source": "ITSP.40.111 section 6.4"},
        ],
        "conditional": [
            {"date": "2031-12-31",
             "clause": "End of 2031: Completion of PQC migration of high priority systems",
             "applies": "only for a high priority non-classified IT system of a Government of "
                        "Canada department; the scan cannot tell",
             "source": "ITSM.40.001 section 4"},
        ],
        "milestones": [
            {"date": "2026-04",
             "clause": "April 2026: Develop an initial departmental PQC migration plan; "
                       "beginning April 2026 and annually after: report on PQC migration "
                       "progress",
             "source": "ITSM.40.001 section 4"},
            {"date": "2035-12-31",
             "clause": "End of 2035: Completion of PQC migration of remaining systems",
             "source": "ITSM.40.001 section 4"},
        ],
        "composite": "ITSP.40.111 sections 5 and 6: each phase-out is of the classical scheme "
                     "used 'without a post-quantum' key establishment or signature scheme",
        "unlisted": "not among the schemes ITSP.40.111 recommends; it gives no date for it",
    },
    # ASD, Information security manual, September 2026, Guidelines for cryptography. "Taking
    # into account projected technological advances in quantum computing, DH will not be
    # approved beyond 2030." -- and the same sentence for ECDH, ECDSA and RSA. "For
    # interoperability and maintainability reasons, ML-DSA-65 will not be approved beyond
    # 2030." "... ML-KEM-768 will not be approved beyond 2030." The approved asymmetric
    # algorithms are DH, ECDH, ECDSA, ML-DSA, ML-KEM and RSA; "Only AACAs or high assurance
    # cryptographic algorithms are used by cryptographic equipment, applications and
    # libraries" (ISM-0471) -- EdDSA and DSA are not among them. ECDH is on "a suitable curve
    # from NIST SP 800-186", which specifies Curve25519 and Curve448 (section 3.2.2; read
    # 17.11.2026), so X25519 and X448 are ECDH here. ISM-1996: "When a
    # post-quantum traditional hybrid scheme is used, either the post-quantum cryptographic
    # algorithm, the traditional cryptographic algorithm or both are AACAs." ISM-1917: "The
    # development and procurement of new cryptographic equipment, applications and libraries
    # ensures support for the use of ML-DSA-87, ML-KEM-1024, SHA-384, SHA-512 and AES-256 by no
    # later than 2030."
    "au-ism": {
        "name": "au-ism",
        "document": "ASD, Information security manual (September 2026), Guidelines for "
                    "cryptography",
        "url": "https://www.cyber.gov.au/sites/default/files/2026-08/Information%20security%20"
               "manual%20%28September%202026%29.pdf",
        # The sentences were read from the PDF fetched on 27.09.2026. On 17.11.2026 the ISM's
        # "latest" page still gave the September 2026 edition (read in a browser; the site
        # refuses scripted fetches), so the reading is dated by the copy.
        "read_on": "2026-09-27",
        "addresses": "organisations applying the ISM (Australian government entities, and "
                     "others by choice)",
        "rules": [
            {"families": ["DH"], "deadline": "2030-12-31",
             "clause": "DH will not be approved beyond 2030",
             "source": "Guidelines for cryptography, Using Diffie-Hellman"},
            {"families": ["ECDH"], "deadline": "2030-12-31",
             "clause": "ECDH will not be approved beyond 2030",
             "source": "Guidelines for cryptography, Using Elliptic Curve Diffie-Hellman"},
            {"families": ["ECDSA"], "deadline": "2030-12-31",
             "clause": "ECDSA will not be approved beyond 2030",
             "source": "Guidelines for cryptography, Using the Elliptic Curve Digital "
                       "Signature Algorithm"},
            {"families": ["RSA"], "deadline": "2030-12-31",
             "clause": "RSA will not be approved beyond 2030",
             "source": "Guidelines for cryptography, Using Rivest-Shamir-Adleman"},
        ],
        "parameter_sets": {
            "ML-KEM-768": {"deadline": "2030-12-31",
                           "clause": "ML-KEM-768 will not be approved beyond 2030",
                           "source": "Guidelines for cryptography, Using the Module-Lattice-"
                                     "Based Key Encapsulation Mechanism"},
            "ML-DSA-65": {"deadline": "2030-12-31",
                          "clause": "ML-DSA-65 will not be approved beyond 2030",
                          "source": "Guidelines for cryptography, Using the Module-Lattice-"
                                    "Based Digital Signature Algorithm"},
        },
        "milestones": [
            {"date": "2030-12-31",
             "clause": "The development and procurement of new cryptographic equipment, "
                       "applications and libraries ensures support for the use of ML-DSA-87, "
                       "ML-KEM-1024, SHA-384, SHA-512 and AES-256 by no later than 2030",
             "source": "ISM-1917"},
        ],
        "composite": "ISM-1996: in a post-quantum traditional hybrid scheme 'either the "
                     "post-quantum cryptographic algorithm, the traditional cryptographic "
                     "algorithm or both are AACAs'",
        "unlisted": "not an ASD-approved asymmetric cryptographic algorithm (ISM-0471: only "
                    "AACAs or high assurance algorithms are used); the ISM gives it no date",
    },
    # Rijksoverheid, "Rijksbrede Quantumstrategie", sent to parliament on 5 oktober 2026, the box
    # "PQC-migratie tijdpad voor de Nederlandse Rijksoverheid": "Uiterlijk eind 2030: ...
    # Rijksoverheidsorganisaties hebben de PQC-migratie voor gebruiksscenario's met een hoog
    # risico voltooid. Software en firmware maken standaard gebruik van quantumveilige
    # cryptografie." "Uiterlijk eind 2035: De Rijksoverheid heeft de PQC-migratie voor
    # gebruiksscenario's met een gemiddeld risico voltooid. De Rijksoverheid heeft PQC-migratie
    # voor gebruiksscenario's met een laag risico voor zover mogelijk voltooid." "Uiterlijk eind
    # 2027: Rijksoverheidsorganisaties hebben een (concept) PQC-migratieplanning opgesteld". Its
    # nature: "De Nederlandse Rijksoverheid streeft ernaar om dit tijdpad aan te houden." For
    # central government organisations only; the EU roadmap's shape, so the same reading.
    "nl-rqs": {
        "name": "nl-rqs",
        "document": "Rijksoverheid, Rijksbrede Quantumstrategie (5 oktober 2026), PQC-migratie "
                    "tijdpad voor de Nederlandse Rijksoverheid",
        "url": "https://zoek.officielebekendmakingen.nl/blg-1279064.pdf",
        "read_on": "2026-11-17",
        "addresses": "Dutch central government organisations (Rijksoverheidsorganisaties); the "
                     "government 'streeft ernaar' (aims) to keep to it",
        "rules": [
            {"families": "*", "deadline": "2035-12-31",
             "clause": "Uiterlijk eind 2035: De Rijksoverheid heeft de PQC-migratie voor "
                       "gebruiksscenario's met een gemiddeld risico voltooid [en] voor "
                       "gebruiksscenario's met een laag risico voor zover mogelijk voltooid",
             "source": "PQC-migratie tijdpad, 'Uiterlijk eind 2035'"},
        ],
        "conditional": [
            {"date": "2030-12-31",
             "clause": "Uiterlijk eind 2030: Rijksoverheidsorganisaties hebben de PQC-migratie "
                       "voor gebruiksscenario's met een hoog risico voltooid",
             "applies": "only for a high-risk use case; the scan cannot tell",
             "source": "PQC-migratie tijdpad, 'Uiterlijk eind 2030'"},
            {"date": "2030-12-31",
             "clause": "Uiterlijk eind 2030: Software en firmware maken standaard gebruik van "
                       "quantumveilige cryptografie",
             "applies": "only if this is the cryptography of software or firmware by default "
                        "(its updates, its signing); the scan cannot tell what a key protects",
             "roles": ["signature", "undetermined"],
             "source": "PQC-migratie tijdpad, 'Uiterlijk eind 2030'"},
        ],
        "milestones": [
            {"date": "2026-12-31",
             "clause": "Uiterlijk eind 2026: het risico van quantumcomputingtechnologie "
                       "meegenomen in het risicomanagementproces; een eigen cryptografiebeleid",
             "source": "PQC-migratie tijdpad, 'Uiterlijk eind 2026'"},
            {"date": "2027-12-31",
             "clause": "Uiterlijk eind 2027: een (concept) PQC-migratieplanning opgesteld",
             "source": "PQC-migratie tijdpad, 'Uiterlijk eind 2027'"},
            {"date": "2028-12-31",
             "clause": "Uiterlijk eind 2028: bij inkoop en aanbestedingen eisen en wensen stellen "
                       "over het gebruik van quantumveilige cryptografie",
             "source": "PQC-migratie tijdpad, 'Uiterlijk eind 2028'"},
        ],
    },
    # NCSC (Sweden), "Nationella rekommendationer för övergången till kvantsäker kryptografi
    # 2026", published 27 maj 2026: "Färdigt 2035: Hela övergången till kvantsäker kryptografi
    # ska vara klar till slutet av år 2035." "Färdigt 2030: För viss information är det dock
    # bråttom och övergången ska vara klar till slutet av 2030. Det gäller information som är
    # känslig mer än tio år framåt i tiden, exempelvis sådan som rör individers hälsodata."
    "se-ncsc": {
        "name": "se-ncsc",
        "document": "NCSC (Sweden), Nationella rekommendationer för övergången till kvantsäker "
                    "kryptografi 2026 (27 maj 2026)",
        "url": "https://www.ncsc.se/siteassets/publikationer/nationella-rekommendationer-for-"
               "overgangen-till-kvantsaker-kryptografi-2026_tga.pdf",
        "read_on": "2026-11-17",
        "addresses": "Swedish organisations, national recommendations (focus on NIS2 and "
                     "Cybersäkerhetslagen entities)",
        "rules": [
            {"families": "*", "deadline": "2035-12-31",
             "clause": "Hela övergången till kvantsäker kryptografi ska vara klar till slutet "
                       "av år 2035",
             "source": "section 'Färdigt 2035'"},
        ],
        "conditional": [
            {"date": "2030-12-31",
             "clause": "övergången ska vara klar till slutet av 2030 [för] information som är "
                       "känslig mer än tio år framåt i tiden",
             "applies": "only if the information is sensitive more than ten years ahead (e.g. "
                        "health data); the scan cannot tell",
             "source": "section 'Färdigt 2030'"},
        ],
    },
    # Cabinet Secretariat (National Cybersecurity Office) and the inter-ministerial PQC
    # liaison council, 「政府機関等における耐量子計算機暗号（PQC）への移行について（中間とりまとめ）」,
    # 令和7年11月 (November 2025), section 4 (1): "原則として、2035 年を目処に、耐量子計算機暗号
    # （PQC）へ移行を行うこととする。" ("In principle, migrate to PQC by around 2035.") It continues:
    # "特に機微な情報や保護期間が非常に長期となることが想定されている情報等を扱う場合等においては、
    # より早期に移行を行うことも含め、情報システムごとに適切に検討を行うこととする。" -- earlier
    # migration for very sensitive or long-protected information, decided per system, with no
    # date. A roadmap (工程表) is to be drawn up in FY2026. For government bodies under the
    # Unified Standards. "2035 年を目処に" is read as the end of 2035.
    "jp-gov": {
        "name": "jp-gov",
        "document": "Cabinet Secretariat (Japan), 政府機関等における耐量子計算機暗号（PQC）への"
                    "移行について（中間とりまとめ） (November 2025)",
        "url": "https://www.cas.go.jp/jp/seisaku/pqc/pdf/report_202511.pdf",
        "read_on": "2026-11-17",
        "addresses": "Japanese government bodies (政府機関等) under the government's Unified "
                     "Standards; a target 'in principle' (原則として)",
        "rules": [
            {"families": "*", "deadline": "2035-12-31",
             "clause": "原則として、2035 年を目処に、耐量子計算機暗号（PQC）へ移行を行うこととする "
                       "(in principle, migrate to PQC by around 2035)",
             "source": "section 4 (1), 耐量子計算機暗号（PQC）への移行期限"},
        ],
        "milestones": [
            {"date": "2027-03-31",
             "clause": "2026 年度に工程表（ロードマップ）を策定 (a roadmap drawn up in FY2026, "
                       "which ends 31 March 2027)",
             "source": "section 1"},
        ],
    },
    # Cyber Security Agency of Singapore, Quantum-Safe Handbook V1 (16 Jul 2026): "Singapore is
    # aligning with this momentum with requirements for Critical Information Infrastructure
    # (CII) owners as part of their quantum-safe migration planning: By 31 Mar 2027: Submission
    # of CII owner's quantum-safe migration plan to CSA. From 1 Jan 2028: Procurement and
    # implementation of new CII computer and computer systems that have a digital component
    # should either (a) support quantum-safe algorithms/ technologies; and/or (b) be
    # quantum-safe ready. By 31 Dec 2031: Completion of quantum-safe migration across CII
    # computer and computer systems, i.e. vulnerable cryptography should no longer be used."
    # MAS Consultation Paper P019-2026 (6 Nov 2026) proposes other dates for financial
    # institutions; a consultation, not in force, so not here.
    "sg-csa-cii": {
        "name": "sg-csa-cii",
        "document": "Cyber Security Agency of Singapore, Quantum-Safe Handbook V1 (16 Jul "
                    "2026), requirements for CII owners",
        "url": "https://www.csa.gov.sg/resources/publications/quantum-safe-handbook-and-"
               "quantum-readiness-index",
        "read_on": "2026-11-17",
        "addresses": "owners of Critical Information Infrastructure (CII) in Singapore only",
        "rules": [
            {"families": "*", "deadline": "2031-12-31",
             "clause": "By 31 Dec 2031: Completion of quantum-safe migration across CII computer "
                       "and computer systems, i.e. vulnerable cryptography should no longer be "
                       "used",
             "source": "requirements for CII owners, third item"},
        ],
        "milestones": [
            {"date": "2027-03-31",
             "clause": "By 31 Mar 2027: Submission of CII owner's quantum-safe migration plan to "
                       "CSA",
             "source": "requirements for CII owners, first item"},
            {"date": "2028-01-01",
             "clause": "From 1 Jan 2028: new CII computer and computer systems that have a "
                       "digital component should support quantum-safe algorithms or be "
                       "quantum-safe ready",
             "source": "requirements for CII owners, second item"},
        ],
    },
    # Department of Science and Technology, National Quantum Mission, Task Force report "Report
    # on Quantum-Safe Ecosystem in India -- Roadmap to Quantum Resiliency" (May 2026): "CII
    # sectors -- government, strategic, defence, power, telecom, transport, and Banking,
    # Financial Services and Insurance (BFSI) -- will follow accelerated timelines: Foundations
    # by 2027, High-Priority Migration by 2028, and Full PQC Adoption by 2029. Other
    # enterprises will follow the baseline timelines of 2028, 2030, and 2033 respectively."
    # "Milestone 3 -- Full PQC Adoption (CII: by 2029 | Enterprises: by 2033): Complete
    # enterprise-wide PQC/hybrid (classical + PQC) adoption." Nature: "It does not constitute a
    # legal or regulatory mandate. Adoption, timelines, and enforcement may be determined by
    # the respective sectoral regulators" (said of the framework in that section).
    "in-dst": {
        "name": "in-dst",
        "document": "DST, National Quantum Mission, Report on Quantum-Safe Ecosystem in India -- "
                    "Roadmap to Quantum Resiliency (May 2026)",
        "url": "https://www.dst.gov.in/static/uploads/2026/07/dba5f97fa8f4c8db5ef668306548a470"
               ".pdf",
        "read_on": "2026-11-17",
        "addresses": "Indian organisations; a Task Force recommendation, not a regulation "
                     "(sectoral regulators may set their own)",
        "rules": [
            {"families": "*", "deadline": "2033-12-31",
             "clause": "Milestone 3 -- Full PQC Adoption (Enterprises: by 2033): Complete "
                       "enterprise-wide PQC/hybrid (classical + PQC) adoption",
             "source": "Milestone 3"},
        ],
        "conditional": [
            {"date": "2029-12-31",
             "clause": "CII sectors ... will follow accelerated timelines: ... Full PQC Adoption "
                       "by 2029",
             "applies": "only for Critical Information Infrastructure (government, strategic, "
                        "defence, power, telecom, transport, BFSI); the scan cannot tell",
             "source": "Milestone 3; the accelerated timelines for CII"},
            {"date": "2030-12-31",
             "clause": "Milestone 2 -- Migrate High-Priority Systems (Enterprises: by 2030)",
             "applies": "only for a high-priority system; the scan cannot tell",
             "source": "Milestone 2"},
        ],
        "milestones": [
            {"date": "2028-12-31",
             "clause": "Milestone 1 -- Build Foundations (CII: by 2027 | Enterprises: by "
                       "2028): inventory cryptographic assets and assess quantum risk",
             "source": "Milestone 1"},
        ],
        "composite": "Milestone 3: 'Complete enterprise-wide PQC/hybrid (classical + PQC) "
                     "adoption'",
    },
    # BSI, Technical Guideline TR-02102-1, "Cryptographic Mechanisms: Recommendations and Key
    # Lengths", Version 2026-01. Section 2.1: "The sole use of classic key agreement mechanisms
    # is only recommended until the end of 2031, see also Section 2.3. For applications with
    # very high protection requirements, the transition to quantum-safe mechanisms should
    # already take place by the end of 2030." "Based on current knowledge, the use of classic
    # signature mechanisms is therefore only recommended until the end of 2035." Section 2.3:
    # "The use of the methods in this chapter beyond 2031 is only recommended in combination
    # with a quantum-safe KEM method from Chapter 2.4 and a key derivation from Chapter 2.2."
    # Section 5.3.1: "The restriction of the recommendation for RSA until 2031 in Table 2.2 only
    # applies to key exchange. Signatures with RSA are expected to be recommended until 2035".
    # BMDS, BMI and BSI, "Leitlinie zur Umstellung auf PQC", 11. September 2026, section 3:
    # "Anwendungsfälle mit hohem Risiko sollten bis Ende 2030 quantensicher sein. Analog sollte
    # dies für Anwendungsfälle mit mittlerem Risiko bis Ende 2035 umgesetzt sein." Section 4.3:
    # "Das kryptografische Inventar sollte regelmäßig auf Aktualität geprüft werden; die
    # initiale Erstellung sollte bis Ende 2026 abgeschlossen sein." Section 4.1: "Die in dieser
    # Roadmap enthaltenen Fristen sind dringende Empfehlungen".
    "de-bsi": {
        "name": "de-bsi",
        "document": "BSI, Technical Guideline TR-02102-1, Cryptographic Mechanisms: "
                    "Recommendations and Key Lengths (Version 2026-01)",
        "url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/"
               "TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile",
        "read_on": "2026-11-17",
        "sources": [
            {"document": "TR-02102-1, Version 2026-01", "read_on": "2026-11-17",
             "url": "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/"
                    "TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile"},
            {"document": "BMDS, BMI and BSI, Leitlinie zur Umstellung auf PQC (11. September "
                         "2026)", "read_on": "2026-11-17",
             "url": "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Krypto/"
                    "Leitlinie-Umstellung-PQC.pdf?__blob=publicationFile"},
        ],
        "addresses": "recommendations of a BSI Technical Guideline; the Leitlinie's dates are "
                     "'dringende Empfehlungen' (urgent recommendations) for Germany",
        "rules": [
            {"families": "*", "role": "key_establishment", "deadline": "2031-12-31",
             "clause": "The sole use of classic key agreement mechanisms is only recommended "
                       "until the end of 2031",
             "source": "TR-02102-1 section 2.1; Table 2.2 'Recommended until 2031'"},
            {"families": "*", "role": "signature", "deadline": "2035-12-31",
             "clause": "the use of classic signature mechanisms is therefore only recommended "
                       "until the end of 2035",
             "source": "TR-02102-1 section 2.1; section 5.3"},
        ],
        "conditional": [
            {"date": "2030-12-31",
             "clause": "For applications with very high protection requirements, the "
                       "transition to quantum-safe mechanisms should already take place by the "
                       "end of 2030",
             "applies": "only for applications with very high protection requirements; the "
                        "scan cannot tell",
             "roles": ["key_establishment", "undetermined"],
             "source": "TR-02102-1 section 2.1"},
            {"date": "2030-12-31",
             "clause": "Anwendungsfälle mit hohem Risiko sollten bis Ende 2030 quantensicher "
                       "sein",
             "applies": "only for a high-risk use case (Leitlinie section 4.5, following the EU "
                        "roadmap); the scan cannot tell",
             "source": "Leitlinie zur Umstellung auf PQC, section 3"},
        ],
        "milestones": [
            {"date": "2026-12-31",
             "clause": "die initiale Erstellung [des kryptografischen Inventars] sollte bis "
                       "Ende 2026 abgeschlossen sein",
             "source": "Leitlinie zur Umstellung auf PQC, section 4.3"},
        ],
        "composite": "TR-02102-1 section 2.3: beyond 2031 the classical methods are 'only "
                     "recommended in combination with a quantum-safe KEM method'",
    },
}


def names() -> list[str]:
    return ["nist", *PROFILES]


def source(profile: str) -> dict[str, str]:
    p = PROFILES[profile]
    return {"standard": f"{p['authority']}: {p['document']}", "what": p["version"],
            "url": p["url"], "read_on": READ_ON,
            **({"also": p["also_sources"]} if p.get("also_sources") else {})}


def parameter_set_name(item: dict[str, Any]) -> str:
    """`ML-KEM-768` from an occurrence's family and `parameter_set` (`768`, or a certificate's
    `ML-DSA-65`)."""
    family, said = str(item.get("algorithm")), str(item["parameter_set"])
    return said if said.startswith(f"{family}-") else f"{family}-{said}"


def standing(profile: str, family: str) -> dict[str, Any] | None:
    """What the profile's document says of a family it recommends beyond NIST's standards."""
    said = PROFILES.get(profile, {}).get("recommends", {}).get(family)
    if not said:
        return None
    return {"profile": profile, "standing": said, "source": source(profile)}
