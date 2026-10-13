"""CERT-In Quantum Bill of Materials (QBOM) layer. CERT-In v2.0, Table 8.

CORRECTION FIRST, because it is material
----------------------------------------
An earlier note in this session asserted that CERT-In's QBOM meant "Quality Bill
of Materials". That was WRONG and has been retracted. CERT-In Technical
Guidelines v2.0 (9 July 2025), Chapter 8, is titled

    "8. Quantum BOM (QBOM) & Cryptographic BOM (CBOM)"
    "8.1 What is Crypto & Quantum BOM? A Quantum Bill of Materials (QBOM) and a
     Cryptographic Bill of Materials (CBOM) are structured inventories that
     provide comprehensive visibility into an organization's cryptographic and
     quantum-related components. The QBOM focuses on components related to
     quantum computing and quantum-safe cryptography. It includes quantum
     algorithms, security frameworks, and related technologies, enabling
     organizations to maintain integrity, compliance, and resilience as they
     adopt post-quantum cryptographic (PQC) solutions."

QBOM is the Quantum Bill of Materials. The confusion is real and worth recording,
because the "Bills of BOMs" acronym soup (SBOM / QBOM / CBOM / AIBOM / HBOM) is
exactly where a plausible-sounding wrong expansion survives review. This module
therefore quotes the definition from the pinned primary source rather than
paraphrasing it.

THE 11 MINIMUM ELEMENTS (Table 8, transcribed from the PDF)
---------------------------------------------------------
Model Name, Version, Vendor & Origin Information, License Information,
Cryptographic Asset, Communication Protocol, Hardware, Software Dependencies,
Environmental Impact, Vulnerabilities Information, Attestations.

WHY MOST OF THEM ARE NOT_OBSERVABLE HERE
----------------------------------------
This is a static source-code analyser. It can see the SBOM, the findings and the
advisories. It cannot see a quantum device sitting in a datacentre. So of the 11
elements, the ones describing the physical asset -- Model Name, Version, Vendor &
Origin, Communication Protocol, Hardware, Environmental Impact -- are classified
NOT_OBSERVABLE_FROM_SOURCE with a stated reason, and are emitted as
`null` with `element_status` recording why.

That is the whole point of emitting the layer at all: a consumer can see which
fields are covered and which are not, rather than receiving a document that looks
complete and is quietly missing six of eleven fields.

WHAT IS NOT INVENTED
--------------------
If the scanned codebase contains no quantum SDK, the quantum_components list is
EMPTY and `quantum_components_detected` is false. No placeholder device is
synthesised, no algorithm is invented, and no example vendor is used. An empty
inventory that says it is empty is the truthful output; a populated one would be
fabrication. This is the single most important property of this module.

ATTESTATIONS ARE REAL, NOT A PLACEHOLDER
-----------------------------------------
Attestations is listed as a minimum element and is genuinely computable here: a
SHA-256 over the canonicalised inventory of everything this tool did observe. It
is a content digest, not a digital signature, and it says so -- claiming a
signature would misrepresent a hash as a cryptographic attestation from a signing
key we do not have.
"""
from __future__ import annotations

import hashlib
import json
import re

# ---------------------------------------------------------------- provenance
CERTIN_DOCUMENT = ("CERT-In Technical Guidelines on SBOM, QBOM & CBOM, "
                   "AIBOM and HBOM")
CERTIN_VERSION = "v2.0"
CERTIN_DATE = "2025-07-09"
CERTIN_PDF_SHA256 = "28AA48F329114D665F8E4F8C4D2F33BAF4981E29168A318E6E719C11A5FF5151"
CERTIN_PDF_PAGES = 66
CERTIN_SOURCE_URL = ("https://www.cert-in.org.in/PDF/TechnicalGuidelines-on-"
                     "SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf")
CERTIN_LICENSE = ("Government of India, Ministry of Electronics and Information "
                  "Technology. Not a licence grant; cited by reference.")

QBOM_DATASET_LABEL = f"{CERTIN_DOCUMENT} {CERTIN_VERSION} (Table 8)"

QBOM_DEFINITION = (
    "CERT-In v2.0 Chapter 8.1, quoted from the pinned primary source: 'A Quantum "
    "Bill of Materials (QBOM) and a Cryptographic Bill of Materials (CBOM) are "
    "structured inventories that provide comprehensive visibility into an "
    "organization's cryptographic and quantum-related components. The QBOM focuses "
    "on components related to quantum computing and quantum-safe cryptography. It "
    "includes quantum algorithms, security frameworks, and related technologies, "
    "enabling organizations to maintain integrity, compliance, and resilience as "
    "they adopt post-quantum cryptographic (PQC) solutions.'"
)

# Package names indicating the codebase actually uses quantum / PQC technology.
# Matched case-insensitively against SBOM component names. This list is used only
# to DETECT, never to invent an entry.
QUANTUM_SDK_HINTS = {
    "qiskit", "qiskit-aer", "cirq", "pennylane", "braket-sdk", "qsharp",
    "pytket", "stim", "qutip", "openqasm", "quantum-circuit", "tket",
    "pyquil", "qcsdk", "azure-quantum", "quri-parts", "pymcmc",
}

# PQC-algorithm indicators found in dependency names or source-level references.
PQC_HINTS = (
    "kyber", "dilithium", "ml-kem", "ml-dsa", "sphincs", "falcon", "crystal",
    "classic-mceliece", "hqc", "cross", "saber", "ntruprime", "ntru",
    "oqs", "liboqs", "pqcrypto", "post-quantum", "postquantum", "quantum-safe",
)

OBSERVABLE = "OBSERVABLE_FROM_SOURCE"
NOT_OBSERVABLE = "NOT_OBSERVABLE_FROM_SOURCE"

# --------------------------------------------------------------------------
# Table 8. Order is the document's own order.
#
# `observable` is True only where a source or asset inventory can state something
# true about the element. Everything describing a physical quantum device is
# False, and `reason` says why in the words a reader would need.
# --------------------------------------------------------------------------
QBOM_MINIMUM_ELEMENTS = {
    "model_name": {
        "name": "Model Name",
        "table": "Table 8",
        "description": ("Provides a unique identifier for the quantum device or "
                        "system, ensuring easy reference and distinction."),
        "observable": False,
        "reason": ("Identifies a physical quantum device or system. A source scan "
                   "observes code, not installed hardware, so no model name can be "
                   "asserted."),
    },
    "version": {
        "name": "Version",
        "table": "Table 8",
        "description": ("Tracks version numbers and updates, including new "
                        "features, security patches, and system enhancements."),
        "observable": False,
        "reason": ("The version of a quantum DEVICE. Component versions are "
                   "recorded under software_dependencies, which is a different "
                   "element and must not be conflated with the device version."),
    },
    "vendor_origin": {
        "name": "Vendor & Origin Information",
        "table": "Table 8",
        "description": ("Records the manufacturer and origin of the quantum "
                        "device, ensuring clarity in vendor communication, support, "
                        "and maintenance."),
        "observable": False,
        "reason": ("Manufacturer and origin of physical quantum hardware, obtainable "
                   "only from a device inventory or procurement record."),
    },
    "license_information": {
        "name": "License Information",
        "table": "Table 8",
        "description": ("Documents the licensing terms and conditions for the "
                        "quantum device, ensuring compliance with legal, regulatory, "
                        "and contractual obligations."),
        "observable": True,
        "reason": ("Populated from the licences already resolved for inventoried "
                   "software components. This covers the SOFTWARE side of the "
                   "element; a hardware licence would need the device record."),
    },
    "cryptographic_asset": {
        "name": "Cryptographic Asset",
        "table": "Table 8 -> Table 9",
        "description": ("For a cryptographic asset, the minimum elements are those "
                        "of Table 9, depending on the cryptographic asset type."),
        "observable": True,
        "reason": ("Cross-referenced from the Cryptographic Bill of Materials this "
                   "tool already emits. The per-asset fields of Table 9 live there, "
                   "not here, so this element points at that artifact rather than "
                   "duplicating it."),
    },
    "communication_protocol": {
        "name": "Communication Protocol",
        "table": "Table 8",
        "description": ("Specifies the communication protocols used by the quantum "
                        "device, ensuring seamless integration and compatibility "
                        "with other systems."),
        "observable": False,
        "reason": ("Wire protocols between a quantum device and control "
                   "infrastructure. Not present in source code."),
    },
    "hardware": {
        "name": "Hardware",
        "table": "Table 8",
        "description": ("Describes the hardware components that make up the quantum "
                        "device, including the processor, simulators, networking "
                        "components, and sensors required for quantum operations."),
        "observable": False,
        "reason": ("Processor, simulator, networking and sensor inventory of a "
                   "physical device. Explicitly a Hardware Bill of Materials "
                   "subject, which is tracked separately as NOT_IMPLEMENTED."),
    },
    "software_dependencies": {
        "name": "Software Dependencies",
        "table": "Table 8",
        "description": ("Describes the software elements interacting with the "
                        "quantum hardware, including libraries, APIs, SDKs, and "
                        "firmware updates."),
        "observable": True,
        "reason": "Derived from the SBOM already produced for this scan.",
    },
    "environmental_impact": {
        "name": "Environmental Impact",
        "table": "Table 8",
        "description": ("Tracks the environmental impact of the quantum system, "
                        "including energy consumption and other sustainability "
                        "factors."),
        "observable": False,
        "reason": ("Energy consumption and sustainability of quantum hardware. "
                   "Requires operational measurement, not source analysis."),
    },
    "vulnerabilities_information": {
        "name": "Vulnerabilities Information",
        "table": "Table 8",
        "description": ("Information about known security vulnerabilities or "
                        "weaknesses associated with the components, including "
                        "severity ratings and references to security advisories or "
                        "CVE identifiers."),
        "observable": True,
        "reason": ("Derived from the advisories and findings of this scan, for the "
                   "components this scan actually inventoried."),
    },
    "attestations": {
        "name": "Attestations",
        "table": "Table 8",
        "description": ("Digital signature for the QBOM to ensure authenticity and "
                        "integrity."),
        "observable": True,
        "reason": ("A SHA-256 content digest over the canonicalised inventory is "
                   "computable and is emitted. It is a content digest, NOT a "
                   "digital signature: no signing key is held, so no signature is "
                   "claimed. The element's authenticity guarantee is therefore only "
                   "partially satisfied, and that limit is recorded in the artifact."),
    },
}

QBOM_OBSERVABLE_ELEMENTS = sorted(k for k, v in QBOM_MINIMUM_ELEMENTS.items()
                                  if v["observable"])
QBOM_NOT_OBSERVABLE_ELEMENTS = sorted(
    k for k, v in QBOM_MINIMUM_ELEMENTS.items() if not v["observable"])

# --------------------------------------------------------------------------
# Phase 4.5 -- PQC policy packs: multi-jurisdiction verdicts on the QBOM.
#
# Each pack is a TRANSCRIPTION of one authority's published post-quantum
# policy position, with a citation, a document date and the key dates the
# document itself states. Nothing here is fetched at scan time and nothing
# here is inferred: where a date could not be confirmed against the primary
# document it is left out rather than carried from secondary reporting.
# The verdict matrix (scanner/crypto_quantum_analyzer.build_pqc_verdict_matrix)
# combines these packs with this scan's own quantum classification.
#
# WHY THE FOUR ARE NOT UNIFORM. The authorities genuinely disagree, and a
# matrix that flattened them into one row per jurisdiction would be hiding
# exactly the comparison it exists to show:
#   * NIST IR 8547 is a DRAFT with calendar dates (deprecate 2030,
#     disallow 2035) and keeps >=128-bit symmetric algorithms approved.
#   * NSA CNSA 2.0 is a per-category timetable binding US National Security
#     Systems only, with a small closed suite (AES-256, SHA-384/512,
#     ML-KEM-1024, ML-DSA-87, LMS/XMSS) that excludes SLH-DSA.
#   * BSI TR-02102-1 is a recommendation with a calendar anchor of its own
#     (solo classical key establishment recommended only until end of 2031)
#     and hybrid operation as the expected mode.
#   * ANSSI has no closed algorithm list and no single deadline; it pushes
#     hybridation hard and states a symmetric target (>= AES-256 level,
#     >= SHA2-384 level) rather than a migration year.
# A consumer comparing jurisdictions should see those differences, so the
# notes and dates below differ per pack on purpose.
# --------------------------------------------------------------------------

# The shared verdict vocabulary. Every cell of the matrix uses one of these
# five values and the matrix ships this legend so no cell needs decoding.
PQC_VERDICT_VOCABULARY = {
    "MIGRATE": (
        "The pack establishes a transition expectation for this class of "
        "algorithm: plan and execute migration within the pack's stated dates "
        "or phases."
    ),
    "REPLACE": (
        "The algorithm fails on its own terms -- broken or with its margin "
        "destroyed -- independently of quantum computing. Replace it; this is "
        "not a migration-to-PQC question."
    ),
    "ACCEPTABLE": (
        "The pack's published position does not require a change for this "
        "observation, given the parameters recorded by the scan."
    ),
    "ALIGNED": (
        "The observed algorithm belongs to a family or parameter set the pack "
        "approves or recommends for post-quantum use."
    ),
    "REVIEW": (
        "The observation cannot be mapped to a pack position: unclassified "
        "algorithm, parameter below or unconfirmable against the pack's rules, "
        "a pre-standardisation spelling, or a family the pack does not list. "
        "Human review required -- this is NOT a pass."
    ),
}

# One shared UNKNOWN note. The verdict is pack-independent because the gap is
# in the observation, not in the policy: no authority can map an unnamed
# primitive, and inventing a mapping would be exactly the unverifiable claim
# this product exists to avoid.
_UNKNOWN_REVIEW_NOTE = (
    "The scan could not classify this observation, so no pack position can "
    "be reached from it. Human review required; this is NOT a pass, and it "
    "is not evidence that the primitive is safe."
)

PQC_POLICY_PACKS: list[dict] = [
    # ------------------------------------------------------------------
    # United States / NIST -- IR 8547.
    # ------------------------------------------------------------------
    {
        "id": "nist-ir-8547",
        "jurisdiction": "United States",
        "authority": "NIST",
        "document": (
            "NIST IR 8547 (Initial Public Draft): Transition to "
            "Post-Quantum Cryptography Standards"
        ),
        "document_status": "initial-public-draft",
        "published": "2024-11-12",
        "source_url": "https://csrc.nist.gov/pubs/ir/8547/ipd",
        "related_sources": [
            "https://csrc.nist.gov/projects/post-quantum-cryptography",
        ],
        "scope": (
            "Describes NIST's EXPECTED APPROACH to the transition and is meant "
            "to inform federal agencies, industry and standards bodies. It is "
            "an informative draft, not a FIPS mandate; its dates are NIST's "
            "expected approach, not a standard in force."
        ),
        "hybrid_position": (
            "IR 8547 does not require hybrid operation; it points to "
            "FIPS 203/204/205 as standards that can and should be put into "
            "use now."
        ),
        "key_dates": {
            "quantum_vulnerable_112bit_deprecated_after": 2030,
            "quantum_vulnerable_112bit_disallowed_after": 2035,
            "quantum_vulnerable_128bit_disallowed_after": 2035,
            "symmetric_112bit_level_disallowed_after": 2030,
        },
        "approved_pqc": [
            "FIPS 203 ML-KEM",
            "FIPS 204 ML-DSA",
            "FIPS 205 SLH-DSA",
            "SP 800-208 LMS/XMSS (single-tree use as specified there)",
        ],
        "position_by_status": {
            "QUANTUM_VULNERABLE": {
                "verdict": "MIGRATE",
                "note": (
                    "Deprecated after 2030 and disallowed after 2035 at the "
                    "112-bit security strength (common RSA, ECDSA/ECDH, FFDH "
                    "sizes); the >=128-bit variants are disallowed after "
                    "2035. NIST states FIPS 203/204/205 can and should be "
                    "put into use now."
                ),
            },
            "QUANTUM_MARGIN_CRITICAL": {
                "verdict": "REPLACE",
                "note": (
                    "Grover-depleted symmetric margin (DES/3DES class). "
                    "NIST's few 112-bit-level symmetric standards are "
                    "disallowed in 2030, and SP 800-131A retired 3DES for "
                    "encryption before any quantum argument."
                ),
            },
            "QUANTUM_IMPACT_ASSESSED": {
                "verdict": "ACCEPTABLE",
                "note": (
                    "Symmetric primitives and hashes providing at least 128 "
                    "bits of classical security remain approved under "
                    "IR 8547. The scan records parameters only where the "
                    "source states them; IR 8547's tables govern any "
                    "individual security level."
                ),
            },
            "PQC": {
                "verdict": "ALIGNED",
                "note": (
                    "A recognised post-quantum family. IR 8547's finalised "
                    "standards are FIPS 203/204/205 (plus SP 800-208 for "
                    "LMS/XMSS); confirm this observation maps to one of them."
                ),
            },
            "UNKNOWN": {
                "verdict": "REVIEW",
                "note": _UNKNOWN_REVIEW_NOTE,
            },
        },
        # Evaluated in order, FIRST MATCH WINS, before the status grid.
        "algorithm_overrides": [
            {
                "match_any": ["sha-1"],
                "verdict": "REPLACE",
                "note": (
                    "Collision-broken since 2017 and disallowed by "
                    "SP 800-131A Rev. 2 for digital signatures. The defect "
                    "is classical; no quantum computer is needed to exploit "
                    "it."
                ),
            },
            {
                "match_any": ["ml-kem", "ml-dsa", "slh-dsa"],
                "verdict": "ALIGNED",
                "note": (
                    "FIPS 203/204/205. IR 8547 states these standards can "
                    "and should be put into use now."
                ),
            },
            {
                "match_any": ["lms", "xmss"],
                "verdict": "ALIGNED",
                "note": (
                    "Stateful hash-based signature schemes standardised by "
                    "NIST SP 800-208 (single-tree variants as specified "
                    "there)."
                ),
            },
            {
                "match_any": ["kyber", "dilithium", "sphincs"],
                "verdict": "REVIEW",
                "note": (
                    "Pre-standardisation spelling. FIPS 203/204/205 "
                    "standardise ML-KEM/ML-DSA/SLH-DSA; confirm the "
                    "deployment uses the standardised variant rather than "
                    "the research-stage one."
                ),
            },
            {
                "match_any": [
                    "falcon", "mceliece", "hqc", "ntruprime",
                    "frodkem", "saber",
                ],
                "verdict": "REVIEW",
                "note": (
                    "Not among NIST's finalised post-quantum standards "
                    "(FIPS 203/204/205) as of the pack date. Verify current "
                    "standardisation status before relying on this family."
                ),
            },
        ],
    },
    # ------------------------------------------------------------------
    # United States / NSA -- CNSA 2.0. Binds National Security Systems.
    # ------------------------------------------------------------------
    {
        "id": "nsa-cnsa-2-0",
        "jurisdiction": "United States (National Security Systems)",
        "authority": "NSA",
        "document": (
            "Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) "
            "Cybersecurity Advisory"
        ),
        "document_status": "advisory-final",
        "published": "2022-09-07",
        "source_url": (
            "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/"
            "CSA_CNSA_2.0_ALGORITHMS_.PDF"
        ),
        "related_sources": [
            ("https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/1/"
             "CSI_CNSA_2.0_FAQ_.PDF"),
        ],
        "scope": (
            "Applies to US National Security Systems (NSS) -- networks with "
            "classified information or otherwise critical to military and "
            "intelligence activities. For non-NSS systems it is a "
            "direction-of-travel reference, not a requirement."
        ),
        "hybrid_position": (
            "Hybrid solutions may be allowed for interoperability, but the "
            "post-quantum component must itself be CNSA 2.0 compliant "
            "(CNSA 2.0 FAQ)."
        ),
        "key_dates": {
            "software_firmware_signing_prefer_by": 2025,
            "software_firmware_signing_exclusive_by": 2030,
            "web_browsers_servers_cloud_prefer_by": 2025,
            "web_browsers_servers_cloud_exclusive_by": 2033,
            "networking_equipment_prefer_by": 2026,
            "networking_equipment_exclusive_by": 2030,
            "operating_systems_prefer_by": 2027,
            "operating_systems_exclusive_by": 2033,
            "niche_equipment_exclusive_by": 2033,
            "custom_and_legacy_replace_by": 2033,
            "new_nss_acquisitions_must_support_from": "2027-01-01",
            "all_nss_quantum_resistant_by": 2035,
        },
        "approved_pqc": [
            "ML-KEM-1024 (FIPS 203)",
            "ML-DSA-87 (FIPS 204)",
            "LMS (SP 800-208, single-tree, software/firmware signing)",
            "XMSS (SP 800-208, single-tree, software/firmware signing)",
        ],
        "position_by_status": {
            "QUANTUM_VULNERABLE": {
                "verdict": "MIGRATE",
                "note": (
                    "Must move to the CNSA 2.0 suite on the category "
                    "timetable: software/firmware signing and networking "
                    "equipment exclusively by 2030; web browsers, servers, "
                    "cloud services and operating systems exclusively by "
                    "2033; all NSS quantum-resistant by 2035 (NSM-10). "
                    "Binds NSS only."
                ),
            },
            "QUANTUM_MARGIN_CRITICAL": {
                "verdict": "REPLACE",
                "note": (
                    "CNSA 2.0's symmetric suite is AES-256. This margin "
                    "class fails on classical terms too -- replace it; PQC "
                    "does not apply to symmetric primitives."
                ),
            },
            "QUANTUM_IMPACT_ASSESSED": {
                "verdict": "REVIEW",
                "note": (
                    "CNSA 2.0's suite is AES-256 with SHA-384/512. The "
                    "observed parameters are either below the suite or "
                    "unrecorded; for NSS they must be upgraded, and for "
                    "other systems CNSA 2.0 does not apply. See the "
                    "parameter overrides for the exact split."
                ),
            },
            "PQC": {
                "verdict": "REVIEW",
                "note": (
                    "Not identified as part of the CNSA 2.0 suite. NSA's "
                    "suite is closed -- everything not explicitly approved "
                    "is not approved -- so an unlisted PQC family needs "
                    "human review rather than an assumed pass."
                ),
            },
            "UNKNOWN": {
                "verdict": "REVIEW",
                "note": _UNKNOWN_REVIEW_NOTE,
            },
        },
        "algorithm_overrides": [
            {
                "match_any": ["sha-1"],
                "verdict": "REPLACE",
                "note": (
                    "Collision-broken and not in the CNSA 2.0 suite. The "
                    "defect is classical; replace it outright."
                ),
            },
            {
                "match_any": [
                    "aes-256", "sha-384", "sha-512",
                    "sha3-384", "sha3-512",
                ],
                "verdict": "ACCEPTABLE",
                "note": (
                    "In the CNSA 2.0 suite: AES-256 for symmetric "
                    "encryption, SHA-384/512 for hashing (SHA-3 for "
                    "internal hardware use)."
                ),
            },
            {
                "match_any": ["ml-kem", "ml-dsa", "lms", "xmss"],
                "verdict": "ALIGNED",
                "note": (
                    "CNSA 2.0 names ML-KEM-1024, ML-DSA-87 and (for "
                    "software and firmware signing) LMS/XMSS. Confirm the "
                    "recorded parameter set matches the CNSA level."
                ),
            },
            {
                "match_any": ["kyber", "dilithium"],
                "verdict": "REVIEW",
                "note": (
                    "Pre-standardisation spelling. CNSA 2.0 names the "
                    "standardised variants ML-KEM-1024 (FIPS 203) and "
                    "ML-DSA-87 (FIPS 204); confirm what is deployed."
                ),
            },
            {
                "match_any": [
                    "slh-dsa", "sphincs", "falcon", "mceliece",
                    "hqc", "ntruprime", "frodkem", "saber",
                ],
                "verdict": "REVIEW",
                "note": (
                    "Not part of the CNSA 2.0 suite -- NSA selected "
                    "ML-KEM/ML-DSA (plus LMS/XMSS for signing) and left "
                    "this family out. Not a NIST-security judgement; a "
                    "suite-membership one."
                ),
            },
            {
                "match_any": [
                    "aes", "aes-128", "aes-192",
                    "sha-224", "sha-256", "md5",
                ],
                "verdict": "REVIEW",
                "note": (
                    "Not CNSA 2.0 suite parameters (suite: AES-256, "
                    "SHA-384/512). For NSS this must be upgraded; for "
                    "other systems CNSA 2.0 does not apply. A bare family "
                    "name with no recorded parameter cannot be confirmed "
                    "against the suite either."
                ),
            },
        ],
    },
    # ------------------------------------------------------------------
    # Germany / BSI -- TR-02102-1.
    # ------------------------------------------------------------------
    {
        "id": "bsi-tr-02102",
        "jurisdiction": "Germany",
        "authority": "BSI",
        "document": (
            "BSI TR-02102-1: Cryptographic Mechanisms: Recommendations and "
            "Key Lengths (Kryptographische Verfahren: Empfehlungen und "
            "Schlüssellängen), Version 2026-01"
        ),
        "document_status": "technical-guideline-final",
        "published": "2026-01-23",
        "source_url": (
            "https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/"
            "Publikationen/TechnischeRichtlinien/TR02102/BSI-TR-02102.pdf"
            "?__blob=publicationFile"
        ),
        "related_sources": [
            ("https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/"
             "Publications/TechGuidelines/TG02102/BSI-TR-02102-2.pdf"
             "?__blob=publicationFile"),
            ("https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Krypto/"
             "Post-Quanten-Kryptografie.pdf?__blob=publicationFile"),
        ],
        "scope": (
            "German federal security authority guidance for new "
            "cryptographic deployments: recommendations with a stated "
            "120-bit security level, not a legal mandate. TR-02102-2 "
            "records that solo classical key establishment is recommended "
            "only until the end of 2031 (TR-02102-1 section 2.1)."
        ),
        "hybrid_position": (
            "BSI intends to recommend quantum-safe procedures in HYBRID use "
            "with recommended classical procedures as suitable standards "
            "mature (TR-02102-2 section 3.1.3); hybridation is the "
            "expected migration mode."
        ),
        "key_dates": {
            "classical_key_establishment_solo_recommended_until_end_of": 2031,
            "dsa_recommendation_withdrawn_from": 2029,
        },
        "approved_pqc": [
            "LMS (RFC 8554 / SP 800-208) -- stateful hash-based signatures "
            "long recommended by BSI (TR-02102, TR-03140)",
            "XMSS (RFC 8391 / SP 800-208) -- as above",
            "Current quantum-safe key-agreement and signature "
            "recommendations: see TR-02102-1 itself (this pack does not "
            "transcribe the guideline's algorithm tables)",
        ],
        "position_by_status": {
            "QUANTUM_VULNERABLE": {
                "verdict": "MIGRATE",
                "note": (
                    "Solo classical key establishment is recommended only "
                    "until the end of 2031 (TR-02102-1 section 2.1, quoted "
                    "in TR-02102-2 section 3.1.3), and the DSA "
                    "recommendation is withdrawn from 2029. Hybrid "
                    "operation with quantum-safe procedures is the "
                    "expected mode."
                ),
            },
            "QUANTUM_MARGIN_CRITICAL": {
                "verdict": "REPLACE",
                "note": (
                    "Below BSI's 120-bit security level on classical terms "
                    "(TR-02102-1). A classical weakness, not a quantum one "
                    "-- replace it with a modern cipher."
                ),
            },
            "QUANTUM_IMPACT_ASSESSED": {
                "verdict": "ACCEPTABLE",
                "note": (
                    "The AES and SHA families at their common parameters "
                    "meet or exceed the guideline's 120-bit security "
                    "level. TR-02102-1's parameter tables govern the "
                    "individual case."
                ),
            },
            "PQC": {
                "verdict": "ALIGNED",
                "note": (
                    "A recognised post-quantum family, consistent with "
                    "BSI's direction. BSI points to TR-02102-1 for its "
                    "current quantum-safe recommendations; this pack does "
                    "not transcribe those tables, so confirm the exact "
                    "family and parameter set there. Hybrid usage is not "
                    "observable from source."
                ),
            },
            "UNKNOWN": {
                "verdict": "REVIEW",
                "note": _UNKNOWN_REVIEW_NOTE,
            },
        },
        "algorithm_overrides": [
            {
                "match_any": ["sha-1"],
                "verdict": "REPLACE",
                "note": (
                    "Collision-broken and far below any acceptable "
                    "security level; excluded by BSI's recommendation "
                    "tables. Classical defect."
                ),
            },
            {
                "match_any": ["lms", "xmss"],
                "verdict": "ALIGNED",
                "note": (
                    "Stateful hash-based signature schemes long "
                    "recommended by BSI (TR-02102, TR-03140; RFC 8554/8391, "
                    "NIST SP 800-208), subject to safe state management."
                ),
            },
            {
                "match_any": ["kyber", "dilithium", "sphincs"],
                "verdict": "REVIEW",
                "note": (
                    "Pre-standardisation spelling. The standardised "
                    "families are ML-KEM/ML-DSA/SLH-DSA (FIPS 203/204/205) "
                    "-- confirm what is deployed before counting it."
                ),
            },
            {
                "match_any": ["falcon"],
                "verdict": "REVIEW",
                "note": (
                    "Falcon/FN-DSA was not yet a finalised NIST standard "
                    "as of the pack date (FIPS 206 in preparation); "
                    "confirm current status against TR-02102-1."
                ),
            },
        ],
    },
    # ------------------------------------------------------------------
    # France / ANSSI -- 2022 avis + 2023 follow-up.
    # ------------------------------------------------------------------
    {
        "id": "anssi-pqc-transition",
        "jurisdiction": "France",
        "authority": "ANSSI",
        "document": (
            "Avis scientifique et technique de l'ANSSI sur la migration "
            "vers la cryptographie post-quantique (11 April 2022), with "
            "ANSSI views on the PQC transition -- 2023 follow up "
            "(21 December 2023)"
        ),
        "document_status": "position-paper-final",
        "published": "2022-04-11",
        "source_url": (
            "https://messervices.cyber.gouv.fr/documents-guides/"
            "anssi-avis-migration-vers-la-cryptographie-post-quantique.pdf"
        ),
        "related_sources": [
            ("https://messervices.cyber.gouv.fr/documents-guides/"
             "follow_up_position_paper_on_post_quantum_cryptography.pdf"),
        ],
        "scope": (
            "French national cyber-security agency guidance shaping ANSSI "
            "security visas: a phased transition agenda and a hybridation "
            "recommendation, not a single calendar deadline."
        ),
        "hybrid_position": (
            "ANSSI strongly emphasizes hybridation wherever post-quantum "
            "mitigation is needed in the short and medium term -- "
            "especially products aiming at confidentiality protection "
            "lasting beyond 2030. Hybrid is mandatory for phase-2 visas; "
            "phase 3 (after years of analysis, roughly post-2030) may make "
            "it optional."
        ),
        "key_dates": {
            "phase_2_runs_at_least_until_approx": 2030,
            "phase_3_hybridation_optional_from": "after 2030 (indicative)",
            "first_hybrid_pqc_visa_expected": "2024-2025",
        },
        "approved_pqc": [
            "No closed list published: ANSSI accepts well-studied "
            "candidates subject to its assurance criteria and states "
            "selected algorithms may not exactly match NIST standards "
            "(2022 avis, section 10)",
        ],
        "position_by_status": {
            "QUANTUM_VULNERABLE": {
                "verdict": "MIGRATE",
                "note": (
                    "Hybridate: ANSSI still strongly emphasizes hybridation "
                    "wherever PQC mitigation is needed, short and medium "
                    "term -- particularly for products whose confidentiality "
                    "protection must last beyond 2030 (2022 avis; 2023 "
                    "follow-up). Phase 2 runs at least until around 2030."
                ),
            },
            "QUANTUM_MARGIN_CRITICAL": {
                "verdict": "REPLACE",
                "note": (
                    "Weak on classical terms and far below ANSSI's "
                    "encouraged post-quantum symmetric level of at least "
                    "AES-256 security (2022 avis). Replace the cipher; PQC "
                    "is not the answer for a symmetric primitive."
                ),
            },
            "QUANTUM_IMPACT_ASSESSED": {
                "verdict": "REVIEW",
                "note": (
                    "ANSSI encourages a post-quantum security level on "
                    "symmetric primitives consistent with the selected PQC "
                    "algorithm -- in practice at least AES-256 for block "
                    "ciphers and SHA2-384 for hashes (2022 avis). The "
                    "observed parameters are below or unconfirmable "
                    "against that level; see the parameter overrides."
                ),
            },
            "PQC": {
                "verdict": "ALIGNED",
                "note": (
                    "A recognised post-quantum family. ANSSI publishes no "
                    "closed algorithm list, so this is direction-consistent "
                    "rather than an approved-list membership. Hybridation "
                    "is ANSSI's strongest position and is not observable "
                    "from source."
                ),
            },
            "UNKNOWN": {
                "verdict": "REVIEW",
                "note": _UNKNOWN_REVIEW_NOTE,
            },
        },
        "algorithm_overrides": [
            {
                "match_any": ["sha-1"],
                "verdict": "REPLACE",
                "note": (
                    "Collision-broken and orders of magnitude below "
                    "ANSSI's encouraged SHA2-384-level hash strength. "
                    "Classical defect."
                ),
            },
            {
                "match_any": ["aes-256", "sha-384", "sha-512"],
                "verdict": "ACCEPTABLE",
                "note": (
                    "Meets ANSSI's encouraged post-quantum symmetric "
                    "level: at least AES-256 security for block ciphers, "
                    "at least SHA2-384 for hashes (2022 avis)."
                ),
            },
            {
                "match_any": [
                    "aes", "aes-128", "aes-192",
                    "sha-224", "sha-256",
                ],
                "verdict": "REVIEW",
                "note": (
                    "Below, or unconfirmable against, ANSSI's encouraged "
                    "post-quantum level (at least AES-256 for block "
                    "ciphers, SHA2-384 for hashes). A bare family name "
                    "with no recorded parameter cannot be confirmed at "
                    "all."
                ),
            },
        ],
    },
]

# --------------------------------------------------------------------------
# Scope statement. Published in the artifact so a reader cannot mistake the
# absence of hardware fields for an oversight.
# --------------------------------------------------------------------------
QBOM_SCOPE = (
    "This QBOM is produced by a static source-code analyser. It covers the Table 8 "
    "elements that a source inventory can state and marks the rest as "
    "NOT_OBSERVABLE_FROM_SOURCE with a reason. Elements describing a physical "
    "quantum device -- model, vendor, communication protocol, hardware, energy -- "
    "cannot be observed from source and are emitted as null by design, not by "
    "omission. A consumer should treat this as PARTIAL coverage of Table 8 and "
    "complete it from a device or procurement inventory."
)

QBOM_STATUS = (
    "CERT-In v2.0 Table 8 implementation, partial by construction: 5 of 11 minimum "
    "elements are observable from source and 6 describe physical quantum hardware "
    "that source analysis cannot see."
)

_NAME_RE = re.compile(r"^([A-Za-z0-9._-]+)")


def _component_name(pkg: dict) -> str:
    for key in ("name", "package", "component", "purl_name", "id"):
        v = pkg.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _component_version(pkg: dict) -> str:
    for key in ("version", "resolved_version", "purl_version"):
        v = pkg.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def detect_quantum_components(sbom: list) -> tuple:
    """Return (components, pqc_references).

    DETECTION ONLY. A component is listed because its resolved name in the SBOM
    matched a known quantum SDK or PQC keyword. Nothing is added when nothing
    matches: an empty list with `detected: false` is the correct output for a
    codebase with no quantum dependency, and manufacturing a plausible entry would
    be fabrication.
    """
    found, pqc = [], []
    for pkg in (sbom or []):
        if not isinstance(pkg, dict):
            continue
        name = _component_name(pkg)
        if not name:
            continue
        low = name.lower()
        base = _NAME_RE.match(low)
        base = base.group(1) if base else low
        if base in QUANTUM_SDK_HINTS or any(h in low for h in QUANTUM_SDK_HINTS):
            found.append({"name": name, "version": _component_version(pkg),
                          "ecosystem": pkg.get("ecosystem") or "unknown",
                          "evidence": "name matches a known quantum SDK",
                          "manifest_file": pkg.get("manifest_file") or ""})
        elif any(h in low for h in PQC_HINTS):
            pqc.append({"name": name, "version": _component_version(pkg),
                        "ecosystem": pkg.get("ecosystem") or "unknown",
                        "evidence": "name matches a post-quantum cryptography term",
                        "manifest_file": pkg.get("manifest_file") or ""})
    found.sort(key=lambda x: x["name"].lower())
    pqc.sort(key=lambda x: x["name"].lower())
    return found, pqc


# Assets listed in the Table 8 cryptographic_asset element. A source scan can
# produce thousands; the element carries a bounded, representative set and the
# true counts beside it, so nothing is silently dropped and the artifact stays
# readable.
_MAX_LISTED_ASSETS = 200


def _cryptographic_asset_element(cbom: list, cbom_present: bool) -> dict | None:
    """The Table 8 cryptographic asset element, with real classified data.

    The element is marked OBSERVABLE_FROM_SOURCE, so it always returns a value.
    None is reserved in this schema for elements a source scan cannot see
    (hardware, vendor, device model), and returning None here would collapse
    "we looked at this project and it uses no cryptography" into "we cannot
    tell" -- two very different claims, and conflating them is how an inventory
    manufactures false assurance.

    UNKNOWN assets are counted separately and never folded into a safe bucket. A
    summary reporting zero quantum-vulnerable assets because everything failed to
    classify is the most misleading thing this element could contain.
    """
    if not cbom:
        return {
            "assets": [],
            "total_assets_in_cbom": 0,
            "assets_listed": 0,
            "assets_truncated": 0,
            "by_quantum_status": {},
            "migration_queue": [],
            "classification_coverage": {"classified": 0, "unclassified": 0},
            "observed": True,
            "note": ("This scan found no cryptographic inventory. That is an "
                     "observation about the scanned source, not a statement that "
                     "the deployed system uses no cryptography."),
        }

    from scanner.crypto_quantum_analyzer import (  # local: keeps this module
        correlate_cbom_to_qbom,                    # importable without scanner
        summarize_quantum_exposure,
    )

    correlated = correlate_cbom_to_qbom(cbom)
    summary = summarize_quantum_exposure(correlated)

    by_status: dict[str, list] = {}
    for asset in correlated:
        by_status.setdefault(asset.get("quantum_status", "UNKNOWN"), []).append(asset)

    # Most exposed first, so a truncated list still shows the assets that matter.
    listed = sorted(
        correlated,
        key=lambda a: (
            {"QUANTUM_VULNERABLE": 0, "QUANTUM_MARGIN_CRITICAL": 0, "PQC": 1,
             "QUANTUM_IMPACT_ASSESSED": 2, "UNKNOWN": 3}.get(
                 a.get("quantum_status"), 4),
            str(a.get("algorithm") or ""),
        ),
    )[:_MAX_LISTED_ASSETS]

    return {
        "total_assets_in_cbom": len(cbom),
        "total_usage_sites": summary["total_usage_sites"],
        "distinct_assets": summary["total_assets"],
        "assets_listed": len(listed),
        "assets_truncated": max(0, len(correlated) - len(listed)),
        "aggregation_note": summary.get("aggregation_note"),
        "classification_coverage": {
            "classified": summary["classified"],
            "unclassified": summary["unclassified"],
            "note": summary["coverage_note"],
        },
        "by_quantum_status": summary["by_quantum_status"],
        "migration_queue": summary["migration_queue"],
        "assets": [
            {
                "qbom_id": a.get("qbom_id"),
                "algorithm": a.get("algorithm"),
                "normalized_algorithm": a.get("normalized_algorithm"),
                "algorithm_provenance": a.get("algorithm_provenance"),
                "key_size": a.get("key_size"),
                "library": a.get("library"),
                "occurrence_count": a.get("occurrence_count"),
                "quantum_status": a.get("quantum_status"),
                "quantum_risk": a.get("quantum_risk"),
                "migration_priority": a.get("migration_priority"),
                "classification_note": a.get("classification_note"),
                "confidence": a.get("confidence"),
            }
            for a in listed
        ],
        "table_9_fields": ("Per-asset CERT-In Table 9 minimum elements remain in the "
                           "CBOM artifact; this element is the quantum-facing view."),
        "source": ("Classified from this scan's own CBOM by "
                   "scanner/crypto_quantum_analyzer. No external database consulted."),
    }


def build_qbom(payload: dict) -> dict:
    """Build the QBOM artifact from an existing scan payload.

    Reads only data this scan produced. Every element Table 8 asks for appears in
    the output, carrying either a value or an explicit
    NOT_OBSERVABLE_FROM_SOURCE status with a reason.
    """
    sbom = payload.get("sbom") or []
    cbom_present = bool(payload.get("cbom") or payload.get("cbom_summary"))
    findings = payload.get("findings") or []

    quantum, pqc = detect_quantum_components(sbom)

    # Software dependencies: the SBOM, capped for readability with the true count
    # kept separately so nothing is silently dropped.
    MAX_DEPS = 500
    deps = []
    for pkg in sbom[:MAX_DEPS]:
        if not isinstance(pkg, dict):
            continue
        deps.append({
            "name": _component_name(pkg),
            "version": _component_version(pkg),
            "ecosystem": pkg.get("ecosystem") or "unknown",
            "license": pkg.get("license") or "unknown",
            "direct": bool(pkg.get("direct")),
            "manifest_file": pkg.get("manifest_file") or "",
        })
    licenses = sorted({d["license"] for d in deps if d["license"]})

    # Vulnerabilities: real findings only, summarised by severity with the rules
    # named. Nothing is inferred.
    sev_counts = {}
    rule_ids = set()
    for f in findings:
        if not isinstance(f, dict):
            continue
        s = str(f.get("severity") or "unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        rid = f.get("rule_id") or f.get("vuln_type")
        if rid:
            rule_ids.add(str(rid))

    elements = {}
    for key, spec in QBOM_MINIMUM_ELEMENTS.items():
        if key == "model_name":
            value = None
        elif key == "version":
            value = None
        elif key == "vendor_origin":
            value = None
        elif key == "license_information":
            value = licenses or None
        elif key == "cryptographic_asset":
            # This element used to be a POINTER -- "see the CBOM artifact",
            # `"table": "Table 9"` -- carrying no asset data whatsoever, while
            # being marked OBSERVABLE_FROM_SOURCE. An element that claims
            # observability and then says nothing is worse than one marked
            # not-observable, because a reader counts it as covered.
            #
            # The CBOM entries are classified here: each primitive is resolved to
            # a quantum status by scanner/crypto_quantum_analyzer, which reads the
            # shape cbom.py actually emits and records whether the algorithm was
            # explicit or inferred from a display label.
            #
            # Table 9's per-asset fields remain in the CBOM artifact; this element
            # is the quantum-facing view of the same assets.
            value = _cryptographic_asset_element(payload.get("cbom") or [],
                                                 cbom_present)
        elif key == "communication_protocol":
            value = None
        elif key == "hardware":
            value = None
        elif key == "software_dependencies":
            value = deps or None
        elif key == "environmental_impact":
            value = None
        elif key == "vulnerabilities_information":
            value = {
                "findings_total": len(findings),
                "by_severity": sev_counts,
                "rules_observed": sorted(rule_ids),
                "source": ("Findings of this scan only. No external vulnerability "
                           "database was consulted for this element."),
            }
        elif key == "attestations":
            value = None          # filled in after the digest is computed
        else:
            value = None

        elements[key] = {
            "element": spec["name"],
            "table": spec["table"],
            "description": spec["description"],
            "element_status": OBSERVABLE if spec["observable"] else NOT_OBSERVABLE,
            "scope_note": spec["reason"],
            "value": value,
        }

    doc = {
        "bom_type": "QBOM",
        "bom_type_expansion": "Quantum Bill of Materials",
        "specification": {
            "document": CERTIN_DOCUMENT,
            "version": CERTIN_VERSION,
            "date": CERTIN_DATE,
            "table": "Table 8: Minimum Elements of QBOM & CBOM",
            "minimum_elements": len(QBOM_MINIMUM_ELEMENTS),
            "pdf_sha256": CERTIN_PDF_SHA256,
            "pdf_pages": CERTIN_PDF_PAGES,
            "source_url": CERTIN_SOURCE_URL,
            "license": CERTIN_LICENSE,
            "dataset_label": QBOM_DATASET_LABEL,
        },
        "definition": QBOM_DEFINITION,
        "scope": QBOM_SCOPE,
        "status": QBOM_STATUS,
        "quantum_components_detected": bool(quantum),
        "quantum_components": quantum,
        "post_quantum_references": pqc,
        "element_coverage": {
            "minimum_elements": len(QBOM_MINIMUM_ELEMENTS),
            "observable_from_source": len(QBOM_OBSERVABLE_ELEMENTS),
            "not_observable_from_source": len(QBOM_NOT_OBSERVABLE_ELEMENTS),
            "observable_elements": QBOM_OBSERVABLE_ELEMENTS,
            "not_observable_elements": QBOM_NOT_OBSERVABLE_ELEMENTS,
            "note": ("Coverage is a property of the analyser, not of the scanned "
                     "system. It does not improve when the codebase has more "
                     "quantum code."),
        },
        "minimum_elements": elements,
        "limits": [
            "Partial coverage of Table 8 by construction: 6 of 11 elements describe "
            "physical quantum hardware and cannot be observed from source.",
            ("The Attestations element is a SHA-256 content digest, NOT a digital "
             "signature. No signing key is held."),
            ("No external vulnerability database was consulted for the "
             "Vulnerabilities Information element; it reflects this scan only."),
            ("A Hardware Bill of Materials (Table 11) is a separate artifact and is "
             "NOT implemented. The Hardware element of Table 8 is correspondingly "
             "null."),
            ("A Quantum BOM that lists no quantum components is the correct output "
             "for a codebase with no quantum dependency. No component is ever "
             "synthesised."),
        ],
    }

    # Attestation last: a digest over everything above except itself.
    elements["attestations"]["value"] = _attest(doc)
    return doc


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def _attest(doc: dict) -> dict:
    """SHA-256 over the document, excluding only this element's own value.

    An earlier version stripped the `value` key from EVERY element before
    hashing. That made the digest cover element names, statuses and descriptions
    while covering none of the inventory: software dependencies, licences and
    vulnerability counts could all be altered and the attestation would not move.
    An attestation that does not detect modification of what it attests to is
    decoration, so only the self-referential element is excluded -- it cannot hash
    itself.
    """
    body = {k: v for k, v in doc.items() if k != "minimum_elements"}
    body["minimum_elements"] = {
        k: ({kk: vv for kk, vv in v.items() if kk != "value"}
            if k == "attestations" else v)
        for k, v in doc["minimum_elements"].items()
    }
    digest = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    return {
        "type": "content-digest",
        "algorithm": "SHA-256",
        "digest": digest,
        "covers": ("every field of this document except this attestations element: "
                   "the specification block, scope, status, quantum_components, "
                   "post_quantum_references, element_coverage, limits, and the "
                   "complete value of all 10 other minimum elements"),
        "excluded": ["minimum_elements.attestations.value"],
        "is_digital_signature": False,
        "note": ("This is a content digest, not a signature. It establishes that "
                 "the document has not changed since it was produced, including "
                 "the inventory it records. It does NOT establish authenticity, "
                 "because no signing key is held and no party vouches for the "
                 "contents."),
    }


def qbom_reference() -> dict:
    """Pinned attribution, for the finding-level enrichment path."""
    return {
        "qbom_specification": QBOM_DATASET_LABEL,
        "qbom_table": "Table 8",
        "qbom_minimum_elements": len(QBOM_MINIMUM_ELEMENTS),
        "qbom_pdf_sha256": CERTIN_PDF_SHA256,
        "qbom_source_url": CERTIN_SOURCE_URL,
        "qbom_status": QBOM_STATUS,
    }