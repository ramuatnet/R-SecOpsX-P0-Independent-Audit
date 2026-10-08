"""Mandatory P0 conformance baseline for R-SecOpsX V11.

This module declares the eleven standards that a V11 scan must be able to speak
to, and defines, for each one, the *executable probes* that decide whether the
standard is actually implemented.  Nothing here is a hardcoded boolean: a
standard is VERIFIED only when every required probe passes against the live
source tree (and, where declared, a produced artifact).

Why probes rather than a checklist
----------------------------------
A conformance claim that is written down but not measured is worse than no
claim, because it converts an absence into an assurance. Every probe below is a
pattern that can be run, so the baseline can fail. On the day this module was
written three of the eleven standards verify and eight do not; that is the
honest state and ``analysis/benchmark_conformance_baseline.py`` exits non-zero
because of it. Closing the gap is the point of declaring the baseline.

Probe kinds
-----------
``code``      regex must match in at least one PRODUCTION source file
``artifact``  dotted path must resolve in a produced ``clean_report.json``
``absent``    sentinel: the probe passes only if the pattern does NOT match,
              used to assert a deprecated path was not reintroduced

Only production code counts as evidence: ``tests/``, ``docs/``, ``reports/``
and ``analysis/`` are excluded, because a benchmark or a document is a
measurement of the system, not the system itself.

Standalone sources used
-----------------------
CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM v2.0
  (CERT-In / MeitY, 9 July 2025). Table 5 = 21 minimum SBOM data fields;
  Table 8 = 11 QBOM minimum elements, PARTIAL by construction (6 of 11
  describe physical quantum hardware); Table 9 = per-cryptographic-asset
  elements; Table 10 = 19 minimum AIBOM elements; Table 11 = HBOM. Section 6
  requires VEX and CSAF for vulnerability state.

SANS Critical AI Security Guidelines v1.1 (April 2025, sans-community/ai-
  guidelines, living document). Six control categories: Access Controls, Data
  Protection, Deployment Strategies, Inference Security, Monitoring, GRC. Its
  Table 1 names MITRE ATLAS, OWASP Top 10 for LLM and NIST AI RMF as the
  frameworks an organisation should track alongside it.
  NOTE: the SANS SEC543 course brochure is a PDF that could not be retrieved by
  the tooling available here. No control is claimed on its authority.

RBI FREE-AI Committee Report (13 August 2025): 7 Sutras, 6 pillars, 26
  recommendations. A committee report, not a binding RBI direction.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

BASELINE_ID = "p0-mandatory-baseline"
BASELINE_VERSION = "2026-10-01"

# Directories that count as production implementation.
PRODUCTION_DIRS = ("scanner", "core", "reporting", "config")
PRODUCTION_FILES = ("main.py",)
SOURCE_SUFFIXES = (".py", ".yaml", ".yml", ".json")

EXCLUDED_PARTS = re.compile(
    r"\\(backup|quarantine|dump|Working folder|__pycache__|\.pytest_cache|"
    r"tests|docs|reports|analysis)\\"
)

# The module that DECLARES the probes must never be able to satisfy them.
#
# Every pattern below is written as a literal string inside this file, so a
# naive self-scan matches its own vocabulary: `wstg_referenced` "passes"
# because the word WSTG appears here, and `spdx_export` "passes" because
# "spdx_export" appears here. That is a false positive that would report a
# standard as VERIFIED when the capability is absent -- precisely the
# absence-to-assurance upgrade this project forbids. Excluded by path, with a
# regression test pinning the exclusion.
PROBE_DECLARATION_FILES = ("core/conformance_baseline.py",)


def production_sources(root: Path) -> dict:
    """Every production source file, keyed by repo-relative POSIX path.

    Excludes tests/, docs/, reports/, analysis/ (measurement, not system) and
    :data:`PROBE_DECLARATION_FILES` (self-match).
    """
    out = {}
    for d in PRODUCTION_DIRS:
        base = root / d
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p.suffix not in SOURCE_SUFFIXES:
                continue
            rel = p.relative_to(root).as_posix()
            if rel in PROBE_DECLARATION_FILES:
                continue
            if EXCLUDED_PARTS.search("\\" + rel + "\\"):
                continue
            try:
                out[rel] = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
    for f in PRODUCTION_FILES:
        p = root / f
        if p.exists():
            out[f] = p.read_text(encoding="utf-8", errors="ignore")
    return out


def _probe(name, kind, pattern, description, required=True):
    return {
        "name": name,
        "kind": kind,
        "pattern": pattern,
        "description": description,
        "required": required,
    }


STANDARD_BASELINE = [
    # ------------------------------------------------------------------ CWE
    {
        "key": "CWE",
        "title": "MITRE Common Weakness Enumeration",
        "authority": "MITRE",
        "version": "CWE 4.20",
        "source_url": "https://cwe.mitre.org/data/published/cwe_v4.20.pdf",
        "mandatory_p0": True,
        "probes": [
            _probe("cwe_ids_in_code", "code", r"CWE-\d+",
                   "CWE identifiers are referenced by detection code."),
            _probe("cwe_map_table", "code", r"CWE_MAP|framework_enrichment",
                   "A CWE mapping table exists for rule enrichment."),
            _probe("cwe_on_findings", "artifact", "findings[].cwe",
                   "Produced findings carry a CWE identifier."),
        ],
    },
    # ----------------------------------------------------------------- OWASP
    {
        "key": "OWASP",
        "title": "OWASP Top 10 (Web) and OWASP Top 10 for LLM/GenAI Applications",
        "authority": "OWASP",
        "version": "LLM Top 10 2025 (published) + 2026 (published 2026-08-04)",
        "source_url": "https://genai.owasp.org/llm-top-10/",
        "mandatory_p0": True,
        "probes": [
            _probe("llm_top10_2025_catalogue", "code",
                   r"OWASP_LLM_TOP10_2025",
                   "The published 2025 LLM Top 10 catalogue is pinned in code."),
            _probe("llm_top10_2026_catalogue", "code",
                   r"OWASP_LLM_TOP10_2026",
                   "The published 2026 edition is tracked with an edition suffix."),
            _probe("llm_edition_resolver", "code", r"owasp_llm_reference",
                   "An edition-aware OWASP LLM resolver exists."),
            _probe("owasp_web_categories", "code", r"owasp_top10|A0[0-9]:2021",
                   "OWASP Top 10 web categories are mapped."),
        ],
    },
    # ----------------------------------------------------------- MITRE ATLAS
    {
        "key": "MITRE_ATLAS",
        "title": "MITRE ATLAS (adversary threat landscape for AI systems)",
        "authority": "MITRE",
        "version": "ATLAS release 2026.09 (format-version 6.0.0)",
        "source_url": "https://atlas.mitre.org/",
        "mandatory_p0": True,
        "probes": [
            _probe("atlas_catalogue_pinned", "code",
                   r"ATLAS_RELEASE\s*=|ATLAS_FORMAT_VERSION\s*=",
                   "An ATLAS catalogue exists with a pinned release and format version."),
            _probe("atlas_enrichment_wired", "code", r"enrich_with_atlas",
                   "ATLAS attribution is applied to emitted findings."),
            _probe("atlas_fails_closed", "code", r"ATLAS_MAPPING_MODE_UNMAPPED",
                   "ATLAS attribution fails closed rather than inferring a technique."),
        ],
    },
    # -------------------------------------------------------- MITRE ATT&CK
    {
        "key": "MITRE_ATTACK",
        "title": "MITRE ATT&CK Enterprise",
        "authority": "MITRE",
        "version": "ATT&CK Enterprise 19.2 (pinned in core/attack_mappings.py, bundle SHA-256 recorded there)",
        "source_url": "https://attack.mitre.org/",
        "mandatory_p0": True,
        "probes": [
            _probe("attack_technique_ids", "code", r"\bT\d{4}\b",
                   "ATT&CK technique identifiers are referenced."),
            _probe("attack_dataset_versioned", "code",
                   r"attack_dataset_version|attack_content_version|ATTACK_DATASET_VERSION|ATTACK_VERSION",
                   "The ATT&CK dataset release in use is recorded, so a tactic "
                   "rollup can be reproduced and compared across scans."),
            _probe("attack_bundle_digest_pinned", "code",
                   r"ATTACK_BUNDLE_SHA256",
                   "The ATT&CK STIX bundle the catalogue was generated from is "
                   "pinned by digest, so technique names are traceable to a "
                   "specific release rather than asserted."),
            _probe("attack_no_placeholder_names", "absent", r"Mapped ATT&CK technique",
                   "NEGATIVE guard. The shipped defect was a fallback that rendered "
                   "the literal string 'Mapped ATT&CK technique' as a technique "
                   "description, so T1595 appeared in both PDFs with no name while "
                   "looking like a resolved entry. This probe passes only while that "
                   "string is ABSENT from production source; if it reappears the probe "
                   "fails and the standard drops back to NOT_VERIFIED."),
            _probe("attack_unresolved_fails_closed", "code",
                   r"ATTACK_UNRESOLVED_REASON|CATALOGUE_UNAVAILABLE",
                   "An identifier absent from the pinned dataset resolves to an "
                   "explicit UNRESOLVED state rather than acquiring a plausible name."),
            _probe("attack_tactic_matrix_complete", "artifact", "mitre",
                   "A full tactic matrix with explicit zeros is emitted, not only "
                   "observed tactics."),
        ],
    },
    # ------------------------------------------------------ NIST AI 100-2
    {
        "key": "NIST_AML",
        "title": "NIST AI 100-2 Adversarial Machine Learning taxonomy",
        "authority": "NIST",
        "version": "AI 100-2e2025 (2025-03-24)",
        "source_url": "https://csrc.nist.gov/pubs/ai/100/2/e2025/final",
        "mandatory_p0": True,
        "probes": [
            _probe("nist_ai_100_2_cited", "code",
                   r"NIST\.AI\.100-2e2025|NISTAML\.\d+",
                   "The AML taxonomy is cited and its identifier scheme is used."),
            _probe("nistaml_catalogue_pinned", "code",
                   r"NISTAML_PUBLISHED\s*=|NISTAML_DATASET_LABEL\s*=",
                   "An AML catalogue exists with a pinned document and publication "
                   "date."),
            _probe("nistaml_enrichment_wired", "code", r"enrich_with_nistaml",
                   "AML attack-class attribution is applied to emitted findings."),
            _probe("nistaml_fails_closed", "code",
                   r'"nistaml_mapping_mode": UNMAPPED|nistaml_rationale',
                   "AML attribution fails closed with a recorded reason rather "
                   "than inferring an attack class."),
        ],
    },
    # ----------------------------------------------------------------- ASVS

    {
        "key": "ASVS",
        "title": "OWASP ASVS",
        "authority": "OWASP",
        "version": "4.0.3 (pinned in core/asvs_mappings.py, enumeration SHA-256 recorded there)",
        "source_url": "https://owasp.org/www-project-application-security-verification-standard/",
        "mandatory_p0": True,
        "probes": [
            _probe("asvs_domain_taxonomy", "code", r"ASVS_V4|ASVS_V5",
                   "ASVS domains are used as a coverage taxonomy."),
            _probe("asvs_requirement_ids", "code",
                   r"V[45]\.\d\.\d{1,2}\b(?![\d.])",
                   "ASVS requirement-level identifiers are mapped, so the report "
                   "can state WHICH requirement is unmet, not just which domain."),
            _probe("asvs_version_pinned", "code",
                   r"ASVS_VERSION\s*=\s*[\"']4\.0\.3[\"']",
                   "The ASVS version is pinned to a specific edition rather than "
                   "'latest', because requirement identifiers are renumbered "
                   "between versions."),
            _probe("asvs_dataset_provenance", "code",
                   r"ASVS_CSV_SHA256",
                   "The ASVS enumeration this catalogue was built from is pinned by "
                   "digest, so the table can be traced to a specific dataset."),
            _probe("asvs_ids_version_qualified", "code",
                   r"ASVS-v4\.0\.3-",
                   "Emitted requirement identifiers carry their version, per OWASP's "
                   "own guidance that bare identifiers are ambiguous across versions."),
            _probe("asvs_semantics_declared", "code",
                   r"does NOT mean the requirement is unmet|NOT an ASVS compliance claim",
                   "The mapping is declared as evidence relevance, not as an unmet-"
                   "requirement or compliance claim."),
        ],
    },
    # ----------------------------------------------------------------- WSTG
    {
        "key": "WSTG",
        "title": "OWASP Web Security Testing Guide",
        "authority": "OWASP",
        "version": "v4.2, catalogue pinned by digest in core/wstg_mappings.py",
        "source_url": "https://owasp.org/www-project-web-security-testing-guide/",
        "mandatory_p0": True,
        "probes": [
            _probe("wstg_referenced", "code",
                   r"WSTG|WEB_SECURITY_TESTING_GUIDE|wstg_mappings",
                   "WSTG identifiers or test-case references exist in code."),
            _probe("wstg_test_cases_mapped", "code",
                   r"wstg_case|WSTG-[A-Z]{2,}",
                   "WSTG test cases are mapped to detections."),
            _probe("wstg_catalogue_pinned", "code",
                   r"WSTG_CATALOGUE_SHA256",
                   "The WSTG catalogue is pinned by digest, so a coverage figure "
                   "traces to one specific extraction of the guide rather than "
                   "being asserted."),
            _probe("wstg_is_a_testing_guide", "code",
                   r"NOT a claim that the test was performed|"
                   r"does NOT mean this scan performed that test|"
                   r"does not mean the procedure was performed",
                   "NEGATIVE-facing integrity check. WSTG is a TESTING guide: its "
                   "entries are procedures against a running application. Without "
                   "this disclaimer a report implying 'tested per WSTG' would be a "
                   "false claim, because this tool performs static source analysis."),
            _probe("wstg_static_attestability_declared", "code",
                   r"static_attestable|catalogue_not_static_attestable",
                   "Test cases a source scan cannot discharge -- login attempts, "
                   "timing, session hijacking, DNS takeover -- are declared rather "
                   "than counted as covered. 29 of 97 cases are in that group."),
            _probe("wstg_licence_not_asserted", "code",
                   r"UNVERIFIED - no LICENSE file",
                   "The checkout carries no root LICENSE file, so no licence is "
                   "asserted. Recording UNVERIFIED is honest where asserting "
                   "CC BY-SA (ASVS) or CC BY (SANS) would have been a guess."),
        ],
    },
    # --------------------------------------------------------------- CERT-In
    {
        "key": "CERT_IN",
        "title": "CERT-In Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM",
        "authority": "CERT-In / MeitY (India)",
        "version": "v2.0 (9 July 2025)",
        "source_url": "https://www.cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf",
        "mandatory_p0": True,
        "probes": [
            _probe("certin_vocabulary", "code", r"CERT-?In|CERTIN_",
                   "CERT-In minimum-element vocabulary is present in code."),
            _probe("aibom_minimum_elements", "code",
                   r"out_of_scope_use|intended_use|preprocessing_method|"
                   r"training_config|eval_metrics",
                   "CERT-In Table 10 AIBOM minimum elements (intended and "
                   "out-of-scope usage, preprocessing, training configuration, "
                   "evaluation metrics) are captured."),
            _probe("qbom_emitted", "artifact", "qbom",
                   "A Quantum BOM is emitted (CERT-In Table 8, 11 minimum elements). "
                   "The emitter is PARTIAL BY CONSTRUCTION: 6 of the 11 "
                   "elements describe a physical quantum device that source "
                   "analysis cannot observe. The artifact records each "
                   "element's status and the reason, so partial coverage is "
                   "visible rather than implied. QBOM here is the QUANTUM "
                   "Bill of Materials per Chapter 8.1, not a Quality BOM."),
            _probe("qbom_table8_elements", "code",
                   r"model_name|vendor_origin|communication_protocol|"
                   r"environmental_impact|software_dependencies",
                   "CERT-In Table 8 QBOM minimum elements are enumerated by "
                   "name, and each is marked OBSERVABLE or NOT_OBSERVABLE "
                   "with a reason."),
            _probe("qbom_never_invents_components", "code",
                   r"quantum_components_detected|is_digital_signature",
                   "NEGATIVE-facing integrity check. Quantum components are "
                   "listed only when a resolved SBOM name matches a known "
                   "quantum SDK, and whether detection found anything is "
                   "stated explicitly. A QBOM that always contained an entry "
                   "would be fabricated, since most codebases have no "
                   "quantum dependency. The Attestations element is likewise "
                   "marked as a content digest and not a digital signature."),
                        _probe("hbom_emitted", "artifact", "hbom",
                   "A Hardware BOM is emitted (CERT-In Table 11, recursive). "
                   "DELIBERATELY STILL FAILING. HBOM was deferred by the "
                   "operator, and this probe is left failing rather than "
                   "relaxed: a deferred item must keep the baseline honest, "
                   "so CERT_IN cannot verify while it is outstanding. The "
                   "Table 8 Hardware element is correspondingly null."),
            _probe("csaf_emitted", "code", r"\bCSAF\b|csaf",
                   "CSAF is supported; CERT-In section 6 requires VEX and CSAF for "
                   "vulnerability state, and only VEX is present today."),
        ],
    },
    # -------------------------------------------------------------- RBI/FREE-AI
    {
        "key": "RBI_FREE_AI",
        "title": "RBI FREE-AI Framework (Responsible and Ethical Enablement of AI)",
        "authority": "Reserve Bank of India",
        "version": "Committee report, 13 August 2025 (7 Sutras / 6 pillars / 26 recommendations)",
        "source_url": "https://www.rbi.org.in/Scripts/PublicationReportDetails.aspx?ID=1306",
        "mandatory_p0": True,
        "probes": [
            _probe("freeai_vocabulary", "code", r"FREE-?AI|free_ai",
                   "The FREE-AI framework is referenced by name in code."),
            _probe("freeai_recommendation_ids", "code",
                   r"FREE_AI_REC|free_ai_rec|rec_23|sutra_",
                   "FREE-AI recommendation and Sutra identifiers are carried on "
                   "findings or controls, so compliance is queryable."),
            _probe("freeai_catalogue_complete", "code",
                   r"FREE_AI_RECOMMENDATIONS",
                   "All 26 recommendations of the committee report are catalogued, "
                   "so a coverage statement has a real denominator."),
            _probe("freeai_sutras_complete", "code",
                   r"FREE_AI_SUTRAS",
                   "All 7 Sutras are catalogued alongside the recommendations."),
            _probe("freeai_legal_status_declared", "code",
                   r"NOT a binding RBI direction",
                   "FREE-AI is a committee report, not a binding direction, and the "
                   "code says so where it maps to it."),
            _probe("freeai_not_attestable_declared", "code",
                   r"NOT_ATTESTABLE_BY_A_SCANNER",
                   "The 16 recommendations addressed to regulated entities are "
                   "marked as not attestable by a source scan rather than counted "
                   "as covered."),
        ],
    },
    # ------------------------------------------------------------- NIST SSDF
    {
        "key": "NIST_SSDF",
        "title": "NIST Secure Software Development Framework (SSDF)",
        "authority": "NIST",
        "version": "SP 800-218 v1.1 (2022-02-03)",
        "source_url": "https://csrc.nist.gov/pubs/sp/800/218/final",
        "mandatory_p0": True,
        "probes": [
            _probe("ssdf_referenced", "code", r"\bSSDF\b|800-218|800218",
                   "SP 800-218 is referenced and version-pinned."),
            _probe("ssdf_practice_ids", "code",
                   r"\b(?:PO|PS|PW|RV)\.\d(?:\.\d)?\b",
                   "SSDF practice identifiers are declared in a pinned catalogue."),
            _probe("ssdf_alignment_emitted", "artifact", "ssdf_alignment",
                   "The artifact carries an SSDF evidence-alignment block, so a "
                   "reader can see which practices this scan can and cannot "
                   "speak to."),
            _probe("ssdf_no_per_finding_claim", "code",
                   r"NOT_ATTESTABLE_BY_A_SCANNER",
                   "Organisational practices are explicitly marked as not "
                   "attestable by a scanner rather than claimed."),
        ],
    },
    # ----------------------------------------------------------------- SANS
    {
        "key": "SANS_AI",
        "title": "SANS Critical AI Security Guidelines",
        "authority": "SANS",
        "version": "v1.4 (March 2026), pinned by PDF SHA-256 in core/sans_mappings.py",
        "source_url": "https://www.sans.org/mlp/critical-ai-security-guidelines",
        "mandatory_p0": True,
        "probes": [
            _probe("sans_referenced", "code",
                   r"SANS|sans_ai|SANS_CRITICAL_AI|sans_mappings",
                   "The SANS Critical AI Security Guidelines are referenced."),
            _probe("sans_control_categories", "code",
                   r"Protecting Augmentation Data|Employ the Principle of Focused "
                   r"Functionality|Protect Your Model Parameters|"
                   r"augmentation_data_protection|focused_functionality|"
                   r"model_integrity_baseline|sans_ai_guideline",
                   "SANS control categories are detectable. The first three "
                   "alternatives are the control names as they appear in v1.4; the "
                   "remainder are the v1.1-era tokens the original probe used."),
            _probe("sans_input_segregation", "code",
                   r"input segregation|segregation is critical",
                   "Input segregation is called out explicitly in v1.4 under Model "
                   "I/O Handling: 'In multiuser environments or applications where "
                   "prompts are composed from multiple sources, input segregation is "
                   "critical.'"),
            _probe("sans_evasion_modalities", "code",
                   r"prompt_encoding_evasion|multilingual_jailbreak|"
                   r"[Gg]uardrail_bypass_encoding|[Cc]ompression_evasion|"
                   r"GUARDRAIL_BYPASS_ENCODING|COMPRESSION_EVASION",
                   "SANS inference-security concerns that extend beyond plain text "
                   "are detected AS SUCH (multilingual, base64/hex/morse and "
                   "compression evasion of guardrails). A bare `base64` reference "
                   "is deliberately NOT accepted: it appears in unrelated code and "
                   "would be a false positive."),
            _probe("sans_catalogue_complete", "code",
                   r"SANS_CONTROLS",
                   "The named controls are catalogued across all 8 v1.4 control "
                   "categories, so a coverage figure has a real denominator."),
            _probe("sans_ids_locally_assigned", "code",
                   r"LOCALLY ASSIGNED BY THIS PROJECT",
                   "NEGATIVE-facing integrity check. The guidelines NUMBER NOTHING, "
                   "so every control id here is a locally assigned convenience "
                   "handle. The module must say so, or a reader would assume SANS "
                   "issued identifiers it never issued."),
            _probe("sans_not_attestable_declared", "code",
                   r"NOT_ATTESTABLE_BY_A_SCANNER",
                   "Controls about governance, hosting and oversight are marked as "
                   "not attestable by a source scan rather than counted as covered."),
        ],
    },
    # ------------------------------------------------------- supply chain
    {
        "key": "SUPPLY_CHAIN",
        "title": "Supply-chain standards (CycloneDX, SPDX, VEX, CSAF, SLSA)",
        "authority": "OWASP / Linux Foundation / OASIS / SLSA",
        "version": "CycloneDX + VEX + SPDX implemented; CSAF / SLSA absent",
        "source_url": "https://cyclonedx.org/",
        "mandatory_p0": True,
        "probes": [
            _probe("cyclonedx_export", "code", r"cyclonedx_export|Security_CycloneDX",
                   "CycloneDX is emitted."),
            _probe("vex_export", "code", r"vex_export|Security_Report\.vex",
                   "VEX is emitted (CERT-In section 6 vulnerability state)."),
            _probe("spdx_export", "code", r"spdx_export|\.spdx|Security_SPDX",
                   "SPDX 2.3 is emitted alongside CycloneDX, so a consumer that "
                   "ingests SPDX is not forced onto CycloneDX alone."),
            _probe("spdx_version_pinned", "code",
                   r"SPDX_VERSION\s*=\s*[\"']SPDX-2\.3[\"']",
                   "The SPDX document version is pinned to 2.3 rather than "
                   "'latest'; the JSON schema forbids vendor extensions and "
                   "renumbers between editions."),
            _probe("spdx_data_license_cc0", "code",
                   r"SPDX_DATA_LICENSE\s*=\s*[\"']CC0-1\.0[\"']",
                   "dataLicense is CC0-1.0 as the SPDX specification requires; it "
                   "is not configurable."),
            _probe("spdx_validated_before_write", "code",
                   r"validate_spdx|SPDX validation failed",
                   "The document is structurally validated against the SPDX 2.3 "
                   "rules before it is written, so an invalid document is "
                   "refused rather than shipped."),
            _probe("slsa_provenance", "code", r"\bSLSA\b|slsa_provenance|in_toto|intoto",
                   "SLSA provenance or in-toto attestations are produced."),
        ],
    },
]


def _artifact_get(artifact, dotted):
    """Resolve a dotted path against the artifact; ``[]`` means any list index."""
    cur = artifact
    for part in re.split(r"\.(?![^\[]*\])", dotted):
        m = re.match(r"^(\w+)\[\]$", part)
        if m:
            key = m.group(1)
            if not isinstance(cur, dict) or key not in cur:
                return False, "key %r absent" % key
            cur = cur[key]
            if not isinstance(cur, list):
                return False, "%r is not a list" % key
            return True, "%d items" % len(cur)
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        elif isinstance(cur, list) and cur:
            cur = cur[0]
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return False, "no item field %r" % part
        else:
            return False, "path %r unresolved" % part
    return (cur is not None), type(cur).__name__


def evaluate_baseline(root: Path, artifact=None) -> dict:
    """Run every probe.  Returns a per-standard result set.

    A standard is VERIFIED only when every REQUIRED probe passes. Probes marked
    ``required=False`` are reported for information and never block.
    """
    root = Path(root)
    sources = production_sources(root)
    joined = "\n".join(sources.values())
    per_file = {rel: text for rel, text in sources.items()}

    results = []
    for std in STANDARD_BASELINE:
        probes = []
        for pr in std["probes"]:
            if pr["kind"] == "code":
                rx = re.compile(pr["pattern"], re.I)
                matched = sorted(rel for rel, t in per_file.items() if rx.search(t))
                if matched:
                    ok, detail = True, "matched in %s" % ", ".join(matched[:3])
                else:
                    ok, detail = False, "no production source matches"
            elif pr["kind"] == "absent":
                rx = re.compile(pr["pattern"], re.I)
                ok = not rx.search(joined)
                detail = "absent as required" if ok else "pattern present"
            else:  # artifact
                if artifact is None:
                    ok, detail = False, "no artifact supplied to probe"
                else:
                    ok, detail = _artifact_get(artifact, pr["pattern"])
            probes.append({
                "name": pr["name"],
                "kind": pr["kind"],
                "required": pr["required"],
                "status": "PASS" if ok else "FAIL",
                "detail": detail,
                "description": pr["description"],
            })

        required = [p for p in probes if p["required"]]
        failed = [p for p in required if p["status"] == "FAIL"]
        results.append({
            "key": std["key"],
            "title": std["title"],
            "authority": std["authority"],
            "version": std["version"],
            "source_url": std["source_url"],
            "mandatory_p0": std["mandatory_p0"],
            "status": "VERIFIED" if not failed else "NOT_VERIFIED",
            "required_probes": len(required),
            "required_failed": len(failed),
            "failed_probes": [p["name"] for p in failed],
            "probes": probes,
        })

    mandatory = [r for r in results if r["mandatory_p0"]]
    verified = [r for r in mandatory if r["status"] == "VERIFIED"]
    return {
        "baseline_id": BASELINE_ID,
        "baseline_version": BASELINE_VERSION,
        "standards": results,
        "mandatory_total": len(mandatory),
        "mandatory_verified": len(verified),
        "mandatory_not_verified": len(mandatory) - len(verified),
        "verified_keys": [r["key"] for r in verified],
        "not_verified_keys": [r["key"] for r in mandatory if r["status"] != "VERIFIED"],
        "coverage_ratio": (len(verified) / len(mandatory)) if mandatory else 0.0,
        "production_source_files": len(sources),
        "artifact_supplied": artifact is not None,
    }


def load_artifact(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))