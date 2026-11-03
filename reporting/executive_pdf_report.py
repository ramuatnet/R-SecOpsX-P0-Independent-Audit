from __future__ import annotations

from reporting.pdf_report import _pdf_normalize_payload



from reportlab.lib.units import cm

from reportlab.platypus import NextPageTemplate, PageBreak, Paragraph, Spacer, Table, TableStyle



from reporting.pdf_report import (

    _Doc, _cover, _toc_section, _TocBookmark, _exec_summary,

    _top_root_causes_section, _compliance, _conclusion, _resolve_logo_path,

    S, DARK_BLUE, GREY_MED, WHITE, LIGHT_BLUE,

)

# Attack-path records arrive in two shapes; see
# reporting/attack_path_view.py. The executive and technical PDFs both read
# through it so they cannot disagree about which chains are CONFIRMED.
from reporting.attack_path_view import (
    attack_path_views as _apv,
    shape_mix as _ap_mix,
)





def _executive_attack_path_summary(payload: dict) -> list:
    """Executive-level attack-path summary.

    Reports the CONFIRMED / CANDIDATE split explicitly rather than describing
    every path the same way. That distinction is decision-relevant: a confirmed
    path has validated source-to-sink evidence, and a reader who cannot tell the
    two apart will either over-trust the output or dismiss it entirely.
    """
    paths = payload.get("attack_paths") or []
    views = _apv(paths)
    mix = _ap_mix(views)

    story = [Paragraph("Exploit-Chain Summary", S["SubTitle"])]

    if not views:
        story.append(Paragraph(
            "No multi-step attack chains were correlated from this scan. This "
            "means no finding carried a source-to-sink path that the analyser "
            "could resolve; it is NOT a statement that the application has no "
            "exploitable chains, because a source scan cannot establish absence.",
            S["Body"]))
        story.append(Spacer(1, 0.2 * cm))
        return story

    story.append(Paragraph(
        f"{mix['total']} exploit chain"
        f"{'s were' if mix['total'] > 1 else ' was'} correlated from the findings. "
        + (f"{mix['confirmed']} carry validated source-to-sink evidence "
           f"(CONFIRMED). " if mix['confirmed'] else "")
        + (f"{mix['candidate']} are pattern-level candidates requiring manual "
           f"validation. " if mix['candidate'] else "")
        + (f"{mix['no_evidence_state']} carry no recorded evidence state. "
           if mix["no_evidence_state"] else "")
        + "Every chain is enumerated with its full node sequence in the technical "
          "report; this summary states how confident each is.",
        S["Body"]))

    story.append(Spacer(1, 0.2 * cm))

    rows = [["#", "Originating rule", "Evidence state", "Chain (source ... sink)"]]
    for i, v in enumerate(views[:8], 1):
        chain = v.get("chain") or []
        arrow = " -> ".join(chain) if chain else "(no chain recorded)"
        rows.append([
            str(i),
            str(v.get("rule_id") or "-")[:34],
            "CONFIRMED" if v.get("confirmed") else
            ("CANDIDATE" if v.get("status") else "NOT RECORDED"),
            arrow[:78],
        ])

    if len(views) > 8:
        rows.append(["", f"... and {len(views) - 8} more; see the technical report",
                     "", ""])

    data = [[Paragraph(c, S["TH"]) for c in rows[0]]]
    for r in rows[1:]:
        data.append([Paragraph(str(c), S["Cell"] if "Cell" in S else S["BodySmall"])
                     for c in r])

    tbl = Table(data, colWidths=[0.8 * cm, 4.6 * cm, 3.0 * cm, 8.0 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.25, GREY_MED),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 0.2 * cm))

    if mix["confirmed"]:
        story.append(Paragraph(
            "CONFIRMED means the chain's source and sink were both observed in "
            "the finding's own taint path. It does not assert that the chain is "
            "exploitable in a live environment, which is a separate question this "
            "tool does not answer.",
            S["Body"]))
    return story


def _compliance_executive_summary(payload: dict) -> list:

    story = [Paragraph("Compliance Mapping Executive Summary", S["SubTitle"])]

    grouped = payload.get("grouped", []) or []

    framework_keys = [

        ("OWASP Top 10", "owasp"), ("MITRE ATT&CK", "mitre"),

        ("PCI DSS", "pci_dss"), ("NIST 800-53", "nist_800_53"),

        ("ISO 27001", "iso_27001"), ("SOC 2", "soc2"),

    ]

    # The "Observed Mappings" column used to present six numbers in one
    # undifferentiated column. They are two different units:
    #
    #   OWASP / MITRE  -> len(dict) == number of DISTINCT categories/techniques
    #   PCI/NIST/ISO/SOC2 -> number of FINDINGS carrying a non-empty value
    #
    # On the Juice Shop corpus (report 06102026 1914) that renders as
    # OWASP 10, MITRE 7, PCI 90, NIST 90, ISO 90, SOC 90 -- the first two look
    # like coverage and are not, the last four look like near-total coverage and
    # are mostly the generic fallback (80 of 102 findings carry the identical
    # default triple from GENERIC_MAPPING). The unit is now stated per row
    # rather than asserted once in prose. No number is changed here, and no
    # measure is promoted to authoritative: that reconciliation is G-064 and
    # remains open.
    category_unit = "distinct categories observed"
    finding_unit = "findings carrying a mapping"

    rows = [[Paragraph(h, S["TH"]) for h in ["Framework", "Observed Mappings", "Unit"]]]

    for label, key in framework_keys:

        if key in {"owasp", "mitre"}:

            value = payload.get(key, {})

            count = len(value) if isinstance(value, (dict, list)) else 0

            unit = category_unit

        else:

            count = 0

            for f in grouped:

                val = f.get(key)

                if val is None and key == "iso_27001":

                    val = f.get("iso27001")

                if val is None and key == "nist_800_53":

                    val = f.get("nist")

                if val not in (None, "", "Not Applicable", "N/A", "NA"):

                    count += 1

            unit = finding_unit

        rows.append([
            Paragraph(label, S["TD"]),
            Paragraph(str(count), S["TDC"]),
            Paragraph(unit, S["TD"]),
        ])

    t = Table(rows, colWidths=[5*cm, 3*cm, 5*cm], repeatRows=1)

    t.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),DARK_BLUE), ("TEXTCOLOR",(0,0),(-1,0),WHITE),

        ("GRID",(0,0),(-1,-1),0.5,GREY_MED),

        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),

        ("TOPPADDING",(0,0),(-1,-1),4), ("BOTTOMPADDING",(0,0),(-1,-1),4),

        ("FONTSIZE",(0,0),(-1,-1),8),

    ]))

    story += [t, Spacer(1, 0.25*cm), Paragraph(

        "This summary reports mappings present in the canonical scan payload. "

        "It is an assessment mapping view, not a certification or compliance attestation. "

        "The two units in the table are not comparable: OWASP and MITRE ATT&CK count "
        "distinct categories/techniques present in the corpus, while PCI DSS, NIST 800-53, "
        "ISO 27001 and SOC 2 count findings carrying a mapping. In particular, a finding "
        "count of 102 for NIST 800-53 does not mean 102 distinct control decisions were "
        "made: a generic fallback (RA-5 / A.8.8 / CC7.1) is applied to findings with no "
        "finding-specific mapping, which on this corpus is the large majority. "
        "The fallback-stamped and finding-specific populations are counted separately in "
        "clean_report.json under compliance_summary_detail.",

        S["BodySmall"])]

    return story





def _executive_ai_framework_summary(payload: dict) -> list:
    """Headline numbers for the two AI/lifecycle frameworks.

    The full tables are in the Compliance Mapping chapter (shared
    `_compliance`). This block exists because an executive will not read a
    15-row practice table, and because the two headline ratios are easy to
    misread: SSDF's `observed` count is small by design (most practices are
    organisational and cannot be attested by a scanner), and NISTAML's
    observed-class ratio is small because the catalogue is deliberately wider
    than the implemented rules. Both are stated here with that context so the
    numbers are not quoted as scores.
    """
    from collections import Counter

    from reporting.report_mappings import humanize_enum

    story = [Paragraph("AI & Secure-Development Framework Position", S["SubTitle"])]

    rows = [[Paragraph(h, S["TH"]) for h in ["Framework", "Position", "What it does not mean"]]]

    # ---- NIST SSDF -------------------------------------------------------
    align = payload.get("ssdf_alignment") or {}
    if isinstance(align, dict) and align.get("practices"):
        total = align.get("total_practices", 0)
        observed = align.get("observed", 0)
        not_attestable = align.get("not_attestable", 0)
        pos = f"{observed} of {total} practices observed on produced evidence; " \
              f"{align.get('not_observed', 0)} {humanize_enum('NOT_OBSERVED')}; " \
              f"{not_attestable} {humanize_enum('NOT_ATTESTABLE_BY_A_SCANNER')}"
        meaning = ("A low observed count is the expected result. SSDF describes "
                   "organisational and lifecycle practice; a source-code scan cannot "
                   "attest those in either direction, so they are recorded as "
                   "not-attestable rather than as failures.")
    elif isinstance(align, dict) and align.get("status") == "REVIEW_REQUIRED":
        pos = "NOT EVALUATED (alignment error)"
        meaning = f"No practice status is claimed. Reason: {align.get('error')}"
    else:
        pos = "NOT EVALUATED"
        meaning = ("No alignment was produced for this report. This is not a claim "
                   "that zero practices were met.")

    rows.append([
        Paragraph("NIST SSDF (SP 800-218) v1.1", S["TD"]),
        Paragraph(str(pos), S["TDC"]),
        Paragraph(str(meaning), S["TD"]),
    ])

    # ---- NIST AI 100-2e2025 ---------------------------------------------
    contributing = 0
    observed_classes = Counter()
    for f in (payload.get("findings", []) or []):
        if not isinstance(f, dict) or "nistaml_mapping_mode" not in f:
            continue
        contributing += 1
        aid = str(f.get("nistaml_id") or "").strip()
        if aid and str(f.get("nistaml_mapping_mode")) != "UNMAPPED":
            observed_classes[aid] += 1

    try:
        from core.nist_aml_mappings import NISTAML_ATTACKS, NISTAML_DATASET_LABEL

        catalogue = len(NISTAML_ATTACKS)
        dataset = NISTAML_DATASET_LABEL
    except Exception:
        catalogue = 0
        dataset = "NIST AI 100-2e2025"

    if contributing == 0:
        pos = "NOT APPLICABLE -- no AI/LLM findings in this corpus"
        meaning = ("No attack class was observed because nothing was attributed. "
                   "This is an absence of AI findings, not evidence that the "
                   "corpus is free of adversarial-ML risk.")
    else:
        pos = f"{len(observed_classes)} of {catalogue} catalogue attack classes " \
              f"attributed across {contributing} AI finding(s)"
        meaning = ("The catalogue is wider than the implemented rule set by design; "
                   "unreferenced classes are recorded detection gaps in "
                   "gap_register.json (G-088), copied alongside this report, "
                   "not findings.")

    rows.append([
        Paragraph(dataset, S["TD"]),
        Paragraph(str(pos), S["TDC"]),
        Paragraph(str(meaning), S["TD"]),
    ])

    t = Table(rows, colWidths=[4.2 * cm, 4.6 * cm, 8.2 * cm], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.5, GREY_MED),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
    ]))

    story += [t, Spacer(1, 0.25 * cm), Paragraph(
        "Both rows are evidence-alignment positions against a pinned dataset, not "
        "certifications and not attestations of organisational process. Full per-practice "
        "and per-attack-class detail follows in the Compliance Mapping chapter.",
        S["BodySmall"])]

    return story


def _metric(label: str, value) -> list:

    return [Paragraph(str(label), S["TD"]), Paragraph(str(value if value not in (None, "") else "--"), S["TDC"])]





def _dependency_summary(payload: dict) -> list:

    sbom = payload.get("sbom", []) or []

    summary = payload.get("dependency_summary", {}) or {}

    vuln = payload.get("vulnerable_packages", []) or []

    total = summary.get("total_components", len(sbom))

    direct = summary.get("direct_dependencies", sum(1 for x in sbom if x.get("direct") is True))

    transitive = summary.get("transitive_dependencies", sum(1 for x in sbom if x.get("direct") is False))

    vulnerable = summary.get("vulnerable_components", len(vuln))

    cves = summary.get("vulnerability_records", summary.get("cve_count", "--"))

    reachable = summary.get("reachable_components", "--")

    reachable_v = summary.get("reachable_vulnerable_components", "--")

    rows = [[Paragraph(h, S["TH"]) for h in ["SBOM Metric", "Value"]]]

    for label, value in [("Total components", total), ("Direct components", direct),

                         ("Transitive components", transitive), ("Vulnerable components", vulnerable),

                         ("Vulnerability records / CVEs", cves), ("Reachable components", reachable),

                         ("Reachable vulnerable components", reachable_v)]:

        rows.append(_metric(label, value))

    t = Table(rows, colWidths=[9*cm, 4*cm], repeatRows=1)

    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),

        ("TEXTCOLOR",(0,0),(-1,0),WHITE),("GRID",(0,0),(-1,-1),0.5,GREY_MED),

        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),("FONTSIZE",(0,0),(-1,-1),8)]))

    return [Paragraph("SBOM & Dependency Executive Summary", S["SubTitle"]), t,

            Spacer(1, 0.2*cm), Paragraph(

                "Detailed package inventory, advisory records and dependency paths remain in the technical report and Excel workbook.",

                S["BodySmall"])]





def _top_dependency_risks(payload: dict) -> list:

    rows = [[Paragraph(h, S["TH"]) for h in ["Package", "Version", "Severity", "Age", "Reachability", "Fixed In"]]]

    items = []

    for pkg in payload.get("sbom", []) or []:

        for v in pkg.get("vulnerabilities", []) or []:

            items.append((pkg, v))

        if not pkg.get("vulnerabilities") and (pkg.get("cve") or pkg.get("advisory_id")):

            items.append((pkg, pkg))

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}

    items.sort(key=lambda x: (rank.get(str(x[1].get("severity", x[0].get("severity", "unknown"))).lower(), 4),

                              -(x[1].get("vulnerability_age_days", x[0].get("vulnerability_age_days", -1)) or -1)))

    for pkg, v in items[:8]:

        rows.append([Paragraph(str(pkg.get("name", "--")), S["TD"]), Paragraph(str(pkg.get("version", "--")), S["TD"]),

                     Paragraph(str(v.get("severity", pkg.get("severity", "--"))), S["TD"]),

                     Paragraph(str(v.get("vulnerability_age_days", pkg.get("vulnerability_age_days", "--"))), S["TDC"]),

                     Paragraph(str(v.get("reachability", pkg.get("reachability", "--"))), S["TD"]),

                     Paragraph(str(v.get("fixed_in", pkg.get("fixed_in", "--"))), S["TD"])])

    if len(rows) == 1:

        return [Paragraph("Top Dependency Risks", S["SubTitle"]), Paragraph("No package-level vulnerability records were available in the canonical payload.", S["BodySmall"])]

    t = Table(rows, colWidths=[3.2*cm, 2*cm, 1.8*cm, 1.5*cm, 3*cm, 2.2*cm], repeatRows=1)

    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),

        ("GRID",(0,0),(-1,-1),0.5,GREY_MED),("FONTSIZE",(0,0),(-1,-1),7),

        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE])]))

    return [Paragraph("Top Dependency Risks", S["SubTitle"]), t,

            Spacer(1,0.15*cm), Paragraph("Age is taken from the canonical vulnerability-age evidence. Reachability is static evidence and is not runtime exploitability proof.", S["BodySmall"])]





def _iac_summary(payload: dict) -> list:

    iac = payload.get("iac", {}) or {}

    rows = [[Paragraph(h, S["TH"]) for h in ["IaC Area", "Observed Findings"]]]

    for label, keys in [("Kubernetes", ["k8s_findings", "kubernetes_findings"]),

                        ("Terraform", ["tf_findings", "terraform_findings"]),

                        ("Dockerfile", ["docker_findings", "dockerfile_findings"]),

                        ("IaC total", ["iac_findings", "total_findings"])]:

        value = next((iac.get(k) for k in keys if k in iac), None)

        rows.append([Paragraph(label, S["TD"]), Paragraph(str(value if value is not None else "--"), S["TDC"])])

    t = Table(rows, colWidths=[9*cm,4*cm], repeatRows=1)

    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),

        ("GRID",(0,0),(-1,-1),0.5,GREY_MED),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),("FONTSIZE",(0,0),(-1,-1),8)]))

    return [Paragraph("Infrastructure-as-Code Executive Summary", S["SubTitle"]), t]





def _licensing_summary(payload: dict) -> list:

    p = payload.get("license_policy_summary", {}) or {}

    rows = [[Paragraph(h, S["TH"]) for h in ["License Metric", "Value"]]]

    for label, keys in [("Total components", ["total_components", "total_packages"]),

                        ("Unknown licenses", ["unknown_licenses", "unknown"]),

                        ("Legal review required", ["legal_review_required", "review_required"]),

                        ("Notice required", ["notice_required"]),

                        ("Summary status", ["status", "summary_status"])]:

        value = next((p.get(k) for k in keys if k in p), None)

        rows.append([Paragraph(label, S["TD"]), Paragraph(str(value if value is not None else "--"), S["TDC"])])

    t = Table(rows, colWidths=[9*cm,4*cm], repeatRows=1)

    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),

        ("GRID",(0,0),(-1,-1),0.5,GREY_MED),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),("FONTSIZE",(0,0),(-1,-1),8)]))

    return [Paragraph("Licensing Executive Summary", S["SubTitle"]), t,

            Spacer(1,0.15*cm), Paragraph("Unknown-license results are surfaced for review and are not an assertion of licensing infringement. Detailed package/license records remain in the technical report and Excel workbook.", S["BodySmall"])]







def _executive_dependency_summary(payload: dict) -> list:

    rows = [[Paragraph(h, S["TH"]) for h in ["Metric", "Value"]]]

    sbom = payload.get("sbom", []) or []

    rv = payload.get("reachability_vulnerability_summary", {}) or {}

    rows += [

        [Paragraph("SBOM components", S["TD"]), Paragraph(str(len(sbom)), S["TDC"])],

        [Paragraph("Vulnerable components", S["TD"]), Paragraph(str(rv.get("vulnerable_packages", rv.get("vulnerable_components", 0))), S["TDC"])],

        [Paragraph("Reachable vulnerable components", S["TD"]), Paragraph(str(rv.get("reachable_vulnerable", rv.get("reachable_vulnerable_packages", 0))), S["TDC"])],

        [Paragraph("Unknown reachability", S["TD"]), Paragraph(str(rv.get("unknown", rv.get("unknown_reachability", 0))), S["TDC"])],

    ]

    t=Table(rows,colWidths=[10*cm,4*cm],repeatRows=1)

    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),("GRID",(0,0),(-1,-1),0.5,GREY_MED),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),("FONTSIZE",(0,0),(-1,-1),8)]))

    return [Paragraph("SBOM & Dependency Summary", S["SubTitle"]), t, Spacer(1,0.2*cm), Paragraph("Detailed component inventory remains in the technical report and Excel workbook.", S["BodySmall"])]



def _executive_bom_summary(payload: dict) -> list:

    rows=[[Paragraph(h,S["TH"]) for h in ["BOM", "Assets", "Status"]]]

    for label,key in [("CBOM","cbom"),("AI-BOM","aibom"),("ML-BOM","mlbom"),("API-BOM","apibom"),("ABOM","abom")]:

        data=payload.get(key,[]) or []

        rows.append([Paragraph(label,S["TD"]),Paragraph(str(len(data)),S["TDC"]),Paragraph("AVAILABLE" if data else "NO DATA",S["TDC"])])

    t=Table(rows,colWidths=[6*cm,4*cm,4*cm],repeatRows=1)

    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),("GRID",(0,0),(-1,-1),0.5,GREY_MED),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),("FONTSIZE",(0,0),(-1,-1),8)]))

    return [Paragraph("Advanced BOM Summary",S["SubTitle"]),t,Spacer(1,0.2*cm)]



def _executive_iac_summary(payload: dict) -> list:

    m=payload.get("metadata",{}) or {}

    rows=[[Paragraph(h,S["TH"]) for h in ["Area","Findings"]]]

    for label,key in [("Kubernetes","k8s_findings"),("Terraform","tf_findings"),("Dockerfile","docker_findings"),("Total IaC","iac_findings")]:

        rows.append([Paragraph(label,S["TD"]),Paragraph(str(m.get(key,0)),S["TDC"])])

    t=Table(rows,colWidths=[10*cm,4*cm],repeatRows=1)

    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),("GRID",(0,0),(-1,-1),0.5,GREY_MED),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),("FONTSIZE",(0,0),(-1,-1),8)]))

    return [Paragraph("IaC Summary",S["SubTitle"]),t]



def _executive_licensing_summary(payload: dict) -> list:

    story = []

    story.append(Paragraph("Licensing Summary", S["SubTitle"]))

    summary = payload.get("license_policy_summary", {}) or {}



    def metric(*keys):

        for key in keys:

            if key in summary and summary.get(key) is not None:

                return summary.get(key)

        return 0



    decision_counts = summary.get("decision_counts", {}) or {}



    rows = [[Paragraph("Metric", S["TH"]), Paragraph("Value", S["TH"])]]

    rows.append([

        Paragraph("Components", S["TD"]),

        Paragraph(str(metric("total_components", "components_evaluated", "total")), S["TDC"])

    ])

    rows.append([

        Paragraph("Unknown licenses", S["TD"]),

        Paragraph(str(metric("unknown_license_components", "unknown_licenses", "unknown_license_count", "unknown")), S["TDC"])

    ])

    rows.append([

        Paragraph("Policy review required", S["TD"]),

        Paragraph(str(decision_counts.get("REVIEW_REQUIRED", metric("policy_review_required_components", "policy_review_required", "review_required"))), S["TDC"])

    ])

    rows.append([

        Paragraph("Legal review required", S["TD"]),

        Paragraph(str(metric("legal_review_required_components", "legal_review_required", "legal_review")), S["TDC"])

    ])

    rows.append([

        Paragraph("Notice required", S["TD"]),

        Paragraph(str(metric("notice_required_components", "notice_required", "notice")), S["TDC"])

    ])

    rows.append([

        Paragraph("Summary status", S["TD"]),

        Paragraph(str(metric("summary_status", "status") or "NOT_REPORTED"), S["TDC"])

    ])



    t = Table(rows, colWidths=[9*cm, 4*cm], repeatRows=1)

    t.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),DARK_BLUE),

        ("TEXTCOLOR",(0,0),(-1,0),WHITE),

        ("GRID",(0,0),(-1,-1),0.5,GREY_MED),

        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),

        ("TOPPADDING",(0,0),(-1,-1),4),

        ("BOTTOMPADDING",(0,0),(-1,-1),4),

        ("FONTSIZE",(0,0),(-1,-1),8),

    ]))

    story.append(t)

    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(

        "Unknown-license results are surfaced for review and are not an assertion of licensing infringement. "

        "Detailed package/license records remain in the technical report and Excel workbook.",

        S["BodySmall"]))

    return story

def _executive_dependency_risk_table(payload: dict) -> list:

    """Executive-level dependency risk summary; detailed inventory remains technical."""

    story = []

    story.append(Paragraph("Top Dependency Risk Signals", S["SubTitle"]))



    sbom = payload.get("sbom", []) or payload.get("sbom_components", []) or []

    rows = [[

        Paragraph("Package", S["TH"]),

        Paragraph("Version", S["TH"]),

        Paragraph("Severity", S["TH"]),

        Paragraph("Age", S["TH"]),

        Paragraph("Reachability", S["TH"]),

        Paragraph("Fixed In", S["TH"]),

    ]]



    candidates = []

    for item in sbom:

        if not isinstance(item, dict):

            continue

        severity = str(item.get("severity") or item.get("max_severity") or "").strip()

        cves = item.get("cves") or item.get("advisories") or item.get("vulnerabilities") or []

        vulnerable = bool(cves) or severity.lower() in {"critical", "high", "medium"}

        if not vulnerable:

            continue

        age = item.get("vulnerability_age_days")

        if age is None:

            age = item.get("age_days")

        try:

            age_sort = int(age)

        except Exception:

            age_sort = -1

        candidates.append((age_sort, item))



    candidates.sort(key=lambda x: (-x[0], str(x[1].get("package") or x[1].get("name") or "")))



    for _, item in candidates[:8]:

        package = item.get("package") or item.get("name") or ""

        version = item.get("version") or ""

        severity = item.get("severity") or item.get("max_severity") or ""

        age = item.get("vulnerability_age_days")

        if age is None:

            age = item.get("age_days")

        age_text = "--" if age in (None, "") else str(age)

        reachable = item.get("reachable")

        if reachable is None:

            reachable = item.get("reachable_vulnerable")

        reach_text = "Unknown" if reachable is None else ("Yes" if bool(reachable) else "No")

        fixed = item.get("fixed_in") or item.get("fixed_version") or ""

        rows.append([

            Paragraph(str(package), S["TD"]),

            Paragraph(str(version), S["TD"]),

            Paragraph(str(severity), S["TD"]),

            Paragraph(age_text, S["TDC"]),

            Paragraph(reach_text, S["TDC"]),

            Paragraph(str(fixed), S["TD"]),

        ])



    if len(rows) == 1:

        rows.append([

            Paragraph("No vulnerable dependency records", S["TD"]),

            Paragraph("", S["TD"]),

            Paragraph("", S["TD"]),

            Paragraph("--", S["TDC"]),

            Paragraph("Unknown", S["TDC"]),

            Paragraph("", S["TD"]),

        ])



    table = Table(rows, colWidths=[4.2*cm, 2.0*cm, 2.0*cm, 1.5*cm, 2.3*cm, 3.0*cm], repeatRows=1)

    table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),DARK_BLUE),

        ("TEXTCOLOR",(0,0),(-1,0),WHITE),

        ("GRID",(0,0),(-1,-1),0.5,GREY_MED),

        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),

        ("FONTSIZE",(0,0),(-1,-1),7),

        ("TOPPADDING",(0,0),(-1,-1),3),

        ("BOTTOMPADDING",(0,0),(-1,-1),3),

    ]))

    story.append(table)

    story.append(Spacer(1, 0.2*cm))

    story.append(Paragraph(

        "This is an executive-level prioritization view derived from the canonical SBOM payload. "

        "Detailed vulnerability records remain in the technical report and Excel workbook.",

        S["BodySmall"]))

    return story

def _build_executive_story(payload: dict, logo_path: str | None = None,

                           page_map: dict | None = None) -> list:

    story = []

    story.append(NextPageTemplate("Cover"))

    story += _cover(payload, logo_path=logo_path)



    # Visible executive ToC; page numbers are populated by the two-pass generator.

    story += _toc_section(payload, page_map)

    story.append(NextPageTemplate("ExecSummary"))

    story.append(PageBreak())



    story.append(_TocBookmark("Executive Summary"))

    story += _exec_summary(payload)

    story += _executive_attack_path_summary(payload)



    story.append(NextPageTemplate("TopCauses"))

    story.append(PageBreak())

    story.append(_TocBookmark("Top Root Causes"))

    story += _top_root_causes_section(payload)



    story.append(NextPageTemplate("Compliance"))

    story.append(PageBreak())

    story.append(_TocBookmark("Compliance Mapping"))

    story += _compliance_executive_summary(payload)

    story += _executive_ai_framework_summary(payload)

    story += _compliance(payload)



    story.append(NextPageTemplate("SBOM"))

    story.append(PageBreak())

    story.append(_TocBookmark("SBOM & Dependencies"))

    story += _executive_dependency_summary(payload)

    story += _executive_dependency_risk_table(payload)

    story += _executive_iac_summary(payload)

    story += _executive_licensing_summary(payload)



    story.append(NextPageTemplate("Conclusion"))

    story.append(PageBreak())

    story.append(_TocBookmark("Conclusion & Remediation SLA"))

    story += _conclusion(payload)



    return story

def generate_executive_pdf_report(payload: dict, output_path: str,

                                  logo_path: str | None = None) -> str:

    payload = _pdf_normalize_payload(payload)
    """Generate executive PDF with a visible, two-pass populated ToC."""

    path = str(output_path)

    resolved_logo = _resolve_logo_path(path, logo_path)



    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:

        tmp_path = tmp.name



    try:

        probe = _Doc(

            tmp_path,

            leftMargin=1.8*cm,

            rightMargin=1.8*cm,

            topMargin=1.8*cm+1.2*cm,

            bottomMargin=1.8*cm+1.1*cm,

        )

        probe.build(_build_executive_story(

            payload, logo_path=resolved_logo, page_map=None

        ))

        page_map = dict(getattr(probe, "_page_map", {}) or {})

    finally:

        try:

            import os

            os.remove(tmp_path)

        except Exception:

            pass



    doc = _Doc(

        path,

        leftMargin=1.8*cm,

        rightMargin=1.8*cm,

        topMargin=1.8*cm+1.2*cm,

        bottomMargin=1.8*cm+1.1*cm,

    )

    doc.build(_build_executive_story(

        payload, logo_path=resolved_logo, page_map=page_map

    ))

    return path




