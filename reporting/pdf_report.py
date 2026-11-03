"""


reporting/pdf_report.py  v2


Big4-style PDF with:


  - Redesigned navy/gold cover (logo support)


  - Full compliance table (PCI DSS, NIST, ISO 27001, SOC2)


  - Attack path section with chain diagrams


  - Per-finding risk score + affected files


  - Enhanced SBOM with EPSS + reachability


"""


from __future__ import annotations


import html





import io, os, re


from datetime import datetime, timezone


from core.config import TOOL_NAME, TOOL_FULL, CLASSIFICATION
from core import report_aggregates, value_state


from pathlib import Path


from reporting.report_mappings import clean_mojibake, format_attack_path_label, format_cvss_assessment, normalize_report_insights, humanize_enum, pkg_has_advisory, sbom_display_sort_key, license_sort_key
# Attack-path records come in two shapes: the current one from
# core/attack_graph.py (path/source/sink/attack_path_status) and the legacy
# one still present in three corpus artifacts (steps/narrative/risk_score/
# evidence_type). Rendering read only the legacy shape and formatted defaults
# for the rest, producing empty chains, "Risk: 0", and -- worst -- labelling
# taint-confirmed paths PATTERN-ONLY.
from reporting.attack_path_view import (
    attack_path_views as _apv,
    introduction as _ap_intro,
    evidence_label as _ap_ev,
    shape_mix as _ap_mix,
)


from analysis.intelligence_provenance import note_from_payload, provenance_pair





os.environ.setdefault("MPLBACKEND","Agg")


import matplotlib; matplotlib.use("Agg")


import matplotlib.pyplot as plt





from reportlab.lib import colors


from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY


from reportlab.lib.pagesizes import A4


from reportlab.lib.styles import ParagraphStyle


from reportlab.lib.units import cm


from reportlab.platypus import (


    BaseDocTemplate, Frame, PageTemplate, NextPageTemplate,


    Paragraph, Spacer, Table, TableStyle, PageBreak, CondPageBreak,


    HRFlowable, Image, KeepTogether,


)





NAVY       = colors.HexColor("#0D1B2A")


DARK_BLUE  = colors.HexColor("#1B3A5C")


MID_BLUE   = colors.HexColor("#2563A8")


ELECTRIC   = colors.HexColor("#00A8E8")


GOLD       = colors.HexColor("#C9A84C")


LIGHT_BLUE = colors.HexColor("#D6E8F7")


RED        = colors.HexColor("#C0392B")


ORANGE     = colors.HexColor("#E67E22")


YELLOW     = colors.HexColor("#F1C40F")


GREEN      = colors.HexColor("#27AE60")


GREY_LIGHT = colors.HexColor("#F4F6F8")


GREY_MED   = colors.HexColor("#D5D8DC")


WHITE      = colors.white


BLACK      = colors.HexColor("#1A1A2E")


PAGE_W, PAGE_H = A4


MARGIN = 1.8*cm


SEV_C  = {"Critical":RED,"High":ORANGE,"Medium":YELLOW,"Low":GREEN,


           "Info":colors.HexColor("#7F8C8D")}









_RSECOPSX_MOJIBAKE_MARKERS = ("A", "a")


def _rsecopsx_mojibake_score(value: str) -> int:
    score = 0
    for marker in (
        "\u00c3", "\u00c2", "\u00e2", "\u00f0", "\ufffd"
    ):
        score += value.count(marker)
    return score


def _pdf_normalize_text(value) -> str:
    if value is None:
        return ""

    text = str(value).replace("\xa0", " ")

    # Recover UTF-8 text that was decoded incorrectly through cp1252/latin1.
    for _ in range(3):
        before = text
        candidates = []

        try:
            candidates.append(
                text.encode("cp1252").decode("utf-8")
            )
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

        try:
            candidates.append(
                text.encode("latin1").decode("utf-8")
            )
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

        improved = [
            candidate
            for candidate in candidates
            if _rsecopsx_mojibake_score(candidate)
            < _rsecopsx_mojibake_score(text)
        ]

        if improved:
            text = min(
                improved,
                key=_rsecopsx_mojibake_score
            )

        if text == before:
            break

    # Explicit mojibake sequences expressed entirely with ASCII escapes.
    residual = {
        "\u00e2\u20ac\u201d": "-",
        "\u00e2\u20ac\u201c": "-",
        "\u00e2\u20ac\u02dc": "'",
        "\u00e2\u20ac\u2122": "'",
        "\u00e2\u20ac\u0153": '"',
        "\u00e2\u20ac\u009d": '"',
        "\u00e2\u20ac\u00a6": "...",
        "\u00e2\u2020\u2019": "->",
        "\u00e2\u2021\u2019": "=>",
        "\u00e2\u0153\u2013": "*",
        "\u00e2\u0161": "[!]",
    }

    for bad, good in residual.items():
        text = text.replace(bad, good)

    # Stable PDF-safe Unicode substitutions.
    replacements = {
        "\u2014": "-",
        "\u2013": "-",
        "\u2012": "-",
        "\u2011": "-",
        "\u2212": "-",
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2026": "...",
        "\u2192": "->",
        "\u2190": "<-",
        "\u21d2": "=>",
        "\u21d0": "<=",
        "\u2713": "[OK]",
        "\u2714": "[OK]",
        "\u2715": "[X]",
        "\u2716": "[X]",
        "[!]": "[!]",
        "\u2726": "*",
        "\u2022": "*",
        # Symbols with no glyph in the report fonts print as a black box.
        "\u26a1": "*",
        "\u25a0": "*",
    }

    for bad, good in replacements.items():
        text = text.replace(bad, good)

    # Nothing unprintable may reach the page.  The C0 controls, DEL and the C1
    # range (U+0080-U+009F) have no glyph in the report fonts, so they print
    # as a black box - one stray U+009D produced three of them in the shipped
    # report.  \n, \t and \r are kept so deliberate line breaks survive.
    #
    # This runs LAST, after `residual` above, because that table matches
    # mojibake sequences that CONTAIN U+009D (the `" entry) and needs the
    # control byte intact to recognise them; removing it first would leave
    # those sequences half-decoded and visible on the page.
    text = "".join(
        ch for ch in text
        if ch in "\n\t\r"
        or not (ord(ch) < 0x20 or ord(ch) == 0x7F or 0x80 <= ord(ch) <= 0x9F)
    )

    return text


def _pdf_normalize_payload(value):
    if isinstance(value, dict):
        return {
            key: _pdf_normalize_payload(item)
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _pdf_normalize_payload(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            _pdf_normalize_payload(item)
            for item in value
        )

    if isinstance(value, str):
        return _pdf_normalize_text(value)

    return value

def _s(n,**k): return ParagraphStyle(name=n,**k)





#Large-text safety helpers 

# ReportLab cannot split an individual Table row.  Large/minified source,


# evidence, descriptions, or file lists must therefore be emitted as multiple


# bounded rows/flowables rather than one giant Paragraph.


def _safe_text(value) -> str:


    if value is None:


        return ""


    return str(value).replace("\r\n", "\n").replace("\r", "\n")





def _chunk_text(value, max_chars=1800) -> list[str]:


    text = _safe_text(value)


    if not text:


        return [""]


    chunks = []


    for line in text.split("\n"):


        if not line:


            chunks.append("")


            continue


        # Preserve line boundaries where possible, but hard-split minified or


        # otherwise unbroken source so no single Paragraph becomes enormous.


        while len(line) > max_chars:


            cut = line.rfind(" ", 0, max_chars)


            if cut < max_chars // 2:


                cut = max_chars


            chunks.append(line[:cut])


            line = line[cut:]


        chunks.append(line)


    return chunks or [""]





def _escaped_chunks(value, max_chars=1800) -> list[str]:


    """Clean encoding and preserve only intentional ReportLab inline tags."""


    allowed = {"<b>": "\x00B\x00", "</b>": "\x00/b\x00",


               "<i>": "\x00I\x00", "</i>": "\x00/i\x00",


               "<br>": "\x00BR\x00", "<br/>": "\x00BR\x00", "<br />": "\x00BR\x00"}


    out = []


    for c in _chunk_text(clean_mojibake(value), max_chars):


        for tag, token in allowed.items():


            c = c.replace(tag, token)


        c = c.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


        c = (c.replace("\x00B\x00", "<b>").replace("\x00/b\x00", "</b>")


               .replace("\x00I\x00", "<i>").replace("\x00/i\x00", "</i>")


               .replace("\x00BR\x00", "<br/>") )


        out.append(c)


    return out





def _ap_clean_text(value):
    """Clean mojibake at the render boundary.

    Source literals are fixed at source, but anything reaching a flowable
    from a manifest, a finding, or a dependency name has travelled an unknown
    number of encodings. Cleaning here means a round trip is repaired before
    a reader sees it, not discovered afterwards. Safe on clean text: the
    decoder only accepts a decode that strictly reduces the signature count.
    """
    from reporting.report_mappings import clean_mojibake as _cm
    return _cm(value)


def _paragraph_chunks(value, style, max_chars=1800) -> list:


    # Cleaned at this boundary on purpose. Source literals are already clean, but
    # prose here originates from manifests, findings and dependency names that have
    # travelled an unknown number of encodings, and a round trip is far cheaper to
    # repair here than to diagnose from a finished PDF. Safe on clean text:
    # clean_mojibake only accepts a decode that strictly reduces its signature
    # count, so legitimate non-ASCII such as an accented filename is untouched.
    return [Paragraph(c or "&nbsp;", style)
            for c in _escaped_chunks(_ap_clean_text(value), max_chars)]





S = {


    "SectionTitle":_s("SectionTitle",fontName="Helvetica-Bold",fontSize=14,


                       textColor=DARK_BLUE,spaceBefore=14,spaceAfter=6,leading=18),


    "SubTitle":    _s("SubTitle",fontName="Helvetica-Bold",fontSize=11,


                       textColor=MID_BLUE,spaceBefore=8,spaceAfter=4,leading=14),


    "Body":        _s("Body",fontName="Helvetica",fontSize=9,textColor=BLACK,


                       alignment=TA_JUSTIFY,spaceAfter=4,leading=13),


    "BodySmall":   _s("BodySmall",fontName="Helvetica",fontSize=8,


                       textColor=BLACK,spaceAfter=2,leading=11),


    "Bullet":      _s("Bullet",fontName="Helvetica",fontSize=9,textColor=BLACK,


                       leftIndent=14,spaceAfter=3,leading=13),


    "Code":        _s("Code",fontName="Courier",fontSize=8,


                       textColor=colors.HexColor("#1a1a2e"),


                       backColor=GREY_LIGHT,spaceAfter=4,leading=11,


                       borderPad=4,leftIndent=8),


    "TH":          _s("TH",fontName="Helvetica-Bold",fontSize=8,


                       textColor=WHITE,alignment=TA_CENTER),


    "TD":          _s("TD",fontName="Helvetica",fontSize=8,


                       textColor=BLACK,alignment=TA_LEFT,leading=11),


    "TDC":         _s("TDC",fontName="Helvetica",fontSize=8,


                       textColor=BLACK,alignment=TA_CENTER,leading=11),


    "TDSm":        _s("TDSm",fontName="Helvetica",fontSize=7,


                       textColor=BLACK,alignment=TA_LEFT,leading=10),


    "AF":          _s("AF",fontName="Courier",fontSize=7,


                       textColor=MID_BLUE,leading=10,spaceAfter=1),


    "Chain":       _s("Chain",fontName="Helvetica",fontSize=8,


                       textColor=DARK_BLUE,leading=12),


}





# Charts 



def _pie(dist):


    cmap={"Critical":"#C0392B","High":"#E67E22","Medium":"#F1C40F",


          "Low":"#27AE60","Info":"#7F8C8D"}


    sizes,labels,clrs=[],[],[]


    for sev in ["Critical","High","Medium","Low","Info"]:


        n=dist.get(sev,0)


        if n:


            labels.append(f"{sev}\n({n})"); sizes.append(n); clrs.append(cmap[sev])


    if not sizes:


        sizes,labels,clrs=[1],["No Findings"],["#27AE60"]


    fig,ax=plt.subplots(figsize=(4.5,3.2),dpi=130)


    _,_,auts=ax.pie(sizes,labels=labels,colors=clrs,autopct="%1.0f%%",startangle=140,


                    wedgeprops=dict(width=0.55,edgecolor="white",linewidth=1.5),


                    textprops={"fontsize":7})


    for a in auts: a.set_fontsize(6);a.set_color("white");a.set_fontweight("bold")


    ax.set_title("Severity Distribution",fontsize=9,fontweight="bold",color="#0D1B2A",pad=10)


    fig.patch.set_facecolor("#F4F6F8"); ax.set_facecolor("#F4F6F8")


    buf=io.BytesIO(); plt.savefig(buf,format="png",bbox_inches="tight",facecolor="#F4F6F8")


    plt.close(fig); buf.seek(0); return buf.read()








def _bar(dist):


    sevs=["Critical","High","Medium","Low","Info"]


    cnts=[dist.get(s,0) for s in sevs]


    clrs=["#C0392B","#E67E22","#F1C40F","#27AE60","#7F8C8D"]


    fig,ax=plt.subplots(figsize=(5.5,2.8),dpi=130)


    bars=ax.bar(sevs,cnts,color=clrs,edgecolor="white",linewidth=0.8,width=0.55)


    for bar,cnt in zip(bars,cnts):


        if cnt:


            ax.text(bar.get_x()+bar.get_width()/2,bar.get_height()+0.05,


                    str(cnt),ha="center",va="bottom",fontsize=9,fontweight="bold",color="#0D1B2A")


    ax.set_ylabel("Count",fontsize=8,color="#0D1B2A")


    ax.set_title("Findings by Severity",fontsize=9,fontweight="bold",color="#0D1B2A")


    ax.tick_params(axis="both",labelsize=7)


    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)


    ax.set_facecolor("#F4F6F8"); fig.patch.set_facecolor("#F4F6F8")


    ax.yaxis.grid(True,alpha=0.4,linestyle="--"); ax.set_axisbelow(True)


    buf=io.BytesIO(); plt.savefig(buf,format="png",bbox_inches="tight",facecolor="#F4F6F8")


    plt.close(fig); buf.seek(0); return buf.read()





# Page template 




# PATCH 8: Section-aware page header 

# Each PageTemplate can carry a custom section label for the running header.


_CURRENT_SECTION = {"label": ""}  # mutable container updated per-section








class _SectionTemplate(PageTemplate):


    """PageTemplate that stamps the current section name into the header."""


    def __init__(self, section_label, *args, **kwargs):


        self.section_label = section_label


        super().__init__(*args, **kwargs)





    def beforeDrawPage(self, canvas, doc):


        _CURRENT_SECTION["label"] = self.section_label








class _Doc(BaseDocTemplate):


    def __init__(self, filename, **kw):


        super().__init__(filename, pagesize=A4, **kw)


        content = Frame(MARGIN, MARGIN+1.2*cm, PAGE_W-2*MARGIN,


                        PAGE_H-2*MARGIN-2.2*cm, id="content")


        cover   = Frame(0, 0, PAGE_W, PAGE_H, id="cover")


        self.addPageTemplates([


            PageTemplate(id="Cover",   frames=[cover],   onPage=_noop),


            # PATCH 8: one template per major section for dynamic header labels


            _SectionTemplate("Executive Summary",


                id="ExecSummary",   frames=[content], onPage=_hf),


            _SectionTemplate("Top Root Causes",


                id="TopCauses",     frames=[content], onPage=_hf),


            _SectionTemplate("Compliance Mapping",


                id="Compliance",    frames=[content], onPage=_hf),


            _SectionTemplate("Attack Path Correlation",


                id="AttackPaths",   frames=[content], onPage=_hf),


            _SectionTemplate("Detailed Findings",


                id="Findings",      frames=[content], onPage=_hf),


            _SectionTemplate("SBOM & Dependencies",


                id="SBOM",          frames=[content], onPage=_hf),


            _SectionTemplate("CBOM",


                id="CBOM",          frames=[content], onPage=_hf),


            _SectionTemplate("AI-BOM",


                id="AIBOM",         frames=[content], onPage=_hf),


            _SectionTemplate("ML-BOM",


                id="MLBOM",         frames=[content], onPage=_hf),


            _SectionTemplate("API-BOM",


                id="APIBOM",        frames=[content], onPage=_hf),


            _SectionTemplate("ABOM",


                id="ABOM",          frames=[content], onPage=_hf),


            _SectionTemplate("Conclusion",


                id="Conclusion",    frames=[content], onPage=_hf),


            # Generic fallback


            _SectionTemplate("Security Assessment Report",


                id="Content",       frames=[content], onPage=_hf),


        ])


        # PATCH 9: enable automatic page number tracking for ToC


        self._page_map: dict[str, int] = {}





    def afterFlowable(self, flowable):


        """Record section page number for Table of Contents."""


        if hasattr(flowable, "_toc_bookmark"):


            self._page_map[flowable._toc_bookmark] = self.page








def _noop(c, d): pass








def _hf(canvas, doc):


    """PATCH 7+8+10: header with section name + footer with confidential notice."""


    canvas.saveState()


    w, h = A4


    section = _CURRENT_SECTION.get("label", "")


    tool    = TOOL_FULL





    #  Top header bar 

    canvas.setFillColor(NAVY)


    canvas.rect(0, h-1.3*cm, w, 1.3*cm, fill=1, stroke=0)


    canvas.setFillColor(GOLD)


    canvas.rect(0, h-1.35*cm, w, 0.05*cm, fill=1, stroke=0)


    canvas.setFillColor(WHITE)


    # Left: "CONFIDENTIAL  |  <Section Name>"


    canvas.setFont("Helvetica-Bold", 7.5)


    canvas.drawString(MARGIN, h-0.58*cm, "CONFIDENTIAL")


    canvas.setFont("Helvetica", 7.5)


    if section:


        canvas.drawString(MARGIN+2.3*cm, h-0.58*cm, f"|  {section}")


    # Right: document title.  The page number is printed by the bottom footer
    # only -- repeating it here put two page numbers on every page (audit L1).


    canvas.setFont("Helvetica", 7)


    canvas.drawRightString(w-MARGIN, h-0.58*cm, "Security Assessment Report")


    # PATCH 10: thin gold separator


    canvas.setFillColor(GOLD)


    canvas.rect(0, h-1.35*cm, w, 0.04*cm, fill=1, stroke=0)





    #  Bottom footer bar (PATCH 10)

    canvas.setFillColor(NAVY)


    canvas.rect(0, 0, w, 1.1*cm, fill=1, stroke=0)


    canvas.setFillColor(GOLD)


    canvas.rect(0, 1.05*cm, w, 0.05*cm, fill=1, stroke=0)


    canvas.setFillColor(WHITE)


    canvas.setFont("Helvetica", 7)


    canvas.drawString(MARGIN, 0.38*cm,


                      f"Generated by {TOOL_FULL}  |  "


                      f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")


    canvas.drawRightString(w-MARGIN, 0.38*cm, f"Page {doc.page}")


    canvas.restoreState()










class _TocBookmark(Spacer):


    """Zero-height spacer that records its section name when rendered."""


    def __init__(self, name: str):


        super().__init__(0, 0)


        self._toc_bookmark = name








def _toc_section(payload: dict, page_map: dict | None = None) -> list:


    """Render the main-report ToC, including advanced BOM sections."""


    sections = [


        ("1.", "Executive Summary"),


        ("2.", "Top Root Causes"),


        ("3.", "Compliance Mapping"),


        ("4.", "Attack Path Correlation"),


        ("5.", "Detailed Findings"),


        ("6.", "SBOM & Dependencies"),


        ("7.", "CBOM - Cryptographic Bill of Materials"),


        ("8.", "AI-BOM - AI Model and Provider Inventory"),


        ("9.", "ML-BOM - ML Framework and Model Inventory"),


        ("10.", "API-BOM - API Route Inventory"),


        ("11.", "ABOM - AI Agent Inventory"),


        ("12.", "Conclusion & Remediation SLA"),


    ]


    pm = page_map or {}


    story = [


        Paragraph("Table of Contents", S["SectionTitle"]),


        HRFlowable(width="100%", thickness=2, color=DARK_BLUE, spaceAfter=8),


        Spacer(1, 0.3*cm),


    ]


    rows = []


    for num, title in sections:


        page_num = pm.get(title, "--")


        rows.append([


            Paragraph("<b>%s</b>" % num, S["TD"]),


            Paragraph(title, S["TD"]),


            Paragraph("." * 24, S["TD"]),


            Paragraph("<b>%s</b>" % page_num, S["TDC"]),


        ])


    t = Table(rows, colWidths=[1.0*cm, 9.0*cm, 4.0*cm, 1.4*cm], repeatRows=0)


    t.setStyle(TableStyle([


        ("GRID",(0,0),(-1,-1),0.35,GREY_MED),


        ("ROWBACKGROUNDS",(0,0),(-1,-1),[WHITE,LIGHT_BLUE]),


        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),


        ("FONTSIZE",(0,0),(-1,-1),8),


        ("TOPPADDING",(0,0),(-1,-1),5),


        ("BOTTOMPADDING",(0,0),(-1,-1),5),


    ]))


    story.append(t)


    return story


def _navy(tbl): # wrap table in full-width navy background


    t=Table([[tbl]],colWidths=[PAGE_W])


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),NAVY),


                            ("LEFTPADDING",(0,0),(-1,-1),1.5*cm),


                            ("RIGHTPADDING",(0,0),(-1,-1),1.5*cm),


                            ("TOPPADDING",(0,0),(-1,-1),0),


                            ("BOTTOMPADDING",(0,0),(-1,-1),0)]))


    return t





def _navy_para(text,style):


    t=Table([[Paragraph(text,style)]],colWidths=[PAGE_W])


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),NAVY),


                            ("TOPPADDING",(0,0),(-1,-1),2),


                            ("BOTTOMPADDING",(0,0),(-1,-1),2)]))


    return t





def _navy_space(h):


    t=Table([[""]],colWidths=[PAGE_W],rowHeights=[h])


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),NAVY)])); return t





def _gold_rule():


    t=Table([[""]],colWidths=[PAGE_W],rowHeights=[0.12*cm])


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),GOLD)])); return t





def _agg(payload):
    """The canonical counts for this payload (taskf T-4.1).

    Renderers read ``payload["aggregates"]`` -- computed once in
    ``build_report_payload`` -- and only rebuild when handed a payload that
    never went through it (unit tests, ingest).  A renderer must never
    re-derive a total from ``metadata`` or ``len(...)`` itself: that is the
    DEF-A divergence this helper exists to end.
    """
    agg = payload.get("aggregates") if isinstance(payload, dict) else None
    if not isinstance(agg, dict) or not agg:
        agg = report_aggregates.build(payload if isinstance(payload, dict) else {})
    return agg


def _cover(payload, logo_path=None):


    meta   = payload.get("metadata",{})


    target = Path(meta.get("target","Unknown")).name or meta.get("target","Unknown")


    # DEF-A: the cover reads the canonical aggregate -- combined severity
    # (SAST + vulnerable packages) and the reported total -- never the
    # metadata fields, which describe a different population.
    _aggd  = _agg(payload)


    _counts = _aggd["counts"]


    dist   = _aggd["severity"]["combined"]


    risk   = meta.get("risk_score",0)


    total  = _counts["total_reported"]


    story  = []





    # Logo


    if logo_path and Path(logo_path).exists():


        try:


            logo_img=Image(logo_path,width=5*cm,height=2*cm,kind="proportional")


            lt=Table([[logo_img]],colWidths=[PAGE_W])


            lt.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),NAVY),


                                    ("ALIGN",(0,0),(-1,-1),"LEFT"),


                                    ("LEFTPADDING",(0,0),(-1,-1),1.8*cm),


                                    ("TOPPADDING",(0,0),(-1,-1),1.2*cm),


                                    ("BOTTOMPADDING",(0,0),(-1,-1),0)]))


            story.append(lt)


        except Exception as exc:


            raise RuntimeError(


                f"R-SecOpsX logo could not be loaded from {logo_path}: {exc}"


            ) from exc


    else:


        # Keep the historical layout fallback for environments that explicitly


        # omit branding, while normal production resolution finds reporting/logo.png.


        story.append(_navy_space(2.5*cm))





    story.append(_navy_para(TOOL_NAME,_s("T1",fontName="Helvetica",fontSize=13,


                             textColor=ELECTRIC,alignment=TA_CENTER,spaceAfter=0,leading=16)))


    story.append(_gold_rule())


    story.append(Spacer(1,0.4*cm))


    story.append(_navy_para("SECURITY ASSESSMENT REPORT",_s("T2",fontName="Helvetica-Bold",


                             fontSize=30,textColor=WHITE,alignment=TA_CENTER,spaceAfter=4,leading=36)))


    story.append(_navy_para("Static Application Security Testing  (SAST)",_s("T3",


                             fontName="Helvetica",fontSize=13,textColor=ELECTRIC,


                             alignment=TA_CENTER,spaceAfter=0,leading=16)))


    story.append(Spacer(1,0.5*cm))


    story.append(_gold_rule())


    story.append(Spacer(1,0.8*cm))





    sast_count = _counts["sast_records"]


    sca_count  = _counts["sca_vulnerable_packages"]


    findings_label = (f"{total}  (SAST: {sast_count} + SCA: {sca_count})"


                      if sca_count > 0 else str(total))





    info=Table([["Target System",target],["Scan Date",meta.get("scan_date","")[:10]],


                ["Classification","CONFIDENTIAL"],


                ["Total reported items",findings_label],


                ["Combined Severity",f"C:{dist.get('Critical',0)} H:{dist.get('High',0)} M:{dist.get('Medium',0)} L:{dist.get('Low',0)} I:{dist.get('Info',0)}"],


                ["Portfolio Risk Score",f"{risk} / 100"]],


               colWidths=[6*cm,10*cm])


    info.setStyle(TableStyle([


        ("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),10),


        ("TEXTCOLOR",(0,0),(0,-1),ELECTRIC),("TEXTCOLOR",(1,0),(1,-1),WHITE),


        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),


        ("ALIGN",(0,0),(0,-1),"RIGHT"),("ALIGN",(1,0),(1,-1),"LEFT"),


        ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),


        ("BACKGROUND",(0,0),(-1,-1),NAVY),


    ]))


    story.append(_navy(info))


    story.append(Spacer(1,0.8*cm))





    pill_data,pill_c=[],[]


    for sev,col in [("Critical",RED),("High",ORANGE),("Medium",YELLOW),("Low",GREEN)]:


        cnt=dist.get(sev,0)


        pill_data.append(Paragraph(f"<b>{sev}</b><br/>{cnt}",


            _s(f"P{sev}",fontName="Helvetica-Bold",fontSize=9,


               textColor=WHITE if sev!="Medium" else BLACK,


               alignment=TA_CENTER,leading=13)))


        pill_c.append(col)


    pt=Table([pill_data],colWidths=[4.2*cm]*4)


    cmds=[("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),


          ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8),


          ("BACKGROUND",(0,0),(-1,-1),NAVY)]


    for i,c in enumerate(pill_c):


        cmds.append(("BACKGROUND",(i,0),(i,0),c))


    pt.setStyle(TableStyle(cmds))


    story.append(_navy(pt))





    story.append(Spacer(1,1.2*cm))


    story.append(_navy_para(


        "This report contains confidential security findings. "


        "Distribution is restricted to authorized personnel only.",


        _s("Disc",fontName="Helvetica-Oblique",fontSize=8,


           textColor=colors.HexColor("#7B93A8"),alignment=TA_CENTER,leading=12)))


    story.append(NextPageTemplate("Content"))


    story.append(PageBreak())


    return story





# Section helper 




def _sec(title,level=1):


    if level>=3:


        # Sub-group heading inside a section.  No rule and one weight heavier


        # than body text, so it reads as a group of the table beneath it rather


        # than as a peer of the section that contains it.


        return [Paragraph(f"<b>{title}</b>",S["SubTitle"])]


    return [HRFlowable(width="100%",thickness=2 if level==1 else 0.5,


                       color=DARK_BLUE if level==1 else MID_BLUE,spaceAfter=4),


            Paragraph(title,S["SectionTitle"] if level==1 else S["SubTitle"])]







def _sca_remediation_priority_section(payload):
    """Render Critical and High SCA packages separately from SAST root causes."""
    sbom = payload.get("sbom") or []
    candidates = []
    seen = set()

    for pkg in sbom:
        if not isinstance(pkg, dict):
            continue

        severity = str(
            pkg.get("severity")
            or pkg.get("highest_vulnerability_severity")
            or ""
        ).strip().title()

        if severity not in {"Critical", "High"}:
            continue

        ids = list(pkg.get("cve_list") or [])
        advisories = list(pkg.get("advisory_ids") or [])
        ids += [x for x in advisories if x not in ids]

        if not ids:
            single = pkg.get("cve") or pkg.get("advisory_id")
            if single:
                ids = [single]

        if not (
            pkg.get("vulnerabilities") or ids
            or pkg.get("cve") or pkg.get("advisory_id")
        ):
            continue

        name = str(pkg.get("name") or pkg.get("purl") or "Unknown package")
        # Version through the one formatter (taskf Gate 3): a component
        # whose pin is unresolvable names its reason instead of printing
        # the producer's bare placeholder into the priority table.
        version = value_state.cell(pkg, "version")

        # Deduplicate identical package/version/vulnerability records only.
        key = (
            str(pkg.get("purl") or name).lower(),
            version.lower(),
            tuple(sorted(str(x).upper() for x in ids))
        )
        if key in seen:
            continue
        seen.add(key)

        epss = pkg.get("epss_score", pkg.get("epss"))
        try:
            epss = f"{float(epss):.3f}" if epss is not None else "--"
        except (TypeError, ValueError):
            epss = str(epss) if epss else "--"

        # Which standard spoke, and what it said. The legacy `cvss` scalar
        # drives severity and risk, so it is deliberately not what this
        # column prints: where the primary assessment is CVSS 4.0 the number
        # beside it has to be 4.0's own score, not its 3.1 sibling's.
        score = pkg.get("cvss_preferred_score")
        if score is None:
            # Both keys are written by the same enrichment pass. A missing
            # preferred score means the record claimed no version, so the
            # legacy scalar is the only number there is.
            score = pkg.get("cvss")
        cvss = format_cvss_assessment(pkg.get("cvss_version"), score)

        reachable = (
            pkg.get("reachability_priority") == "REACHABLE_VULNERABLE"
            or pkg.get("reachable") is True
            or str(pkg.get("reachability_status") or "").upper() == "REACHABLE"
        )

        fixed_raw = pkg.get("fixed_versions") or pkg.get("fixed_in")
        if isinstance(fixed_raw, (list, tuple)):
            fixed_raw = list(fixed_raw[:3])
        # One formatter with the Excel sheet (taskf Gate 3): the old
        # ``or "--"`` chain printed the producer's bare "Unknown" seed
        # here while the SBOM table said "unknown (not published)".
        fixed = value_state.cell({**pkg, "fixed_versions": fixed_raw},
                                 "fixed_versions", has_advisory=True)

        candidates.append({
            "severity": severity,
            "name": name,
            "version": version,
            # No truncation: the priority table's job is to name what to
            # patch; ids[:5] silently dropped the rest with no ellipsis.
            "ids": ", ".join(str(x) for x in ids) or "See advisory",
            "cvss": str(cvss),
            "epss": epss,
            "reachable": "Yes" if reachable else "No / Unknown",
            "fixed": str(fixed),
        })

    candidates.sort(key=lambda x: (
        0 if x["severity"] == "Critical" else 1,
        x["name"].lower(),
        x["version"]
    ))

    story = _sec("Critical and High Remediation Priorities", level=2)
    story.append(Paragraph(
        "Vulnerable dependency packages are listed separately from SAST root "
        "causes. 'No / Unknown' reachability does not prove a vulnerability "
        "is unreachable.",
        S["BodySmall"]
    ))

    critical = sum(x["severity"] == "Critical" for x in candidates)
    high = sum(x["severity"] == "High" for x in candidates)

    story.append(Paragraph(
        f"<b>{critical}</b> Critical and <b>{high}</b> High "
        "package records in this section. These are package records, "
        "not unique CVE counts.",
        S["Body"]
    ))

    if not candidates:
        story.append(Paragraph(
            "No Critical or High vulnerable dependency records were found "
            "in the SBOM payload.",
            S["Body"]
        ))
        return story

    headers = [
        "Severity", "Package", "Version", "CVE / Advisory",
        "CVSS", "EPSS", "Reachable", "Fixed In"
    ]
    rows = [[Paragraph(html.escape(x), S["TH"]) for x in headers]]

    for item in candidates:
        rows.append([
            Paragraph(html.escape(item["severity"]), S["TDC"]),
            Paragraph(html.escape(item["name"]), S["TDSm"]),
            Paragraph(html.escape(item["version"]), S["TDC"]),
            Paragraph(html.escape(item["ids"]), S["TDSm"]),
            Paragraph(html.escape(item["cvss"]), S["TDC"]),
            Paragraph(html.escape(item["epss"]), S["TDC"]),
            Paragraph(html.escape(item["reachable"]), S["TDC"]),
            Paragraph(html.escape(item["fixed"]), S["TDSm"]),
        ])

    table = Table(
        rows,
        colWidths=[
            # A column must hold its widest unbreakable token, and the
            # header word counts: reportlab wraps only at spaces, so at
            # 1.35 / 0.90 / 1.65 cm the three labels rendered as
            # "Versio n", "EP SS" and "Reachab le".  Widths are
            # stringWidth(token, Helvetica-Bold 8pt) + 6pt each side,
            # measured against this payload:
            #   Version   29.34+12 = 41.34pt = 1.46cm
            #   EPSS      21.34+12 = 33.34pt = 1.18cm  (its 0.085 cell
            #             needs 1.13cm, so the header binds)
            #   Reachable 40.02+12 = 52.02pt = 1.84cm
            # This table was leaving 1.00cm unused (16.40 of the 17.40cm
            # frame); the three of them spend it, which fills the frame
            # exactly.  CVSS keeps the 2.0cm it needs to carry
            # "CVSS 4.0 — 6.9", and no other column moves.
            1.55*cm, 2.75*cm, 1.60*cm, 3.35*cm,
            2.0*cm, 1.29*cm, 2.01*cm, 2.85*cm
        ],
        repeatRows=1,
        splitByRow=1,
        splitInRow=1
    )

    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
        ("GRID", (0, 0), (-1, -1), 0.4, GREY_MED),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]

    for row_index, item in enumerate(candidates, start=1):
        color = RED if item["severity"] == "Critical" else ORANGE
        commands.append(("BACKGROUND", (0, row_index), (0, row_index), color))

    table.setStyle(TableStyle(commands))
    story.append(table)
    story.append(Spacer(1, 0.3*cm))
    return story

def _top_root_causes_section(payload):


    """


    'Top Root Causes to Fix First'  ranked by total occurrence count.


    Shows the N vulnerabilities whose fix will eliminate the most instances.


    """


    top = payload.get("top_root_causes", [])


    if not top:


        return []





    story = _sec("2. Top Root Causes to Fix First")


    story.append(Paragraph(


        "The following vulnerabilities appear most frequently across the codebase. "


        "Fixing the root cause in shared code eliminates all occurrences at once — "


        "highest remediation leverage.",


        S["Body"]


    ))


    story.append(Spacer(1, 0.3*cm))





    SEV_BG = {"Critical": RED, "High": ORANGE, "Medium": YELLOW,


              "Low": GREEN, "Info": colors.HexColor("#7F8C8D")}


    SEV_FG = {"Critical": WHITE, "High": WHITE, "Medium": BLACK,


              "Low": WHITE,     "Info": WHITE}





    rows = [[Paragraph(h, S["TH"]) for h in


             ["#", "Vulnerability", "Severity", "Occurrences", "Files Affected", "Risk Score"]]]





    for i, f in enumerate(top, 1):


        sev        = f.get("severity", "Medium")


        instances  = f.get("instances", 1)


        files      = len(f.get("affected_files", [f.get("file","")]))


        risk       = f.get("risk_score", "")


        risk_str   = f"{risk}" if risk else "N/A"


        # A root cause is a *class* of vulnerability spanning findings from
        # different introduction dates, and the payload carries no age for it
        # (top_root_causes entries have no vulnerability_age* field at all),
        # so the old Age column rendered "--" on every single row.
        sev_para = Paragraph(sev, _s(f"SevR{i}", fontName="Helvetica-Bold",


                                      fontSize=8, textColor=SEV_FG.get(sev, WHITE),


                                      alignment=TA_CENTER))


        rows.append([


            Paragraph(str(i),              S["TDC"]),


            Paragraph(f.get("title",""),   S["TD"]),


            sev_para,


            Paragraph(str(instances),      S["TDC"]),


            Paragraph(str(files),          S["TDC"]),


            Paragraph(risk_str,            S["TDC"]),


        ])





    # Six columns now that Age is gone; its 2.0cm goes to the title, which is
    # the only column that actually wraps.
    t = Table(rows, colWidths=[0.8*cm, 7.8*cm, 2.3*cm, 2.2*cm, 2.2*cm, 1.5*cm])


    cmds = [


        ("BACKGROUND",    (0, 0), (-1, 0), DARK_BLUE),


        ("GRID",          (0, 0), (-1, -1), 0.5, GREY_MED),


        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),


        ("TOPPADDING",    (0, 0), (-1, -1), 5),


        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),


        ("FONTSIZE",      (0, 0), (-1, -1), 9),


    ]


    for i, f in enumerate(top, 1):


        sev = f.get("severity", "Medium")


        bg  = SEV_BG.get(sev, GREY_MED)


        cmds.append(("BACKGROUND", (2, i), (2, i), bg))


    t.setStyle(TableStyle(cmds))


    story.append(t)


    story.append(Spacer(1, 0.4*cm))





    # Narrative bullets


    for i, f in enumerate(top, 1):


        instances = f.get("instances", 1)


        files     = len(f.get("affected_files", [f.get("file","")]))


        impact_note = (


            f" - Fixing this root cause eliminates {instances} occurrences across "


            f"{files} file{'s' if files!=1 else ''}."


            if instances > 1 else ""


        )


        story.append(Paragraph(


            f"<b>{i}. {f.get('title','')}:</b> {instances} occurrence"


            f"{'s' if instances != 1 else ''} across {files} file"


            f"{'s' if files != 1 else ''}."


            f"{impact_note}",


            S["Bullet"]


        ))


    story.append(Spacer(1, 0.4*cm))


    return story








# Executive summary 




def _exec_summary(payload):


    # DEF-A: one aggregate drives the headline, the severity table, the pie
    # and the bar -- combined SAST + vulnerable-package severity, so the
    # table can reconcile with the rows beneath it.
    _aggd=_agg(payload); _counts=_aggd["counts"]; dist=_aggd["severity"]["combined"]


    meta=payload.get("metadata",{})


    risk=meta.get("risk_score",0);   total=_counts["total_reported"]


    story=_sec("1. Executive Summary")


    # Issue 7: risk label aligns score with executive recommendation


    risk_label = (


        "CRITICAL - immediate remediation required" if risk >= 80 else


        "HIGH - address before next release"         if risk >= 60 else


        "MEDIUM - schedule remediation"              if risk >= 40 else


        "LOW - monitor and track"


    )


    sast_dist = _aggd["severity"]["sast"]


    sca_dist = _aggd["severity"]["sca"]


    sca_critical = int(sca_dist.get("Critical", 0) or 0)


    sca_high = int(sca_dist.get("High", 0) or 0)


    story.append(Paragraph(


        f"The security assessment of <b>{Path(meta.get('target','')).name or meta.get('target','')}</b> "


        f"identified <b>{_counts['sast_records']} SAST findings and {_counts['sca_vulnerable_packages']} "


        f"vulnerable dependency packages ({total} reported items)</b>. "


        f"<br/><i>Severity scope: {_aggd['severity']['scope']}</i> "


        f"Portfolio risk score: <b>{risk}/100  {risk_label}</b>. "


        f"The risk score is the static-analysis portfolio score; release governance also "


        f"considers dependency intelligence and other enterprise gates. "


        f"SCA currently contributes <b>{sca_critical} Critical</b> and <b>{sca_high} High</b> "


        f"vulnerable dependency packages. "


        f"Each finding is individually scored using a 6-factor enterprise risk model "


        f"(severity, exploitability, data sensitivity, exposure, privilege, business impact).",


        S["Body"]))


    story.append(Spacer(1,0.3*cm))





    slas={"Critical":"< 24 hours","High":"7 days","Medium":"30 days","Low":"90 days","Info":"Next sprint"}


    pris={"Critical":"P1","High":"P2","Medium":"P3","Low":"P4","Info":"P4"}


    bg  ={"Critical":"#C0392B","High":"#E67E22","Medium":"#F1C40F","Low":"#27AE60","Info":"#7F8C8D"}


    rows=[[Paragraph(h,S["TH"]) for h in ["Severity","Count","Priority","SLA"]]]


    for sev in ["Critical","High","Medium","Low","Info"]:


        rows.append([Paragraph(sev,S["TDC"]),Paragraph(str(dist.get(sev,0)),S["TDC"]),


                     Paragraph(pris[sev],S["TDC"]),Paragraph(slas[sev],S["TDC"])])


    t=Table(rows,colWidths=[4*cm,3*cm,3*cm,5*cm])


    cmds=[("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("GRID",(0,0),(-1,-1),0.5,WHITE),


          ("TEXTCOLOR",(0,0),(-1,-1),WHITE),("TOPPADDING",(0,0),(-1,-1),6),


          ("BOTTOMPADDING",(0,0),(-1,-1),6),("FONTSIZE",(0,0),(-1,-1),9)]


    for i,sev in enumerate(["Critical","High","Medium","Low","Info"],1):


        cmds.append(("BACKGROUND",(0,i),(-1,i),colors.HexColor(bg[sev])))


        if sev=="Medium": cmds.append(("TEXTCOLOR",(0,i),(-1,i),BLACK))


    t.setStyle(TableStyle(cmds)); story.append(t); story.append(Spacer(1,0.4*cm))





    pi=Image(io.BytesIO(_pie(dist)),width=7.5*cm,height=5.5*cm)


    bi=Image(io.BytesIO(_bar(dist)),width=9*cm,  height=5.5*cm)


    # H1: this held 18.00cm of columns in a 17.40cm frame, so the pair sat
    # 0.30cm past the right margin on both sides.  Only the image column had
    # to move - the pie is 7.5cm and the bar 9.0cm, both still clear of their
    # cells at 8.0 / 9.4.
    ct=Table([[pi,bi]],colWidths=[8*cm,9.4*cm])


    ct.setStyle(TableStyle([("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE"),


                             ("BACKGROUND",(0,0),(-1,-1),GREY_LIGHT),("BOX",(0,0),(-1,-1),0.5,GREY_MED)]))


    story.append(ct); story.append(Spacer(1,0.4*cm))


    story+=_sec("Key Intelligence Insights",level=2)


    for ins in normalize_report_insights(payload.get("insights", []), dist):


        # Issue 6: enhance typosquat insight with explanation


        if ins.startswith("DEPENDENCY CONFUSION"):


            ins = ins + (


                " Typosquatted packages are indistinguishable from legitimate ones by name  "


                "they execute malicious code silently on pip/npm install, stealing credentials "


                "or establishing backdoors. Remove immediately and audit install history."


            )


        story.append(Paragraph(f"* {ins}", S["Bullet"]))


    story.append(Spacer(1,0.3*cm))





    # PATCH 14: executive prioritization block


    top_causes = payload.get("top_root_causes", [])


    if top_causes:


        top3_inst  = sum(f.get("instances",1) for f in top_causes[:3])


        total_inst = sum(f.get("instances",1) for f in payload.get("grouped",[]))

        # D3: three different quantities shared the label "findings". Name each
        # one so the headline can be reconciled against the Detailed Findings
        # list it points at:
        #   SAST records     = len(grouped)          -> what Detailed Findings lists
        #   SAST occurrences = sum(instances)        -> the root-cause denominator
        #   dependency vulns = unique vulnerable packages (separate population)
        # taskf Phase 4 fix: the headline above now reads
        # payload["aggregates"].counts (total_reported = sast_records +
        # sca_vulnerable_packages) and the severity table reads
        # severity.combined, so this population line and the headline can no
        # longer disagree.  metadata.total_findings is deliberately left
        # untouched -- it is a different population (taskf non-goal).
        _aggd = _agg(payload)
        _counts = _aggd["counts"]
        _grouped_records = _counts["grouped_records"]

        _dep_vulns = _counts["sca_vulnerable_packages"]

        if _grouped_records:
            _pop_line = (
                f"<b>Population:</b> {_counts['sast_records']} "
                f"SAST findings in {total_inst} occurrences across "
                f"{_grouped_records} listed records"
            )

            if _dep_vulns:
                _pop_line += f", plus {_dep_vulns} vulnerable dependency packages"

            _pop_line += (
                f" (reported total {_counts['total_reported']}). "
                "Severity figures combine SAST findings and vulnerable dependency packages; "
                f"scope: {_aggd['severity']['scope']}."
            )

            story.append(Paragraph(_pop_line, S["Body"]))

            story.append(Spacer(1, 6))


        if total_inst > 0:


            pct   = int(100 * top3_inst / total_inst)


            names = ", ".join(str(f.get("title", "")).strip() for f in top_causes[:3] if str(f.get("title", "")).strip())


            prio_tbl = Table([[Paragraph(


                # H4: '&#x26A1;' (U+26A1) has no glyph in the report fonts and
                # printed as a black box on page 4.  Written as an entity it
                # also slipped past _pdf_normalize_text, which matches the
                # character and not the markup, so the substitution never ran.
                # Going through the sanitizer keeps the two in step: whatever
                # it does to a stray lightning bolt in payload data it now does
                # here too, and both land on a glyph Helvetica can draw.
                f"<b>{_pdf_normalize_text(chr(0x26A1))} Executive Prioritization:</b> Fixing the top "


                f"{min(3,len(top_causes))} root causes (<i>{names}</i>) eliminates "


                f"<b>{top3_inst} of {total_inst} occurrences (~{pct}% of occurrences)</b>. "


                "Remediate these first for maximum risk reduction with minimum effort.",


                S["Body"]


            )]], colWidths=[17*cm])


            prio_tbl.setStyle(TableStyle([


                ("BACKGROUND",    (0,0),(-1,-1), colors.HexColor("#EAF4FB")),


                ("BOX",           (0,0),(-1,-1), 1, MID_BLUE),


                ("TOPPADDING",    (0,0),(-1,-1), 8),


                ("BOTTOMPADDING", (0,0),(-1,-1), 8),


                ("LEFTPADDING",   (0,0),(-1,-1), 10),


            ]))


            story.append(prio_tbl)


    story.append(Spacer(1,0.4*cm))


    return story












PDF_COMPLIANCE_DIRECT_FALLBACK = {


    "tenant isolation failure indicator": {


        "pci_dss": "Req 7 / Req 8 - Access control and tenant data segregation",


        "nist": "AC-3 / AC-6 / SC-7",


        "nist_800_53": "AC-3 / AC-6 / SC-7",


        "iso27001": "A.5.15 / A.8.3 / A.8.20",


        "iso_27001": "A.5.15 / A.8.3 / A.8.20",


        "soc2": "CC6.1 / CC6.6 / CC7.2",


    },


    "graphql introspection exposure": {


        "pci_dss": "Req 6.2.4 - Secure API configuration",


        "nist": "CM-7 / AC-3 / SC-7",


        "nist_800_53": "CM-7 / AC-3 / SC-7",


        "iso27001": "A.8.9 / A.8.20",


        "iso_27001": "A.8.9 / A.8.20",


        "soc2": "CC6.6 / CC7.2",


    },


    "graphql resolver bola / idor indicator": {


        "pci_dss": "Req 7 / Req 8 - Access control",


        "nist": "AC-3 / AC-6 / SI-10",


        "nist_800_53": "AC-3 / AC-6 / SI-10",


        "iso27001": "A.5.15 / A.8.3 / A.8.20",


        "iso_27001": "A.5.15 / A.8.3 / A.8.20",


        "soc2": "CC6.1 / CC6.6",


    },


    "dangerous reflection setaccessible(true)": {


        "pci_dss": "Req 6.2.4 - Secure coding and unsafe reflection prevention",


        "nist": "SI-10 / CM-7 / SA-11",


        "nist_800_53": "SI-10 / CM-7 / SA-11",


        "iso27001": "A.8.28 / A.8.29",


        "iso_27001": "A.8.28 / A.8.29",


        "soc2": "CC7.1 / CC7.2",


    },


}





def _pdf_is_empty_compliance_value(value):


    text = str(value or "").strip()


    return (not text) or text.lower() in {"not applicable", "n/a", "na", "none", "null", "unknown", "-"}





def _pdf_compliance_fallback_map(finding):


    title = str(finding.get("title", "")).strip().lower()


    rule_id = str(finding.get("rule_id", "")).strip().lower()


    vuln_type = str(finding.get("vuln_type", "")).strip().lower()


    combined = f"{title} {rule_id} {vuln_type}"





    for key, value in PDF_COMPLIANCE_DIRECT_FALLBACK.items():


        if key in combined:


            return value





    if "tenant" in combined and "isolation" in combined:


        return PDF_COMPLIANCE_DIRECT_FALLBACK["tenant isolation failure indicator"]


    if "graphql" in combined and "introspection" in combined:


        return PDF_COMPLIANCE_DIRECT_FALLBACK["graphql introspection exposure"]


    if "graphql" in combined and ("idor" in combined or "bola" in combined):


        return PDF_COMPLIANCE_DIRECT_FALLBACK["graphql resolver bola / idor indicator"]


    if "setaccessible" in combined or "set_accessible" in combined:


        return PDF_COMPLIANCE_DIRECT_FALLBACK["dangerous reflection setaccessible(true)"]


    return {}





def _pdf_compliance_cell(finding, field):


    """Return compliance value for PDF cells with direct title/rule/vuln fallback."""


    aliases = {


        "nist_800_53": ["nist_800_53", "nist"],


        "nist": ["nist", "nist_800_53"],


        "iso_27001": ["iso_27001", "iso27001"],


        "iso27001": ["iso27001", "iso_27001"],


        "pci_dss": ["pci_dss"],


        "soc2": ["soc2"],


    }





    fallback = _pdf_compliance_fallback_map(finding)





    # Prefer fallback for known problematic families where upstream grouped rows


    # may still carry Not Applicable in flattened fields.


    title = str(finding.get("title", "")).lower()


    vt = str(finding.get("vuln_type", "")).lower()


    rid = str(finding.get("rule_id", "")).lower()


    combined = f"{title} {vt} {rid}"


    known_family = (


        ("tenant" in combined and "isolation" in combined)


        or ("graphql" in combined and ("introspection" in combined or "idor" in combined or "bola" in combined))


        or ("setaccessible" in combined or "set_accessible" in combined)


    )


    if known_family and fallback:


        for key in aliases.get(field, [field]):


            value = fallback.get(key)


            if not _pdf_is_empty_compliance_value(value):


                return value





    for key in aliases.get(field, [field]):


        value = finding.get(key)


        if not _pdf_is_empty_compliance_value(value):


            return value





    for key in aliases.get(field, [field]):


        value = fallback.get(key)


        if not _pdf_is_empty_compliance_value(value):


            return value





    return "Not Applicable"





# Compliance 




def _compliance(payload):


    story=_sec("3. Compliance Mapping")


    # Population header (taskf T-4.1): mappings are computed from the SAST
    # findings list; every count below names what it counts.
    story.append(Paragraph(
        "Population: SAST findings (grouped records) plus vulnerable "
        "dependency packages where noted; each count below names its "
        "population.", S["BodySmall"]))
    story.append(Spacer(1, 0.15 * cm))





    # Findings by security category (audit M6 / L10).
    #
    # payload['owasp'] carries only the categories that have at least one
    # finding -- A06 and A09 are absent because neither has any -- and it
    # mixes three separate catalogues in one flat list.  Titled "OWASP Top 10"
    # the block claimed coverage the rows did not show and put LLM02 beside
    # A07 as though they shared a numbering scheme.  So: title it by what it
    # counts, group the rows by the catalogue their id belongs to, and
    # reconcile the rows to the report total before a reader does it for us.
    owasp=payload.get("owasp",{})


    if owasp:


        story+=_sec("Findings by Security Category",level=2)


        _cat_agg=_agg(payload)["counts"]
        _cat_total=sum(int((info or {}).get("count",0) or 0) for info in owasp.values())
        _cat_reported=int(_cat_agg["total_reported"])
        _cat_sca=int(_cat_agg["sca_vulnerable_packages"])
        _cat_gap=_cat_reported-_cat_total


        if _cat_reported and _cat_total!=_cat_reported:
            _note=(f"The categories below account for {_cat_total} of "
                   f"{_cat_reported} reported findings.")
        else:
            _note=f"The categories below account for {_cat_total} findings."


        if _cat_gap>0 and _cat_gap==_cat_sca:
            _note+=(f" The other {_cat_gap} are vulnerable dependency packages, "
                    f"reported under Dependencies; they carry no OWASP category "
                    f"and so are not counted here.")


        _note+=(" Only categories with at least one finding are listed, so an id "
                "that is absent means a genuine zero rather than a row that was "
                "dropped.")


        story.append(Paragraph(_note,S["BodySmall"]))
        story.append(Spacer(1,0.15*cm))


        # Which catalogue an id belongs to is decided by its id shape; the rows
        # themselves still come entirely from the payload's own keys.  The digit
        # guard matters: without it "API4" matches the bare "A" list and lands
        # in the Top 10 table.
        _catalogues=(("OWASP Top 10 (2021)",
                      lambda k: k.startswith("A") and k[1:].isdigit()),
                     ("OWASP API Security Top 10 (2023)",
                      lambda k: k.startswith("API")),
                     ("OWASP Top 10 for LLM Applications",
                      lambda k: k.startswith("LLM")))


        _buckets={}
        for _oid,_info in owasp.items():
            _key=str(_oid).strip()
            _up=_key.upper()
            _bucket=next((title for title,pred in _catalogues if pred(_up)),
                         "Other mappings")
            _buckets.setdefault(_bucket,[]).append((_key,_info))


        _known=[title for title,_ in _catalogues]


        for _bucket in _known+[b for b in _buckets if b not in _known]:
            if not _buckets.get(_bucket):
                continue


            story+=_sec(_bucket,level=3)


            rows=[[Paragraph(h,S["TH"]) for h in ["ID","Category","Findings"]]]


            for oid,info in sorted(_buckets[_bucket],key=lambda kv:kv[0]):
                info=info or {}
                cat=str(info.get("category","") or "")
                # The ID column already carries 'A08'; do not print it twice.
                title=(cat.split(" - ",1)[1].strip()
                       if cat.startswith(oid+":") and " - " in cat else cat)
                rows.append([Paragraph(oid,S["TDC"]),
                             Paragraph(title or oid,S["TD"]),
                             Paragraph(str(info.get("count",0)),S["TDC"])])


            t=Table(rows,colWidths=[3*cm,11*cm,3*cm])


            t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


                                    ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                                    ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                                    ("FONTSIZE",(0,0),(-1,-1),8)]))


            story.append(t); story.append(Spacer(1,0.2*cm))





    # MITRE


    mitre=payload.get("mitre",[])


    if mitre:


        story+=_sec("MITRE ATT&amp;CK",level=2)


        # The payload's mitre entries carry no count of their own, so count the
        # findings that attribute each technique -- the same unit the OWASP
        # table reports, which is what made this column's absence noticeable
        # (audit L11).
        _mitre_counts={}
        for _f in (payload.get("findings") or payload.get("grouped") or []):
            _v=_f.get("mitre")
            for _t in (_v if isinstance(_v,list) else ([_v] if _v else [])):
                if _t:
                    _mitre_counts[_t]=_mitre_counts.get(_t,0)+1


        rows=[[Paragraph(h,S["TH"]) for h in ["Technique ID","Description","Findings"]]]


        for te in mitre:
            _tid=te.get("id","")
            rows.append([Paragraph(_tid,S["TDC"]),Paragraph(te.get("description",""),S["TD"]),
                         Paragraph(str(_mitre_counts.get(_tid,0)),S["TDC"])])


        t=Table(rows,colWidths=[4*cm,11*cm,2*cm])


        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


                                ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                                ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                                ("FONTSIZE",(0,0),(-1,-1),8)]))


        story.append(t); story.append(Spacer(1,0.15*cm))


        story.append(Paragraph(
            f"The Findings column counts how many findings attribute each "
            f"technique; a single finding may attribute more than one, so the "
            f"column is not a partition of the {_agg(payload)['counts']['sast_records']} "
            f"SAST findings in this report.", S["BodySmall"]))
        story.append(Spacer(1,0.15*cm))





    # PCI DSS + NIST + ISO 27001 + SOC2 consolidated table


    story+=_sec("PCI DSS / NIST / ISO 27001 / SOC 2",level=2)


    seen_types: set = set()


    rows=[[Paragraph(h,S["TH"]) for h in ["Vulnerability","PCI DSS","NIST 800-53","ISO 27001","SOC 2"]]]


    for f in payload.get("grouped",[]):


        vt=f.get("vuln_type","")


        if vt in seen_types: continue


        seen_types.add(vt)


        rows.append([


            Paragraph(f.get("title", ""), S["TDSm"]),


            Paragraph(_pdf_compliance_cell(f, "pci_dss"), S["TDSm"]),


            Paragraph(_pdf_compliance_cell(f, "nist_800_53"), S["TDSm"]),


            Paragraph(_pdf_compliance_cell(f, "iso_27001"), S["TDSm"]),


            Paragraph(_pdf_compliance_cell(f, "soc2"), S["TDSm"]),


        ])


    if len(rows)>1:


        t=Table(rows,colWidths=[3.85*cm,3.39*cm,3.39*cm,3.39*cm,3.38*cm],


                repeatRows=1)          # repeat header on every page


        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


                                ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                                ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),


                                ("FONTSIZE",(0,0),(-1,-1),7)]))


        # repeatRows=1 ensures the column header re-appears if table spans pages.


        story.append(t)


    story += _nistaml_section(payload)


    story += _asvs_section(payload)


    story += _ssdf_alignment_section(payload)


    return story


# ---------------------------------------------------------------------------
# OWASP ASVS v4.0.3 requirement-level mapping.
#
# This is the framework the report previously represented only at chapter level
# (OWASP_ASVS_V2, _V4, _V5, ... in the control-coverage engine), which can say a
# chapter is under-covered and cannot say which requirement is in question.
#
# Three things this section refuses to do, because each would be a false claim:
#
#   1. Present a mapped requirement as an UNMET requirement. A finding is
#      evidence relevant to a requirement; ASVS requirements are "Verify that"
#      statements settled by testing, so relevance is not failure.
#   2. Present the reachability ratio as a compliance or coverage score. Most
#      ASVS requirements are verification activities no source scan performs, so
#      a low ratio is expected and unremarkable.
#   3. Print the catalogue as though it were observed. A corpus that reaches 12
#      requirements out of 278 has told you nothing about the other 266, and the
#      section says so in the same table it prints.
# ---------------------------------------------------------------------------


def _asvs_section(payload):
    """Render ASVS v4.0.3 requirement-level reachability and its limits."""
    try:
        from core.asvs_mappings import (
            ASVS_BY_CWE,
            ASVS_CHAPTERS,
            ASVS_CSV_SHA256,
            ASVS_DATASET_LABEL,
            ASVS_LICENSE,
            ASVS_REQUIREMENTS,
            ASVS_SECTIONS,
            ASVS_SOURCE_URL,
            UNMAPPED_RATIONALE,
            asvs_catalogue_cwe_coverage,
            evidence_class,
        )
    except Exception:
        return []

    summary = payload.get("asvs_summary") or {}

    story = _sec("OWASP ASVS v4.0.3 -- Requirement-Level Mapping", level=2)

    if not isinstance(summary, dict) or not summary or summary.get("status") == "REVIEW_REQUIRED":
        story.append(Paragraph(
            "No ASVS requirement-level mapping was produced for this report"
            + (f": {summary.get('error')}" if summary.get("error") else "")
            + ". ASVS requirements are verification statements established by "
              "testing an application; no requirement status is claimed here.",
            S["Body"]))
        return story

    catalogue = summary.get("catalogue_size") or len(ASVS_CHAPTERS) and 278
    reachable = summary.get("requirements_reachable") or []
    reachable_ratio = (len(reachable) / catalogue) if catalogue else 0.0
    # `by_mode` lives on the cwe / vuln_type families, NOT on `combined`
    # (which only carries totals). Reading it off `combined` silently yields {}
    # and drops the mode table entirely.
    by_mode = dict((summary.get("cwe") or {}).get("by_mode") or {})
    for fam in ("vuln_type",):
        for mode, count in ((summary.get(fam) or {}).get("by_mode") or {}).items():
            by_mode[mode] = by_mode.get(mode, 0) + count
    attributed = summary.get("findings_mapped") or 0
    unmapped = summary.get("findings_unmapped") or 0

    story.append(Paragraph(
        f"Dataset: {_safe_text(summary.get('dataset') or ASVS_DATASET_LABEL)} "
        f"({_safe_text(ASVS_LICENSE)}, enumeration SHA-256 "
        f"{_safe_text(ASVS_CSV_SHA256)[:16]}...). Source: {_safe_text(ASVS_SOURCE_URL)}",
        S["BodySmall"]))

    story.append(Spacer(1, 0.15 * cm))

    story.append(Paragraph(
        f"Catalogue: {catalogue} live requirements across {len(ASVS_CHAPTERS)} chapters, "
        f"plus {summary.get('tombstones_excluded') or 0} ASVS-published "
        f"[DELETED, ...] rows excluded as tombstones rather than requirements. "
        f"This artifact reaches {len(reachable)} of them "
        f"(ratio {reachable_ratio:.3f}) -- that is reachability, NOT compliance, and "
        f"NOT an ASVS coverage score.", S["BodySmall"]))

    # --- the honesty paragraph, before any ratio --------------------------
    story.append(Spacer(1, 0.1 * cm))
    story.append(Paragraph(
        "What a mapped requirement means: it means this finding is EVIDENCE "
        "RELEVANT to that requirement. It does NOT mean the requirement is unmet, and "
        "it is not an ASVS compliance claim. ASVS requirements are "
        "&quot;Verify that ...&quot; statements established by testing an application. "
        f"The {len(reachable)} reached requirements below are the ones whose subject is "
        "a detectable weakness class; the remainder are verification activities, "
        "architecture and process statements that no source-code scan can decide in "
        "either direction, so they are neither passed nor failed here.",
        S["BodySmall"]))

    # --- mapping-mode table ------------------------------------------------
    if by_mode:
        # The counts are ATTRIBUTION columns (one CWE edge + one vuln_type
        # edge per finding), not distinct findings: DIRECT 56 + RELATED 6 +
        # UNMAPPED 64 = 126 on a 63-finding report. The header used to say
        # "Findings", which read as 126 findings over a 63-finding report.
        rows = [[Paragraph(h, S["TH"]) for h in ["Resolution Mode", "Attributions", "Meaning"]]]
        meanings = {
            "DIRECT": "Reached through ASVS's OWN CWE cross-reference column. The "
                      "linkage is OWASP's, not this tool's.",
            "RELATED": "Reached through this project's vuln_type table, where each edge "
                       "is justified by that requirement's own text naming the construct. "
                       "Judgement, so never reported as DIRECT.",
            "UNMAPPED": "No defensible edge. Counted, not dropped. Absence of a mapping is "
                        "not a clean result.",
        }
        for mode in ("DIRECT", "RELATED", "UNMAPPED"):
            if mode in by_mode:
                rows.append([
                    Paragraph(mode, S["TDSm"]),
                    Paragraph(str(by_mode[mode]), S["TDSm"]),
                    Paragraph(meanings[mode], S["TDSm"]),
                ])
        # Middle column widened 1.60 -> 2.10cm: "Attributions" at TH
        # (Helvetica-Bold 8pt) measures 45.33pt + 12pt padding = 57.33pt =
        # 2.02cm, so 1.60cm wrapped it mid-word ("Attributi/ons") and 1.90cm
        # still wrapped the final "s". The 0.50cm comes out of Meaning, whose
        # prose wraps over several lines anyway; total stays 17.20cm.
        t = Table(rows, colWidths=[2.6 * cm, 2.1 * cm, 12.5 * cm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("GRID", (0, 0), (-1, -1), 0.5, GREY_MED),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTSIZE", (0, 0), (-1, -1), 7)]))
        story.append(t)
        story.append(Paragraph(
            "Counts are attribution columns (CWE + vuln_type), up to 2 per "
            "finding -- not distinct findings; the sum may exceed the report's "
            "finding count.", S["BodySmall"]))

    # --- reachable requirements -------------------------------------------
    if reachable:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(
            f"Requirements reached by this artifact ({len(reachable)} of {catalogue}):",
            S["BodySmall"]))
        rrows = [[Paragraph(h, S["TH"]) for h in ["Requirement", "Section", "Evidence Class"]]]
        for rid in reachable:
            # `reachable` holds version-qualified ids; strip the prefix to reach
            # the catalogue key. Anything not in the catalogue renders as the id
            # alone rather than being dropped.
            bare = rid.split("ASVS-v4.0.3-")[-1]
            spec = ASVS_REQUIREMENTS.get(bare) or {}
            rrows.append([
                Paragraph(_safe_text(rid), S["TDSm"]),
                Paragraph(_safe_text(ASVS_SECTIONS.get(spec.get("section") or "", bare)),
                          S["TDSm"]),
                Paragraph(_safe_text(evidence_class(bare)), S["TDSm"]),
            ])
        rt = Table(rrows, colWidths=[4 * cm, 9 * cm, 4.2 * cm], repeatRows=1)
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("GRID", (0, 0), (-1, -1), 0.5, GREY_MED),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTSIZE", (0, 0), (-1, -1), 7)]))
        story.append(rt)

    # --- unreferenced CWE classes: declared limits, not findings -----------
    unreferenced = summary.get("unreferenced_cwe") or {}
    if unreferenced:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(
            f"{len(unreferenced)} weakness class(es) observed in this corpus are cited "
            "nowhere in the ASVS v4.0.3 enumeration, so no requirement could be "
            "attributed to them. They are declared limits of the framework's "
            "enumeration, not ASVS failures and not suppressed findings:",
            S["BodySmall"]))
        story.append(Paragraph(
            ", ".join(sorted(unreferenced)), S["BodySmall"]))

    cov = asvs_catalogue_cwe_coverage()
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        f"Catalogue edge coverage: ASVS publishes a CWE cross-reference for "
        f"{cov['with_cwe_edge']} of {cov['total']} requirements; "
        f"{cov['without_cwe_edge']} carry none and are therefore unreachable through "
        "the CWE path by construction. Findings mapped: "
        f"{attributed}; findings resolved UNMAPPED: {unmapped}. Unmapped findings "
        f"are reported with the reason "
        f"(&quot;{_safe_text(UNMAPPED_RATIONALE)[:120]}...&quot;).",
        S["BodySmall"]))

    return story


# ---------------------------------------------------------------------------
# NIST AI 100-2e2025 (Adversarial Machine Learning) attack-class attribution.
#
# Derived from the `nistaml_*` fields the two AI scanners stamp onto each
# finding. This is the one framework here that IS a per-finding attribution:
# an attack class describes an adversary behaviour that a detection can
# evidence, so attaching one to a finding is a claim about the finding.
#
# Two honesty rules, both load-bearing:
#
#   1. A corpus with no AI findings gets a section that says so. It does NOT
#      get the catalogue printed as if the corpus exhibited those attacks. The
#      distinction matters because "no attack class observed" and "these attack
#      classes are covered" are opposite statements.
#   2. Coverage is reported against the catalogue's own size, so a low ratio is
#      visible rather than implied. The detection gaps are listed, because a
#      coverage number without its denominator's blind spots invites a reader to
#      treat the ratio as a score.
# ---------------------------------------------------------------------------


def _nistaml_rows(payload):
    """Collect NISTAML attribution from every finding that carries it.

    Returns (by_attack, objective_hits, contributing, unmapped) where
    `contributing` is the number of findings that actually bear a NISTAML field
    -- which is NOT the total finding count. Keeping that separate is what stops
    the section from implying the framework covers the whole report.
    """
    by_attack = {}
    objective_hits = {}
    contributing = 0
    unmapped = 0

    for f in (payload.get("findings", []) or []):

        if not isinstance(f, dict) or "nistaml_mapping_mode" not in f:

            continue

        contributing += 1

        mode = str(f.get("nistaml_mapping_mode") or "").strip()

        attack_id = str(f.get("nistaml_id") or "").strip()

        if mode == "UNMAPPED" or not attack_id:

            unmapped += 1

            continue

        label = f.get("nistaml_attack") or attack_id

        rec = by_attack.setdefault(
            attack_id,
            {"id": attack_id, "attack": str(label), "findings": 0,
             "modes": {}, "rules": set(), "related": set()},
        )

        rec["findings"] += 1

        rec["modes"][mode] = rec["modes"].get(mode, 0) + 1

        rid = str(f.get("rule_id") or "").strip()

        if rid:

            rec["rules"].add(rid)

        for rel in (f.get("nistaml_related") or []):

            rec["related"].add(str(rel))

        obj = str(f.get("nistaml_objective") or "").strip()

        if obj:

            prev = objective_hits.get(obj, 0)

            objective_hits[obj] = prev + 1

    for rec in by_attack.values():

        rec["rules"] = sorted(rec["rules"])

        rec["related"] = sorted(rec["related"])

    return by_attack, objective_hits, contributing, unmapped


def _nistaml_section(payload):
    """Render the NIST AI 100-2e2025 attack-class attribution table."""
    try:
        from core.nist_aml_mappings import (
            NISTAML_ATTACKS,
            NISTAML_DATASET_LABEL,
            NISTAML_DETECTION_GAPS,
            NISTAML_OBJECTIVES,
        )
    except Exception:
        return []

    story = _sec("NIST AI 100-2e2025 -- Adversarial ML Attack Classes", level=2)

    by_attack, objective_hits, contributing, unmapped = _nistaml_rows(payload)

    catalogue = len(NISTAML_ATTACKS)

    story.append(Paragraph(
        f"Dataset: {NISTAML_DATASET_LABEL}. Attribution is per-finding, produced by "
        f"core/nist_aml_mappings.py. Every finding reaching this table carries a "
        f"resolution mode (DIRECT / RELATED / UNMAPPED); UNMAPPED findings are counted "
        f"below rather than silently dropped, because a dropped unmapped finding would "
        f"inflate the ratio.", S["BodySmall"]))

    if contributing == 0:
        story.append(Spacer(1, 0.2 * cm))
        story.append(Paragraph(
            "No finding in this report carries NIST AML attack-class attribution. This "
            "corpus produced no AI/LLM findings, so there is nothing to attribute. The "
            "catalogue below is reference scope, NOT an observation: no attack class in "
            "it was observed here.", S["Body"]))
    else:
        story.append(Paragraph(
            f"Findings carrying an attribution decision: {contributing} of "
            f"{_agg(payload)['counts']['sast_records']} SAST findings in this report "
            f"({unmapped} resolved UNMAPPED).", S["Body"]))

        if by_attack:
            story.append(Spacer(1, 0.2 * cm))
            rows = [[Paragraph(h, S["TH"]) for h in
                     ["Attack Class", "Name", "Objective", "Findings", "Modes", "Rules"]]]

            for aid in sorted(by_attack):
                rec = by_attack[aid]
                modes = ", ".join(f"{k}:{v}" for k, v in sorted(rec["modes"].items()))
                obj = (NISTAML_ATTACKS.get(aid) or {}).get("objective") or ""
                rows.append([
                    Paragraph(aid, S["TDSm"]),
                    Paragraph(_safe_text(rec["attack"]), S["TDSm"]),
                    Paragraph(obj, S["TDSm"]),
                    Paragraph(str(rec["findings"]), S["TDSm"]),
                    Paragraph(modes, S["TDSm"]),
                    Paragraph(", ".join(rec["rules"]) or "--", S["TDSm"]),
                ])

            t = Table(rows, colWidths=[1.9 * cm, 4.2 * cm, 2.1 * cm, 1.5 * cm,
                                       2.4 * cm, 5.1 * cm], repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
                ("GRID", (0, 0), (-1, -1), 0.5, GREY_MED),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("FONTSIZE", (0, 0), (-1, -1), 7)]))
            story.append(t)

        if objective_hits:
            story.append(Spacer(1, 0.15 * cm))
            story.append(Paragraph(
                "Adversarial objectives touched: "
                + ", ".join(
                    f"{o} {NISTAML_OBJECTIVES.get(o, '')} ({n} finding(s))"
                    for o, n in sorted(objective_hits.items())),
                S["BodySmall"]))

    # Coverage against the catalogue, with the denominator stated.
    observed_ids = sorted(by_attack)
    ratio = (len(observed_ids) / catalogue) if catalogue else 0.0
    story.append(Spacer(1, 0.15 * cm))
    story.append(Paragraph(
        f"Attack classes observed: {len(observed_ids)} of {catalogue} in the catalogue "
        f"(ratio {ratio:.3f})."
        + (f" Observed: {', '.join(observed_ids)}." if observed_ids else ""),
        S["BodySmall"]))

    if NISTAML_DETECTION_GAPS:
        # The count is the recorded gaps (len(NISTAML_DETECTION_GAPS)), NOT
        # `catalogue - observed`: those are different sets. The old sentence
        # claimed "The remaining 17 catalogue attack classes have no detection
        # rule" directly above a 7-row gap table -- unobserved classes were
        # presented as classes with no rule. The citation names the register
        # shipped beside the report (main.py ship_gap_register), not the
        # gitignored repo path the reader never receives.
        story.append(Spacer(1, 0.15 * cm))
        story.append(Paragraph(
            f"{len(NISTAML_DETECTION_GAPS)} of the {catalogue} catalogue attack "
            f"classes are recorded as detection gaps (no detection rule in this "
            f"release) -- see gap_register.json (G-088), copied alongside this "
            f"report. Gaps are recorded, not absent findings:", S["BodySmall"]))
        gap_rows = [[Paragraph(h, S["TH"]) for h in ["Attack Class", "Name", "Gap"]]]
        for gid in sorted(NISTAML_DETECTION_GAPS):
            gap = NISTAML_DETECTION_GAPS[gid]
            gap_rows.append([
                Paragraph(gid, S["TDSm"]),
                Paragraph(_safe_text((NISTAML_ATTACKS.get(gid) or {}).get("name") or ""), S["TDSm"]),
                Paragraph(_safe_text(gap.get("gap") if isinstance(gap, dict) else gap), S["TDSm"]),
            ])
        # "Attack Class" holds ids like NISTAML.012, which have no space to
        # wrap at: stringWidth(Helvetica 7pt) + 6pt/side = 43.96 + 12 =
        # 55.96pt = 1.97cm, against the 1.90cm this column used to be.  The
        # extra 0.10cm comes out of the 0.20cm this table leaves unused, so
        # the total stays inside the 17.40cm frame.
        gt = Table(gap_rows, colWidths=[2.0 * cm, 4.2 * cm, 11.1 * cm], repeatRows=1)
        gt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("GRID", (0, 0), (-1, -1), 0.5, GREY_MED),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTSIZE", (0, 0), (-1, -1), 7)]))
        story.append(gt)

    return story


# ---------------------------------------------------------------------------
# NIST SSDF (SP 800-218 v1.1) evidence alignment.
#
# Deliberately NOT a per-finding table. SSDF describes organisational and
# lifecycle practices; a scanner cannot evidence them. The section therefore
# renders the per-practice OBSERVED / NOT_OBSERVED / NOT_ATTESTABLE verdict
# with the artifact path that decided it, and states in-line that
# NOT_ATTESTABLE is the largest bucket -- so the section cannot be skimmed as a
# score.
# ---------------------------------------------------------------------------


def _ssdf_alignment_section(payload):
    """Render the SSDF per-practice evidence alignment table."""
    align = payload.get("ssdf_alignment") or {}

    if not isinstance(align, dict) or not align:

        story = _sec("NIST SSDF (SP 800-218) Evidence Alignment", level=2)

        story.append(Paragraph(
            "No SSDF alignment was produced for this report. The alignment is "
            "evaluated immediately before the report is serialized; its absence "
            "means it was not evaluated or the evaluation failed, and it must not "
            "be read as zero practices met.", S["Body"]))

        return story

    if align.get("status") == "REVIEW_REQUIRED":

        story = _sec("NIST SSDF (SP 800-218) Evidence Alignment", level=2)

        story.append(Paragraph(
            f"SSDF alignment could not be evaluated: {align.get('error')}. "
            "No practice status is claimed.", S["Body"]))

        return story

    practices = align.get("practices") or []

    story = _sec("NIST SSDF (SP 800-218) Evidence Alignment", level=2)

    story.append(Paragraph(
        f"Dataset: {_safe_text(align.get('dataset'))}. "
        f"{_safe_text(align.get('method'))}", S["BodySmall"]))

    story.append(Spacer(1, 0.15 * cm))

    story.append(Paragraph(
        f"Observed {align.get('observed', 0)} of {align.get('total_practices', 0)} practices. "
        f"{humanize_enum('NOT_OBSERVED')} {align.get('not_observed', 0)}. "
        f"{humanize_enum('NOT_ATTESTABLE_BY_A_SCANNER')} "
        f"{align.get('not_attestable', 0)} -- this last "
        f"bucket is the majority of the catalogue and is the honest result: those "
        f"practices concern organisation, process and release governance, which no "
        f"source-code scan can attest in either direction.",
        S["BodySmall"]))

    if align.get("observed_ids"):
        story.append(Paragraph(
            "Observed practice ids: " + ", ".join(align["observed_ids"]), S["BodySmall"]))

    if practices:
        rows = [[Paragraph(h, S["TH"]) for h in
                 ["Practice", "Group", "Status", "Evidence Path(s)", "Findings"]]]

        for p in practices:
            ev = p.get("evidence") or []
            if ev:
                ev_txt = "; ".join(
                    f"{e.get('path')} ({e.get('detail')})" for e in ev if isinstance(e, dict))
            else:
                ev_txt = "-- (no probe declared)"

            status = str(p.get("status") or "")
            # The stored verdict is an identifier (NOT_ATTESTABLE_BY_A_SCANNER);
            # the table column and the prose above it must read as words.
            shown = humanize_enum(status)
            cell = Paragraph(
                _safe_text(shown) + (f": {_safe_text(p.get('rationale'))}"
                                     if status != "OBSERVED" and p.get("rationale") else ""),
                S["TDSm"])

            rows.append([
                Paragraph(_safe_text(p.get("practice") or p.get("practice_id") or ""), S["TDSm"]),
                Paragraph(_safe_text(p.get("group") or ""), S["TDSm"]),
                cell,
                Paragraph(_safe_text(ev_txt), S["TDSm"]),
                Paragraph(str(len(ev)), S["TDSm"]),
            ])

        # "Findings" was 1.00cm against a 1.60cm requirement, so the header
        # rendered as two broken halves.  reportlab wraps only at spaces and
        # "Findings" has none: stringWidth(Helvetica-Bold 8pt) + 6pt/side =
        # 33.34 + 12 = 45.34pt = 1.60cm.  The 0.60cm comes half from the
        # 0.20cm this table left unused and half from "Status", which holds
        # prose that wraps at spaces either way.  Total 17.40cm, exactly the
        # frame.  The column's own cells are counts, so nothing else moves.
        t = Table(rows, colWidths=[4.4 * cm, 1.5 * cm, 5.2 * cm, 4.7 * cm, 1.6 * cm],
                  repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("GRID", (0, 0), (-1, -1), 0.5, GREY_MED),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTSIZE", (0, 0), (-1, -1), 6)]))
        story.append(t)

    return story








def _ap_header_widths(has_risk: bool):
    """Column widths matching the header row, which omits the risk column when
    the record carries no score."""
    return [2.5*cm, 9*cm, 2.5*cm, 3*cm] if has_risk else [2.5*cm, 9*cm, 2.5*cm]


def _ap_evidence_label(view):
    return _ap_ev(view)


def _ap_introduction(views):
    return _ap_intro(views)


def _attack_paths_section(payload):


    story=_sec("4. Attack Path Correlation")


    paths=payload.get("attack_paths",[])


    if not paths:


        story.append(Paragraph("No multi-step attack chains detected.",S["Body"]))


        return story





    # Derived from the actual confirmed/candidate mix, not asserted. The
    # previous text described EVERY path as a candidate needing manual
    # validation, which is false whenever the paths carry taint evidence --
    # babyagi-main had eight CONFIRMED paths described that way.
    _ap_views = _apv(paths)

    story.append(Paragraph(_ap_introduction(_ap_views), S["Body"]))


    story.append(Spacer(1,0.3*cm))





    for i,_v in enumerate(_ap_views,1):

        ap = _v

        sev=_v.get("severity") or "Medium"; sc=SEV_C.get(sev,GREY_MED)

        steps=_v.get("chain") or []

        chains=_v.get("chains_to") or []

        # Evidence state comes from the normalised view, which reads
        # `attack_path_status` / `evidence_valid` FIRST. Reading a defaulted
        # `evidence_type` here labelled every taint-confirmed path
        # "PATTERN-ONLY ... Manual validation is required".
        _confirmed = bool(_v.get("confirmed"))

        ev_color = "#E9F7EF" if _confirmed else "#FFF8E7"

        ev_border = colors.HexColor("#27AE60") if _confirmed else GOLD

        evidence_note = _v.get("evidence_note") or ""

        ev_label = _ap_evidence_label(_v)


        # An absent risk score is OMITTED, not formatted as 0. "Risk: 0" came
        # from `ap.get('risk_score', 0)` rendering a default that reads like a
        # measurement. The column count therefore varies per row, so the widths
        # come from _ap_header_widths -- passing 4 widths to a 3-column Table
        # raises LayoutError.
        _hdr_cells=[Paragraph(f"Chain #{i:02d}",S["TH"]),
                    Paragraph(_v.get("title") or "",S["TH"]),
                    Paragraph(sev.upper(),S["TH"])]
        if _v.get("risk_score") is not None:
            _hdr_cells.append(
                Paragraph(f"Risk: {_v['risk_score']}",S["TH"]))

        hdr=Table([_hdr_cells],

                  colWidths=_ap_header_widths(
                      _v.get("risk_score") is not None))


        hdr.setStyle(TableStyle([("BACKGROUND",(0,0),(1,0),DARK_BLUE),


                                  ("BACKGROUND",(2,0),(2,0),sc),


("BACKGROUND",(3,0),(3,0),MID_BLUE)
                                  if len(_hdr_cells)>3 else ("BACKGROUND",(2,0),(2,0),sc),


                                  ("TEXTCOLOR",(0,0),(-1,-1),WHITE),


                                  ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),


                                  ("FONTSIZE",(0,0),(-1,-1),9),


                                  ("ALIGN",(0,0),(-1,-1),"CENTER"),


                                  ("TOPPADDING",(0,0),(-1,-1),5),


                                  ("BOTTOMPADDING",(0,0),(-1,-1),5)]))





        # Step chain arrow row


        arrow="  -->  "


        chain_str=arrow.join(steps)


        chain_rows=[[Paragraph("<b>Chain:</b>", S["Chain"])]]


        for _chunk in _paragraph_chunks(chain_str, S["Chain"], 1600):


            chain_rows.append([_chunk])


        # Location. The record carries file and line from the finding, and the
        # old format showed them here too -- a reader acting on a confirmed chain
        # otherwise has to go hunting through the findings chapter.
        _loc = _v.get("file") or ""
        if _loc:
            _loc += f":{_v['line']}" if _v.get("line") else ""
            chain_rows.append([Paragraph(f"<b>Location:</b> {_loc}", S["Chain"])] )


        chain_tbl=Table(chain_rows, colWidths=[17*cm], splitByRow=1, splitInRow=1)


        chain_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),GREY_LIGHT),


                                        ("TOPPADDING",(0,0),(-1,-1),5),


                                        ("BOTTOMPADDING",(0,0),(-1,-1),5),


                                        ("LEFTPADDING",(0,0),(-1,-1),8),


                                        ("BOX",(0,0),(-1,-1),0.5,GREY_MED)]))







        narr_rows=[[Paragraph("<b>Narrative</b>", S["BodySmall"])]]


        for _chunk in _paragraph_chunks(ap.get("narrative",""), S["Body"], 1800):


            narr_rows.append([_chunk])


        narr_tbl=Table(narr_rows, colWidths=[17*cm], splitByRow=1, splitInRow=1)


        narr_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),LIGHT_BLUE),


                                       ("BACKGROUND",(0,1),(-1,-1),WHITE),


                                       ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                       ("TOPPADDING",(0,0),(-1,-1),4),


                                       ("BOTTOMPADDING",(0,0),(-1,-1),4),


                                       ("LEFTPADDING",(0,0),(-1,-1),6)]))





        chain_note=""


        if chains:


            chain_note=f"<b>Chains to:</b> {', '.join(chains)} remediate these together."


        note_content = f"{ev_label}  {chain_note}" if chain_note else ev_label


        note_rows=[[p] for p in _paragraph_chunks(note_content, S["BodySmall"], 1600)]


        note_tbl=Table(note_rows,colWidths=[17*cm])


        note_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),colors.HexColor(ev_color)),


                                       ("BOX",(0,0),(-1,-1),0.5,ev_border),


                                       ("TOPPADDING",(0,0),(-1,-1),4),


                                       ("BOTTOMPADDING",(0,0),(-1,-1),4),


                                       ("LEFTPADDING",(0,0),(-1,-1),6)]))





        story.extend([hdr, chain_tbl, narr_tbl, note_tbl, Spacer(1,0.4*cm)])


    return story








def _v17923_benchmark_note(f):


    note = str(f.get("benchmark_note") or "").strip()


    if note:


        return note


    bg = f.get("benchmark_ground_truth")


    if isinstance(bg, dict):


        status = str(bg.get("status") or "").upper()


        if status == "DECLARED_INTENTIONAL":


            return "Benchmark-intentional case; not a production waiver. Remediation remains developer-actionable unless separately risk-accepted."


        if status == "UNRESOLVED":


            return "Benchmark classification unresolved; production TP/FP status remains pending adjudication."


    return ""





def _v17923_fixed_text(pkg):
    """Fixed-version cell through the one formatter (taskf T-2.1/T-4.1).

    Why: this helper used to hand-code both absence forms -- a long
    fixed-version-absence sentence when an advisory existed, a dash when it
    did not -- while Excel's ``_sbom_fixed_versions`` returned a dash for
    the same case, so the two artifacts disagreed by design.  ``value_state``
    resolves one ladder from provenance + has_advisory and never prints the
    old sentence (ground rules 5 and 6).
    """
    return value_state.cell(pkg, "fixed_versions",
                            has_advisory=pkg_has_advisory(pkg))






# Rendering for the three per-finding decision fields (D5).
#
# These are the fields that distinguish "the scanner produced a finding" from
# "the pipeline decided this finding is reportable on this evidence". They were
# computed for every finding and then never rendered, so a reader of Detailed
# Findings could not tell a reportable finding from one the pipeline held back.
#
# The one rule these helpers enforce is that an ABSENT value never becomes a
# positive claim. `reportable_finding` absent does not mean "not reportable"
# and `evidence_valid` absent does not mean "valid"; both mean the pipeline did
# not record a decision, which is a different and worse thing than either
# verdict. So absence renders as NOT RECORDED, never as a verdict, and never as
# a blank cell a reader would skip past.
_NOT_RECORDED = "NOT RECORDED"


def _decision_state_display(finding) -> str:
    """Render `decision_state` in reader wording, or NOT RECORDED when absent.

    The stored value is a pipeline identifier (`REVIEW_REQUIRED`), which used
    to be printed verbatim into every finding card's Decision State field.
    Known identifiers are humanised; anything unrecognised still renders as
    itself, so a status introduced later is never silently swallowed.
    """
    value = (finding or {}).get("decision_state")

    if isinstance(value, str):

        text = value.strip()

        return humanize_enum(text) if text else _NOT_RECORDED

    if value is None:

        return _NOT_RECORDED

    return humanize_enum(str(value))


def _reportable_display(finding) -> str:
    """Render `reportable_finding` as YES / NO, or NOT RECORDED when absent.

    Only a real boolean (or its unambiguous string form) produces a verdict.
    Anything else -- None, empty string, an unrecognised token -- is reported as
    NOT RECORDED so an unparsed value cannot be read as a decision.
    """
    value = (finding or {}).get("reportable_finding")

    if isinstance(value, bool):

        return "YES" if value else "NO"

    if isinstance(value, str):

        token = value.strip().upper()

        if token in {"TRUE", "YES"}:

            return "YES"

        if token in {"FALSE", "NO"}:

            return "NO"

    return _NOT_RECORDED


def _evidence_valid_display(finding) -> str:
    """Render `evidence_valid` as VALID / INVALID, or NOT RECORDED when absent.

    Same rule as `_reportable_display`: an unrecognised value is not a verdict.
    The reason the evidence did not validate is carried alongside it, because
    INVALID on its own tells a reader nothing about what to do.
    """
    value = (finding or {}).get("evidence_valid")

    verdict = _NOT_RECORDED

    if isinstance(value, bool):

        verdict = "VALID" if value else "INVALID"

    elif isinstance(value, str):

        token = value.strip().upper()

        if token in {"TRUE", "VALID"}:

            verdict = "VALID"

        elif token in {"FALSE", "INVALID"}:

            verdict = "INVALID"

    if verdict == "INVALID":

        reason = (finding or {}).get("evidence_reason") or (finding or {}).get("evidence_state")

        if reason:

            verdict = f"INVALID -- {_safe_text(reason)}"

    return verdict


def _accuracy_display(finding) -> str:
    """Render this finding's accuracy-layer verdict, or NOT RECORDED.

    The accuracy audit (``metadata.accuracy_summary`` / per-finding
    ``accuracy``) decided which findings the pipeline itself doubts. It
    reached clean_report.json but no PDF page, so a reader could not tell a
    TRUE_POSITIVE from a LIKELY_FALSE_POSITIVE. Verdicts render verbatim
    (the JSON token) so all three artifacts can be grepped for the same
    string; absence is NOT RECORDED, never a pass.
    """
    acc = (finding or {}).get("accuracy")
    if not isinstance(acc, dict):
        return _NOT_RECORDED
    verdict = str(acc.get("verdict") or "").strip()
    return verdict or _NOT_RECORDED


def _accuracy_confidence_display(finding) -> str:
    """Render the accuracy verdict's own confidence, or NOT RECORDED."""
    acc = (finding or {}).get("accuracy")
    if not isinstance(acc, dict):
        return _NOT_RECORDED
    conf = acc.get("confidence")
    if conf is None:
        return _NOT_RECORDED
    try:
        return f"{float(conf):.2f}"
    except (TypeError, ValueError):
        text = str(conf).strip()
        return text or _NOT_RECORDED


def _findings_section(payload):


    story=_sec("5. Detailed Findings")


    grouped=payload.get("grouped",[])


    if not grouped:


        story.append(Paragraph("No findings detected.",S["Body"])); return story


    # Population header (taskf T-4.1 / ground rule 4): this list is the SAST
    # population only -- the reported total also counts vulnerable packages.
    story.append(Paragraph(
        f"{len(grouped)} SAST findings (grouped records). This list is the SAST "
        f"population only; the report total "
        f"({_agg(payload)['counts']['total_reported']} reported items) also "
        "counts vulnerable dependency packages.",
        S["BodySmall"]))
    story.append(Spacer(1, 0.15 * cm))


    # D3: disclose the accuracy layer before the cards. The per-card row
    # shows this finding's verdict; this line shows what the audit decided
    # across the whole report, so a filtered count can never hide behind a
    # clean-looking card list.
    _acc = (payload.get("metadata") or {}).get("accuracy_summary") or payload.get("accuracy") or {}
    _acc_verdicts = _acc.get("verdicts") if isinstance(_acc, dict) else None
    if isinstance(_acc_verdicts, dict) and _acc_verdicts:
        _acc_parts = ", ".join(f"{k}: {v}" for k, v in sorted(_acc_verdicts.items()))
        story.append(Paragraph(
            f"Accuracy layer: {_acc.get('filtered', 0)} of {_acc.get('total', len(grouped))} "
            f"findings filtered by the accuracy audit; verdicts — {_acc_parts}.",
            S["BodySmall"]))
        story.append(Spacer(1, 0.15 * cm))




    for idx,f in enumerate(grouped,1):


        sev=f.get("severity","Medium"); sc=SEV_C.get(sev,GREY_MED)


        instances=f.get("instances",1)


        affected =f.get("affected_files",[f.get("file","")])





        hdr=Table([[Paragraph(f"#{idx:02d}",S["TH"]),


                    Paragraph(f.get("title","Unknown"),S["TH"]),


                    Paragraph(sev.upper(),S["TH"]),


                    Paragraph(f.get("priority",""),S["TH"]),


                    Paragraph(f"Risk: {f.get('risk_score','')}",S["TH"])]],


                  colWidths=[1.8*cm,9.2*cm,2.5*cm,2*cm,1.5*cm])


        hdr.setStyle(TableStyle([("BACKGROUND",(0,0),(1,0),DARK_BLUE),


                                  ("BACKGROUND",(2,0),(2,0),sc),


                                  ("BACKGROUND",(3,0),(3,0),MID_BLUE),


                                  ("BACKGROUND",(4,0),(4,0),colors.HexColor("#1B3A5C")),


                                  ("TEXTCOLOR",(0,0),(-1,-1),WHITE),


                                  ("FONTNAME",(0,0),(-1,-1),"Helvetica-Bold"),


                                  ("FONTSIZE",(0,0),(-1,-1),8),


                                  ("ALIGN",(0,0),(-1,-1),"CENTER"),


                                  ("TOPPADDING",(0,0),(-1,-1),5),


                                  ("BOTTOMPADDING",(0,0),(-1,-1),5)]))





        # PATCH 12: display the file path without the volume/drive root.

        #

        # The original implementation returned only the LAST TWO path segments
        # ("keep it readable"). That is not safe: it is lossy. Validated against
        # the Juice Shop artifact, `terraform/networking.tf` and
        # `infrastructure/terraform/networking.tf` both collapsed to
        # `terraform/networking.tf`, so two genuinely distinct findings rendered
        # identically in Detailed Findings and a reader could not tell which file
        # to fix. The string `infrastructure/terraform` appeared ZERO times in
        # the 796 KB technical PDF even though the JSON carried it.
        #

        # Readability is now preserved by dropping ONLY the volume or drive
        # root, never a distinguishing path segment, so distinct paths can never
        # render to the same string.

        #

        def _clean_path(fp: str) -> str:

            raw = str(fp or "").strip()

            if not raw:

                return ""

            was_absolute = Path(raw).is_absolute()

            parts = [seg for seg in Path(raw.replace("\\", "/")).parts if seg not in ("/", "\\")]

            if parts and (parts[0].endswith(":") or parts[0].startswith("\\\\")):

                parts = parts[1:]

            if was_absolute and len(parts) > 1:

                # drop only the volume/repository folder that the scan root added

                parts = parts[1:]

            if not parts:

                return Path(raw).name or raw

            return "/".join(parts)


        pf = _clean_path(affected[0]) if affected else ""





        # PATCH 6: enrich IDOR description with access type context


        desc = f.get("description", "") or f.get("business_impact", "")


        if f.get("vuln_type") == "api_idor":


            snippet_low = (f.get("snippet","") or "").lower()


            idor_type = "Vertical IDOR" if any(


                x in snippet_low for x in ("admin","role","permission","privilege")


            ) else "Horizontal IDOR"


            access = "Write access" if any(


                x in snippet_low for x in ("post","put","delete","update","save","write")


            ) else "Read access"


            desc = (f"[{idor_type} / {access}] Missing authorization validation. "


                    + (desc or "User-controlled ID used in object access without ownership check."))


        exploit_val = f.get("exploitability","")


        exploit_disp = exploit_val.upper() if exploit_val else "N/A"


        # Issue 5: single Detection value, used in both Exploitability and Confidence rows


        det_label = (


            "TAINT-VALIDATED"


            if (f.get("taint_path") and "->" in str(f.get("taint_path","")))


               or f.get("detection") == "TAINT-VALIDATED"


            else ("Regex + Contextual Analysis"


                  if f.get("detection") == "Regex Pattern"


                  else f.get("detection",""))


        )


        # J6-N: ReportLab Paragraph cannot consume None. These five compliance


        # metadata fields are proven nullable in the authoritative OWASP report.


        # Normalize only these fields at the rendering boundary.


        _pdf_text = lambda v: "" if v is None else str(v)





        meta_rows=[


            ["File",_pdf_text(pf),                    "Line",          _pdf_text(f.get("line",""))],


            ["CWE", _pdf_text(f.get("cwe","")),       "OWASP",         _pdf_text(f.get("owasp",""))],


            ["MITRE",_pdf_text(f.get("mitre","")),    "CVE",           _pdf_text(f.get("cve") or "N/A")],


            ["PCI DSS",_pdf_text(f.get("pci_dss","")),"NIST",          _pdf_text(f.get("nist",""))],


            ["ISO 27001",_pdf_text(f.get("iso27001","")),"SOC2",       _pdf_text(f.get("soc2",""))],


            ["Detection",    det_label,


             "Sink Category", f.get("sink_category","unknown").title().replace("_"," ")],


            ["Confidence",   f.get("confidence_label","") or f.get("confidence",""),


             "Exploitability", exploit_disp],


            # D5: the pipeline's own verdict on this finding. Without these a
            # reader cannot distinguish a finding the pipeline stands behind
            # from one it flagged REVIEW_REQUIRED or could not evidence, and
            # cannot tell whether an absent field means "fine" or "never
            # recorded". Absence renders as NOT RECORDED, never as a pass.
            ["Decision State", _decision_state_display(f),

             "Reportable", _reportable_display(f)],


            ["Evidence Valid", _evidence_valid_display(f),

             "Evidence State", _pdf_text(f.get("evidence_state") or f.get("quality_state") or "")],


            # D3: the accuracy layer's own verdict on this finding. Without
            # it a reader cannot tell a finding the accuracy audit stands
            # behind from one it flagged LIKELY_FALSE_POSITIVE or
            # NEEDS_REVIEW. Absence renders as NOT RECORDED, never as a pass.
            ["Accuracy", _accuracy_display(f),

             "Accuracy Conf.", _accuracy_confidence_display(f)],


        ]


        meta_tbl=Table([[Paragraph(c,S["BodySmall"]) for c in row] for row in meta_rows],


                       # col1 holds file paths and CVE/GHSA ids, none of which
                       # have a space to wrap at.  The widest is
                       # frontend/src/app/change-password/change-password.component.ts
                       # at 238.78pt = 8.42cm, so with 6pt/side padding it
                       # needs 8.85cm against the 8.00cm it had.  The 0.90cm
                       # comes out of col3, whose own widest token is
                       # "Misconfiguration" at 2.06cm, so 4.10cm still fits it
                       # nearly three times over.  Total unchanged at 17.00cm.
                       colWidths=[2*cm,8.9*cm,2*cm,4.1*cm])


        meta_tbl.setStyle(TableStyle([


            ("BACKGROUND",(0,0),(0,-1),GREY_LIGHT),("BACKGROUND",(2,0),(2,-1),GREY_LIGHT),


            ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTNAME",(2,0),(2,-1),"Helvetica-Bold"),


            ("GRID",(0,0),(-1,-1),0.5,GREY_MED),("FONTSIZE",(0,0),(-1,-1),7),


            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3)]))





        af_tbl=None


        if instances>1:


            # Large consolidated findings can contain hundreds of affected files.


            # Never place the entire list in one Paragraph/Table row: ReportLab


            # cannot split an individual oversized table row across pages.


            # Keep one file per row so the table itself can paginate safely.


            af_rows=[[Paragraph(f"<b>Found in {instances} files (consolidated)</b>",S["BodySmall"])]]


            for i, fp in enumerate(affected, 1):


                af_rows.append([Paragraph(


                    f"&nbsp;&nbsp;{i}. {_clean_path(fp)}",


                    S["AF"]


                )])


            af_tbl=Table(af_rows,colWidths=[17*cm], repeatRows=1,


                         splitByRow=1, splitInRow=1, hAlign="LEFT")


            af_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#EBF5FB")),


                                         ("BACKGROUND",(0,1),(-1,-1),colors.HexColor("#F8FBFD")),


                                         ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                         ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                                         ("LEFTPADDING",(0,0),(-1,-1),6)]))





        # Issue 8 FIX: show description only if different from business_impact


        raw_desc   = f.get("description","").strip()


        raw_impact = (f.get("business_impact") or "").strip()


        show_desc  = raw_desc and raw_desc != raw_impact


        desc_rows  = []


        if show_desc:


            desc_rows.append([Paragraph("<b>Description</b>", S["BodySmall"])])


            for _chunk in _paragraph_chunks(raw_desc, S["Body"], 1800):


                desc_rows.append([_chunk])


        desc_rows.append([Paragraph("<b>Business Impact</b>", S["BodySmall"])])


        for _chunk in _paragraph_chunks(raw_impact or raw_desc, S["Body"], 1800):


            desc_rows.append([_chunk])


        desc_tbl=Table(desc_rows, colWidths=[17*cm], splitByRow=1, splitInRow=1)


        _hdr_rows = [i for i,r in enumerate(desc_rows)


                     if r and hasattr(r[0],"text") and "<b>" in (r[0].text or "")]


        _style8 = [("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                   ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                   ("LEFTPADDING",(0,0),(-1,-1),6)]


        for _ri in _hdr_rows:


            _style8.append(("BACKGROUND",(0,_ri),(-1,_ri),LIGHT_BLUE))


        desc_tbl.setStyle(TableStyle(_style8))





        snippet = f.get("snippet","").strip()


        ev_rows=[[Paragraph("<b>Code Evidence</b>",S["BodySmall"])]]


        ev_rows.append([Paragraph(


            f"{_clean_path(affected[0]) if affected else ''}:{f.get('line','')}",


            S["Code"])])


        for _chunk in _code_safe_paragraph_chunks(


            snippet or "[no snippet]",


            S["Code"],


            1200,


        ):


            ev_rows.append([_chunk])


        if f.get("taint_path"):


            for _chunk in _paragraph_chunks(


                f"<b>Taint Path:</b> {f['taint_path']}", S["BodySmall"], 1200


            ):


                ev_rows.append([_chunk])


        qualification = str(f.get("evidence_qualification") or "").strip()


        benchmark_note = _v17923_benchmark_note(f)


        if qualification or benchmark_note:


            if qualification:


                ev_rows.append([Paragraph(f"<b>Evidence Qualification:</b> {qualification}", S["BodySmall"])])


            if benchmark_note:


                ev_rows.append([Paragraph(f"<b>Benchmark Disposition:</b> {benchmark_note}", S["BodySmall"])])


        ev_tbl=Table(ev_rows,colWidths=[17*cm])


        ev_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#E8F0FE")),


                                     ("BACKGROUND",(0,1),(-1,-1),GREY_LIGHT),


                                     ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                     ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                                     ("LEFTPADDING",(0,0),(-1,-1),6)]))





        rem=f.get("remediation",[])


        rem_rows=[[Paragraph("<b>Remediation Steps</b>", S["BodySmall"])]]


        if rem:


            for i, step in enumerate(rem, 1):


                for _chunk in _paragraph_chunks(


                    f"{i}. {step}", S["Body"], 1800


                ):


                    rem_rows.append([_chunk])


        else:


            rem_rows.append([Paragraph(


                "Follow secure coding best practices.", S["Body"]


            )])


        rem_tbl=Table(rem_rows, colWidths=[17*cm], splitByRow=1, splitInRow=1)


        rem_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#E9F7EF")),


                                      ("BACKGROUND",(0,1),(-1,-1),WHITE),


                                      ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                      ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                                      ("LEFTPADDING",(0,0),(-1,-1),6)]))





        items=[hdr,meta_tbl]


        if af_tbl: items.append(af_tbl)


        items+=[desc_tbl,ev_tbl,rem_tbl,Spacer(1,0.5*cm)]


        # L5: a card header landing in the last centimetre of a page leaves the
        # reader with a title bar and no finding -- the body starts on the next
        # page.  KeepTogether was the wrong instrument here: pinning the header
        # to the metadata table reserves that table's full height, so every
        # page with less than ~7cm free was abandoned (232 -> 253 pages) and in
        # a short document the pair was dropped altogether.  A conditional break
        # instead only asks for room for the header and the line that names the
        # file, and leaves the rest of the card free to flow.
        story.append(CondPageBreak(3*cm))


        story.extend(items)


    return story









def _pq_qbom_section(payload):
    """Post-quantum cryptographic exposure, reported as its own section.

    Kept separate from the SBOM section on purpose. The SBOM answers "which
    dependencies are vulnerable today"; this answers "which of this project's
    cryptographic assets break under a cryptographically relevant quantum
    computer, and in what order should they be migrated". Those are different
    questions with different audiences and different timescales, and a reader who
    finds a migration queue under a heading about dependency CVEs will reasonably
    assume it is urgent.

    Three honesty constraints, each of which corresponds to a defect that has
    actually occurred in this codebase:

      * UNKNOWN is printed as its own status with its count, never folded into a
        "not affected" bucket. A summary that reports zero exposed assets because
        everything failed to classify is the most misleading output possible here.
      * The aggregation is declared. The corpus contains a project whose 3,111
        crypto usage sites resolve to 4 distinct assets; both numbers appear, or
        the table reads as a complete inventory when it is not.
      * The CERT-In conformance document is cross-referenced rather than merged.
        It lives in Security_QBOM.qbom.json and answers a different question.
    """

    story = _sec("Post-Quantum Cryptographic Exposure (PQ QBOM)")

    pq = payload.get("qbom_pq") or {}
    summary = pq.get("exposure_summary") or {}
    assets = pq.get("assets") or []

    if not pq:
        story.append(Paragraph(
            "No post-quantum exposure assessment was produced for this scan. "
            "That is not a statement that the project is post-quantum ready; it "
            "means this layer did not run or produced nothing.", S["Body"]))
        return story

    sites = summary.get("total_usage_sites")
    total = summary.get("total_assets")
    classified = summary.get("classified")
    unclassified = summary.get("unclassified")
    needs = summary.get("needs_migration")

    lead = (f"<b>{sites or 0} cryptographic usage sites resolve to "
            f"{total or 0} distinct cryptographic assets.</b> "
            f"{needs or 0} asset(s) require migration.")
    story.append(Paragraph(lead, S["Body"]))

    # UNKNOWN is stated before the table, because "0 need migration" is only
    # meaningful beside the number that could not be assessed.
    if unclassified:
        story.append(Spacer(1, 0.15*cm))
        story.append(Paragraph(
            f"<b>{unclassified} of {total or 0} asset(s) could not be "
            "classified and are reported as UNKNOWN.</b> UNKNOWN is not a safe "
            "result: it means this inventory cannot determine whether the "
            "primitive is affected by a quantum algorithm. It must not be read as "
            "'no action required'.", S["Body"]))
    else:
        story.append(Spacer(1, 0.15*cm))
        story.append(Paragraph(
            f"All {total or 0} asset(s) were classified.", S["Body"]))

    if summary.get("aggregation_note"):
        story.append(Spacer(1, 0.15*cm))
        story.append(Paragraph(
            html.escape(summary["aggregation_note"]), S["BodySmall"]))

    if assets:
        story.append(Spacer(1, 0.25*cm))
        rows = [[Paragraph(h, S["TH"]) for h in
                 ["Algorithm", "Key Size", "Uses", "Quantum Status", "Risk",
                  "Migration", "Basis"]]]

        for a in assets:
            # quantum_status is a classifier OUTPUT: "UNKNOWN" is a real
            # enum answer (the prose above tells the reader so), and only a
            # missing field dashes -- value_state keeps that distinction.
            status = value_state.cell(a, "quantum_status")
            provenance = a.get("algorithm_provenance") or ""
            basis = provenance
            note = a.get("classification_note")
            if note:
                basis = (provenance + " - " + note) if provenance else note
            rows.append([
                Paragraph(html.escape(str(a.get("algorithm") or "--")), S["TDSm"]),
                Paragraph(str(a.get("key_size") if a.get("key_size") is not None
                              else "not recorded"), S["TDC"]),
                Paragraph(str(a.get("occurrence_count") or 0), S["TDC"]),
                Paragraph(html.escape(status), S["TDC"]),
                Paragraph(str(a.get("quantum_risk") or "--"), S["TDC"]),
                Paragraph(str(a.get("migration_priority") or "NONE"), S["TDC"]),
                Paragraph(html.escape(basis or "--"), S["TDSm"]),
            ])

        # H1: 17.60cm, 0.20cm past the frame.  Every header word and every
        # cell token now fits on one line within 17.40 - notably Risk, which
        # was 1.60cm wide against a 1.91cm 'UNKNOWN' and printed as
        # 'UNKNO / WN'.
        t = Table(rows,
                  colWidths=[2.47*cm, 1.85*cm, 1.19*cm, 3.17*cm, 1.92*cm,
                             1.95*cm, 4.85*cm],
                  repeatRows=1, splitByRow=1, splitInRow=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("GRID", (0, 0), (-1, -1), 0.5, GREY_MED),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BLUE]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("FONTSIZE", (0, 0), (-1, -1), 7)]))
        story.append(t)

    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "<b>How these statuses are assigned.</b> QUANTUM_VULNERABLE means broken "
        "by Shor's algorithm and applies to asymmetric primitives - RSA, DSA, DH, "
        "ECDSA, ECDH and the Edwards curves, including ed25519, which is vulnerable "
        "precisely because it is strong. QUANTUM_MARGIN_CRITICAL means Grover's "
        "algorithm destroys the margin outright, as with a 64-bit DES or 3DES key. "
        "QUANTUM_IMPACT_ASSESSED means the margin is reduced but not removed, as "
        "with AES or the SHA-2 family. PQC means the ML-KEM, ML-DSA or SLH-DSA "
        "family, including its parameter sets.", S["BodySmall"]))
    story.append(Spacer(1, 0.1*cm))
    story.append(Paragraph(
        "<b>Scope.</b> Classified from this scan's own cryptographic inventory by "
        "scanner/crypto_quantum_analyzer. No external vulnerability or quantum "
        "database was consulted. An asset absent from this section was not observed "
        "in source; that is not evidence the deployed system does not use it. The "
        "CERT-In v2.0 Table 8 conformance document is a separate artifact, "
        "Security_QBOM.qbom.json, and answers a different question.", S["BodySmall"]))

    return story


def _sbom_section(payload):


    story=_sec("6. SBOM & Dependency Vulnerabilities")


    sbom=payload.get("sbom",[])


    if not sbom:


        story.append(Paragraph("No dependency manifests found.",S["Body"])); return story





    # Reader order: vulnerable components first, ordered Critical -> High ->
    # Medium -> Low, then every clean component, each group alphabetical by
    # name then version (sbom_display_sort_key, shared with the Excel SBOM
    # sheet so both artifacts list the same rows in the same order).  The
    # payload order is manifest order, which scatters the vulnerable rows
    # across the whole inventory and makes the reader hunt for them.
    # sorted() copies, so the payload contract comes back untouched.
    sbom=sorted(sbom,key=sbom_display_sort_key)

    vuln_deps=[d for d in sbom if pkg_has_advisory(d)]


    reachable=[d for d in vuln_deps if d.get("reachability_priority") == "REACHABLE_VULNERABLE" or d.get("reachable") is True or str(d.get("reachability_status") or "").upper() == "REACHABLE"]


    cve_count = int((payload.get("metadata", {}) or {}).get("cve_count", 0) or 0)


    advisory_count = int((payload.get("metadata", {}) or {}).get("advisory_count", 0) or 0)


    # L6: the two counters were printed side by side whether or not they
    # differed, so a target where every advisory carries exactly one CVE read
    # "13 unique CVEs and 13 advisory records" -- one population described
    # twice under two nouns, which invites the reader to go looking for 26
    # things.  Only name the advisory records when they really are another
    # number; on this corpus cve_count == advisory_count == 13 and the payload
    # has 13 top_cves rows carrying 13 distinct CVE ids.
    _cve_sentence = f"{cve_count} unique CVEs"
    if advisory_count and advisory_count != cve_count:
        _cve_sentence += f" across {advisory_count} advisory records"
    _cve_sentence += " were identified. "


    story.append(Paragraph(


        f"<b>{len(vuln_deps)} of {len(sbom)} packages have known vulnerabilities</b>; "
        + _cve_sentence +
        f"<b>{len(reachable)} of {len(vuln_deps)} vulnerable packages are reachable</b> "
        "in the scanned application context. Components with known vulnerabilities "
        "are listed first ordered by severity (Critical, High, Medium, Low), then "
        "the remaining components alphabetically by name.",S["Body"]))





    # Everything a reader needs to interpret the cells sits ABOVE the table:
    # this table runs ~100 pages, and a legend printed after it is never seen
    # by anyone still reading row 60.  (The Type and CVSS notes were moved up
    # from below the table for that reason -- audit M2 could not find them.)
    story.append(Spacer(1, 0.15*cm))

    # The Type column is a single letter; without a legend the reader has to
    # guess that D/T means direct/transitive (audit M2).  Derived from the
    # same field the column renders, so they cannot drift apart.
    story.append(Paragraph(
        "<b>Type:</b> D = declared directly in a manifest "
        "(dependencies / devDependencies); T = transitive, pulled in by "
        "another dependency.",
        S["BodySmall"]))

    story.append(Spacer(1, 0.1*cm))

    # A row with no advisory used to print Severity "Unknown", Age "Not
    # applicable" and Reachable "Yes"/"No" beside dashes in CVE/CVSS/EPSS --
    # three vocabularies for "there is no vulnerability here", and Reachable
    # "Yes" on @gradio/client read as an exploitability claim when it only
    # meant the package's import was observed.  The dash now covers every
    # advisory-derived cell; Yes/No is reserved for rows that actually have
    # an advisory to reach.  "Unknown"/"score unavailable" still appear in
    # words where an advisory exists but the value is not published.
    story.append(Paragraph(
        "<b>Severity / Age / Reachable:</b> on a row whose CVE / Advisory "
        "cell reads <b>--</b>, Severity, Age and Reachable read <b>--</b> "
        "too: there is no advisory, so there is no severity, no age and no "
        "vulnerability to reach. Reachable Yes/No asks one question of a "
        "vulnerable package - was it marked reachable by the offline table "
        "behind this report? Yes/No on a table-sourced row is a curated "
        "guess from that table, not observed imports, until a computed "
        "reachability engine replaces it; Yes is not proof that the code "
        "runs or that the flaw is exploitable.",
        S["BodySmall"]))

    story.append(Spacer(1, 0.1*cm))

    # The CVSS column names the standard that produced its number, so the
    # reader needs to know why two cells in it can look like the same
    # admission and mean opposite things: a dash denies the finding exists,
    # "score unavailable" affirms it does and declines to rate it. Without
    # this, a missing score reads as a clean result.
    story.append(Paragraph(
        "<b>CVSS:</b> the version and score of the advisory's preferred "
        "assessment - where an advisory publishes both a 4.0 and a 3.x "
        "assessment of the same flaw, 4.0 is shown and each assessment "
        "keeps its own score, so the number beside a version label is "
        "always that version's number. <i>version unknown</i> means the "
        "source published a score without saying which standard produced "
        "it, and no version has been guessed from the number. "
        "<i>score unavailable</i> means the vulnerability exists but no "
        "score is published for it - it is not an absence of risk. "
        "<b>--</b> means no vulnerability was recorded against that package.",
        S["BodySmall"]))

    story.append(Spacer(1, 0.2*cm))

    rows=[[Paragraph(h,S["TH"]) for h in


           ["Package","Ver","Type","CVE / Advisory","CVSS","EPSS","Severity","Age","Reachable","Fixed In"]]]


    for pkg in sbom:


        # Same predicate the section's prose count uses (pkg_has_advisory,
        # shared with the Excel sheets), so a cell can never claim a
        # vulnerability the prose did not count, nor omit one that it did.
        # Every advisory-derived cell below branches on it: a component
        # without an advisory has no severity, no age and no vulnerability
        # to reach, so those cells read "--" -- the same dash already shown
        # in CVE / CVSS / EPSS -- instead of a placeholder word that reads
        # like a finding ("Unknown") or a claim that invites the question
        # this section got: Reachable "Yes" on a row with no advisory.
        has_vulnerability = pkg_has_advisory(pkg)

        # Advisory-derived cells resolve through the one formatter (taskf
        # T-2.1): no advisory dashes, an advisory with a genuinely
        # unpublished value says "unknown (...)" in words -- never a bare
        # placeholder.  The literal-'None' sentinel is filtered inside
        # value_state, exactly as the Excel sheet filters it
        # (scanner.package_intelligence._ABSENT_SEVERITY_VALUES): "None" is
        # a truthy string, so a bare `or` fallback misses it.
        sev = value_state.cell(pkg, "severity", has_advisory=has_vulnerability)
        age = "--"
        fixed = "--"
        reachable_cell = "--"
        epss_str = "--"
        id_str = "--"
        if has_vulnerability:

            cves = list(pkg.get("cve_list") or [])
            advisories = list(pkg.get("advisory_ids") or [])
            # Every id, no truncation: the caption beside this table states
            # the full unique-CVE count, so a silent cves[:3]+advisories[:2]
            # cut (5 of 16 ids on Juice Shop) read as the complete list.
            vuln_ids = cves + [a for a in advisories if a not in cves]
            id_str = (", ".join(vuln_ids) if vuln_ids
                      else (pkg.get("cve") or pkg.get("advisory_id") or "--"))

            age_days = pkg.get("vulnerability_age_days")
            age_bucket = pkg.get("vulnerability_age_bucket")
            age_value = pkg.get("vulnerability_age")
            if age_days not in (None, "", "--"):
                age_value = (f"{age_days}d"
                             + (f" ({humanize_enum(age_bucket)})"
                                if age_bucket else ""))
            # Overlay the derived display value on the record so
            # value_state sees one dict (provenance rides along).
            age = value_state.cell({**pkg, "vulnerability_age": age_value},
                                   "vulnerability_age", has_advisory=True)

            epss = pkg.get("epss_score", pkg.get("epss"))
            epss_str = f"{float(epss):.3f}" if epss is not None else "--"

            reachable_cell = ("Yes" if (
                pkg.get("reachability_priority") == "REACHABLE_VULNERABLE"
                or pkg.get("reachable") is True
                or str(pkg.get("reachability_status") or "").upper() == "REACHABLE"
            ) else "No")

            fixed = _v17923_fixed_text(pkg)

        direct=pkg.get("direct",True)
        score = pkg.get("cvss_preferred_score")
        if score is None:
            # Both keys are written by the same enrichment pass. A missing
            # preferred score means the record claimed no version, so the
            # legacy scalar is the only number there is.
            score = pkg.get("cvss")
        cvss_cell = html.escape(format_cvss_assessment(
            pkg.get("cvss_version"), score, has_vulnerability
        ))


        rows.append([


            Paragraph(str(pkg.get("name","")), S["TDSm"]),


            Paragraph(str(value_state.cell(pkg, "version")), S["TDC"]),


            Paragraph("D" if direct else "T", S["TDC"]),


            Paragraph(str(id_str), S["TDSm"]),


            Paragraph(cvss_cell, S["TDC"]),


            Paragraph(epss_str, S["TDC"]),


            Paragraph(str(sev), S["TDC"]),


            Paragraph(str(age), S["TDC"]),


            Paragraph(str(reachable_cell), S["TDC"]),


            Paragraph(str(fixed), S["TDSm"]),


        ])


    # Widest table in the report and it must still total exactly the 17.4cm
    # frame.  The CVSS cell now names a version as well as a score, so it
    # needs 1.14 -> 1.71cm.
    #
    # A column has to hold its widest unbreakable token, and that includes
    # the HEADER word: reportlab wraps a Paragraph only at spaces, so
    # "Type" and "Reachable" (no space in either) were force-split into
    # "Type" mid-word and "Reachab le" when those columns were set from
    # their data alone -- a one-character cell does not make a
    # one-character label.  Every width below is now
    #
    #     stringWidth(widest token, that cell's own font, size) + 4pt + 4pt
    #
    # measured with pdfmetrics against the shipped payload (this table was
    # forked to 4pt/side padding by H1; other tables keep reportlab's 6pt).
    # The two headers that broke cost 0.95 and 1.70cm; they are paid for by
    # returning the other columns to their own measured requirement rather
    # than by shaving them further -- no token that fits today starts
    # wrapping, and "Package" gains 0.02cm.  3.10+1.42+0.95+2.99+1.71+1.04+
    # 1.46+1.56+1.70+1.47 = 17.40cm.
    # B1 (2026-10-16, Open-Assistant): a single cell taller than the content
    # frame used to drop the ENTIRE PDF.  The Fixed In cell is the plain
    # ", ".join(vals) of _v17923_fixed_text -- `next`'s advisory carries 60+
    # fixed versions (571 chars joined into a 1.47cm column => a 656pt row)
    # against a 665pt frame.  reportlab's Table.split() cannot advance past a
    # row taller than the frame when only splitByRow is set: it returns [],
    # doctemplate raises LayoutError ("... too large on page 124 in frame
    # 'content' ... of template 'SBOM'"), pages 1-123 had already rendered,
    # and the run shipped no Security_Report.pdf at all -- the executive PDF
    # generator is nested inside the same try, so it never ran either.
    #
    # splitInRow=1 is strictly a FALLBACK: Table.split() still tries the
    # row-wise split first and only splits inside a row when that yields
    # nothing, which is exactly the LayoutError case, so every table that
    # renders today renders identically afterwards.  Nothing is truncated:
    # the version list continues on the next page under the repeated header.
    # The flag is therefore added to every table in this module that
    # declares splitByRow (the explicit declaration marks the wide data
    # tables whose cells this can happen to) -- any narrow cell that joins a
    # list can cross the frame height on a future target (probe:
    # probe_table_split.py, split() -> 0 pieces before, 2 after).
    t=Table(rows,colWidths=[3.10*cm,1.42*cm,0.95*cm,2.99*cm,1.71*cm,1.04*cm,1.46*cm,1.56*cm,1.70*cm,1.47*cm],


            repeatRows=1, splitByRow=1, splitInRow=1)


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


                            ("TEXTCOLOR",(0,0),(-1,0),WHITE),


                            ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),


                            # H1: widest table in the report (10 columns).  Its
                            # content needs more room than the 17.4cm frame
                            # grants at reportlab's 6pt default, and widths
                            # alone cannot give it - shaving columns instead
                            # broke ~60 package names mid-token.  4pt per side
                            # frees 0.14cm per column, which is enough for every
                            # column to keep every token that fits today while
                            # the total lands exactly on the frame.  Measured by
                            # rendering, not estimated.  Other tables untouched.
                            ("LEFTPADDING",(0,0),(-1,-1),4),
                            ("RIGHTPADDING",(0,0),(-1,-1),4),


                            ("FONTSIZE",(0,0),(-1,-1),7)]))


    story.append(t)


    # The Type and CVSS cell legends moved ABOVE the table (see the
    # "Everything a reader needs" block before the header row): this table
    # runs ~100 pages and a legend printed after row 823 is never read.


    story.append(Spacer(1, 0.1*cm))


    # G-001/G-002: caption derived from the provenance the table above
    # actually carries, so a live-sourced report cannot be captioned offline
    # (nor the reverse) - both the header and the sentence come from the one
    # shared module rather than being restated here.
    _epss_prov, _kev_prov = provenance_pair(payload)
    _agg_warn = ""
    if (payload.get("metadata") or {}).get("aggregates_inconsistent"):
        # T-1.3: a broken aggregate must surface in every artifact's
        # provenance line, not only in the ERROR log.
        _agg_warn = (" WARNING: report aggregates failed their consistency "
                     "checks (metadata.aggregates_inconsistent); treat the "
                     "totals above as unreliable.")
    story.append(Paragraph(
        f"<b>EPSS provenance: {_epss_prov} / KEV provenance: {_kev_prov}.</b> "
        + html.escape(note_from_payload(payload) + _agg_warn),
        S["BodySmall"]))


    if vuln_deps:


        story.append(Spacer(1, 0.25*cm))


        story.append(Paragraph("<b>Developer Upgrade Guidance</b>", S["SubTitle"]))


        story.append(Paragraph(


            "For each vulnerable dependency, select a compatible fixed version from the advisory set "


            "and update the manifest and lockfile together. Do not blindly downgrade a package when an "


            "advisory lists an older fixed branch; choose a fixed version compatible with the application's "


            "current major version. After upgrading, run the project's tests, rebuild, and re-scan the SBOM.",


            S["BodySmall"]))


        action_rows = [[Paragraph(h, S["TH"]) for h in ["Package", "Current", "Developer Action"]]]


        for pkg in vuln_deps[:15]:


            fixed_raw = pkg.get("fixed_versions") or pkg.get("fixed_in")


            if isinstance(fixed_raw, list):


                fixed_text = ", ".join(str(x) for x in fixed_raw[:3])


            else:


                fixed_text = str(fixed_raw or "").strip()


            if not fixed_text or fixed_text.lower() in {"unknown", "--"}:


                action = "No fixed version published in the advisory data; investigate a supported patched release or replace the dependency."


            else:


                action = f"Upgrade to a compatible fixed release (advisory: {fixed_text}). Then run tests and re-scan."


            action_rows.append([


                Paragraph(str(pkg.get("name") or "--"), S["TDSm"]),


                Paragraph(str(value_state.cell(pkg, "version")), S["TDC"]),


                Paragraph(action, S["TDSm"]),


            ])


        at = Table(action_rows, colWidths=[3.5*cm, 2.2*cm, 11.3*cm], splitByRow=1, splitInRow=1, repeatRows=1)


        at.setStyle(TableStyle([


            ("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


            ("TEXTCOLOR",(0,0),(-1,0),WHITE),


            ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


            ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


            ("FONTSIZE",(0,0),(-1,-1),7.5),


        ]))


        story.append(at)


    return story





def _iac_section(payload):


    story=_sec("Infrastructure / IaC")


    meta=payload.get("metadata", {}) or {}


    k8s=int(meta.get("k8s_findings",0) or 0)


    tf=int(meta.get("tf_findings",0) or 0)


    docker=int(meta.get("docker_findings",0) or 0)


    total=int(meta.get("iac_findings",k8s+tf+docker) or 0)


    story.append(Paragraph(


        f"<b>{total} Infrastructure / IaC findings</b> were recorded: "


        f"{k8s} Kubernetes, {tf} Terraform, and {docker} Dockerfile findings. "


        "These IaC findings are a sub-population of the SAST records in the "
        "report totals -- not a separate total. Counts are derived from the "
        "scanner rule families present in the canonical payload.",


        S["Body"]))


    rows=[[Paragraph(h,S["TH"]) for h in ["Type","Rule","Severity","File","Line","Finding"]]]


    iac=[]


    seen=set()


    for f in list(payload.get("grouped",[]) or []) + list(payload.get("findings",[]) or []):


        rid=str(f.get("rule_id",""))


        vt=str(f.get("vuln_type",""))


        if rid.startswith(("K8S_","TF_","DOCKER_")) or vt.startswith(("k8s_","tf_","docker_","iac_")):


            key=(rid,str(f.get("file") or f.get("file_path") or ""),str(f.get("line") or ""),str(f.get("title") or ""))


            if key not in seen:


                seen.add(key)


                iac.append(f)


    for f in iac[:30]:


        rows.append([


            Paragraph("Kubernetes" if str(f.get("rule_id","")).startswith("K8S_") else


                      "Terraform" if str(f.get("rule_id","")).startswith("TF_") else "Dockerfile", S["TDSm"]),


            Paragraph(str(f.get("rule_id") or "--"),S["TDSm"]),


            Paragraph(str(f.get("severity") or "--"),S["TDC"]),


            Paragraph(str(f.get("file") or f.get("file_path") or "--"),S["TDSm"]),


            Paragraph(str(f.get("line") or "--"),S["TDC"]),


            Paragraph(str(f.get("title") or f.get("description") or "--"),S["TDSm"]),


        ])


    if len(rows)==1:


        rows.append([Paragraph("--",S["TDC"])]*6)


    # H1: 18.00cm in a 17.40cm frame.  Two cells hold single unbreakable
    # tokens - the rule id 'TF_OPEN_SECURITY_GROUP_INGRESS' (5.24cm) and the
    # path 'juice-shop-git/infrastructure/terraform/networking.tf' (5.95cm) -
    # which both wrapped mid-token at 2.5 / 5.0.  All six columns plus both
    # of those fit inside 17.40, so nothing here breaks except at spaces.
    t=Table(rows,colWidths=[1.6*cm,5.24*cm,1.59*cm,5.95*cm,1.05*cm,1.97*cm],repeatRows=1,splitByRow=1,splitInRow=1)


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),


                           ("GRID",(0,0),(-1,-1),0.5,GREY_MED),("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                           ("FONTSIZE",(0,0),(-1,-1),7),("VALIGN",(0,0),(-1,-1),"TOP")]))


    story.append(t)


    return story








def _licensing_section(payload):


    story=_sec("Licensing Details")


    summary=payload.get("license_evidence_summary",{}) or {}


    policy=payload.get("license_policy_summary",{}) or {}


    cats=summary.get("category_counts",{}) or {}


    # Build the category list FROM the counts rather than from a fixed set of


    # names.  The old list named four categories, two of which never occur, and


    # omitted the two that do -- so "Known / Canonical: 48" never appeared while


    # the sentence above it claimed all 168 components were covered.  Iterating


    # the counter makes that class of omission impossible: anything present is


    # printed, anything absent is not.


    _cat_order = (


        "Permissive",


        "Known / Canonical",


        "Composite / Review",


        "Custom / Review",


        "Evidence Unavailable",


        "Unknown",


    )


    _names = [c for c in _cat_order if cats.get(c)]


    _names += [c for c in sorted(cats) if c not in _cat_order and cats.get(c)]


    cats_text = (


        "; ".join(f"{c}: <b>{int(cats.get(c, 0))}</b>" for c in _names)


        if _names else "no licence categories recorded"


    )


    _status_counts = summary.get("resolution_status_counts", {}) or {}


    _total = int(


        summary.get("total_components", len(payload.get("sbom", []) or []))


    )


    _resolved = int(_status_counts.get("RESOLVED_FROM_CANONICAL_REPORT", 0))


    _no_evidence = int(_status_counts.get("NO_LICENSE_EVIDENCE", 0))


    story.append(Paragraph(


        f"<b>{_total}</b> components assessed for licence evidence: "


        f"<b>{_resolved}</b> resolved from the canonical report, "


        f"<b>{_no_evidence}</b> with no licence evidence available. "


        f"{cats_text}. "


        f"Evidence review required: <b>{summary.get('review_required_components', 0)}</b>; "


        f"Policy review required: <b>{summary.get('policy_review_required_components', 0)}</b>; "


        f"Legal review required: <b>{summary.get('legal_review_required_components', 0)}</b>; "


        f"Unknown license components: <b>{summary.get('unknown_license_components', 0)}</b>. "


        f"Existing policy summary status remains "
        f"<b>{humanize_enum(policy.get('summary_status') or 'NOT_AVAILABLE')}</b>. "
        "Records below are ordered by resolved licence, then by component name.",


        S["Body"]))


    # L12 -- presentation only. Two of this table's nine columns were measured
    # across all 168 evidence rows and are constant: `license_review_required`
    # prints "No" 168 times, `license_provenance` prints an identical string
    # 168 times. A column whose every cell reads the same thing costs width
    # and tells a reader nothing, so both are dropped from the render. The
    # fields themselves stay in the payload exactly as delivered -- the JSON
    # contract is untouched by this; only what the PDF draws changes.
    #
    # Column widths below are derived, not eyeballed. reportlab wraps a
    # Paragraph only at spaces, so each column is set from
    # pdfmetrics.stringWidth against the shipped payload:
    #   widest unbreakable token + 6pt left + 6pt right padding.
    #     Component 4.23 + 0.42 = 4.65  @fortawesome/fontawesome-svg-core
    #     Source    2.61 + 0.42 = 3.03  CANONICAL_REPORT
    # At the old 2.55 and 1.74 cm both were force-split mid-token. Dropping
    # the two constant columns frees 3.59 cm, which is what pays for that:
    # Component and Source are set to 4.77 and 3.11 cm (minimum plus a
    # proportional share of the 0.20 cm left over), and the five columns that
    # already fitted keep their original widths untouched. All seven still
    # total exactly the 17.40 cm frame this table has always occupied.
    #
    # JSON redundancy, documented rather than "repaired": on this payload
    # license_declared, license_resolved, license_expression and
    # license_evidence_raw carry the same four distinct values, and
    # license_evidence is null on every row. Collapsing them would change
    # the payload contract, so all eight licence fields are retained as
    # delivered and the redundancy is reported instead of acted on.
    rows=[[Paragraph(h,S["TH"]) for h in [


        "Component","Version","Declared License","Resolved License",


        "License Category","Resolution Status","Evidence Source"


    ]]]


    evidence_rows=payload.get("license_evidence",[]) or []

    # Ordered by resolved licence, then component -- one contiguous block per
    # licence so "what ships under LGPL here?" is a single read.  sorted()
    # copies: the L12 contract test requires the payload to come back
    # untouched, and the Excel Licensing Details sheet sorts its rows with
    # the same shared key (license_sort_key) so both artifacts agree.
    for item in sorted(evidence_rows,key=license_sort_key):


        rows.append([


            Paragraph(str(item.get("package") or "--"),S["TDSm"]),


            Paragraph(str(item.get("version") or "--"),S["TDC"]),


            Paragraph(value_state.cell(item, "license_declared", has_advisory=False),S["TDSm"]),


            Paragraph(value_state.cell(item, "license_resolved", has_advisory=False),S["TDSm"]),


            Paragraph(value_state.cell(item, "license_category", has_advisory=False),S["TDSm"]),


            Paragraph(humanize_enum(value_state.cell(item, "license_resolution_status", has_advisory=False)),S["TDSm"]),


            Paragraph(str(item.get("license_evidence_source") or "--"),S["TDSm"]),


        ])


    if len(rows)==1:


        rows.append([Paragraph("--",S["TDC"])]*7)


    t=Table(


        rows,


        colWidths=[4.77*cm,1.61*cm,2.10*cm,2.10*cm,1.72*cm,1.99*cm,3.11*cm],


        repeatRows=1,splitByRow=1,splitInRow=1


    )


    t.setStyle(TableStyle([


        ("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


        ("TEXTCOLOR",(0,0),(-1,0),WHITE),


        ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


        ("FONTSIZE",(0,0),(-1,-1),6.5),


        ("VALIGN",(0,0),(-1,-1),"TOP"),


        ("TOPPADDING",(0,0),(-1,-1),3),


        ("BOTTOMPADDING",(0,0),(-1,-1),3),


    ]))


    story.append(t)


    return story







def _conclusion(payload):


    story=_sec("7. Conclusion & Remediation SLA")


    # DEF-A: the closing headline and SLA table read the same aggregate as
    # the cover and the executive summary.
    _aggd=_agg(payload); dist=_aggd["severity"]["combined"]


    meta=payload.get("metadata",{}); risk=meta.get("risk_score",0)


    story.append(Paragraph(


        f"This assessment identified <b>{_aggd['counts']['total_reported']} unique findings</b> "


        f"with a portfolio risk score of <b>{risk}/100</b>. "


        f"All critical and high findings must be verified post-remediation before next production release.",S["Body"]))


    story.append(Spacer(1,0.3*cm))


    rows=[[Paragraph(h,S["TH"]) for h in ["Priority","Severity","Count","SLA","Owner"]],


          ["P1","Critical",str(dist.get("Critical",0)),"< 24 hours","Security Team + Dev Lead"],


          ["P2","High",    str(dist.get("High",    0)),"7 days",     "Dev Team"],


          ["P3","Medium",  str(dist.get("Medium",  0)),"30 days",    "Dev Team"],


          ["P4","Low",     str(dist.get("Low",     0)),"90 days",    "Dev Team (backlog)"]]


    # H1: 18.00cm in a 17.40cm frame.  These cells are plain strings, which
    # reportlab does not wrap, so each whole value must fit - the longest,
    # 'Security Team + Dev Lead', needs 4.19cm and still has 5.86cm.
    t=Table(rows,colWidths=[1.95*cm,3.35*cm,2.4*cm,3.84*cm,5.86*cm])


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),


                            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),


                            ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                            ("ALIGN",(0,0),(-1,-1),"CENTER"),


                            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),


                            ("FONTSIZE",(0,0),(-1,-1),9)]))


    story.append(t); story.append(Spacer(1,0.4*cm))


    story.append(Paragraph("This report is confidential and restricted to authorized personnel.",S["Body"]))





    # Final Recommendation block 

    story.append(Spacer(1,0.5*cm))


    story+=_sec("Final Recommendation")





    crit  = dist.get("Critical", 0)


    high  = dist.get("High",     0)


    grouped = payload.get("grouped", [])





    # Collect the most severe vuln titles for the bullet list


    critical_vulns = [f.get("title","") for f in grouped


                      if f.get("severity") in ("Critical","High")][:5]





    release_readiness = payload.get("release_readiness", {}) or {}


    executive_decision = payload.get("executive_decision", {}) or {}


    # One formatter for both decisions (taskf T-2.1): a real decision
    # prints, an absent/placeholder one dashes -- the old truthy-string
    # fallback chain could not tell "engine did not decide" from a value.
    release_decision = value_state.cell(
        release_readiness, "release_decision", has_advisory=False)
    if release_decision == "--":
        release_decision = value_state.cell(
            meta, "canonical_release_decision", has_advisory=False)


    executive_decision_value = value_state.cell(
        executive_decision, "executive_decision", has_advisory=False)
    if executive_decision_value == "--":
        executive_decision_value = value_state.cell(
            meta, "executive_decision", has_advisory=False)


    # Final recommendation follows the higher-level executive decision when present,


    # while keeping the underlying release-readiness decision visible.


    canonical_decision = executive_decision_value if executive_decision_value != "--" else release_decision


    blocking = release_decision == "DO_NOT_RELEASE"


    remediation_required = release_decision == "REMEDIATE_BEFORE_RELEASE"


    review_required = canonical_decision == "SECURITY_REVIEW_REQUIRED"


    conditional = canonical_decision == "CONDITIONAL_RELEASE"


    review_gates = release_readiness.get("review_gates", []) or []


    blocking_gates = release_readiness.get("blocking_gates", []) or []





    if blocking:


        # Red DO NOT RELEASE banner


        banner_tbl = Table(


            [[Paragraph("š   DO NOT RELEASE", _s("Banner",


                fontName="Helvetica-Bold", fontSize=14,


                textColor=WHITE, alignment=TA_CENTER, leading=18))]],


            colWidths=[17*cm]


        )


        banner_tbl.setStyle(TableStyle([


            ("BACKGROUND",    (0,0), (-1,-1), RED),


            ("TOPPADDING",    (0,0), (-1,-1), 10),


            ("BOTTOMPADDING", (0,0), (-1,-1), 10),


            ("LEFTPADDING",   (0,0), (-1,-1), 8),


        ]))


        story.append(banner_tbl)


        story.append(Spacer(1, 0.3*cm))





        story.append(Paragraph(


            f"Executive decision: <b>{executive_decision_value}</b>. "


            f"Release readiness: <b>{release_decision}</b>. "


            "Production deployment is <b>blocked</b> until the blocking decision is remediated "


            "or formally risk-accepted and re-verified by a full re-scan.",


            S["Body"]


        ))


        story.append(Spacer(1, 0.2*cm))





        if blocking_gates:


            story.append(Paragraph("<b>Blocking governance gates:</b>", S["BodySmall"]))


            for gate in blocking_gates[:8]:


                gate_id = str(gate.get("gate_id") or "Unknown gate")


                reason = str(gate.get("reason") or "")


                story.append(Paragraph(f"* {gate_id}: {reason}", S["Bullet"]))


        elif critical_vulns:


            story.append(Paragraph("<b>Critical / High findings requiring attention:</b>", S["BodySmall"]))


            for title in critical_vulns:


                story.append(Paragraph(f"* {title}", S["Bullet"]))





        story.append(Spacer(1, 0.3*cm))


        story.append(Paragraph(


            "<b>Required actions before re-scan:</b>",


            S["BodySmall"]


        ))


        actions = [


            "Remediate each blocking gate and its supporting evidence.",


            "Complete required security/governance sign-off or formally record risk acceptance.",


            "Perform a full re-scan after material remediation changes.",


            "Verify that the final release decision is recalculated from the canonical JSON payload.",


        ]


        for a in actions:


            story.append(Paragraph(f"* {a}", S["Bullet"]))


    elif remediation_required:


        banner_tbl = Table(


            [[Paragraph("REMEDIATE BEFORE RELEASE: NOT APPROVED", _s("BannerRemediate",


                fontName="Helvetica-Bold", fontSize=12,


                textColor=WHITE, alignment=TA_CENTER, leading=16))]],


            colWidths=[17*cm]


        )


        banner_tbl.setStyle(TableStyle([


            ("BACKGROUND", (0,0), (-1,-1), RED),


            ("TOPPADDING", (0,0), (-1,-1), 9),


            ("BOTTOMPADDING", (0,0), (-1,-1), 9),


        ]))


        story.append(banner_tbl)


        story.append(Spacer(1, 0.3*cm))


        story.append(Paragraph(


            # L7: "not approved because the canonical release-readiness decision
            # requires remediation before release" gave the conclusion as its own
            # cause.  Name what actually blocks the build instead.
            "Release is <b>not approved</b>. "
            + ("The blocking gates below are each a release blocker in their own "
               "right and must be cleared first. " if blocking_gates else "")
            + "Clear each one by remediating the underlying finding, or by "
              "recording formal risk acceptance from a named owner, then "
              "re-run the assessment.",


            S["Body"]


        ))


        # D5: the blocking branch prints these two lines; this branch used
        # not to, so executive_decision=DO_NOT_RELEASE over
        # release_decision=REMEDIATE_BEFORE_RELEASE (the Juice Shop payload)
        # reached zero pages. Both decision layers always render.
        story.append(Paragraph(
            f"Executive decision: <b>{executive_decision_value}</b>. "
            f"Release readiness: <b>{release_decision}</b>.",
            S["Body"]))


        story.append(Spacer(1, 0.2*cm))


        for gate in blocking_gates[:8]:


            story.append(Paragraph(


                f"* {gate.get('gate_id','Unknown gate')}: {gate.get('reason','')}",


                S["Bullet"]


            ))


        for gate in review_gates[:8]:


            story.append(Paragraph(


                f"* Review gate - {gate.get('gate_id','Unknown gate')}: {gate.get('reason','')}",


                S["Bullet"]


            ))


        story.append(Spacer(1, 0.2*cm))


        story.append(Paragraph(


            "<b>Required actions:</b> remediate or formally risk-accept blocking gates, complete security review, and re-scan.",


            S["BodySmall"]


        ))





    elif review_required:


        banner_tbl = Table(


            [[Paragraph("SECURITY REVIEW REQUIRED: NOT APPROVED", _s("BannerReview",


                fontName="Helvetica-Bold", fontSize=12,


                textColor=WHITE, alignment=TA_CENTER, leading=16))]],


            colWidths=[17*cm]


        )


        banner_tbl.setStyle(TableStyle([


            ("BACKGROUND", (0,0), (-1,-1), ORANGE),


            ("TOPPADDING", (0,0), (-1,-1), 9),


            ("BOTTOMPADDING", (0,0), (-1,-1), 9),


        ]))


        story.append(banner_tbl)


        story.append(Spacer(1, 0.3*cm))


        story.append(Paragraph(


            "Release is <b>not approved</b> until the required security/governance review is completed and the decision is explicitly recorded.",


            S["Body"]


        ))


        # D5: same rule as the remediation branch -- both decision layers
        # always render, whichever branch the payload lands in.
        story.append(Paragraph(
            f"Executive decision: <b>{executive_decision_value}</b>. "
            f"Release readiness: <b>{release_decision}</b>.",
            S["Body"]))


        story.append(Spacer(1, 0.2*cm))


        story.append(Paragraph("<b>Required review actions:</b>", S["BodySmall"]))





        # Keep recommendation text aligned with the canonical decision


        # and the actual severity/governance state. Do not claim that


        # P1/P2 findings require review when both counts are zero.


        review_actions = []





        try:


            critical_count = int(crit or 0)


        except (TypeError, ValueError):


            critical_count = 0





        try:


            high_count = int(high or 0)


        except (TypeError, ValueError):


            high_count = 0





        if critical_count > 0 or high_count > 0:


            review_actions.append(


                "Review the P1/P2 findings and associated governance gates."


            )


        elif review_gates:


            review_actions.append(


                "Review the associated governance gates."


            )





        if review_gates:


            for gate in review_gates[:8]:


                gate_id = str(gate.get("gate_id") or "Unknown gate")


                reason = str(gate.get("reason") or "").strip()





                if reason:


                    review_actions.append(


                        f"Review gate - {gate_id}: {reason}"


                    )


                else:


                    review_actions.append(


                        f"Review gate - {gate_id}."


                    )





        review_actions.append(


            "Complete security/governance sign-off or formally record risk acceptance."


        )





        review_actions.append(


            "Re-run the assessment after material remediation changes."


        )





        for action in review_actions:


            story.append(Paragraph(f"* {action}", S["Bullet"]))





    elif conditional:


        banner_tbl = Table(


            [[Paragraph("CONDITIONAL RELEASE", _s("BannerConditional",


                fontName="Helvetica-Bold", fontSize=12,


                textColor=WHITE, alignment=TA_CENTER, leading=16))]],


            colWidths=[17*cm]


        )


        banner_tbl.setStyle(TableStyle([


            ("BACKGROUND", (0,0), (-1,-1), GREEN),


            ("TOPPADDING", (0,0), (-1,-1), 8),


            ("BOTTOMPADDING", (0,0), (-1,-1), 8),


        ]))


        story.append(banner_tbl)


        story.append(Spacer(1, 0.3*cm))


        story.append(Paragraph(


            "Release may proceed only under the documented conditions, owner approval, monitoring, and follow-up remediation.",


            S["Body"]


        ))


        # D5: both decision layers always render, whichever branch the
        # payload lands in.
        story.append(Paragraph(
            f"Executive decision: <b>{executive_decision_value}</b>. "
            f"Release readiness: <b>{release_decision}</b>.",
            S["Body"]))





    else:


        banner_tbl = Table(


            [[Paragraph(" RELEASE READY", _s("BannerOK",


                fontName="Helvetica-Bold", fontSize=12,


                textColor=WHITE, alignment=TA_CENTER, leading=16))]],


            colWidths=[17*cm]


        )


        banner_tbl.setStyle(TableStyle([


            ("BACKGROUND", (0,0), (-1,-1), GREEN),


            ("TOPPADDING", (0,0), (-1,-1), 8),


            ("BOTTOMPADDING", (0,0), (-1,-1), 8),


        ]))


        story.append(banner_tbl)


        story.append(Spacer(1, 0.3*cm))


        story.append(Paragraph(


            "No release-blocking governance gates were triggered.",


            S["Body"]


        ))





    return story






# Booleans and collections must never reach a client-facing table through
# str(): the ABOM/API-BOM sections printed 50 bare "True"/"False" and 412
# Python list reprs ("[':id']", "['POST']") that way.
def _bom_scalar_text(value) -> str:
    """Render one BOM value without leaking Python repr syntax."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        return ", ".join(part for part in (_bom_scalar_text(v) for v in value) if part)
    if isinstance(value, dict):
        return "; ".join(f"{k}={_bom_scalar_text(v)}" for k, v in value.items())
    # Machine status identifiers (AUTH_HINT_PRESENT, MODEL_HINT, UNKNOWN, ...)
    # are rendered as words here rather than shouted back at the reader.
    return humanize_enum(value)


# Hot path for BOM path normalisation.  The two patterns below used to be
# recompiled through the re cache once per cell value (56.5M cache lookups
# on a transformers-sized report); the common-root walk used to run once
# per cell as well (80.5M recursive visits).  Both are now per-payload.
_BOM_ABS_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_BOM_JUICE_SHOP_RE = re.compile(r"(?:^|[\\/])(juice-shop-git)[\\/](.+)$", re.I)

# Single-entry memo: (payload_object, common_root).  Holding a reference to
# the payload keeps id() unique for as long as the entry lives; the cache is
# replaced wholesale on a miss so it can never leak or go stale across the
# two render passes (both passes share the same normalised payload object).
_BOM_PATH_ROOT_CACHE: dict = {}


def _bom_common_path_root(payload: dict) -> str:
    """Common filesystem root of every absolute path in the BOM trees.

    Computed once per payload instead of once per rendered cell.  The value
    is identical to what the previous per-cell walk returned because the
    candidate set depends only on the payload, never on the cell being
    rendered.
    """
    import os as _os

    key = id(payload)
    hit = _BOM_PATH_ROOT_CACHE.get(key)
    if hit is not None and hit[0] is payload:
        return hit[1]

    candidates = []

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str) and (_BOM_ABS_PATH_RE.match(v) or v.startswith("/")):
            candidates.append(v)

    for k in ("cbom", "aibom", "mlbom", "apibom", "abom"):
        walk(payload.get(k, []) or [])

    root = ""
    if candidates:
        try:
            root = _os.path.commonpath([_os.path.normpath(x) for x in candidates])
        except Exception:
            root = ""

    _BOM_PATH_ROOT_CACHE.clear()
    _BOM_PATH_ROOT_CACHE[key] = (payload, root)
    return root


def _bom_display_value(value, payload: dict) -> str:

    """Normalize report-facing BOM paths without changing canonical payload data."""

    import os, html

    text = _bom_scalar_text(value)

    if not text:
        return ""

    if _BOM_ABS_PATH_RE.match(text) or text.startswith("/"):
        root = _bom_common_path_root(payload)

        try:
            if root:
                cur = os.path.normpath(text)
                if os.path.commonpath([root, cur]) == root:
                    rel = os.path.relpath(cur, root)
                    if rel and rel != ".":
                        text = rel
        except Exception:
            pass

        if _BOM_ABS_PATH_RE.match(text):
            m = _BOM_JUICE_SHOP_RE.search(text)
            if m:
                text = m.group(2)
            else:
                text = os.path.basename(text)
        elif text.startswith("/"):
            text = text.lstrip("/")

    return html.escape(text).replace("\n", "<br/>")











# Maximum source lines in one rendered code Paragraph.
#
# Derived from measurement, not guessed: the Code style leads at ~11 points, so
# 50 one-word lines measure 550 points. 55 lines stays near 605 points, with
# headroom under the 665.48-point Findings frame. Character count alone does
# not bound height -- 1200 single-character lines would be ~13,200 points --
# so height needs its own axis.
_CODE_MAX_LINES = 55


def _split_oversized_line(line: str, max_chars: int) -> list:
    """Break one over-long line into pieces of at most max_chars.

    A minified or bundled asset is ONE source line with no whitespace, and the
    chunker used to bound only the running TOTAL across lines -- so a single
    enormous line bypassed max_chars entirely and became one Paragraph.

    Prefers a whitespace boundary near the limit so a line that does have spaces
    is not cut mid-word; falls back to a hard cut, because an unbreakable run is
    exactly the case that has to be handled.
    """
    if max_chars <= 0 or len(line) <= max_chars:
        return [line]
    out = []
    remaining = line
    while len(remaining) > max_chars:
        window = remaining[:max_chars]
        cut = window.rfind(" ")
        if cut < max_chars // 2:
            # No usable space, or one so close to the limit that it would leave
            # a near-empty chunk.
            cut = max_chars
        out.append(remaining[:cut])
        remaining = remaining[cut:]
    if remaining:
        out.append(remaining)
    return out


def _code_safe_paragraph_chunks(value, style, max_chars: int = 1200) -> list:


    """


    Render source/code as escaped ReportLab Paragraphs.





    The source may legitimately contain HTML-like text such as:


        <br/>


        <html>


        &quot;


    Those must remain code, not ReportLab markup.





    Chunking is performed on raw source text before HTML escaping so


    entities/tags can never be split across paragraph chunks.


    """


    raw = "" if value is None else str(value)


    raw = html.unescape(raw)





    if not raw:


        raw = "[no snippet]"





    lines = raw.splitlines()


    if not lines:


        lines = [raw]





    raw_chunks = []


    current = []


    current_len = 0





    for line in lines:


        # Preserve source line boundaries.


        addition = len(line) + (1 if current else 0)





        if current and current_len + addition > max_chars:


            raw_chunks.append("\n".join(current))


            current = [line]


            current_len = len(line)


        else:


            current.append(line)


            current_len += addition





    if current:


        raw_chunks.append("\n".join(current))

    # Only the running TOTAL across lines used to be bounded, so a single
    # over-long line bypassed max_chars entirely: a minified asset became one
    # Paragraph of arbitrary length.
    #
    # Fix: pre-split any over-long line into max_chars pieces, then re-run the
    # ORIGINAL grouping over the expanded line list. Re-grouping rather than
    # flattening is deliberate: flattening made every source line its own
    # Paragraph, which changed layout for every report in the product. Because
    # the expansion is a no-op when no line exceeds the cap, ordinary
    # multi-line snippets group exactly as they did before.
    #
    # Each piece is its own Paragraph. Re-joining pieces with a newline would
    # put them back inside one Paragraph as <br/>-separated lines, and each
    # 1200-char piece still wraps to ~20 lines -- which is how an 80,015-char
    # minified line produced a 9537-point paragraph, far beyond the 665-point
    # frame. Measured: a 1200-char unbreakable token wraps to 72.0 points.
    expanded = []
    for _chunk in raw_chunks:
        for _line in _chunk.split("\n"):
            expanded.extend(_split_oversized_line(_line, max_chars))
    raw_chunks = []
    current = []
    current_len = 0
    for _line in expanded:
        _add = len(_line) + (1 if current else 0)
        # Bound BOTH axes. The character bound alone still lets many short
        # lines group into one Paragraph: the Code style leads at ~11 points,
        # so 50 one-word lines measure 550 points against a 665-point frame,
        # and 1200 single-character lines would be about 13,200 points -- the
        # same LayoutError by the other route.
        if current and (current_len + _add > max_chars
                      or len(current) >= _CODE_MAX_LINES):
            raw_chunks.append("\n".join(current))
            current = [_line]
            current_len = len(_line)
        else:
            current.append(_line)
            current_len += _add
    if current:
        raw_chunks.append("\n".join(current))










    paragraphs = []





    for chunk in raw_chunks:


        escaped = html.escape(chunk, quote=False).replace("\n", "<br/>")


        paragraphs.append(Paragraph(escaped, style))





    return paragraphs








def _bom_safe_chunks(rendered: str, max_chars: int = 900) -> list:


    """


    Safely chunk the already-normalized BOM display value.





    _bom_display_value() returns escaped text with <br/> line breaks.


    Convert back to raw display text, chunk safely, then escape again.


    This prevents splitting <br/> or HTML entities across chunks.


    """


    text = html.unescape(str(rendered or "")).replace("<br/>", "\n")





    if not text:


        return [""]





    raw_chunks = []


    current = []


    current_len = 0





    for line in text.splitlines():


        # Split very long individual lines on raw characters.


        if len(line) <= max_chars:


            pieces = [line]


        else:


            pieces = [


                line[i:i + max_chars]


                for i in range(0, len(line), max_chars)


            ]





        for piece in pieces:


            addition = len(piece) + (1 if current else 0)





            if current and current_len + addition > max_chars:


                raw_chunks.append("\n".join(current))


                current = [piece]


                current_len = len(piece)


            else:


                current.append(piece)


                current_len += addition





    if current:


        raw_chunks.append("\n".join(current))





    return [


        html.escape(chunk, quote=False).replace("\n", "<br/>")


        for chunk in raw_chunks


    ]








def _bom_detail_section(payload: dict, title: str, key: str) -> list:


    """Render BOM data as bounded Field/Value rows with an explicit empty state."""


    story = [Paragraph(title, S["SectionTitle"])]


    data = payload.get(key, []) or []





    if not data:


        empty_messages = {


            "cbom": "No cryptographic assets were detected in this scan.",


            "aibom": "No AI model or provider assets were detected in this scan.",


            "mlbom": "No ML framework or model assets were detected in this scan.",


            "apibom": "No API routes were detected in this scan.",


            "abom": "No AI agents were detected in this scan.",


        }





        message = empty_messages.get(


            str(key).strip().lower(),


            "No inventory records were detected in this scan.",


        )





        empty_table = Table(


            [[


                Paragraph("Inventory Status", S["TH"]),


                Paragraph(


                    html.escape(message),


                    S["TD"]


                ),


            ]],


            colWidths=[4.2*cm, 12.0*cm],


        )





        empty_table.setStyle(TableStyle([


            ("BACKGROUND", (0,0), (0,0), DARK_BLUE),


            ("TEXTCOLOR", (0,0), (0,0), WHITE),


            ("BACKGROUND", (1,0), (1,0), LIGHT_BLUE),


            ("GRID", (0,0), (-1,-1), 0.4, GREY_MED),


            ("FONTSIZE", (0,0), (-1,-1), 8),


            ("VALIGN", (0,0), (-1,-1), "TOP"),


            ("LEFTPADDING", (0,0), (-1,-1), 6),


            ("RIGHTPADDING", (0,0), (-1,-1), 6),


            ("TOPPADDING", (0,0), (-1,-1), 6),


            ("BOTTOMPADDING", (0,0), (-1,-1), 6),


        ]))





        story.append(empty_table)





        story.append(


            Spacer(1, 0.25*cm)


        )





        story.append(


            Paragraph(


                f"<b>Detected records:</b> 0",


                S["Body"]


            )


        )





        return story


    rows = [[Paragraph("Field", S["TH"]), Paragraph("Value", S["TH"])]]


    for index, item in enumerate(data, 1):


        if not isinstance(item, dict):


            item = {"value": item}


        for field, raw in item.items():


            rendered = _bom_display_value(raw, payload)


            if not rendered:


                rendered = ""


            # Keep each table row bounded while ensuring ReportLab markup


            # tags/entities are never split across chunk boundaries.


            chunks = _bom_safe_chunks(rendered, 900)


            for n, chunk in enumerate(chunks):


                label = str(field) if n == 0 else ""


                rows.append([


                    Paragraph(html.escape(label), S["TD"]),


                    Paragraph(chunk or "&nbsp;", S["TD"]),


                ])


    # Bounded table chunks.  reportlab re-measures every row of a Table on
    # each split pass, so a single Table with inventory-scale row counts
    # (~150k rows at benchmark scale) costs superlinearly -- measured
    # O(rows^1.9) on synthetic long-text tables.  Emitting the same rows as
    # consecutive same-styled tables of at most _BOM_TABLE_CHUNK body rows
    # keeps layout cost linear.  Every chunk repeats the header row, which
    # is exactly what repeatRows=1 already does at page breaks, so the
    # document is visually unchanged apart from chunk seams that read as
    # ordinary header repeats.  The even chunk size preserves the
    # WHITE/LIGHT_BLUE zebra parity across seams.  No row is dropped,
    # capped, abbreviated, or reordered.
    _BOM_TABLE_CHUNK = 400

    bom_style = TableStyle([
        ("BACKGROUND",(0,0),(-1,0),DARK_BLUE),
        ("TEXTCOLOR",(0,0),(-1,0),WHITE),
        ("GRID",(0,0),(-1,-1),0.4,GREY_MED),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),
        ("FONTSIZE",(0,0),(-1,-1),6),
        ("VALIGN",(0,0),(-1,-1),"TOP"),
        ("LEFTPADDING",(0,0),(-1,-1),4),
        ("RIGHTPADDING",(0,0),(-1,-1),4),
        ("TOPPADDING",(0,0),(-1,-1),3),
        ("BOTTOMPADDING",(0,0),(-1,-1),3),
    ])

    body_rows = rows[1:]
    if not body_rows:
        # Header-only table (every inventory item was an empty dict): keep
        # the previous single-table rendering rather than emitting nothing.
        t = Table(rows, colWidths=[4.2*cm, 12.0*cm], repeatRows=1)
        t.setStyle(bom_style)
        story.append(t)
        return story
    for _start in range(0, len(body_rows), _BOM_TABLE_CHUNK):
        part = [rows[0]] + body_rows[_start:_start + _BOM_TABLE_CHUNK]
        t = Table(part, colWidths=[4.2*cm, 12.0*cm], repeatRows=1)
        t.setStyle(bom_style)
        story.append(t)

    return story





def _advanced_bom_sections(payload: dict) -> list:


    story=[]


    sections=[


        ("CBOM - Cryptographic Bill of Materials","cbom","CBOM"),


        ("AI-BOM - AI Model and Provider Inventory","aibom","AIBOM"),


        ("ML-BOM - ML Framework and Model Inventory","mlbom","MLBOM"),


        ("API-BOM - API Route Inventory","apibom","APIBOM"),


        ("ABOM - AI Agent Inventory","abom","ABOM"),


    ]


    for title,key,template in sections:


        story.append(NextPageTemplate(template))


        story.append(PageBreak())


        story.append(_TocBookmark(title))


        story += _bom_detail_section(payload,title,key)


    return story





def _build_pdf_story(payload: dict, logo_path: str | None = None, page_map: dict | None = None) -> list:


    """Build a fresh story for ReportLab. Required for two-pass ToC rendering."""


    story: list = []


    story.append(NextPageTemplate("Cover"))


    story += _cover(payload, logo_path=logo_path)


    story += _toc_section(payload, page_map)


    story.append(NextPageTemplate("ExecSummary")); story.append(PageBreak())


    story.append(_TocBookmark("Executive Summary")); story += _exec_summary(payload)


    story.append(NextPageTemplate("TopCauses")); story.append(PageBreak())


    story.append(_TocBookmark("Top Root Causes")); story += _top_root_causes_section(payload)

    story += _sca_remediation_priority_section(payload)


    story.append(NextPageTemplate("Compliance")); story.append(PageBreak())


    story.append(_TocBookmark("Compliance Mapping")); story += _compliance(payload)


    story.append(NextPageTemplate("AttackPaths")); story.append(PageBreak())


    story.append(_TocBookmark("Attack Path Correlation")); story += _attack_paths_section(payload)


    story.append(NextPageTemplate("Findings")); story.append(PageBreak())


    story.append(_TocBookmark("Detailed Findings")); story += _findings_section(payload)


    story.append(NextPageTemplate("SBOM")); story.append(PageBreak())


    story.append(_TocBookmark("SBOM & Dependencies")); story += _sbom_section(payload)
    story.append(_TocBookmark("Post-Quantum Exposure")); story += _pq_qbom_section(payload)


    story += _iac_section(payload); story += _licensing_section(payload)


    story += _advanced_bom_sections(payload)


    story.append(NextPageTemplate("Conclusion")); story.append(PageBreak())


    # The conclusion bookmark is deliberately after all advanced BOM sections.


    # This makes the two-pass page map point to the actual conclusion page.


    story.append(_TocBookmark("Conclusion & Remediation SLA"))


    story += _conclusion(payload)


    return story





def _resolve_logo_path(output_path: str, logo_path: str | None = None) -> str | None:


    """Resolve the canonical R-SecOpsX logo deterministically.





    Resolution order:


      1. Explicit caller-supplied logo_path.


      2. logo.png beside this renderer (reporting/logo.png).


      3. logo.png at the production package root.


      4. logo.png beside the generated PDF.


      5. logo.png in the reports parent directory.


      6. logo.png in the current working directory.





    The module-relative location is the preferred deployment location because


    it travels with the PDF renderer and does not depend on the report output


    directory layout.


    """


    candidates = []


    if logo_path:


        candidates.append(Path(logo_path))





    module_dir = Path(__file__).resolve().parent


    candidates.extend([


        module_dir / "logo.png",


        module_dir.parent / "logo.png",


        Path(output_path).parent / "logo.png",


        Path(output_path).parent.parent / "logo.png",


        Path.cwd() / "logo.png",


    ])





    seen = set()


    for candidate in candidates:


        try:


            resolved = candidate.resolve()


        except Exception:


            resolved = candidate


        key = str(resolved).lower()


        if key in seen:


            continue


        seen.add(key)


        if resolved.is_file():


            return str(resolved)





    return None








def generate_pdf_report(payload:dict, output_path:str,


                        logo_path:str|None=None) -> str:


    payload = _pdf_normalize_payload(payload)
    """Generate PDF report with two-pass ToC page number rendering."""


    path=Path(output_path); path.parent.mkdir(parents=True,exist_ok=True)


    logo_path = _resolve_logo_path(output_path, logo_path)





    # First pass: build a temporary PDF to collect section page numbers.


    import tempfile


    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:


        tmp_path = tmp.name


    try:


        probe=_Doc(tmp_path,leftMargin=MARGIN,rightMargin=MARGIN,


                  topMargin=MARGIN+1.2*cm,bottomMargin=MARGIN+1.1*cm)


        probe.build(_build_pdf_story(payload, logo_path=logo_path, page_map=None))


        page_map = dict(getattr(probe, "_page_map", {}) or {})


    finally:


        try:


            os.remove(tmp_path)


        except Exception:


            pass





    # Second pass: final PDF with populated ToC page numbers.


    doc=_Doc(str(path),leftMargin=MARGIN,rightMargin=MARGIN,


              topMargin=MARGIN+1.2*cm,bottomMargin=MARGIN+1.1*cm)


    doc.build(_build_pdf_story(payload, logo_path=logo_path, page_map=page_map))


    return str(path)









