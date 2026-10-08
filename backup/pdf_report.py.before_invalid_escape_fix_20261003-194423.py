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





import io, os


from datetime import datetime


from core.config import TOOL_NAME, TOOL_FULL, CLASSIFICATION


from pathlib import Path


from reporting.report_mappings import clean_mojibake, normalize_fixed_versions, format_attack_path_label, normalize_report_insights





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


    Paragraph, Spacer, Table, TableStyle, PageBreak,


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
        "\[!]": "[!]",
        "\u2726": "*",
        "\u2022": "*",
    }

    for bad, good in replacements.items():
        text = text.replace(bad, good)

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





# â”€â”€ Large-text safety helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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





def _paragraph_chunks(value, style, max_chars=1800) -> list:


    return [Paragraph(c or "&nbsp;", style) for c in _escaped_chunks(value, max_chars)]





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





# â”€â”€ Charts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€





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





# â”€â”€ Page template â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€





# â”€â”€ PATCH 8: Section-aware page header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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


        """Record section â†’ page number for Table of Contents."""


        if hasattr(flowable, "_toc_bookmark"):


            self._page_map[flowable._toc_bookmark] = self.page








def _noop(c, d): pass








def _hf(canvas, doc):


    """PATCH 7+8+10: header with section name + footer with confidential notice."""


    canvas.saveState()


    w, h = A4


    section = _CURRENT_SECTION.get("label", "")


    tool    = TOOL_FULL





    # â”€â”€ Top header bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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


    # Right: tool name + page


    canvas.setFont("Helvetica", 7)


    canvas.drawRightString(w-MARGIN, h-0.58*cm,


                           f"Security Assessment Report  |  Page {doc.page}")


    # PATCH 10: thin gold separator


    canvas.setFillColor(GOLD)


    canvas.rect(0, h-1.35*cm, w, 0.04*cm, fill=1, stroke=0)





    # â”€â”€ Bottom footer bar (PATCH 10) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


    canvas.setFillColor(NAVY)


    canvas.rect(0, 0, w, 1.1*cm, fill=1, stroke=0)


    canvas.setFillColor(GOLD)


    canvas.rect(0, 1.05*cm, w, 0.05*cm, fill=1, stroke=0)


    canvas.setFillColor(WHITE)


    canvas.setFont("Helvetica", 7)


    canvas.drawString(MARGIN, 0.38*cm,


                      f"Generated by {TOOL_FULL}  |  "


                      f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")


    canvas.drawRightString(w-MARGIN, 0.38*cm, f"Page {doc.page}")


    canvas.restoreState()








# â”€â”€ PATCH 9: Table of Contents helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€





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





def _cover(payload, logo_path=None):


    meta   = payload.get("metadata",{})


    target = Path(meta.get("target","Unknown")).name or meta.get("target","Unknown")


    dist   = meta.get("severity_distribution",{})


    risk   = meta.get("risk_score",0)


    total  = meta.get("total_findings",0)


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





    sast_count = meta.get("sast_findings", total)


    sca_count  = meta.get("sca_findings",  0)


    findings_label = (f"{total}  (SAST: {sast_count} + SCA: {sca_count})"


                      if sca_count > 0 else str(total))





    info=Table([["Target System",target],["Scan Date",meta.get("scan_date","")[:10]],


                ["Classification","CONFIDENTIAL"],


                ["Total Findings",findings_label],


                ["Combined Severity",f"C:{dist.get('Critical',0)} H:{dist.get('High',0)} M:{dist.get('Medium',0)} L:{dist.get('Low',0)}"],


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





# â”€â”€ Section helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€





def _sec(title,level=1):


    return [HRFlowable(width="100%",thickness=2 if level==1 else 0.5,


                       color=DARK_BLUE if level==1 else MID_BLUE,spaceAfter=4),


            Paragraph(title,S["SectionTitle"] if level==1 else S["SubTitle"])]







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


        "Fixing the root cause in shared code eliminates all occurrences at once” "


        "highest remediation leverage.",


        S["Body"]


    ))


    story.append(Spacer(1, 0.3*cm))





    SEV_BG = {"Critical": RED, "High": ORANGE, "Medium": YELLOW,


              "Low": GREEN, "Info": colors.HexColor("#7F8C8D")}


    SEV_FG = {"Critical": WHITE, "High": WHITE, "Medium": BLACK,


              "Low": WHITE,     "Info": WHITE}





    rows = [[Paragraph(h, S["TH"]) for h in


             ["#", "Vulnerability", "Severity", "Occurrences", "Files Affected", "Age", "Risk Score"]]]





    for i, f in enumerate(top, 1):


        sev        = f.get("severity", "Medium")


        instances  = f.get("instances", 1)


        files      = len(f.get("affected_files", [f.get("file","")]))


        risk       = f.get("risk_score", "")


        risk_str   = f"{risk}" if risk else "N/A"


        age_days = f.get("vulnerability_age_days")


        age_bucket = f.get("vulnerability_age_bucket")


        age_str = (f"{age_days}d" + (f" ({age_bucket})" if age_bucket else "")) if age_days not in (None, "", "--") else str(f.get("vulnerability_age") or "--")





        sev_para = Paragraph(sev, _s(f"SevR{i}", fontName="Helvetica-Bold",


                                      fontSize=8, textColor=SEV_FG.get(sev, WHITE),


                                      alignment=TA_CENTER))


        rows.append([


            Paragraph(str(i),              S["TDC"]),


            Paragraph(f.get("title",""),   S["TD"]),


            sev_para,


            Paragraph(str(instances),      S["TDC"]),


            Paragraph(str(files),          S["TDC"]),


            Paragraph(str(age_str),         S["TDC"]),


            Paragraph(risk_str,            S["TDC"]),


        ])





    t = Table(rows, colWidths=[0.8*cm, 5.8*cm, 2.3*cm, 2.2*cm, 2.2*cm, 2.0*cm, 1.5*cm])


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


            f" âœ¦ Fixing this root cause eliminates {instances} occurrences across "


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








# â”€â”€ Executive summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€





def _exec_summary(payload):


    meta=payload.get("metadata",{}); dist=meta.get("severity_distribution",{})


    risk=meta.get("risk_score",0);   total=meta.get("total_findings",0)


    story=_sec("1. Executive Summary")


    # Issue 7: risk label aligns score with executive recommendation


    risk_label = (


        "CRITICAL - immediate remediation required" if risk >= 80 else


        "HIGH - address before next release"         if risk >= 60 else


        "MEDIUM - schedule remediation"              if risk >= 40 else


        "LOW - monitor and track"


    )


    sast_dist = meta.get("severity_distribution_sast", {})


    sca_dist = meta.get("severity_distribution_sca", {})


    sca_critical = int(sca_dist.get("Critical", 0) or 0)


    sca_high = int(sca_dist.get("High", 0) or 0)


    story.append(Paragraph(


        f"The security assessment of <b>{Path(meta.get('target','')).name or meta.get('target','')}</b> "


        f"identified <b>{total} unique findings</b> "


        f"(SAST: {meta.get('sast_findings', 0)} + SCA: {meta.get('sca_findings', 0)}). "


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


    ct=Table([[pi,bi]],colWidths=[8*cm,10*cm])


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


        if total_inst > 0:


            pct   = int(100 * top3_inst / total_inst)


            names = ", ".join(str(f.get("title", "")).strip() for f in top_causes[:3] if str(f.get("title", "")).strip())


            prio_tbl = Table([[Paragraph(


                f"<b>&#x26A1; Executive Prioritization:</b> Fixing the top "


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





# â”€â”€ Compliance â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€





def _compliance(payload):


    story=_sec("3. Compliance Mapping")





    # OWASP


    owasp=payload.get("owasp",{})


    if owasp:


        story+=_sec("OWASP Top 10",level=2)


        rows=[[Paragraph(h,S["TH"]) for h in ["OWASP ID","Category","Findings"]]]


        for oid,info in sorted(owasp.items()):


            rows.append([Paragraph(oid,S["TDC"]),Paragraph(info.get("category",""),S["TD"]),


                         Paragraph(str(info.get("count",0)),S["TDC"])])


        t=Table(rows,colWidths=[3*cm,11*cm,3*cm])


        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


                                ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                                ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                                ("FONTSIZE",(0,0),(-1,-1),8)]))


        story.append(t); story.append(Spacer(1,0.3*cm))





    # MITRE


    mitre=payload.get("mitre",[])


    if mitre:


        story+=_sec("MITRE ATT&amp;CK",level=2)


        rows=[[Paragraph(h,S["TH"]) for h in ["Technique ID","Description"]]]


        for te in mitre:


            rows.append([Paragraph(te.get("id",""),S["TDC"]),Paragraph(te.get("description",""),S["TD"])])


        t=Table(rows,colWidths=[4*cm,13*cm])


        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


                                ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                                ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                                ("FONTSIZE",(0,0),(-1,-1),8)]))


        story.append(t); story.append(Spacer(1,0.3*cm))





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


        t=Table(rows,colWidths=[4*cm,3.5*cm,3.5*cm,3.5*cm,3.5*cm],


                repeatRows=1)          # repeat header on every page


        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


                                ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                                ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),


                                ("FONTSIZE",(0,0),(-1,-1),7)]))


        # repeatRows=1 ensures the column header re-appears if table spans pages.


        story.append(t)


    return story








def _attack_paths_section(payload):


    story=_sec("4. Attack Path Correlation")


    paths=payload.get("attack_paths",[])


    if not paths:


        story.append(Paragraph("No multi-step attack chains detected.",S["Body"]))


        return story





    story.append(Paragraph(


        f"The following {len(paths)} attack path"


        f"{'s were' if len(paths)>1 else ' was'} identified by correlating "


        f"vulnerability findings into exploit chains. "


        f"These are modeled attack-path candidates; exploitability requires validated "


        f"source-to-sink evidence or explicit confirmation.",


        S["Body"]))


    story.append(Spacer(1,0.3*cm))





    for i,ap in enumerate(paths,1):


        sev=ap.get("severity","Medium"); sc=SEV_C.get(sev,GREY_MED)


        steps=ap.get("steps",[])


        chains=ap.get("chains_to",[])


        evidence_type = ap.get("evidence_type", "pattern-detected")


        evidence_note = ap.get("evidence_note", "")


        ev_color = "#E9F7EF" if evidence_type == "taint-confirmed" else "#FFF8E7"


        ev_border = colors.HexColor("#27AE60") if evidence_type == "taint-confirmed" else GOLD


        ev_label = format_attack_path_label(evidence_type == "taint-confirmed")





        hdr=Table([[Paragraph(f"Chain #{i:02d}",S["TH"]),


                    Paragraph(ap.get("title",""),S["TH"]),


                    Paragraph(sev.upper(),S["TH"]),


                    Paragraph(f"Risk: {ap.get('risk_score',0)}",S["TH"])]],


                  colWidths=[2.5*cm,9*cm,2.5*cm,3*cm])


        hdr.setStyle(TableStyle([("BACKGROUND",(0,0),(1,0),DARK_BLUE),


                                  ("BACKGROUND",(2,0),(2,0),sc),


                                  ("BACKGROUND",(3,0),(3,0),MID_BLUE),


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


        chain_tbl=Table(chain_rows, colWidths=[17*cm], splitByRow=1)


        chain_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),GREY_LIGHT),


                                        ("TOPPADDING",(0,0),(-1,-1),5),


                                        ("BOTTOMPADDING",(0,0),(-1,-1),5),


                                        ("LEFTPADDING",(0,0),(-1,-1),8),


                                        ("BOX",(0,0),(-1,-1),0.5,GREY_MED)]))





        narr_rows=[[Paragraph("<b>Narrative</b>", S["BodySmall"])]]


        for _chunk in _paragraph_chunks(ap.get("narrative",""), S["Body"], 1800):


            narr_rows.append([_chunk])


        narr_tbl=Table(narr_rows, colWidths=[17*cm], splitByRow=1)


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


    raw = pkg.get("fixed_in") or pkg.get("fixed_versions")


    has_advisory = bool(


        pkg.get("cve") or pkg.get("advisory_id") or pkg.get("cve_list") or


        pkg.get("advisory_ids") or pkg.get("vulnerabilities") or


        pkg.get("vulnerability_intelligence")


    )


    if not raw:


        return ("No fixed version identified in current advisory dataset."


                if pkg.get("cve") or pkg.get("advisory_id") else "--")


    vals = normalize_fixed_versions(raw)


    if all(str(v).strip().lower() in {"", "unknown", "none", "null", "n/a", "na", "--"} for v in vals):


        return ("No fixed version identified in current advisory dataset."


                if has_advisory else "--")


    if vals == ["No fixed version identified in current advisory dataset."]:


        return "No fixed version identified in current advisory dataset."


    return ", ".join(vals)






def _findings_section(payload):


    story=_sec("5. Detailed Findings")


    grouped=payload.get("grouped",[])


    if not grouped:


        story.append(Paragraph("No findings detected.",S["Body"])); return story





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





        # PATCH 12: clean file path show only relative tail, not full absolute path


        def _clean_path(fp: str) -> str:


            p = Path(fp)


            # Return last 2 parts of path (folder/file.py) to keep it readable


            parts = p.parts


            if len(parts) >= 2:


                return str(Path(*parts[-2:]))


            return p.name or fp


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


        ]


        meta_tbl=Table([[Paragraph(c,S["BodySmall"]) for c in row] for row in meta_rows],


                       colWidths=[2*cm,8*cm,2*cm,5*cm])


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


                         splitByRow=1, hAlign="LEFT")


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


        desc_tbl=Table(desc_rows, colWidths=[17*cm], splitByRow=1)


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


        rem_tbl=Table(rem_rows, colWidths=[17*cm], splitByRow=1)


        rem_tbl.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#E9F7EF")),


                                      ("BACKGROUND",(0,1),(-1,-1),WHITE),


                                      ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                                      ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4),


                                      ("LEFTPADDING",(0,0),(-1,-1),6)]))





        items=[hdr,meta_tbl]


        if af_tbl: items.append(af_tbl)


        items+=[desc_tbl,ev_tbl,rem_tbl,Spacer(1,0.5*cm)]


        story.extend(items)


    return story









def _sbom_section(payload):


    story=_sec("6. SBOM & Dependency Vulnerabilities")


    sbom=payload.get("sbom",[])


    if not sbom:


        story.append(Paragraph("No dependency manifests found.",S["Body"])); return story





    vuln_deps=[d for d in sbom if (d.get("vulnerabilities") or d.get("cve") or d.get("advisory_id"))]


    reachable=[d for d in vuln_deps if d.get("reachability_priority") == "REACHABLE_VULNERABLE" or d.get("reachable") is True or str(d.get("reachability_status") or "").upper() == "REACHABLE"]


    cve_count = int((payload.get("metadata", {}) or {}).get("cve_count", 0) or 0)


    advisory_count = int((payload.get("metadata", {}) or {}).get("advisory_count", 0) or 0)


    story.append(Paragraph(


        f"<b>{len(vuln_deps)} of {len(sbom)} packages have known vulnerabilities</b>; "


        f"{cve_count} unique CVEs and {advisory_count} advisory records were identified. "


        f"<b>{len(reachable)} of {len(vuln_deps)} vulnerable packages are reachable</b> "


        "in the scanned application context.",S["Body"]))





    rows=[[Paragraph(h,S["TH"]) for h in


           ["Package","Ver","Type","CVE / Advisory","CVSS","EPSS","Severity","Age","Reachable","Fixed In"]]]


    for pkg in sbom:


        sev=pkg.get("severity") or pkg.get("highest_vulnerability_severity") or "Unknown"


        epss=pkg.get("epss_score", pkg.get("epss"))


        epss_str=f"{float(epss):.3f}" if epss is not None else "--"


        direct=pkg.get("direct",True)


        cves = list(pkg.get("cve_list") or [])


        advisories = list(pkg.get("advisory_ids") or [])


        vuln_ids = cves[:3] + [a for a in advisories if a not in cves][:2]


        id_str = ", ".join(vuln_ids) if vuln_ids else (pkg.get("cve") or pkg.get("advisory_id") or "--")


        age_days = pkg.get("vulnerability_age_days")


        age_bucket = pkg.get("vulnerability_age_bucket")


        age = pkg.get("vulnerability_age")


        if age_days not in (None, "", "--"):


            age = f"{age_days}d" + (f" ({age_bucket})" if age_bucket else "")


        age = age or "Unknown"


        reachable_yes = pkg.get("reachability_priority") == "REACHABLE_VULNERABLE" or pkg.get("reachable") is True or str(pkg.get("reachability_status") or "").upper() == "REACHABLE"


        fixed = _v17923_fixed_text(pkg)


        rows.append([


            Paragraph(str(pkg.get("name","")), S["TDSm"]),


            Paragraph(str(pkg.get("version","")), S["TDC"]),


            Paragraph("D" if direct else "T", S["TDC"]),


            Paragraph(str(id_str), S["TDSm"]),


            Paragraph(str(pkg.get("cvss") or "--"), S["TDC"]),


            Paragraph(epss_str, S["TDC"]),


            Paragraph(str(sev), S["TDC"]),


            Paragraph(str(age), S["TDC"]),


            Paragraph("Yes" if reachable_yes else "No", S["TDC"]),


            Paragraph(str(fixed), S["TDSm"]),


        ])


    t=Table(rows,colWidths=[3.1*cm,1.6*cm,1.0*cm,3.0*cm,1.3*cm,1.3*cm,1.8*cm,1.8*cm,1.6*cm,2.1*cm],


            repeatRows=1, splitByRow=1)


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),


                            ("TEXTCOLOR",(0,0),(-1,0),WHITE),


                            ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),


                            ("FONTSIZE",(0,0),(-1,-1),7)]))


    story.append(t)


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


                action = "No fixed version identified in current advisory dataset; investigate a supported patched release or replace the dependency."


            else:


                action = f"Upgrade to a compatible fixed release (advisory: {fixed_text}). Then run tests and re-scan."


            action_rows.append([


                Paragraph(str(pkg.get("name") or "--"), S["TDSm"]),


                Paragraph(str(pkg.get("version") or "--"), S["TDC"]),


                Paragraph(action, S["TDSm"]),


            ])


        at = Table(action_rows, colWidths=[3.5*cm, 2.2*cm, 11.3*cm], splitByRow=1, repeatRows=1)


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


        "Counts are derived from the scanner rule families present in the canonical payload.",


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


    t=Table(rows,colWidths=[2.1*cm,2.5*cm,2.0*cm,5.0*cm,1.3*cm,5.1*cm],repeatRows=1,splitByRow=1)


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


    story.append(Paragraph(


        f"<b>{summary.get('total_components', len(payload.get('sbom',[]) or []))} components</b> "


        f"are covered by canonical license evidence. "


        f"Permissive: <b>{cats.get('Permissive',0)}</b>; "


        f"Composite / Review: <b>{cats.get('Composite / Review',0)}</b>; "


        f"Custom / Review: <b>{cats.get('Custom / Review',0)}</b>; "


        f"Evidence Unavailable: <b>{cats.get('Evidence Unavailable',0)}</b>. "


        f"Evidence review required: <b>{summary.get('review_required_components',0)}</b>; "


        f"Policy review required: <b>{summary.get('policy_review_required_components',0)}</b>; "


        f"Legal review required: <b>{summary.get('legal_review_required_components',0)}</b>; "


        f"Unknown license components: <b>{summary.get('unknown_license_components',0)}</b>. "


        f"Existing policy summary status remains <b>{policy.get('summary_status','NOT_AVAILABLE')}</b>.",


        S["Body"]))


    rows=[[Paragraph(h,S["TH"]) for h in [


        "Component","Version","Declared License","Resolved License",


        "License Category","Resolution Status","Evidence Source",


        "Review","Provenance"


    ]]]


    evidence_rows=payload.get("license_evidence",[]) or []


    for item in evidence_rows:


        provenance=item.get("license_provenance") or {}


        provenance_text="; ".join(


            f"{k}={v}" for k,v in provenance.items()


            if v not in (None,"",[],{})


        ) or "--"


        rows.append([


            Paragraph(str(item.get("package") or "--"),S["TDSm"]),


            Paragraph(str(item.get("version") or "--"),S["TDC"]),


            Paragraph(str(item.get("license_declared") or "UNKNOWN"),S["TDSm"]),


            Paragraph(str(item.get("license_resolved") or "UNKNOWN"),S["TDSm"]),


            Paragraph(str(item.get("license_category") or "Unknown"),S["TDSm"]),


            Paragraph(str(item.get("license_resolution_status") or "UNKNOWN"),S["TDSm"]),


            Paragraph(str(item.get("license_evidence_source") or "--"),S["TDSm"]),


            Paragraph("Yes" if item.get("license_review_required") else "No",S["TDC"]),


            Paragraph(provenance_text,S["TDSm"]),


        ])


    if len(rows)==1:


        rows.append([Paragraph("--",S["TDC"])]*9)


    t=Table(


        rows,


        colWidths=[2.5*cm,1.3*cm,2.0*cm,2.0*cm,1.8*cm,2.2*cm,1.8*cm,1.2*cm,2.4*cm],


        repeatRows=1,splitByRow=1


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


    meta=payload.get("metadata",{}); dist=meta.get("severity_distribution",{}); risk=meta.get("risk_score",0)


    story.append(Paragraph(


        f"This assessment identified <b>{meta.get('total_findings',0)} unique findings</b> "


        f"with a portfolio risk score of <b>{risk}/100</b>. "


        f"All critical and high findings must be verified post-remediation before next production release.",S["Body"]))


    story.append(Spacer(1,0.3*cm))


    rows=[[Paragraph(h,S["TH"]) for h in ["Priority","Severity","Count","SLA","Owner"]],


          ["P1","Critical",str(dist.get("Critical",0)),"< 24 hours","Security Team + Dev Lead"],


          ["P2","High",    str(dist.get("High",    0)),"7 days",     "Dev Team"],


          ["P3","Medium",  str(dist.get("Medium",  0)),"30 days",    "Dev Team"],


          ["P4","Low",     str(dist.get("Low",     0)),"90 days",    "Dev Team (backlog)"]]


    t=Table(rows,colWidths=[2*cm,3.5*cm,2.5*cm,4*cm,6*cm])


    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),DARK_BLUE),("TEXTCOLOR",(0,0),(-1,0),WHITE),


                            ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),


                            ("GRID",(0,0),(-1,-1),0.5,GREY_MED),


                            ("ROWBACKGROUNDS",(0,1),(-1,-1),[WHITE,LIGHT_BLUE]),


                            ("ALIGN",(0,0),(-1,-1),"CENTER"),


                            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),


                            ("FONTSIZE",(0,0),(-1,-1),9)]))


    story.append(t); story.append(Spacer(1,0.4*cm))


    story.append(Paragraph("This report is confidential and restricted to authorized personnel.",S["Body"]))





    # â”€â”€ Final Recommendation block â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


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


    release_decision = release_readiness.get("release_decision") or (meta.get("canonical_release_decision") if isinstance(meta, dict) else None) or "UNKNOWN"


    executive_decision_value = executive_decision.get("executive_decision") or meta.get("executive_decision") or "UNKNOWN"


    # Final recommendation follows the higher-level executive decision when present,


    # while keeping the underlying release-readiness decision visible.


    canonical_decision = executive_decision_value if executive_decision_value != "UNKNOWN" else release_decision


    blocking = release_decision == "DO_NOT_RELEASE"


    remediation_required = release_decision == "REMEDIATE_BEFORE_RELEASE"


    review_required = canonical_decision == "SECURITY_REVIEW_REQUIRED"


    conditional = canonical_decision == "CONDITIONAL_RELEASE"


    review_gates = release_readiness.get("review_gates", []) or []


    blocking_gates = release_readiness.get("blocking_gates", []) or []





    if blocking:


        # Red DO NOT RELEASE banner


        banner_tbl = Table(


            [[Paragraph("⚠  DO NOT RELEASE", _s("Banner",


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


            [[Paragraph("\[!] REMEDIATE BEFORE RELEASE \[!]  NOT APPROVED", _s("BannerRemediate",


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


            "Release is <b>not approved</b> because the canonical release-readiness decision requires remediation before release. "


            "Review the blocking gates, complete remediation or formal risk acceptance, and re-run the assessment.",


            S["Body"]


        ))


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


            [[Paragraph("\[!] SECURITY REVIEW REQUIRED \[!] NOT APPROVED", _s("BannerReview",


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


            [[Paragraph("[!] CONDITIONAL RELEASE", _s("BannerConditional",


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






def _bom_display_value(value, payload: dict) -> str:


    """Normalize report-facing BOM paths without changing canonical payload data."""


    import os, re, html


    text = "" if value is None else str(value)


    if not text:


        return ""


    if re.match(r"^[A-Za-z]:[\\/]", text) or text.startswith("/"):


        candidates = []


        def walk(v):


            if isinstance(v, dict):


                for x in v.values(): walk(x)


            elif isinstance(v, list):


                for x in v: walk(x)


            elif isinstance(v, str) and (re.match(r"^[A-Za-z]:[\\/]", v) or v.startswith("/")):


                candidates.append(v)


        for k in ("cbom", "aibom", "mlbom", "apibom", "abom"):


            walk(payload.get(k, []) or [])


        try:


            if candidates:


                norm = [os.path.normpath(x) for x in candidates]


                root = os.path.commonpath(norm)


                cur = os.path.normpath(text)


                if root and os.path.commonpath([root, cur]) == root:


                    rel = os.path.relpath(cur, root)


                    if rel and rel != ".":


                        text = rel


        except Exception:


            pass


        if re.match(r"^[A-Za-z]:[\\/]", text):


            m = re.search(r"(?:^|[\\/])(juice-shop-git)[\\/](.+)$", text, re.I)


            if m:


                text = m.group(2)


            else:


                text = os.path.basename(text)


        elif text.startswith("/"):


            text = text.lstrip("/")


    return html.escape(text).replace("\n", "<br/>")











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


    t = Table(rows, colWidths=[4.2*cm, 12.0*cm], repeatRows=1)


    t.setStyle(TableStyle([


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


    ]))


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


    story.append(NextPageTemplate("Compliance")); story.append(PageBreak())


    story.append(_TocBookmark("Compliance Mapping")); story += _compliance(payload)


    story.append(NextPageTemplate("AttackPaths")); story.append(PageBreak())


    story.append(_TocBookmark("Attack Path Correlation")); story += _attack_paths_section(payload)


    story.append(NextPageTemplate("Findings")); story.append(PageBreak())


    story.append(_TocBookmark("Detailed Findings")); story += _findings_section(payload)


    story.append(NextPageTemplate("SBOM")); story.append(PageBreak())


    story.append(_TocBookmark("SBOM & Dependencies")); story += _sbom_section(payload)


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








