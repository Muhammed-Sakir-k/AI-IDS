# ============================================================
# AI-IDS  —  PDF Incident Report Generator
# File: dashboard/report_generator.py
# REQUIRES: pip install reportlab
# ============================================================

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_CENTER

C_BG      = colors.HexColor("#0f172a")
C_ACCENT  = colors.HexColor("#6366f1")
C_RED     = colors.HexColor("#ef4444")
C_ORANGE  = colors.HexColor("#f97316")
C_YELLOW  = colors.HexColor("#eab308")
C_GREEN   = colors.HexColor("#22c55e")
C_WHITE   = colors.white
C_GREY    = colors.HexColor("#94a3b8")
C_LIGHT   = colors.HexColor("#f8fafc")

SEV_COLOR = {
    "CRITICAL": C_RED, "HIGH": C_ORANGE,
    "MEDIUM": C_YELLOW, "LOW": C_GREEN,
}

def _styles():
    base = getSampleStyleSheet()
    base.add(ParagraphStyle("Title2", fontSize=26, leading=32,
        textColor=C_WHITE, alignment=TA_CENTER, fontName="Helvetica-Bold"))
    base.add(ParagraphStyle("Sub2", fontSize=11, leading=16,
        textColor=C_GREY, alignment=TA_CENTER, fontName="Helvetica"))
    base.add(ParagraphStyle("SecHead", fontSize=13, leading=18,
        textColor=C_WHITE, fontName="Helvetica-Bold"))
    base.add(ParagraphStyle("Body2", fontSize=9, leading=14,
        textColor=colors.HexColor("#1e293b"), fontName="Helvetica"))
    base.add(ParagraphStyle("Small", fontSize=8, leading=12,
        textColor=C_GREY, fontName="Helvetica"))
    base.add(ParagraphStyle("AIText", fontSize=9, leading=14,
        textColor=colors.HexColor("#1e293b"), fontName="Helvetica", leftIndent=8))
    return base

def _sev_color(sev):
    return SEV_COLOR.get(str(sev).upper(), C_GREY)

def _section(title, styles):
    data = [[Paragraph(f"  {title}", styles["SecHead"])]]
    t = Table(data, colWidths=[17*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_ACCENT),
        ("TOPPADDING", (0,0), (-1,-1), 7),
        ("BOTTOMPADDING", (0,0), (-1,-1), 7),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
    ]))
    return [Spacer(1, 0.4*cm), t, Spacer(1, 0.25*cm)]

def _alert_table(alerts, styles):
    if not alerts:
        return [Paragraph("No alerts recorded.", styles["Body2"])]
    rows = [["#", "Timestamp", "Source IP", "Threat Type", "Severity"]]
    for i, a in enumerate(alerts[-20:], 1):
        rows.append([str(i), str(a.get("Timestamp","—")),
                     str(a.get("Source_IP","—")),
                     str(a.get("Threat_Type","—")),
                     str(a.get("Severity","—"))])
    t = Table(rows, colWidths=[1*cm,3.8*cm,3.5*cm,5.2*cm,2.5*cm], repeatRows=1)
    style = [
        ("BACKGROUND",(0,0),(-1,0),C_BG),
        ("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT, C_WHITE]),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#e2e8f0")),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),6),
    ]
    for i, a in enumerate(alerts[-20:], 1):
        c = _sev_color(a.get("Severity",""))
        style += [("TEXTCOLOR",(4,i),(4,i),c),("FONTNAME",(4,i),(4,i),"Helvetica-Bold")]
    t.setStyle(TableStyle(style))
    return [t]

def _risk_table(risk_scores, styles):
    if not risk_scores:
        return [Paragraph("No risk data available.", styles["Body2"])]
    rows = [["IP Address","Risk Score","Level","Alerts","Top Threat"]]
    for r in risk_scores[:10]:
        rows.append([str(r.get("ip","—")), str(r.get("score",0)),
                     str(r.get("level","—")), str(r.get("alerts",0)),
                     str(r.get("top_threat","—"))])
    t = Table(rows, colWidths=[4*cm,2.5*cm,2.5*cm,2*cm,6*cm], repeatRows=1)
    style = [
        ("BACKGROUND",(0,0),(-1,0),C_BG),
        ("TEXTCOLOR",(0,0),(-1,0),C_WHITE),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),8),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT,C_WHITE]),
        ("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#e2e8f0")),
        ("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("LEFTPADDING",(0,0),(-1,-1),6),
        ("ALIGN",(1,0),(3,-1),"CENTER"),
    ]
    for i, r in enumerate(risk_scores[:10], 1):
        c = _sev_color(r.get("level","LOW"))
        style += [("TEXTCOLOR",(2,i),(2,i),c),("FONTNAME",(2,i),(2,i),"Helvetica-Bold")]
    t.setStyle(TableStyle(style))
    return [t]

def _ai_block(report, styles):
    if not report:
        return [Paragraph("No AI analysis available.", styles["Body2"])]
    elems = []

    def row(label, value):
        if not value: return
        t = Table([
            [Paragraph(f"<b>{label}</b>", styles["Body2"])],
            [Paragraph(str(value), styles["AIText"])]
        ], colWidths=[16*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,0),colors.HexColor("#ede9fe")),
            ("BACKGROUND",(0,1),(0,1),C_LIGHT),
            ("LEFTPADDING",(0,0),(-1,-1),8),
            ("TOPPADDING",(0,0),(-1,-1),4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ]))
        elems.append(t); elems.append(Spacer(1,0.15*cm))

    def lst(label, items):
        if not items: return
        bullets = "".join(f"• {i}<br/>" for i in items)
        t = Table([
            [Paragraph(f"<b>{label}</b>", styles["Body2"])],
            [Paragraph(bullets, styles["AIText"])]
        ], colWidths=[16*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,0),colors.HexColor("#ede9fe")),
            ("BACKGROUND",(0,1),(0,1),C_LIGHT),
            ("LEFTPADDING",(0,0),(-1,-1),8),
            ("TOPPADDING",(0,0),(-1,-1),4),
            ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ]))
        elems.append(t); elems.append(Spacer(1,0.15*cm))

    # Badge row
    badge = Table([[
        Paragraph(f"<b>Risk Level:</b> {report.get('risk_level','—')}", styles["Body2"]),
        Paragraph(f"<b>Confidence:</b> {report.get('confidence','—')}", styles["Body2"]),
        Paragraph(f"<b>MITRE:</b> {report.get('mitre_technique','—')}", styles["Body2"]),
    ]], colWidths=[5*cm,5*cm,6*cm])
    badge.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#ede9fe")),
        ("LEFTPADDING",(0,0),(-1,-1),10),
        ("TOPPADDING",(0,0),(-1,-1),8),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
    ]))
    elems.append(badge); elems.append(Spacer(1,0.2*cm))

    row("Attack Summary",           report.get("attack_summary"))
    row("Attack Type Explanation",  report.get("attack_type_explanation"))
    row("What the Attacker Wanted", report.get("what_they_were_trying"))
    row("Why This IP",              report.get("why_this_ip"))
    row("Severity Reason",          report.get("severity_reason"))
    lst("Threat Indicators",        report.get("threat_indicators",[]))
    lst("Immediate Actions",        report.get("immediate_actions",[]))
    lst("Remediation Steps",        report.get("remediation_steps",[]))
    lst("Long-Term Prevention",     report.get("prevention",[]))
    return elems


def generate_pdf_report(stats: dict, ai_report: dict = None) -> bytes:
    """
    Returns PDF as raw bytes.
    Pass to Flask send_file() wrapped in io.BytesIO.
    """
    buf     = io.BytesIO()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    styles  = _styles()

    doc = SimpleDocTemplate(buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=1.5*cm, bottomMargin=1.5*cm,
        title="AI-IDS Incident Report")

    story = []

    # Cover banner
    banner = Table([[Paragraph("🛡  AI-IDS Incident Report", styles["Title2"])]],
                   colWidths=[17*cm])
    banner.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),C_BG),
        ("TOPPADDING",(0,0),(-1,-1),24),
        ("BOTTOMPADDING",(0,0),(-1,-1),24),
    ]))
    story.append(banner)
    story.append(Spacer(1,0.3*cm))
    story.append(Paragraph(f"Generated: {now_str}", styles["Small"]))
    story.append(Spacer(1,0.4*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT))
    story.append(Spacer(1,0.4*cm))

    # Summary stats
    story += _section("Executive Summary", styles)
    for label, val in [
        ("Total Packets",    stats.get("total_packets", 0)),
        ("Total Alerts",     stats.get("attack_count", 0)),
        ("Threats Today",    stats.get("threats_today", 0)),
        ("Highest Severity", stats.get("highest_severity", "—")),
        ("Top Threat IP",    stats.get("top_threat_ip", "—")),
        ("Top Threat Type",  stats.get("top_threat_type", "—")),
    ]:
        story.append(Paragraph(f"<b>{label}:</b>  {val}", styles["Body2"]))
        story.append(Spacer(1, 0.1*cm))

    # Alert table
    story += _section("Recent Alerts (Last 20)", styles)
    story += _alert_table(stats.get("alerts", []), styles)

    # Risk scores
    story += _section("Top Attacker Risk Scores", styles)
    story += _risk_table(stats.get("risk_scores", []), styles)

    # AI analysis
    story += _section("AI Forensic Analysis — Worst Alert", styles)
    story += _ai_block(ai_report, styles)

    # Footer
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_GREY))
    story.append(Paragraph(
        f"AI-IDS · Automated Intrusion Detection System · {now_str} · Confidential",
        styles["Small"]
    ))

    doc.build(story)
    return buf.getvalue()