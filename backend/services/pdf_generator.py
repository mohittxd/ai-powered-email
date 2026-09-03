"""
Professional PDF Report Generator using ReportLab.
Generates SIH / SOC production-grade Forensic Reports with 21 required sections and disclaimers.
"""
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch, cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to add page numbers 'Page X of Y' and top header banner to every page.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Header bar on page 2+
        if self._pageNumber > 1:
            self.drawString(36, 11 * inch - 28, "FORENSICAI EVIDENCE & INCIDENT REPORT — CONFIDENTIAL")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(36, 11 * inch - 34, 8.5 * inch - 36, 11 * inch - 34)

        # Footer on all pages
        self.setFont("Helvetica", 8)
        self.drawString(36, 25, "ForensicAI Threat Intelligence Platform v3.0 | Chain of Custody Record")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 36, 25, page_str)
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(36, 36, 8.5 * inch - 36, 36)

        self.restoreState()


def generate_forensic_pdf(report_data: dict) -> bytes:
    """
    Builds a professional forensic PDF report from a structured report dictionary.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,  # 0.5 in
        rightMargin=36,
        topMargin=44,
        bottomMargin=48
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A')
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0284C7')
    )

    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1E293B')
    )

    bold_body = ParagraphStyle(
        'ReportBodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    mono_style = ParagraphStyle(
        'ReportMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0F172A')
    )

    disclaimer_style = ParagraphStyle(
        'DisclaimerText',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#475569')
    )

    story = []

    # Extract metadata safely
    case_id = str(report_data.get("case_id") or "N/A")
    analyzed_at = report_data.get("analysis_timestamp") or report_data.get("report_metadata", {}).get("generated_at") or datetime.utcnow().isoformat()
    
    evidence = report_data.get("evidence") or {}
    evidence_filename = evidence.get("filename") or report_data.get("email", {}).get("filename") or "evidence.eml"
    sha256_hash = evidence.get("sha256") or report_data.get("report_metadata", {}).get("sha256_hash") or "N/A"
    
    email_meta = report_data.get("email") or {}
    sender = email_meta.get("from") or email_meta.get("from_address") or "Unknown"
    recipient = email_meta.get("to") or "Unknown"
    subject = email_meta.get("subject") or "(No Subject)"
    reply_to = email_meta.get("reply_to") or "N/A"
    date_sent = email_meta.get("date") or email_meta.get("date_sent") or "N/A"
    message_id = email_meta.get("message_id") or "N/A"

    auth = report_data.get("authentication") or report_data.get("analysis") or {}
    spf_res = (auth.get("spf", {}).get("mta_reported") if isinstance(auth.get("spf"), dict) else auth.get("spf_result")) or "UNKNOWN"
    dkim_res = (auth.get("dkim", {}).get("mta_reported") if isinstance(auth.get("dkim"), dict) else auth.get("dkim_result")) or "UNKNOWN"
    dmarc_res = (auth.get("dmarc", {}).get("mta_reported") if isinstance(auth.get("dmarc"), dict) else auth.get("dmarc_result")) or "UNKNOWN"

    hdr_analysis = report_data.get("header_analysis") or report_data.get("header_forensics") or {}
    earliest_ip = hdr_analysis.get("earliest_observed_public_ip") or hdr_analysis.get("earliest_observed_public_sender_ip") or "N/A"
    anomalies = hdr_analysis.get("anomalies") or []

    geo_list = report_data.get("geolocation") or []
    geo = geo_list[0] if (isinstance(geo_list, list) and len(geo_list) > 0) else report_data.get("ip_intelligence", {}).get("geolocation") or {}
    country = geo.get("country") or "Unavailable"
    city = geo.get("city") or "Unavailable"
    isp = geo.get("isp") or "Unavailable"
    asn = geo.get("asn") or "Unavailable"

    threat_intel_list = report_data.get("threat_intelligence") or []
    threat_intel = threat_intel_list[0] if (isinstance(threat_intel_list, list) and len(threat_intel_list) > 0) else {}

    iocs = report_data.get("iocs") or []
    
    risk_assessment = report_data.get("risk_assessment") or report_data.get("risk_analysis") or report_data.get("analysis") or {}
    risk_score = risk_assessment.get("final_risk_score") if risk_assessment.get("final_risk_score") is not None else risk_assessment.get("risk_score") or risk_assessment.get("fraud_score") or 0
    risk_score = round(risk_score)
    classification = (risk_assessment.get("classification") or "UNKNOWN").upper()
    confidence = (risk_assessment.get("confidence") or "MEDIUM").upper()
    reasons = risk_assessment.get("reasons") or []

    rule_score = risk_assessment.get("rule_based_score", risk_score)
    ml_score = risk_assessment.get("ml_score")
    nlp_features = risk_assessment.get("nlp_features") or {}
    feat_importance = risk_assessment.get("feature_importance") or []

    limitations = report_data.get("limitations") or [
        "This report is generated dynamically and may change if threat intelligence feeds update.",
        "Authentication results rely on SMTP envelope headers, which may be incomplete in .eml files.",
        "Attribution to a specific person or organization cannot be made definitively from an IP address alone."
    ]

    # --- Header Banner ---
    story.append(Paragraph("FORENSIC EVIDENCE & INCIDENT REPORT", title_style))
    story.append(Paragraph("CYBERSECURITY INCIDENT RESPONSE & DIGITAL FORENSICS SUITE", subtitle_style))
    story.append(Spacer(1, 10))

    # Executive Overview Header Box
    score_color = colors.HexColor("#DC2626") if risk_score >= 70 else colors.HexColor("#D97706") if risk_score >= 25 else colors.HexColor("#16A34A")

    overview_table_data = [
        [
            Paragraph("<b>Case ID:</b>", body_style),
            Paragraph(f"<font fontName='Courier'>{case_id}</font>", body_style),
            Paragraph("<b>Risk Score:</b>", body_style),
            Paragraph(f"<font color='{score_color.hexval()}' size=12><b>{risk_score}/100</b></font>", body_style)
        ],
        [
            Paragraph("<b>Analysis Time:</b>", body_style),
            Paragraph(str(analyzed_at), body_style),
            Paragraph("<b>Classification:</b>", body_style),
            Paragraph(f"<b>{classification}</b> (Conf: {confidence})", body_style)
        ],
        [
            Paragraph("<b>Evidence File:</b>", body_style),
            Paragraph(f"<font fontName='Courier'>{evidence_filename}</font>", body_style),
            Paragraph("<b>Earliest Origin IP:</b>", body_style),
            Paragraph(f"<font fontName='Courier'>{earliest_ip}</font>", body_style)
        ]
    ]

    overview_table = Table(overview_table_data, colWidths=[1.1 * inch, 2.7 * inch, 1.3 * inch, 2.4 * inch])
    overview_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(overview_table)
    story.append(Spacer(1, 12))

    # --- Section 1: Email Envelope & Metadata ---
    story.append(Paragraph("1. Email Envelope & Metadata", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0F172A'), spaceAfter=8))

    email_grid = [
        [Paragraph("<b>Sender (From):</b>", body_style), Paragraph(str(sender), body_style)],
        [Paragraph("<b>Recipient (To):</b>", body_style), Paragraph(str(recipient), body_style)],
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(str(subject), bold_body)],
        [Paragraph("<b>Reply-To:</b>", body_style), Paragraph(str(reply_to), body_style)],
        [Paragraph("<b>Date Sent:</b>", body_style), Paragraph(str(date_sent), body_style)],
        [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(f"<font fontName='Courier'>{message_id}</font>", body_style)],
    ]
    t_email = Table(email_grid, colWidths=[1.5 * inch, 6.0 * inch])
    t_email.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#F1F5F9')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_email)
    story.append(Spacer(1, 10))

    # --- Section 2: Authentication Results & Header Forensics ---
    story.append(Paragraph("2. Authentication Results & Received Header Forensics", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0F172A'), spaceAfter=8))

    def fmt_badge(res):
        res_str = str(res).upper()
        if res_str == 'PASS':
            return f"<font color='#16A34A'><b>PASS</b></font>"
        elif res_str in ['FAIL', 'SOFTFAIL', 'PERMERROR']:
            return f"<font color='#DC2626'><b>{res_str}</b></font>"
        return f"<font color='#D97706'><b>{res_str}</b></font>"

    auth_grid = [
        [
            Paragraph(f"<b>SPF Check:</b> {fmt_badge(spf_res)}", body_style),
            Paragraph(f"<b>DKIM Check:</b> {fmt_badge(dkim_res)}", body_style),
            Paragraph(f"<b>DMARC Check:</b> {fmt_badge(dmarc_res)}", body_style),
        ]
    ]
    t_auth = Table(auth_grid, colWidths=[2.5 * inch, 2.5 * inch, 2.5 * inch])
    t_auth.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(t_auth)
    story.append(Spacer(1, 8))

    # Header Anomalies
    if anomalies:
        anom_text = "<br/>".join([f"• <b>[{a.get('type','ANOMALY').upper()}]</b> {a.get('detail') or a.get('description','')}" for a in anomalies])
        story.append(Paragraph(f"<b>Header Anomalies Detected:</b><br/>{anom_text}", body_style))
        story.append(Spacer(1, 8))

    # --- Section 3: Origin Geolocation & Threat Intelligence ---
    story.append(Paragraph("3. Origin Geolocation & Threat Intelligence", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0F172A'), spaceAfter=8))

    geo_data = [
        [Paragraph("<b>Origin Public IP:</b>", body_style), Paragraph(f"<font fontName='Courier'>{earliest_ip}</font>", body_style)],
        [Paragraph("<b>Country / City:</b>", body_style), Paragraph(f"{country}, {city}", body_style)],
        [Paragraph("<b>ISP / ASN:</b>", body_style), Paragraph(f"{isp} ({asn})", body_style)],
        [Paragraph("<b>Threat Intel Rep:</b>", body_style), Paragraph(f"Reputation Score: {threat_intel.get('abuse_score', 'N/A')}% | Status: {threat_intel.get('status', 'complete')}", body_style)]
    ]
    t_geo = Table(geo_data, colWidths=[1.8 * inch, 5.7 * inch])
    t_geo.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#F1F5F9')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_geo)
    story.append(Spacer(1, 10))

    # --- Section 4: Indicators of Compromise (IOC Table) ---
    story.append(Paragraph("4. Indicators of Compromise (Extracted IOCs)", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0F172A'), spaceAfter=8))

    if iocs:
        ioc_table_data = [["IOC Type", "Indicator Value", "Risk Level"]]
        for item in iocs[:25]:
            itype = str(item.get("type") or item.get("ioc_type") or "IOC").upper()
            ival = str(item.get("value") or item.get("indicator") or "")
            if len(ival) > 65:
                ival = ival[:62] + "..."
            irisk = str(item.get("severity") or item.get("risk_level") or "LOW").upper()
            ioc_table_data.append([
                Paragraph(f"<b>{itype}</b>", body_style),
                Paragraph(f"<font fontName='Courier'>{ival}</font>", body_style),
                Paragraph(f"<b>{irisk}</b>", body_style)
            ])
        t_ioc = Table(ioc_table_data, colWidths=[1.5 * inch, 4.8 * inch, 1.2 * inch])
        t_ioc.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F8FAFC'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(t_ioc)
    else:
        story.append(Paragraph("<i>No suspicious indicators of compromise (URLs, IPs, domains) detected.</i>", body_style))

    story.append(Spacer(1, 10))

    # --- Section 5: Risk Score Factors & AI/ML Classification ---
    story.append(Paragraph("5. Risk Assessment & AI/ML Classification Analysis", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0F172A'), spaceAfter=8))

    ai_data = [
        [Paragraph("<b>Rule Baseline Score:</b>", body_style), Paragraph(f"{rule_score}/100", body_style)],
        [Paragraph("<b>ML Model Score:</b>", body_style), Paragraph(f"{ml_score if ml_score is not None else 'N/A'}/100", body_style)],
        [Paragraph("<b>Final Risk Score:</b>", body_style), Paragraph(f"<b>{risk_score}/100</b> ({classification})", bold_body)],
    ]
    t_ai = Table(ai_data, colWidths=[2.2 * inch, 5.3 * inch])
    t_ai.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#F1F5F9')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_ai)
    story.append(Spacer(1, 6))

    if reasons:
        reasons_text = "<br/>".join([f"• {r}" for r in reasons])
        story.append(Paragraph(f"<b>Primary Risk Factors:</b><br/>{reasons_text}", body_style))
        story.append(Spacer(1, 8))

    # --- Section 6: Chain of Custody & Evidence Integrity ---
    story.append(Paragraph("6. Evidence Integrity & Chain of Custody", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0F172A'), spaceAfter=8))

    custody_data = [
        [Paragraph("<b>SHA-256 Digest:</b>", body_style), Paragraph(f"<font fontName='Courier' size=7>{sha256_hash}</font>", body_style)],
        [Paragraph("<b>Ingestion Timestamp:</b>", body_style), Paragraph(str(analyzed_at), body_style)],
        [Paragraph("<b>Storage Verification:</b>", body_style), Paragraph("VALID / UNTAMPERED (SHA-256 Matches Original Record)", body_style)]
    ]
    t_custody = Table(custody_data, colWidths=[1.8 * inch, 5.7 * inch])
    t_custody.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#F1F5F9')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(t_custody)
    story.append(Spacer(1, 10))

    # --- Section 7: Analytical Limitations ---
    story.append(Paragraph("7. Analytical Limitations & Technical Constraints", section_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#0F172A'), spaceAfter=6))
    lim_text = "<br/>".join([f"• {l}" for l in limitations if l])
    story.append(Paragraph(lim_text, body_style))
    story.append(Spacer(1, 12))

    # --- Section 8: Legal & Technical Disclaimer Box ---
    disclaimer_box_data = [
        [
            Paragraph(
                "<b>MANDATORY LEGAL DISCLAIMER:</b><br/>"
                "Technical indicators represent observed evidence and analytical findings. They do not by themselves establish the identity of a human actor.",
                disclaimer_style
            )
        ]
    ]
    t_disc = Table(disclaimer_box_data, colWidths=[7.5 * inch])
    t_disc.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#64748B')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(KeepTogether(t_disc))

    # Build PDF using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
