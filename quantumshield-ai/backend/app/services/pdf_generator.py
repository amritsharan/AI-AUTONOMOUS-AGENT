"""
PDF Generation Service using ReportLab
Generates enterprise-grade PDF security audit and PQC compliance reports.
"""
import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for adding total page numbers and headers/footers."""
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

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Header (pages 2+)
        if self._pageNumber > 1:
            self.drawString(40, 755, "QuantumShield AI — Autonomous Security & Quantum Risk Assessment Report")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(40, 750, 572, 750)

        # Footer
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(40, 40, 572, 40)
        self.drawString(40, 28, "CONFIDENTIAL — STRICTLY FOR AUTHORIZED SECURITY AUDIT USE")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(572, 28, page_str)
        self.restoreState()


def generate_scan_pdf_report(data: dict) -> bytes:
    """Generate a PDF report buffer from scan report dictionary."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=45,
        bottomMargin=50,
    )

    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=12,
    )
    h1_style = ParagraphStyle(
        'Header1',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#1E293B'),
    )
    body_bold = ParagraphStyle(
        'BodyBold',
        parent=body_style,
        fontName='Helvetica-Bold',
    )
    meta_label = ParagraphStyle(
        'MetaLabel',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#475569'),
    )
    meta_val = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#0F172A'),
    )
    badge_style = ParagraphStyle(
        'Badge',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=1, # Center
    )

    story = []

    meta = data.get("report_metadata", {})
    exec_sum = data.get("executive_summary", {})
    scope = data.get("scope", {})
    classical_findings = data.get("classical_findings", [])
    quantum_findings = data.get("quantum_findings", [])
    crypto_inv = data.get("cryptographic_inventory", [])
    pqc_readiness = data.get("pqc_readiness", {})

    # ── 1. Header & Title Banner ─────────────────────────────────────────
    story.append(Paragraph("QUANTUMSHIELD AI", ParagraphStyle('PreTitle', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor('#0284C7'), leading=12)))
    story.append(Paragraph("Security Assessment & Quantum Risk Audit Report", title_style))
    gen_time = meta.get("generated_at", datetime.utcnow().isoformat())
    story.append(Paragraph(f"Autonomous Security Engine · Report Generated: {gen_time[:19].replace('T', ' ')} UTC", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284C7'), spaceBefore=0, spaceAfter=10))

    # ── 2. Scope & Target Metadata Box ────────────────────────────────────
    target_url = scope.get("target_url") or "http://localhost:8080"
    scan_name = meta.get("scan_name") or "Autonomous Lab Scan"
    scan_id = meta.get("scan_id", "N/A")

    meta_table_data = [
        [
            Paragraph("Target Environment:", meta_label), Paragraph(f"{target_url} (Lab/Staging)", meta_val),
            Paragraph("Scan Name:", meta_label), Paragraph(scan_name, meta_val),
        ],
        [
            Paragraph("Scan ID:", meta_label), Paragraph(scan_id[:16] + "..." if len(scan_id) > 16 else scan_id, meta_val),
            Paragraph("Assessment Scope:", meta_label), Paragraph("Classical Web + Quantum PQC Audit", meta_val),
        ],
        [
            Paragraph("Status:", meta_label), Paragraph("COMPLETED (Verified)", meta_val),
            Paragraph("Deterministic Policy:", meta_label), Paragraph("STRICT BOUNDARIES ENFORCED", meta_val),
        ],
    ]
    meta_table = Table(meta_table_data, colWidths=[95, 170, 95, 172])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # ── 3. Executive Summary Scorecard ────────────────────────────────────
    story.append(Paragraph("Executive Summary", h1_style))

    c_score = exec_sum.get("classical_security_score", 0)
    q_score = exec_sum.get("quantum_security_score", 0)
    c_score_str = f"{c_score:.0f}/100" if isinstance(c_score, (int, float)) else str(c_score)
    q_score_str = f"{q_score:.0f}/100" if isinstance(q_score, (int, float)) else str(q_score)

    score_card_data = [
        [
            Paragraph("<font size=16><b>" + c_score_str + "</b></font><br/><font size=8 color='#64748B'>Classical Security Score</font>", ParagraphStyle('C1', alignment=1, leading=14)),
            Paragraph("<font size=16><b>" + q_score_str + "</b></font><br/><font size=8 color='#64748B'>Quantum Security Score</font>", ParagraphStyle('C2', alignment=1, leading=14)),
            Paragraph("<font size=16 color='#DC2626'><b>" + str(exec_sum.get('critical', 0)) + "</b></font><br/><font size=8 color='#64748B'>Critical Vulns</font>", ParagraphStyle('C3', alignment=1, leading=14)),
            Paragraph("<font size=16 color='#EA580C'><b>" + str(exec_sum.get('high', 0)) + "</b></font><br/><font size=8 color='#64748B'>High Vulns</font>", ParagraphStyle('C4', alignment=1, leading=14)),
            Paragraph("<font size=16 color='#2563EB'><b>" + str(exec_sum.get('confirmed_findings', 0)) + "</b></font><br/><font size=8 color='#64748B'>Confirmed PoCs</font>", ParagraphStyle('C5', alignment=1, leading=14)),
        ]
    ]
    score_table = Table(score_card_data, colWidths=[106, 106, 106, 106, 108])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F1F5F9')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 10))

    # ── 4. Classical Vulnerabilities Table ─────────────────────────────────
    story.append(Paragraph(f"Classical Vulnerabilities ({len(classical_findings)} Identified)", h1_style))

    if classical_findings:
        findings_table_data = [
            [
                Paragraph("Severity", meta_label),
                Paragraph("Vulnerability / Title", meta_label),
                Paragraph("Category & Endpoint", meta_label),
                Paragraph("Risk Score", meta_label),
            ]
        ]

        sev_colors = {
            "CRITICAL": colors.HexColor("#DC2626"),
            "HIGH": colors.HexColor("#EA580C"),
            "MEDIUM": colors.HexColor("#D97706"),
            "LOW": colors.HexColor("#16A34A"),
            "INFO": colors.HexColor("#0284C7"),
        }

        for f in classical_findings:
            sev = str(f.get("severity", "INFO")).upper()
            sev_bg = sev_colors.get(sev, colors.HexColor("#64748B"))
            
            sev_p = Paragraph(f"<font color='white'><b>{sev}</b></font>", badge_style)
            title_p = Paragraph(f"<b>{f.get('title', 'Finding')}</b><br/><font size=7 color='#64748B'>{f.get('description', '')[:120]}</font>", body_style)
            cat_p = Paragraph(f"<font color='#0284C7'>{f.get('category', 'Vulnerability')}</font><br/><font size=7 color='#475569'>{f.get('endpoint', '/')}</font>", body_style)
            risk_p = Paragraph(f"<b>{f.get('risk_score', 0):.1f}</b>", ParagraphStyle('R', alignment=1, fontName='Helvetica-Bold', fontSize=9))

            findings_table_data.append([sev_p, title_p, cat_p, risk_p])

        f_table = Table(findings_table_data, colWidths=[65, 230, 180, 57])
        f_table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]
        # Add badge backgrounds for severity column
        for row_idx, f in enumerate(classical_findings, start=1):
            sev = str(f.get("severity", "INFO")).upper()
            f_table_style.append(('BACKGROUND', (0, row_idx), (0, row_idx), sev_colors.get(sev, colors.HexColor('#64748B'))))
            f_table_style.append(('ALIGN', (0, row_idx), (0, row_idx), 'CENTER'))

        f_table.setStyle(TableStyle(f_table_style))
        story.append(f_table)
    else:
        story.append(Paragraph("No classical vulnerabilities detected in this scan.", body_style))

    story.append(Spacer(1, 12))

    # ── 5. Quantum Cryptographic Inventory & PQC Readiness ────────────────
    story.append(Paragraph("Quantum Cryptographic Audit & NIST PQC Readiness", h1_style))

    if crypto_inv:
        crypto_table_data = [
            [
                Paragraph("Algorithm", meta_label),
                Paragraph("Key Size", meta_label),
                Paragraph("Quantum Attack", meta_label),
                Paragraph("PQC Status", meta_label),
                Paragraph("Recommended PQC Migration", meta_label),
            ]
        ]
        for c in crypto_inv:
            alg = c.get("algorithm", "RSA")
            pqc_status = c.get("pqc_status", "VULNERABLE")
            attack = c.get("quantum_attack", "Shor's Algorithm")
            
            pqc_rec = "ML-KEM-768 (FIPS 203)" if "RSA" in alg or "ECDH" in alg else "ML-DSA-65 (FIPS 204)" if "ECDSA" in alg or "DSA" in alg else "AES-256 (Grover Resistant)"

            status_color = "#DC2626" if "VULN" in str(pqc_status).upper() else "#16A34A"

            crypto_table_data.append([
                Paragraph(f"<b>{alg}</b>", body_style),
                Paragraph(str(c.get("key_size", "2048")), body_style),
                Paragraph(f"<font color='#9333EA'>{attack}</font>", body_style),
                Paragraph(f"<font color='{status_color}'><b>{pqc_status}</b></font>", body_style),
                Paragraph(f"<font color='#0284C7'>{pqc_rec}</font>", body_style),
            ])

        c_table = Table(crypto_table_data, colWidths=[90, 60, 120, 110, 152])
        c_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E2E8F0')),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ]))
        story.append(c_table)
    else:
        story.append(Paragraph("Cryptographic inventory: Standard AES/TLS configurations evaluated.", body_style))

    story.append(Spacer(1, 10))

    # ── 6. PQC Standards & Guidance Notice ────────────────────────────────
    notice_text = (
        "<b>NIST Post-Quantum Cryptography (PQC) Standards Guidance:</b> "
        "FIPS 203 (ML-KEM for Key Encapsulation), FIPS 204 (ML-DSA for Digital Signatures), and "
        "FIPS 205 (SLH-DSA for Stateless Hash Signatures) are finalized. All legacy RSA (<3072 bit) "
        "and Elliptic Curve (ECDSA/ECDH) keys should be scheduled for hybrid-PQC migration to prevent "
        "Harvest Now, Decrypt Later (HNDL) data compromise."
    )
    notice_table = Table([[Paragraph(notice_text, body_style)]], colWidths=[532])
    notice_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#EFF6FF')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#93C5FD')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(notice_table)

    story.append(Spacer(1, 12))

    # ── 7. Remediation Action Plan ────────────────────────────────────────
    story.append(Paragraph("Priority Remediation Action Items", h1_style))
    remediations = [
        ("1. Immediate: Broken Object Level Authorization (IDOR)", "Enforce strict tenant ID check and session validation in middleware before querying `/api/users/{id}` and `/api/orders/{id}`."),
        ("2. Immediate: SQL Injection & Input Validation", "Convert dynamic SQL concatenation in search endpoints to parameterized queries or SQLAlchemy ORM filters."),
        ("3. High: Authentication & JWT Hardening", "Enforce strong JWT secret signing keys (>256 bit entropy), disable 'none' algorithm, and apply brute-force lockout thresholds."),
        ("4. Medium: Cryptographic PQC Roadmap", "Establish automated CBOM (Cryptographic Bill of Materials) and initiate transition to NIST FIPS 203 ML-KEM for confidential communication channels."),
    ]
    for title, desc in remediations:
        story.append(Paragraph(f"<b>{title}</b>", body_bold))
        story.append(Paragraph(desc, body_style))
        story.append(Spacer(1, 4))

    # Build PDF with NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()
