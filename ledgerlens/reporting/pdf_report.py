from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

from ledgerlens.models import AuditReport

def _add_watermark(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica-Bold", 60)
    canvas.setFillGray(0.9, 0.5)
    canvas.translate(doc.pagesize[0] / 2, doc.pagesize[1] / 2)
    canvas.rotate(45)
    canvas.drawCentredString(0, 0, "CONFIDENTIAL")
    canvas.restoreState()
    
    # Page number
    canvas.saveState()
    canvas.setFont("Helvetica", 9)
    canvas.drawString(doc.pagesize[0] - 50, 30, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()

def _get_risk_color(tier: str) -> colors.Color:
    if tier == "CRITICAL":
        return colors.red
    elif tier == "HIGH":
        return colors.orange
    elif tier == "MEDIUM":
        return colors.goldenrod
    else:
        return colors.green

def generate_pdf_report(report: AuditReport, output_dir: Path) -> Path:
    """Generates a PDF audit report.
    
    Args:
        report: The AuditReport instance.
        output_dir: The directory to write the PDF report to.
        
    Returns:
        The path to the generated PDF report.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "Financial_Ledger_Compliance_Return.pdf"
    
    doc = SimpleDocTemplate(
        str(report_path),
        pagesize=letter,
        rightMargin=30, leftMargin=30,
        topMargin=30, bottomMargin=50
    )
    
    styles = getSampleStyleSheet()
    
    header_style = ParagraphStyle(
        'HeaderStyle',
        parent=styles['Heading1'],
        textColor=colors.HexColor('#1a1a2e'),
        fontSize=18,
        spaceAfter=10
    )
    
    sub_header_style = ParagraphStyle(
        'SubHeaderStyle',
        parent=styles['Heading2'],
        textColor=colors.HexColor('#0f3460'),
        fontSize=14,
        spaceAfter=10
    )
    
    normal_style = styles['Normal']
    
    elements = []
    
    # Section 1: Cover Page
    elements.append(Paragraph("FINANCIAL LEDGER & DB INTEGRITY AUDIT RETURN", header_style))
    elements.append(Paragraph("Automated Regulatory Audit Report — LedgerLens v2.0", sub_header_style))
    elements.append(Spacer(1, 20))
    
    overall_risk_color = _get_risk_color(report.overall_risk_tier.value).hexval()
    
    elements.append(Paragraph(f"<b>Target Path:</b> {report.target.root_path}", normal_style))
    elements.append(Paragraph(f"<b>Scan Fingerprint:</b> {report.target.fingerprint}", normal_style))
    elements.append(Paragraph(f"<b>Scan Timestamp:</b> {report.target.scan_started_at.isoformat()}", normal_style))
    elements.append(Paragraph(f"<b>Overall Risk Tier:</b> <font color='{overall_risk_color}'>{report.overall_risk_tier.value}</font>", normal_style))
    elements.append(Paragraph(f"<b>Compliance Score:</b> {report.compliance_score}%", normal_style))
    elements.append(PageBreak())
    
    # Section 2: Executive Summary
    elements.append(Paragraph("Executive Summary", header_style))
    
    exec_summary_data = [
        ["Metric", "Value"],
        ["Tables Audited", str(report.total_tables_audited)],
        ["Ledger Tables Found", str(report.total_ledger_tables_found)],
        ["Secrets/PII Redacted", str(report.total_secrets_redacted)]
    ]
    t = Table(exec_summary_data, colWidths=[200, 100])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("Risk Breakdown", sub_header_style))
    risk_summary = report.risk_summary
    risk_data = [
        ["Risk Tier", "Count"],
        ["CRITICAL", str(risk_summary.get("CRITICAL", 0))],
        ["HIGH", str(risk_summary.get("HIGH", 0))],
        ["MEDIUM", str(risk_summary.get("MEDIUM", 0))],
        ["LOW", str(risk_summary.get("LOW", 0))]
    ]
    t2 = Table(risk_data, colWidths=[200, 100])
    t2.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(t2)
    elements.append(Spacer(1, 20))
    
    elements.append(Paragraph("Framework Breakdown", sub_header_style))
    fw_summary = report.framework_summary
    fw_data = [["Framework", "Count"]]
    for fw, count in fw_summary.items():
        fw_data.append([fw, str(count)])
        
    t3 = Table(fw_data, colWidths=[400, 100])
    t3.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(t3)
    elements.append(PageBreak())
    
    # Section 3: Detailed Ledger Findings
    elements.append(Paragraph("Detailed Ledger Findings", header_style))
    
    sorted_findings = sorted(report.findings, key=lambda f: f.risk_tier, reverse=True)
    
    for finding in sorted_findings:
        color = _get_risk_color(finding.risk_tier.value).hexval()
        elements.append(Paragraph(f"<b>Rule ID:</b> {finding.rule_id}", normal_style))
        elements.append(Paragraph(f"<b>Risk Tier:</b> <font color='{color}'>{finding.risk_tier.value}</font>", normal_style))
        elements.append(Paragraph(f"<b>Framework:</b> {finding.framework.value}", normal_style))
        elements.append(Paragraph(f"<b>Table Name:</b> {finding.table_name or 'N/A'}", normal_style))
        elements.append(Paragraph(f"<b>Column Name:</b> {finding.column_name or 'N/A'}", normal_style))
        elements.append(Paragraph(f"<b>File:</b> {finding.file_path} (Line {finding.line_number or 'N/A'})", normal_style))
        
        if finding.code_snippet:
            elements.append(Spacer(1, 5))
            snippet_style = ParagraphStyle(
                'SnippetStyle',
                parent=styles['Code'],
                fontSize=8,
                backColor=colors.lightgrey,
                wordWrap='CJK'
            )
            elements.append(Paragraph(finding.code_snippet.replace('\\n', '<br/>'), snippet_style))
            
        elements.append(Spacer(1, 5))
        elements.append(Paragraph(f"<b>Remediation:</b> {finding.remediation}", normal_style))
        elements.append(Spacer(1, 15))
        
    elements.append(PageBreak())
    
    # Section 4: Technical Remediation Matrix
    elements.append(Paragraph("Technical Remediation Matrix", header_style))
    
    rem_data = [["Rule ID", "Table", "Risk Tier", "Remediation Steps"]]
    for finding in sorted_findings:
        rem_data.append([
            finding.rule_id,
            finding.table_name or 'N/A',
            finding.risk_tier.value,
            Paragraph(finding.remediation, styles['Normal'])
        ])
        
    if len(rem_data) > 1:
        t4 = Table(rem_data, colWidths=[70, 100, 70, 280])
        t4.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1a1a2e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(t4)
    else:
        elements.append(Paragraph("No findings require remediation.", normal_style))
        
    doc.build(elements, onFirstPage=_add_watermark, onLaterPages=_add_watermark)
    
    return report_path
