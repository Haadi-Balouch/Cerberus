# ============================
#  - Professional Security Report Generator
# Part 1: Imports, Styles, and Helper Functions
# ============================

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    KeepTogether, Frame, PageTemplate
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.units import inch, mm
from reportlab.pdfgen import canvas
import datetime
import os
import tempfile


# -----------------------------
# CUSTOM PAGE TEMPLATE
# -----------------------------
class HeaderFooterCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self.pages = []
        
    def showPage(self):
        self.pages.append(dict(self.__dict__))
        self._startPage()
        
    def save(self):
        page_count = len(self.pages)
        for page_num, page in enumerate(self.pages, 1):
            self.__dict__.update(page)
            if page_num > 1:  # Skip header/footer on cover page
                self.draw_header_footer(page_num, page_count)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)
        
    def draw_header_footer(self, page_num, page_count):
        # Header
        self.saveState()
        self.setStrokeColor(colors.HexColor("#024180"))
        self.setLineWidth(2)
        self.line(40, A4[1] - 40, A4[0] - 40, A4[1] - 40)
        
        self.setFont("Helvetica-Bold", 10)
        self.setFillColor(colors.HexColor("#024180"))
        self.drawString(40, A4[1] - 32, "CERBERUS SECURITY ASSESSMENT")
        
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.grey)
        self.drawRightString(A4[0] - 40, A4[1] - 32, 
                            datetime.datetime.now().strftime("%B %d, %Y"))
        
        # Footer
        self.setStrokeColor(colors.HexColor("#024180"))
        self.setLineWidth(1)
        self.line(40, 40, A4[0] - 40, 40)
        
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.grey)
        self.drawString(40, 30, "Confidential")
        self.drawCentredString(A4[0] / 2, 30, f"Page {page_num} of {page_count}")
        self.drawRightString(A4[0] - 40, 30, "Cerberus Framework")
        
        self.restoreState()


# -----------------------------
# ENHANCED STYLES
# -----------------------------
styles = getSampleStyleSheet()

CoverTitle = ParagraphStyle(
    "CoverTitle",
    parent=styles["Title"],
    fontSize=36,
    alignment=TA_CENTER,
    textColor=colors.HexColor("#024180"),
    fontName="Helvetica-Bold",
    spaceAfter=30,
    leading=48,
)

CoverSubtitle = ParagraphStyle(
    "CoverSubtitle",
    parent=styles["Normal"],
    fontSize=16,
    alignment=TA_CENTER,
    textColor=colors.HexColor("#333333"),
    spaceAfter=50,
)

SectionHeader = ParagraphStyle(
    "SectionHeader",
    parent=styles["Heading1"],
    fontSize=20,
    textColor=colors.white,
    backColor=colors.HexColor("#024180"),
    spaceAfter=12,
    spaceBefore=12,
    leftIndent=10,
    rightIndent=10,
    borderPadding=(8, 3, 8, 3),
)

SubHeader = ParagraphStyle(
    "SubHeader",
    parent=styles["Heading2"],
    fontSize=14,
    textColor=colors.HexColor("#024180"),
    spaceAfter=8,
    spaceBefore=10,
    borderColor=colors.HexColor("#024180"),
    borderWidth=0,
    leftIndent=0,
)

RiskBox = ParagraphStyle(
    "RiskBox",
    parent=styles["Normal"],
    fontSize=11,
    alignment=TA_CENTER,
    textColor=colors.white,
)

BodyText = ParagraphStyle(
    "BodyText",
    parent=styles["Normal"],
    fontSize=10,
    alignment=TA_JUSTIFY,
    spaceAfter=8,
)

SmallText = ParagraphStyle(
    "SmallText",
    parent=styles["Normal"],
    fontSize=8,
    leading=10,
)

BulletText = ParagraphStyle(
    "BulletText",
    parent=styles["Normal"],
    fontSize=10,
    leftIndent=20,
    bulletIndent=10,
    spaceAfter=4,
)


# -----------------------------
# SEVERITY UTILITIES
# -----------------------------
def severity_color(sev):
    sev = (sev or "").upper()
    mapping = {
        "CRITICAL": colors.HexColor("#8B0000"),
        "HIGH": colors.HexColor("#FF934F"),
        "MEDIUM": colors.HexColor("#FFD900"),
        "LOW": colors.HexColor("#4AAD29"),
        "INFO": colors.HexColor("#4682B4")
    }
    return mapping.get(sev, colors.grey)


def calculate_risk_score(sev_counts, web_vuln_count=0):
    """Calculate overall risk score (0-100) including web vulnerabilities"""
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 0.5}
    total = sum(sev_counts.get(s, 0) * w for s, w in weights.items())
    
    # Add web vulnerability weight
    total += web_vuln_count * 3
    
    return min(100, total)


def risk_rating(score):
    """Convert score to rating"""
    if score >= 75:
        return "CRITICAL", colors.HexColor("#8B0000")
    elif score >= 50:
        return "HIGH", colors.HexColor("#FF934F")
    elif score >= 25:
        return "MEDIUM", colors.HexColor("#FFD900")
    else:
        return "LOW", colors.HexColor("#4AAD29")


# -----------------------------
# COVER PAGE
# -----------------------------
def build_cover_page(story, target, sev_counts, web_vuln_count=0):
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("CERBERUS SECURITY<br/>REPORT", CoverTitle))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Vulnerability Analysis & Risk Assessment", CoverSubtitle))
    story.append(Spacer(1, 0.5 * inch))
    
    # Target Info Box
    target_data = [
        ["Target", target],
        ["Assessment Date", datetime.datetime.now().strftime("%B %d, %Y")],
        ["Report Generated", datetime.datetime.now().strftime("%B %d, %Y %H:%M:%S")],
        ["Assessment Type", "Automated Vulnerability Scan"]
    ]
    
    target_table = Table(target_data, colWidths=[2*inch, 4*inch])
    target_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#024180")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("BACKGROUND", (1, 0), (1, -1), colors.whitesmoke),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 1, colors.grey),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    
    story.append(target_table)
    story.append(Spacer(1, 0.8 * inch))
    
    # Risk Score Box
    score = calculate_risk_score(sev_counts, web_vuln_count)
    rating, rating_color = risk_rating(score)
    
    risk_data = [
        [Paragraph(f"<b>OVERALL RISK SCORE</b>", RiskBox)],
        [Spacer(1, 10)],
        [Paragraph(f"<font size=48><b>{score:.0f}</b></font>", RiskBox)],
        [Spacer(1, 10)],
        [Paragraph(f"<b>{rating} RISK</b>", RiskBox)]
    ]
    
    risk_table = Table(risk_data, colWidths=[3*inch])
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), rating_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    
    story.append(risk_table)
    story.append(Spacer(1, 1 * inch))
    
    # Disclaimer
    story.append(Paragraph(
        "<i>This report contains confidential information about security vulnerabilities "
        "identified during an automated security assessment. The information should be "
        "treated as sensitive and distributed only to authorized personnel.</i>",
        BodyText
    ))
    
    story.append(PageBreak())


# -----------------------------
# EXECUTIVE SUMMARY
# -----------------------------
def build_executive_summary(story, data, sev_counts, web_vuln_count):
    story.append(Paragraph("EXECUTIVE SUMMARY", SectionHeader))
    story.append(Spacer(1, 10))
    
    # Summary Text
    total_vulns = sum(sev_counts.values())
    score = calculate_risk_score(sev_counts, web_vuln_count)
    rating, _ = risk_rating(score)
    
    web_text = f" and <b>{web_vuln_count} web vulnerabilities</b>" if web_vuln_count > 0 else ""
    
    summary_text = f"""
    This report presents the findings of an automated security assessment conducted on 
    <b>{data['target']}</b>. The assessment identified <b>{total_vulns} CVE vulnerabilities</b>{web_text}, 
    resulting in an overall risk score of <b>{score:.0f}/100 ({rating} Risk)</b>.
    <br/><br/>
    The assessment included network reconnaissance, port and service enumeration, CVE vulnerability 
    mapping, and web application security analysis. Key findings and remediation recommendations 
    are detailed in the following sections.
    """
    
    story.append(Paragraph(summary_text, BodyText))
    story.append(Spacer(1, 15))
    
    # Vulnerability Summary Table
    story.append(Paragraph("Vulnerability Distribution", SubHeader))
    
    vuln_data = [
        ["Severity", "Count", "Percentage", "Risk Impact"],
        ["Critical", str(sev_counts.get("CRITICAL", 0)), 
         f"{(sev_counts.get('CRITICAL', 0)/max(total_vulns,1)*100):.1f}%", "Immediate Action Required"],
        ["High", str(sev_counts.get("HIGH", 0)), 
         f"{(sev_counts.get('HIGH', 0)/max(total_vulns,1)*100):.1f}%", "Urgent Remediation"],
        ["Medium", str(sev_counts.get("MEDIUM", 0)), 
         f"{(sev_counts.get('MEDIUM', 0)/max(total_vulns,1)*100):.1f}%", "Scheduled Fix"],
        ["Low", str(sev_counts.get("LOW", 0)), 
         f"{(sev_counts.get('LOW', 0)/max(total_vulns,1)*100):.1f}%", "Best Practice"]
    ]
    
    vuln_table = Table(vuln_data, colWidths=[1.5*inch, 1*inch, 1.3*inch, 2.5*inch])
    vuln_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#024180")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("ALIGN", (3, 1), (3, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
        ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#8B0000") if sev_counts.get("CRITICAL", 0) > 0 else colors.white),
        ("BACKGROUND", (0, 2), (0, 2), colors.HexColor("#FF934F") if sev_counts.get("HIGH", 0) > 0 else colors.white),
        ("BACKGROUND", (0, 3), (0, 3), colors.HexColor("#FFD900") if sev_counts.get("MEDIUM", 0) > 0 else colors.white),
        ("BACKGROUND", (0, 4), (0, 4), colors.HexColor("#4AAD29") if sev_counts.get("LOW", 0) > 0 else colors.white),
        ("TEXTCOLOR", (0, 1), (0, 4), colors.white),
    ]))
    
    story.append(vuln_table)
    story.append(Spacer(1, 20))
    
    # Visual Chart
    if total_vulns > 0:
        story.append(build_severity_pie(sev_counts))
    
    story.append(PageBreak())


# -----------------------------
# ENHANCED PIE CHART
# -----------------------------
def build_severity_pie(sev_counts):
    total = sum(sev_counts.values())
    if total == 0:
        return Paragraph("No vulnerabilities detected.", BodyText)
    
    data = [
        sev_counts.get("CRITICAL", 0),
        sev_counts.get("HIGH", 0),
        sev_counts.get("MEDIUM", 0),
        sev_counts.get("LOW", 0)
    ]
    
    labels = [f"Critical\n({data[0]})", f"High\n({data[1]})", 
              f"Medium\n({data[2]})", f"Low\n({data[3]})"]
    
    colors_list = [
        colors.HexColor("#8B0000"),
        colors.HexColor("#FF934F"),
        colors.HexColor("#FFD900"),
        colors.HexColor("#4AAD29")
    ]
    
    d = Drawing(400, 200)
    pie = Pie()
    pie.x = 100
    pie.y = 20
    pie.width = 160
    pie.height = 160
    pie.data = data
    pie.labels = labels
    pie.slices.strokeWidth = 1
    pie.slices.strokeColor = colors.white
    pie.slices.fontName = "Helvetica-Bold"
    pie.slices.fontSize = 10
    
    for i, c in enumerate(colors_list):
        pie.slices[i].fillColor = c
        pie.slices[i].fontColor = colors.black
    
    d.add(pie)
    return d


# -----------------------------
# RECONNAISSANCE SECTION
# -----------------------------
def build_recon_section(story, recon_data):
    story.append(Paragraph("1. RECONNAISSANCE SUMMARY", SectionHeader))
    story.append(Spacer(1, 10))
    
    story.append(Paragraph(
        "The following information was gathered during the reconnaissance phase:",
        BodyText
    ))
    story.append(Spacer(1, 10))
    
    recon_rows = []
    for key, value in recon_data.items():
        recon_rows.append([key.replace("_", " ").title(), str(value)])
    
    recon_table = Table(recon_rows, colWidths=[2*inch, 4.5*inch])
    recon_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#E8F4F8")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    
    story.append(recon_table)
    story.append(Spacer(1, 20))


# -----------------------------
# PORT SCAN SECTION
# -----------------------------
def build_port_section(story, port_results):
    story.append(Paragraph("2. PORT & SERVICE ENUMERATION", SectionHeader))
    story.append(Spacer(1, 10))
    
    if not port_results:
        story.append(Paragraph("No open ports detected.", BodyText))
        return
    
    story.append(Paragraph(
        f"The scan identified {len(port_results)} open port(s) with the following services:",
        BodyText
    ))
    story.append(Spacer(1, 10))
    
    rows = [["Port", "Service", "Version", "Vulnerabilities"]]
    for p in port_results:
        cve_count = len(p["cves"])
        vuln_text = f"{cve_count} CVE(s)" if cve_count > 0 else "None"
        
        rows.append([
            Paragraph(f"<b>{p['port']}</b>", SmallText),
            Paragraph(p["service"], SmallText),
            Paragraph(p["version"], SmallText),
            Paragraph(vuln_text, SmallText),
        ])
    
    table = Table(rows, colWidths=[0.8*inch, 1.5*inch, 2.5*inch, 1.5*inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#024180")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.whitesmoke]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    
    story.append(table)
    story.append(Spacer(1, 20))


# -----------------------------
# CVE DETAILS SECTION
# -----------------------------
def build_cve_section(story, all_cves):
    story.append(Paragraph("3. VULNERABILITY FINDINGS", SectionHeader))
    story.append(Spacer(1, 10))
    
    if not all_cves:
        story.append(Paragraph("No CVE vulnerabilities detected.", BodyText))
        return
    
    story.append(Paragraph(
        f"Detailed analysis of {len(all_cves)} identified vulnerabilities:",
        BodyText
    ))
    story.append(Spacer(1, 15))
    
    # Group by severity
    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for cve in all_cves:
        sev = cve.get("severity", "LOW").upper()
        by_severity.get(sev, by_severity["LOW"]).append(cve)
    
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cves = by_severity[sev]
        if not cves:
            continue
        
        story.append(Paragraph(f"{sev} Severity Vulnerabilities ({len(cves)})", SubHeader))
        
        for cve in cves:
            # Truncate long descriptions
            desc = cve.get("description", "No description available.")
            if len(desc) > 400:
                desc = desc[:397] + "..."
            
            cve_data = [
                [Paragraph(f"<b>{cve.get('cve', 'N/A')}</b>", BodyText), ""],
                ["Description", Paragraph(desc, SmallText)],
                ["Recommendation", Paragraph(cve.get("recommendation", "Apply security patches and mitigate exposure."), SmallText)]
            ]
            
            cve_table = Table(cve_data, colWidths=[1.3*inch, 5*inch])
            cve_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), severity_color(sev)),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                ("SPAN", (0, 0), (1, 0)),
                ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F5F5F5")),
                ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            
            story.append(cve_table)
            story.append(Spacer(1, 8))
        
        story.append(Spacer(1, 15))

# -----------------------------
# WEB VULNERABILITY SECTIONS
# -----------------------------

def build_web_xss_section(story, xss_data):
    """Build XSS findings section"""
    if not xss_data or not xss_data.get("xss"):
        return
    
    story.append(Paragraph("Cross-Site Scripting (XSS) Vulnerabilities", SubHeader))
    story.append(Spacer(1, 8))
    
    findings = xss_data.get("findings", [])
    if findings:
        story.append(Paragraph(
            f"<b>CRITICAL:</b> Detected {len(findings)} potential XSS vulnerability point(s).",
            BodyText
        ))
        story.append(Spacer(1, 8))
        
        for idx, finding in enumerate(findings[:10], 1):  # Limit to 10 to prevent overflow
            rows = [
                ["Parameter", finding.get("param", "N/A")],
                ["Payload", finding.get("payload", "N/A")],
                ["Status Code", str(finding.get("status_code", "N/A"))],
                ["Evidence", finding.get("evidence", "Reflected in response")],
            ]
            
            table = Table(rows, colWidths=[1.5*inch, 5*inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#FF934F")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            
            story.append(Paragraph(f"<b>XSS Finding #{idx}</b>", SmallText))
            story.append(table)
            story.append(Spacer(1, 8))
        
        if len(findings) > 10:
            story.append(Paragraph(
                f"<i>+ {len(findings) - 10} additional XSS findings not shown</i>",
                SmallText
            ))
    
    story.append(Spacer(1, 12))


def build_web_sqli_section(story, sqli_data):
    """Build SQL Injection findings section"""
    if not sqli_data or not sqli_data.get("sqli"):
        return
    
    story.append(Paragraph("SQL Injection Vulnerabilities", SubHeader))
    story.append(Spacer(1, 8))
    
    details = sqli_data.get("details", [])
    if details:
        story.append(Paragraph(
            f"<b>CRITICAL:</b> Detected {len(details)} potential SQL injection point(s).",
            BodyText
        ))
        story.append(Spacer(1, 8))
        
        for idx, finding in enumerate(details[:10], 1):
            inj_type = finding.get("type", "unknown")
            
            rows = [
                ["Parameter", finding.get("param", "N/A")],
                ["Injection Type", inj_type.replace("-", " ").title()],
            ]
            
            if inj_type == "error-based":
                rows.append(["Payload", finding.get("payload", "N/A")])
                rows.append(["DB Error", finding.get("evidence", "N/A")])
            elif inj_type == "boolean-based":
                rows.append(["Payload (True)", finding.get("payload_true", "N/A")])
                rows.append(["Payload (False)", finding.get("payload_false", "N/A")])
                evidence = finding.get("evidence", {})
                if isinstance(evidence, dict):
                    rows.append(["Evidence", f"Response length difference detected"])
                else:
                    rows.append(["Evidence", str(evidence)])
            
            table = Table(rows, colWidths=[1.5*inch, 5*inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#8B0000")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            
            story.append(Paragraph(f"<b>SQLi Finding #{idx}</b>", SmallText))
            story.append(table)
            story.append(Spacer(1, 8))
        
        if len(details) > 10:
            story.append(Paragraph(
                f"<i>+ {len(details) - 10} additional SQLi findings not shown</i>",
                SmallText
            ))
    
    story.append(Spacer(1, 12))


def build_web_headers_section(story, headers_data):
    """Build security headers analysis section"""
    if not headers_data:
        return
    
    story.append(Paragraph("HTTP Security Headers Analysis", SubHeader))
    story.append(Spacer(1, 8))
    
    missing = headers_data.get("missing_headers", [])
    secure = headers_data.get("secure", False)
    
    if secure:
        story.append(Paragraph(
            "<b>PASS:</b> All recommended security headers are present.",
            BodyText
        ))
    else:
        story.append(Paragraph(
            f"<b>WARNING:</b> {len(missing)} security header(s) missing.",
            BodyText
        ))
        story.append(Spacer(1, 8))
        
        if missing:
            rows = [["Missing Header", "Purpose"]]
            
            header_info = {
                "Content-Security-Policy": "Prevents XSS and data injection attacks",
                "Strict-Transport-Security": "Enforces HTTPS connections",
                "X-Frame-Options": "Prevents clickjacking attacks",
                "X-XSS-Protection": "Enables browser XSS filtering",
                "Referrer-Policy": "Controls referrer information"
            }
            
            for h in missing:
                purpose = header_info.get(h, "Security enhancement")
                rows.append([h, purpose])
            
            table = Table(rows, colWidths=[2.5*inch, 4*inch])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#FFD900")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            
            story.append(table)
    
    story.append(Spacer(1, 12))


def build_web_admin_section(story, admin_data):
    """Build admin panel discovery section"""
    if not admin_data or len(admin_data) == 0:
        return
    
    story.append(Paragraph("Admin Panel Discovery", SubHeader))
    story.append(Spacer(1, 8))
    
    story.append(Paragraph(
        f"Discovered {len(admin_data)} potential admin panel(s) or sensitive path(s):",
        BodyText
    ))
    story.append(Spacer(1, 8))
    
    rows = [["URL", "Status Code"]]
    for panel in admin_data[:20]:  # Limit to 20
        rows.append([
            panel.get("url", "N/A"),
            str(panel.get("status_code", "N/A"))
        ])
    
    table = Table(rows, colWidths=[4.5*inch, 1.5*inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4682B4")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    
    story.append(table)
    
    if len(admin_data) > 20:
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"<i>+ {len(admin_data) - 20} additional paths not shown</i>",
            SmallText
        ))
    
    story.append(Spacer(1, 12))


def build_web_directories_section(story, dir_data):
    """Build directory enumeration section"""
    if not dir_data or len(dir_data) == 0:
        return
    
    story.append(Paragraph("Directory Enumeration", SubHeader))
    story.append(Spacer(1, 8))
    
    story.append(Paragraph(
        f"Discovered {len(dir_data)} accessible directory/file(s):",
        BodyText
    ))
    story.append(Spacer(1, 8))
    
    rows = [["URL", "Status", "Size"]]
    for item in dir_data[:25]:  # Limit to 25
        size = item.get("content_length", 0)
        size_str = f"{size} bytes" if size else "N/A"
        
        rows.append([
            item.get("url", "N/A"),
            str(item.get("status_code", "N/A")),
            size_str
        ])
    
    table = Table(rows, colWidths=[4*inch, 1*inch, 1.5*inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4682B4")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    
    story.append(table)
    
    if len(dir_data) > 25:
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            f"<i>+ {len(dir_data) - 25} additional paths not shown</i>",
            SmallText
        ))
    
    story.append(Spacer(1, 12))


# -----------------------------
# COMBINED WEB SECTION
# -----------------------------
def build_web_section(story, web_data, url):
    if not url or not web_data:
        return
    
    story.append(PageBreak())
    story.append(Paragraph("4. WEB APPLICATION SECURITY", SectionHeader))
    story.append(Spacer(1, 10))
    
    story.append(Paragraph(f"Web application assessment for: <b>{url}</b>", BodyText))
    story.append(Spacer(1, 15))
    
    # Build each web vulnerability section
    build_web_sqli_section(story, web_data.get("sqli"))
    build_web_xss_section(story, web_data.get("xss"))
    build_web_headers_section(story, web_data.get("headers"))
    build_web_admin_section(story, web_data.get("admin_panels"))
    build_web_directories_section(story, web_data.get("directories"))


# -----------------------------
# RECOMMENDATIONS SECTION
# -----------------------------
def build_recommendations(story, sev_counts, web_vuln_count):
    story.append(PageBreak())
    story.append(Paragraph("5. REMEDIATION RECOMMENDATIONS", SectionHeader))
    story.append(Spacer(1, 10))
    
    recommendations = []
    
    if sev_counts.get("CRITICAL", 0) > 0:
        recommendations.append(
            "• <b>IMMEDIATE ACTION:</b> Address all Critical severity vulnerabilities within 24-48 hours. "
            "These vulnerabilities pose an immediate threat to system security."
        )
    
    if sev_counts.get("HIGH", 0) > 0:
        recommendations.append(
            "• <b>URGENT:</b> Remediate High severity vulnerabilities within 1-2 weeks. "
            "These issues can be easily exploited and may lead to system compromise."
        )
    
    if sev_counts.get("MEDIUM", 0) > 0:
        recommendations.append(
            "• <b>SCHEDULED:</b> Plan remediation of Medium severity vulnerabilities within 1-3 months. "
            "While not immediately critical, these should be addressed in regular maintenance cycles."
        )
    
    if sev_counts.get("LOW", 0) > 0:
        recommendations.append(
            "• <b>BEST PRACTICE:</b> Address Low severity findings as part of ongoing security improvements. "
            "These represent security best practices and hardening opportunities."
        )
    
    if web_vuln_count > 0:
        recommendations.append(
            "• <b>WEB SECURITY:</b> Address identified web vulnerabilities immediately, especially XSS and SQL injection. "
            "Implement input validation, output encoding, and use parameterized queries."
        )
    
    recommendations.extend([
        "• Implement a regular vulnerability scanning schedule (monthly recommended).",
        "• Establish a patch management process for timely security updates.",
        "• Consider penetration testing for comprehensive security validation.",
        "• Review and update security policies based on identified vulnerabilities.",
        "• Implement network segmentation and least privilege access controls.",
        "• Enable security headers on all web applications.",
        "• Implement Web Application Firewall (WAF) for additional protection."
    ])
    
    for rec in recommendations:
        story.append(Paragraph(rec, BulletText))
    
    story.append(Spacer(1, 20))


# -----------------------------
# HELPER: COUNT WEB VULNERABILITIES
# -----------------------------
def count_web_vulnerabilities(web_data):
    """Count total web vulnerabilities for risk scoring"""
    count = 0
    
    if not web_data:
        return 0
    
    # XSS findings
    if web_data.get("xss", {}).get("xss"):
        count += len(web_data["xss"].get("findings", []))
    
    # SQLi findings
    if web_data.get("sqli", {}).get("sqli"):
        count += len(web_data["sqli"].get("details", []))
    
    # Missing security headers
    if web_data.get("headers"):
        count += len(web_data["headers"].get("missing_headers", []))
    
    return count


# -----------------------------
# MAIN GENERATE FUNCTION
# -----------------------------
def generate_pdf(data):
    target = data["target"]
    OUTPUT_DIR = os.path.join(tempfile.gettempdir(), "cerberus_outputs")
    filename = os.path.join(OUTPUT_DIR, f"report_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.pdf")
    
    story = []
    
    # Calculate severity counts from CVEs
    all_cves = []
    for p in data.get("ports", []):
        all_cves.extend(p.get("cves", []))
    
    sev_counts = {
        "CRITICAL": sum(1 for c in all_cves if c.get("severity", "").upper() == "CRITICAL"),
        "HIGH": sum(1 for c in all_cves if c.get("severity", "").upper() == "HIGH"),
        "MEDIUM": sum(1 for c in all_cves if c.get("severity", "").upper() == "MEDIUM"),
        "LOW": sum(1 for c in all_cves if c.get("severity", "").upper() == "LOW"),
    }
    
    # Count web vulnerabilities
    web_vuln_count = count_web_vulnerabilities(data.get("web", {}))
    
    # Build report sections
    build_cover_page(story, target, sev_counts, web_vuln_count)
    build_executive_summary(story, data, sev_counts, web_vuln_count)
    build_recon_section(story, data.get("recon", {}))
    build_port_section(story, data.get("ports", []))
    build_cve_section(story, all_cves)
    build_web_section(story, data.get("web", {}), data.get("url"))
    build_recommendations(story, sev_counts, web_vuln_count)
    
    # Generate PDF with custom canvas
    doc = SimpleDocTemplate(filename, pagesize=A4,
                           topMargin=60, bottomMargin=60,
                           leftMargin=40, rightMargin=40)
    doc.build(story, canvasmaker=HeaderFooterCanvas)
    
    return filename
