#lowk copy pasted a large portion of this file 
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    LongTable
)
from io import BytesIO
from xml.sax.saxutils import escape
from datetime import datetime
from reportlab.platypus import Flowable


def generatePDF(url, findings):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch
    )

    styles = getSampleStyleSheet()
    content = []

    # Title
    content.append(Paragraph("Website Security Assessment", styles["Title"]))
    content.append(Spacer(1, 15))

    # Assessment information
    content.append(Paragraph(f"<b>Target:</b> {escape(url)}", styles["Normal"]))
    content.append(Paragraph(
        f"<b>Date:</b> {datetime.now().strftime('%B %d, %Y %I:%M %p')}",
        styles["Normal"]
    ))
    content.append(Spacer(1, 20))

    # Summary
    severityCounts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "NONE": 0
    }

    for finding in findings:
        severity = finding.get("severity", "NONE").upper()
        if severity in severityCounts:
            severityCounts[severity] += 1

    content.append(Paragraph("Executive Summary", styles["Heading2"]))

    summaryData = [
        ["Severity", "Number of Findings"],
        *[[severity, count] for severity, count in severityCounts.items()]
    ]

    summaryTable = Table(summaryData)
    summaryTable.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))

    content.append(summaryTable)
    content.append(Spacer(1, 20))

    # Detailed findings
    content.append(Paragraph("Detailed Findings", styles["Heading2"]))

    findingData: list[list[str | Flowable]] = [
        ["Name", "Status", "Severity", "Description", "Evidence"]
    ]

    for finding in findings:
        findingData.append([
            Paragraph(escape(str(finding.get("name", "")),), styles["BodyText"]),
            Paragraph(escape(str(finding.get("status", ""))), styles["BodyText"]),
            Paragraph(escape(str(finding.get("severity", ""))), styles["BodyText"]),
            Paragraph(escape(str(finding.get("description", ""))), styles["BodyText"]),
            Paragraph(escape(str(finding.get("evidence", ""))), styles["BodyText"])
        ])

    findingsTable = LongTable(
        findingData,
        repeatRows=1,
        colWidths=[1.0*inch, 0.7*inch, 0.7*inch, 2.0*inch, 2.0*inch]
    )

    findingsTable.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))

    content.append(findingsTable)

    document.build(content)

    buffer.seek(0)
    return buffer.getvalue()
