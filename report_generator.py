from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from recommendations import get_recommendations


def generate_report(url, results, ports):

    filename = "report.pdf"

    pdf = SimpleDocTemplate(filename)
    styles = getSampleStyleSheet()

    elements = []

    # Title
    elements.append(
        Paragraph(
            "ONION WEBSITE SECURITY SCAN REPORT",
            styles['Title']
        )
    )

    elements.append(Spacer(1, 20))

    # Target URL
    elements.append(
        Paragraph(
            f"Target Website: {url}",
            styles['Normal']
        )
    )

    elements.append(Spacer(1, 25))

    # Security Headers
    elements.append(
        Paragraph(
            "Security Headers",
            styles['Heading2']
        )
    )

    for key, value in results.items():
        elements.append(
            Paragraph(
                f"{key}: {value}",
                styles['Normal']
            )
        )

    elements.append(Spacer(1, 25))

    # Open Ports
    elements.append(
        Paragraph(
            "Open Ports",
            styles['Heading2']
        )
    )

    for port in ports:
        elements.append(
            Paragraph(
                f"Port {port['port']} : {port['service']}",
                styles['Normal']
            )
        )

    elements.append(Spacer(1, 25))

    # Dynamic Recommendations
    elements.append(
        Paragraph(
            "Security Recommendations",
            styles['Heading2']
        )
    )

    recommendations = get_recommendations(results, ports)

    for rec in recommendations:
        elements.append(
            Paragraph(
                f"• {rec}",
                styles['Normal']
            )
        )

    # Build PDF
    pdf.build(elements)

    return filename