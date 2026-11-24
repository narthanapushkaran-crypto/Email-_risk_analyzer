
import re
import sys
import os
import html
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet


# --------------------------------
# CONFIGURATION
# --------------------------------

URGENT_WORDS = [
    "urgent", "immediately", "act now",
    "verify your account", "account suspended",
    "password expired", "limited time",
    "click here", "payment failed",
    "confirm your identity", "security alert",
    "update your information"
]

SUSPICIOUS_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".js"
)


# --------------------------------
# HTML LINK EXTRACTION
# --------------------------------

class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self.links.append(value)


# --------------------------------
# EMAIL BODY EXTRACTION
# --------------------------------

def extract_body(message):
    bodies = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue

            if part.get_content_disposition() == "attachment":
                continue

            if part.get_content_type() in (
                "text/plain", "text/html"
            ):
                try:
                    content = part.get_content()
                    bodies.append(str(content))
                except Exception:
                    continue
    else:
        try:
            bodies.append(str(message.get_content()))
        except Exception:
            pass

    return "\n".join(bodies)


# --------------------------------
# DOMAIN EXTRACTION
# --------------------------------

def get_domain(address):
    _, email_address = parseaddr(address)

    if "@" not in email_address:
        return ""

    return email_address.rsplit("@", 1)[1].lower().strip(".")


def get_url_host(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return ""

        return (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def same_domain(host, sender_domain):
    """
    Conservative hostname comparison.
    This is not a public-suffix-list or
    organizational-domain verification.
    """
    if not host or not sender_domain:
        return False

    return (
        host == sender_domain or
        host.endswith("." + sender_domain)
    )


# --------------------------------
# EMAIL ANALYSIS
# --------------------------------

def analyze_email(filename):

    with open(filename, "rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    findings = []
    score = 0

    sender = message.get("From", "")
    return_path = message.get("Return-Path", "")
    subject = message.get("Subject", "No Subject")

    sender_domain = get_domain(sender)
    return_domain = get_domain(return_path)

    body = extract_body(message)
    body_text = html.unescape(body)
    lower_body = body_text.lower()

    # --------------------------------
    # 1. SENDER ANALYSIS
    # --------------------------------

    if not sender_domain:
        score += 10
        findings.append(
            "Sender email domain is missing or invalid."
        )

    # --------------------------------
    # 2. RETURN-PATH ANALYSIS
    # --------------------------------

    if return_domain and sender_domain:
        if not same_domain(return_domain, sender_domain):
            score += 15
            findings.append(
                "Return-Path domain differs from sender domain."
            )

    elif not return_path:
        findings.append(
            "Return-Path header is missing."
        )

    # --------------------------------
    # 3. SPF ANALYSIS
    # --------------------------------

    auth_headers = message.get_all(
        "Authentication-Results", []
    )

    spf_values = []

    for header in auth_headers:
        match = re.search(
            r"\bspf\s*=\s*([a-zA-Z]+)",
            str(header),
            re.IGNORECASE
        )

        if match:
            spf_values.append(match.group(1).lower())

    if not spf_values:
        findings.append(
            "SPF result not found in Authentication-Results."
        )

    elif "fail" in spf_values:
        score += 25
        findings.append(
            "SPF authentication failed."
        )

    elif "softfail" in spf_values:
        score += 15
        findings.append(
            "SPF authentication returned softfail."
        )

    elif "none" in spf_values:
        score += 10
        findings.append(
            "SPF authentication result is none."
        )

    elif "pass" in spf_values:
        findings.append(
            "SPF authentication passed."
        )

    # --------------------------------
    # 4. DKIM ANALYSIS
    # --------------------------------

    dkim_values = []

    for header in auth_headers:
        match = re.search(
            r"\bdkim\s*=\s*([a-zA-Z]+)",
            str(header),
            re.IGNORECASE
        )

        if match:
            dkim_values.append(match.group(1).lower())

    if not dkim_values:
        findings.append(
            "DKIM result not found in Authentication-Results."
        )

    elif "fail" in dkim_values:
        score += 25
        findings.append(
            "DKIM authentication failed."
        )

    elif "pass" in dkim_values:
        findings.append(
            "DKIM authentication passed."
        )

    # --------------------------------
    # 5. RECEIVED HEADER ANALYSIS
    # --------------------------------

    received_headers = message.get_all(
        "Received", []
    )

    if not received_headers:
        findings.append(
            "No Received headers were found."
        )
    else:
        findings.append(
            f"Found {len(received_headers)} Received headers."
        )

    # --------------------------------
    # 6. URGENT LANGUAGE DETECTION
    # --------------------------------

    detected_urgent = []

    for word in URGENT_WORDS:
        if word in lower_body:
            detected_urgent.append(word)

    if detected_urgent:
        score += min(20, len(detected_urgent) * 5)

        findings.append(
            "Urgent language detected: " +
            ", ".join(detected_urgent)
        )

    # --------------------------------
    # 7. URL EXTRACTION
    # --------------------------------

    parser = LinkExtractor()
    parser.feed(body)

    extracted_urls = list(parser.links)

    plain_urls = re.findall(
        r"https?://[^\s<>\"']+",
        body_text,
        re.IGNORECASE
    )

    all_urls = list(dict.fromkeys(
        extracted_urls + plain_urls
    ))

    suspicious_urls = []

    for url in all_urls:

        host = get_url_host(url)

        if not host:
            continue

        reasons = []

        # IP address URL
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
            reasons.append("IP-address URL")

        # Punycode domain
        if "xn--" in host:
            reasons.append("Punycode domain")

        # Sender and destination domain mismatch
        if sender_domain and not same_domain(
            host, sender_domain
        ):
            reasons.append(
                "Link domain differs from sender domain"
            )

        # Suspicious file extension
        path = urlparse(url).path.lower()

        if path.endswith(SUSPICIOUS_EXTENSIONS):
            reasons.append(
                "Potentially dangerous file extension"
            )

        if reasons:
            suspicious_urls.append({
                "url": url,
                "reasons": reasons
            })

    if suspicious_urls:
        score += min(25, len(suspicious_urls) * 10)

        findings.append(
            f"Found {len(suspicious_urls)} suspicious URL(s)."
        )

    # --------------------------------
    # 8. FINAL RISK CALCULATION
    # --------------------------------

    score = min(score, 100)

    if score >= 70:
        risk = "HIGH"
    elif score >= 35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # --------------------------------
    # RESULTS
    # --------------------------------

    results = {
        "sender": sender,
        "sender_domain": sender_domain,
        "return_path": return_path,
        "subject": subject,
        "score": score,
        "risk": risk,
        "findings": findings,
        "urls": all_urls,
        "suspicious_urls": suspicious_urls,
        "received_count": len(received_headers),
        "urgent_words": detected_urgent,
        "spf": spf_values,
        "dkim": dkim_values,
        "date": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    }

    return results


# --------------------------------
# PDF REPORT GENERATION
# --------------------------------

def generate_pdf(results, output_file):

    document = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()
    story = []

    story.append(
        Paragraph(
            "EMAIL SECURITY AUDIT REPORT",
            styles["Title"]
        )
    )

    story.append(Spacer(1, 15))

    summary = [
        ["Field", "Analysis Result"],
        ["Subject", results["subject"]],
        ["Sender", results["sender"]],
        ["Sender Domain", results["sender_domain"]],
        ["Return-Path", results["return_path"] or "Not found"],
        ["Risk Score", f'{results["score"]}/100'],
        ["Risk Level", results["risk"]],
        ["Received Headers", str(results["received_count"])],
        ["SPF", ", ".join(results["spf"]) or "Not found"],
        ["DKIM", ", ".join(results["dkim"]) or "Not found"],
        ["Analysis Date", results["date"]]
    ]

    table = Table(
        summary,
        colWidths=[130, 350]
    )

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))

    story.append(table)
    story.append(Spacer(1, 20))

    story.append(
        Paragraph("Detection Findings", styles["Heading2"])
    )

    for finding in results["findings"]:
        story.append(
            Paragraph(
                "&#8226; " + html.escape(finding),
                styles["BodyText"]
            )
        )
        story.append(Spacer(1, 5))

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("Suspicious URLs", styles["Heading2"])
    )

    if results["suspicious_urls"]:
        for item in results["suspicious_urls"]:
            story.append(
                Paragraph(
                    html.escape(item["url"]),
                    styles["BodyText"]
                )
            )

            story.append(
                Paragraph(
                    "Reasons: " + html.escape(
                        ", ".join(item["reasons"])
                    ),
                    styles["BodyText"]
                )
            )
            story.append(Spacer(1, 7))
    else:
        story.append(
            Paragraph(
                "No suspicious URLs detected by the configured rules.",
                styles["BodyText"]
            )
        )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("Risk Assessment", styles["Heading2"])
    )

    assessment = (
        "High risk: Strong phishing indicators detected."
        if results["risk"] == "HIGH"
        else
        "Medium risk: Some suspicious indicators require investigation."
        if results["risk"] == "MEDIUM"
        else
        "Low risk: Few configured phishing indicators detected."
    )

    story.append(
        Paragraph(assessment, styles["BodyText"])
    )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("Security Recommendations", styles["Heading2"])
    )

    recommendations = [
        "Do not click suspicious links or open unexpected attachments.",
        "Verify the sender through an independent trusted channel.",
        "Check SPF, DKIM and DMARC using trusted mail-server evidence.",
        "Do not enter passwords or payment information on unverified sites.",
        "Escalate high-risk messages to the security team."
    ]

    for recommendation in recommendations:
        story.append(
            Paragraph(
                "&#8226; " + recommendation,
                styles["BodyText"]
            )
        )
        story.append(Spacer(1, 5))

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            "Disclaimer: This is a heuristic screening tool. "
            "A low score does not prove an email is safe. "
            "Authentication results must be verified against "
            "trusted receiving-server evidence.",
            styles["Italic"]
        )
    )

    document.build(story)


# --------------------------------
# MAIN PROGRAM
# --------------------------------

def main():

    if len(sys.argv) < 2:
        print("Usage: python email_analyzer.py sample_email.eml")
        return

    filename = sys.argv[1]

    if not os.path.isfile(filename):
        print("Error: Email file not found.")
        return

    os.makedirs("output", exist_ok=True)

    print("\nStarting Email Risk Analyzer...\n")

    results = analyze_email(filename)

    print("========== EMAIL ANALYSIS ==========")
    print("Subject:", results["subject"])
    print("Sender:", results["sender"])
    print("Risk Score:", results["score"], "/100")
    print("Risk Level:", results["risk"])

    print("\nFindings:")

    for finding in results["findings"]:
        print("-", finding)

    print("\nGenerating PDF report...")

    pdf_file = os.path.join(
        "output",
        "Phishing_Analysis_Report.pdf"
    )

    generate_pdf(results, pdf_file)

    print("\nAnalysis completed successfully.")
    print("PDF Report:", pdf_file)


if __name__ == "__main__":
    main()
