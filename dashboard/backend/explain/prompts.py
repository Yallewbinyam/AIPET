"""
AIPET Explain — Prompt Templates
Builds structured prompts for Claude API calls.

Two prompt types:
1. finding_explanation_prompt() — explains a single vulnerability
2. executive_report_prompt()    — generates a CEO-readable scan summary
"""


def finding_explanation_prompt(finding):
    """
    Builds a prompt that asks Claude to explain a single finding
    in plain English for a non-technical audience.

    Args:
        finding (dict): {
            "attack":      "open_telnet",
            "severity":    "Critical",
            "description": "Telnet service detected on port 23",
            "target":      "192.168.1.1",
            "module":      "network"
        }

    Returns:
        str: A structured prompt ready to send to Claude
    """
    attack      = finding.get("attack",      "Unknown vulnerability")
    severity    = finding.get("severity",    "Unknown")
    description = finding.get("description", "No description available")
    target      = finding.get("target",      "Unknown device")
    module      = finding.get("module",      "Unknown module")

    prompt = f"""You are a cybersecurity expert writing for a non-technical business audience.

A security scan found this vulnerability on an IoT device:

- Device/Target: {target}
- Vulnerability: {attack}
- Severity: {severity}
- Technical Description: {description}
- Detected by: {module} security module

Write exactly two paragraphs with these headings:

WHY THIS IS DANGEROUS
Explain the real-world business risk in plain English. What could an attacker actually do if they exploited this? What is the worst case scenario? Write for a hospital administrator, factory owner, or small business manager — not a technical expert. Maximum 3 sentences. No technical jargon.

WHAT THIS MEANS FOR YOUR BUSINESS
Explain the practical impact on the organisation. Is data at risk? Could operations be disrupted? Could there be regulatory consequences? Maximum 2 sentences. No technical jargon.

Rules:
- Never use technical terms like CVE, CVSS, exploit, payload, shell, or buffer overflow
- Use plain business language
- Be specific about real consequences, not vague threats
- Do not include the headings as markdown — just write the heading in plain text followed by the paragraph"""

    return prompt


def executive_report_prompt(scan_data):
    """
    Builds a prompt that asks Claude to generate a CEO-readable
    one-page security report for a complete scan.

    Args:
        scan_data (dict): {
            "target":        "192.168.1.0/24",
            "total_findings": 12,
            "critical":      3,
            "high":          4,
            "medium":        3,
            "low":           2,
            "risk_level":    "CRITICAL",
            "top_findings":  [
                {"attack": "open_telnet", "severity": "Critical", "target": "192.168.1.1"},
                ...
            ],
            "devices_scanned": 4,
            "fixed_count":   2,
            "risk_reduction_pct": 27
        }

    Returns:
        str: A structured prompt ready to send to Claude
    """
    target           = scan_data.get("target",           "Network")
    total_findings   = scan_data.get("total_findings",   0)
    critical         = scan_data.get("critical",         0)
    high             = scan_data.get("high",             0)
    medium           = scan_data.get("medium",           0)
    low              = scan_data.get("low",              0)
    risk_level       = scan_data.get("risk_level",       "Unknown")
    devices_scanned  = scan_data.get("devices_scanned",  0)
    fixed_count      = scan_data.get("fixed_count",      0)
    risk_reduction   = scan_data.get("risk_reduction_pct", 0)
    top_findings     = scan_data.get("top_findings",     [])

    # Format top findings as readable text
    top_findings_text = ""
    for i, f in enumerate(top_findings[:5], 1):
        top_findings_text += f"{i}. {f.get('attack', 'Unknown')} on {f.get('target', 'Unknown device')} — {f.get('severity', 'Unknown')} severity\n"

    if not top_findings_text:
        top_findings_text = "No findings recorded."

    prompt = f"""You are a Chief Information Security Officer writing a board-level security report.

SCAN RESULTS SUMMARY:
- Network scanned: {target}
- Devices assessed: {devices_scanned}
- Total vulnerabilities found: {total_findings}
- Critical severity: {critical}
- High severity: {high}
- Medium severity: {medium}
- Low severity: {low}
- Overall risk rating: {risk_level}
- Vulnerabilities resolved: {fixed_count} of {total_findings} ({risk_reduction}% risk reduced)

TOP VULNERABILITIES FOUND:
{top_findings_text}

Write a professional board-level security report with exactly these four sections:

EXECUTIVE SUMMARY
Two sentences. What was assessed and what is the overall conclusion. Write for a CEO or board member.

KEY RISKS IDENTIFIED
A bullet point list of the 3-5 most important risks in plain business language. Each bullet should explain what the risk is and what could happen if exploited. No technical jargon.

IMMEDIATE ACTIONS REQUIRED
A numbered list of the top 3 actions the organisation should take in the next 7 days. Be specific and practical. Write as if giving instructions to an IT manager.

OVERALL SECURITY ASSESSMENT
One paragraph. Give an honest assessment of the organisation's current security posture. Is this situation serious? What is the trend if nothing is done? What is the outlook if recommended actions are taken?

Rules:
- Write in professional business English
- No technical jargon — if you must use a technical term, explain it in brackets
- Be honest about severity — do not downplay critical risks
- Keep the entire report under 400 words
- Do NOT use any markdown formatting whatsoever
- Do NOT use asterisks, hashes, underscores, or any special characters for formatting
- Write in plain text only — no **bold**, no *italic*, no # headers
- Section headings should be plain text in ALL CAPS only"""

    return prompt