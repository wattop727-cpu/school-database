"""
analyzer.py
-----------
Analyses parsed email header data and produces a risk assessment.
Uses: conditional statements, for loops, dictionaries, lists, tuples
"""

from parser import (
    parse_headers,
    extract_email_address,
    extract_display_name,
    extract_domain,
    extract_received_hops,
    parse_authentication_results,
)


# ── Detection rules ────────────────────────────────────────────────────────
# Each rule is a tuple: (rule_name, description, weight)
# Weight contributes to cumulative risk score
DETECTION_RULES = [
    ("spf_fail",       "SPF check failed — sender domain could not be verified",         3),
    ("spf_softfail",   "SPF softfail — sender is not fully authorised by domain policy",  2),
    ("dkim_fail",      "DKIM signature failed — message may have been tampered with",     3),
    ("dmarc_fail",     "DMARC policy failed — high likelihood of spoofing",               4),
    ("domain_mismatch","Display name domain differs from actual sending domain",           4),
    ("replyto_mismatch","Reply-To address domain differs from From address domain",        3),
    ("no_auth",        "No authentication headers found (SPF/DKIM/DMARC all missing)",    2),
]

# Risk thresholds
RISK_THRESHOLDS = {
    "Low":    (0, 3),
    "Medium": (4, 7),
    "High":   (8, 999),
}


def calculate_verdict(score):
    """
    Convert a numeric risk score into a verdict string.

    Parameters:
        score (int): Cumulative risk score

    Returns:
        str: 'Low Risk', 'Medium Risk', or 'High Risk'
    """
    for label, (low, high) in RISK_THRESHOLDS.items():   # for loop over dict
        if low <= score <= high:
            return f"{label} Risk"
    return "High Risk"


def analyse_headers(raw_text):
    """
    Main analysis function. Parses raw header text and runs all
    detection checks, returning a full results dictionary.

    Parameters:
        raw_text (str): Raw email header text

    Returns:
        dict: Full analysis results containing all extracted data and findings
    """
    # ── Step 1: Parse ──────────────────────────────────────────────────────
    headers     = parse_headers(raw_text)
    auth        = parse_authentication_results(headers)
    hops        = extract_received_hops(headers)

    # ── Step 2: Extract key fields ─────────────────────────────────────────
    from_raw      = headers.get("From", "")
    reply_to_raw  = headers.get("Reply-To", "")
    subject       = headers.get("Subject", "(No Subject)")
    date          = headers.get("Date", "(No Date)")
    message_id    = headers.get("Message-ID", "(No Message-ID)")

    from_address  = extract_email_address(from_raw)
    from_display  = extract_display_name(from_raw)
    from_domain   = extract_domain(from_address)

    reply_to_addr = extract_email_address(reply_to_raw) if reply_to_raw else ""
    reply_domain  = extract_domain(reply_to_addr) if reply_to_addr else ""

    # Display name domain (if display name contains an @ or domain hint)
    display_domain = extract_domain(from_display) if "@" in from_display else ""

    # ── Step 3: Run detection rules ────────────────────────────────────────
    findings      = []    # list of triggered rule descriptions
    score         = 0

    # Conditional checks for each authentication result
    if auth.get("spf") == "fail":
        findings.append(("spf_fail", "SPF check failed — sender domain could not be verified", 3))
        score += 3

    if auth.get("spf") == "softfail":
        findings.append(("spf_softfail", "SPF softfail — sender not fully authorised", 2))
        score += 2

    if auth.get("dkim") == "fail":
        findings.append(("dkim_fail", "DKIM signature failed — message may have been tampered with", 3))
        score += 3

    if auth.get("dmarc") == "fail":
        findings.append(("dmarc_fail", "DMARC policy failed — high likelihood of spoofing", 4))
        score += 4

    # Check for domain mismatch between display name and envelope from
    if display_domain and from_domain:
        if display_domain.lower() != from_domain.lower():
            findings.append(("domain_mismatch",
                              f"Display name domain '{display_domain}' differs from sending domain '{from_domain}'", 4))
            score += 4

    # Check for Reply-To mismatch
    if reply_domain and from_domain:
        if reply_domain.lower() != from_domain.lower():
            findings.append(("replyto_mismatch",
                              f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'", 3))
            score += 3

    # Check if no authentication headers at all
    all_missing = all(v == "not found" for v in auth.values())
    if all_missing:
        findings.append(("no_auth", "No SPF/DKIM/DMARC authentication headers found", 2))
        score += 2

    # ── Step 4: Build results dictionary ──────────────────────────────────
    verdict = calculate_verdict(score)

    results = {
        "subject":       subject,
        "date":          date,
        "message_id":    message_id,
        "from_raw":      from_raw,
        "from_address":  from_address,
        "from_display":  from_display,
        "from_domain":   from_domain,
        "reply_to":      reply_to_addr,
        "auth":          auth,          # dict: {spf, dkim, dmarc}
        "hops":          hops,          # list of tuples
        "findings":      findings,      # list of tuples (id, description, weight)
        "score":         score,
        "verdict":       verdict,
        "all_headers":   headers,       # full headers dict
    }

    return results
