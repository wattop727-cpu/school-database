"""
parser.py
---------
Responsible for parsing raw email header text into structured data.
Uses: for loops, while loops, dictionaries, lists, tuples, recursive functions
"""

import re


# ── Regex patterns (compiled once for efficiency) ──────────────────────────
IPV4_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# Private / reserved IP ranges to ignore
PRIVATE_RANGES = [
    "10.", "192.168.", "127.", "0.", "172.16.", "172.17.",
    "172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
    "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31."
]


def is_private_ip(ip):
    """
    Check if an IP address is private or reserved.

    Parameters:
        ip (str): IPv4 address string

    Returns:
        bool: True if private, False if public
    """
    for prefix in PRIVATE_RANGES:         # for loop over list
        if ip.startswith(prefix):
            return True
    return False


def unfold_header_lines(raw_text):
    """
    Recursively unfold multi-line (folded) header values.
    RFC 5322 allows header values to continue on the next line
    if the next line starts with a space or tab.

    Parameters:
        raw_text (str): Raw header text, possibly with folded lines

    Returns:
        str: Unfolded header text
    """
    # Base case: if no folded lines remain, return as-is
    if "\r\n " not in raw_text and "\r\n\t" not in raw_text \
            and "\n " not in raw_text and "\n\t" not in raw_text:
        return raw_text

    # Recursive case: replace one fold and recurse
    unfolded = raw_text.replace("\r\n ", " ").replace("\r\n\t", " ")
    unfolded = unfolded.replace("\n ", " ").replace("\n\t", " ")
    return unfold_header_lines(unfolded)   # recursive call


def parse_headers(raw_text):
    """
    Parse raw email header text into a dictionary of field names → values.
    If a field appears more than once (e.g. Received), its values are
    stored as a list.

    Parameters:
        raw_text (str): The full raw email header string

    Returns:
        dict: Parsed header fields  {field_name: value_or_list}
    """
    unfolded = unfold_header_lines(raw_text)   # recursive function used here
    headers = {}       # dictionary to store results
    lines = unfolded.splitlines()

    for line in lines:                         # for loop over list
        if ": " in line and not line.startswith(" ") and not line.startswith("\t"):
            colon_index = line.index(": ")
            field_name  = line[:colon_index].strip()
            field_value = line[colon_index + 2:].strip()

            if field_name in headers:
                # Field already exists — convert to list or append
                if isinstance(headers[field_name], list):
                    headers[field_name].append(field_value)
                else:
                    headers[field_name] = [headers[field_name], field_value]
            else:
                headers[field_name] = field_value

    return headers


def extract_email_address(field_value):
    """
    Extract a plain email address from a header value that may contain
    a display name, e.g. 'John Smith <john@example.com>' → 'john@example.com'

    Parameters:
        field_value (str): Raw header field value

    Returns:
        str: Extracted email address, or the original value if none found
    """
    if "<" in field_value and ">" in field_value:
        start = field_value.index("<") + 1
        end   = field_value.index(">")
        return field_value[start:end].strip()
    return field_value.strip()


def extract_display_name(field_value):
    """
    Extract the display name from a From/To header value.
    e.g. 'John Smith <john@example.com>' → 'John Smith'

    Parameters:
        field_value (str): Raw header field value

    Returns:
        str: Display name, or empty string if none
    """
    if "<" in field_value:
        return field_value[:field_value.index("<")].strip().strip('"')
    return ""


def extract_domain(email_address):
    """
    Extract the domain part from an email address.
    e.g. 'john@example.com' → 'example.com'

    Parameters:
        email_address (str): Email address string

    Returns:
        str: Domain part, or empty string
    """
    if "@" in email_address:
        return email_address.split("@")[1].strip()
    return ""


def extract_received_hops(headers):
    """
    Extract all relay hop information from Received headers.
    Returns a list of tuples: (hop_number, ip_address, raw_received_line)

    Parameters:
        headers (dict): Parsed headers dictionary

    Returns:
        list: List of tuples (hop_number, ip, raw_line)
    """
    hops = []    # list to store hop tuples

    received_values = headers.get("Received", [])

    # Normalise to list even if only one Received header
    if isinstance(received_values, str):
        received_values = [received_values]

    # Received headers are in reverse order — reverse so hop 1 = origin
    received_values = list(reversed(received_values))

    hop_number = 1
    for raw_line in received_values:               # for loop
        matches = IPV4_PATTERN.findall(raw_line)
        for ip in matches:                         # for loop
            if not is_private_ip(ip):
                # Store as tuple: (hop_number, ip_address, raw_line)
                hop_tuple = (hop_number, ip, raw_line)
                hops.append(hop_tuple)
                break   # one public IP per hop is enough
        hop_number += 1

    return hops


def parse_authentication_results(headers):
    """
    Parse the Authentication-Results header to extract SPF, DKIM, DMARC results.

    Parameters:
        headers (dict): Parsed headers dictionary

    Returns:
        dict: {mechanism: result}  e.g. {"spf": "pass", "dkim": "fail"}
    """
    auth_results = {}    # dictionary for results
    auth_header  = headers.get("Authentication-Results", "")

    if isinstance(auth_header, list):
        auth_header = " ".join(auth_header)

    auth_header = auth_header.lower()

    # Check each mechanism using conditional statements
    for mechanism in ["spf", "dkim", "dmarc"]:        # for loop over list
        if mechanism in auth_header:
            # Find result after mechanism name
            idx = auth_header.index(mechanism)
            snippet = auth_header[idx: idx + 30]

            if "=pass" in snippet:
                auth_results[mechanism] = "pass"
            elif "=fail" in snippet:
                auth_results[mechanism] = "fail"
            elif "=softfail" in snippet:
                auth_results[mechanism] = "softfail"
            elif "=neutral" in snippet:
                auth_results[mechanism] = "neutral"
            elif "=none" in snippet:
                auth_results[mechanism] = "none"
            else:
                auth_results[mechanism] = "unknown"
        else:
            auth_results[mechanism] = "not found"

    # Also check Received-SPF header as fallback
    if auth_results["spf"] == "not found":
        spf_header = headers.get("Received-SPF", "").lower()
        if "pass" in spf_header:
            auth_results["spf"] = "pass"
        elif "fail" in spf_header:
            auth_results["spf"] = "fail"
        elif "softfail" in spf_header:
            auth_results["spf"] = "softfail"

    return auth_results
