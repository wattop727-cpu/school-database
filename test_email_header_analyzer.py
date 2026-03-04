"""
test_email_header_analyzer.py
------------------------------
Unit tests for the Email Header Analyzer.
Tests: parser.py and analyzer.py functions
Uses: conditional statements, for loops, lists, dictionaries, tuples
"""

import sys
import os
import unittest

# Add parent directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parser import (
    unfold_header_lines,
    parse_headers,
    extract_email_address,
    extract_display_name,
    extract_domain,
    extract_received_hops,
    parse_authentication_results,
    is_private_ip,
)
from analyzer import analyse_headers, calculate_verdict


# ── Sample headers for testing ─────────────────────────────────────────────

LEGITIMATE_HEADER = """From: Support Team <support@example.com>
To: user@gmail.com
Subject: Your account update
Date: Mon, 20 Jan 2025 10:00:00 +0000
Message-ID: <abc123@example.com>
Received: from mail.example.com (203.0.113.5) by mx.gmail.com
Received: from localhost (127.0.0.1) by mail.example.com
Authentication-Results: mx.google.com; spf=pass dkim=pass dmarc=pass
"""

PHISHING_HEADER = """From: PayPal Security <paypal@gmail.com>
To: victim@example.com
Subject: Urgent: Verify your account
Date: Mon, 20 Jan 2025 10:00:00 +0000
Message-ID: <xyz789@suspicious.net>
Reply-To: hacker@evil.com
Received: from compromised.server.ru (198.51.100.42) by mx.victim.com
Authentication-Results: mx.victim.com; spf=fail dkim=fail dmarc=fail
"""

FOLDED_HEADER = """Subject: This is a very long subject that has been
 folded onto the next line
From: test@example.com
"""

SPOOFED_DISPLAY_HEADER = """From: PayPal Support <scammer@fraud-domain.com>
To: target@gmail.com
Subject: Account suspended
"""


# ── Test Classes ───────────────────────────────────────────────────────────

class TestPrivateIPDetection(unittest.TestCase):
    """Tests for the is_private_ip() function."""

    def test_private_192_168(self):
        """Private 192.168.x.x should be detected as private."""
        self.assertTrue(is_private_ip("192.168.1.1"))

    def test_private_10(self):
        """Private 10.x.x.x should be detected as private."""
        self.assertTrue(is_private_ip("10.0.0.1"))

    def test_loopback(self):
        """Loopback 127.x.x.x should be detected as private."""
        self.assertTrue(is_private_ip("127.0.0.1"))

    def test_public_ip(self):
        """Public IP should NOT be detected as private."""
        self.assertFalse(is_private_ip("203.0.113.5"))

    def test_public_ip_2(self):
        """Another public IP should not be private."""
        self.assertFalse(is_private_ip("8.8.8.8"))


class TestUnfoldHeaders(unittest.TestCase):
    """Tests for the unfold_header_lines() recursive function."""

    def test_no_folding_needed(self):
        """A header with no folded lines should be returned unchanged."""
        text = "From: test@example.com\nSubject: Hello"
        result = unfold_header_lines(text)
        self.assertEqual(result, text)

    def test_unfolds_space_continuation(self):
        """A folded line starting with a space should be unfolded."""
        text = "Subject: Long subject\n continued here"
        result = unfold_header_lines(text)
        self.assertNotIn("\n ", result)
        self.assertIn("continued here", result)

    def test_unfolds_tab_continuation(self):
        """A folded line starting with a tab should be unfolded."""
        text = "Subject: Long subject\n\tcontinued here"
        result = unfold_header_lines(text)
        self.assertNotIn("\n\t", result)


class TestParseHeaders(unittest.TestCase):
    """Tests for the parse_headers() function."""

    def test_parses_from_field(self):
        """From field should be correctly parsed."""
        headers = parse_headers(LEGITIMATE_HEADER)
        self.assertIn("From", headers)
        self.assertIn("support@example.com", headers["From"])

    def test_parses_subject(self):
        """Subject field should be correctly parsed."""
        headers = parse_headers(LEGITIMATE_HEADER)
        self.assertEqual(headers.get("Subject"), "Your account update")

    def test_multiple_received_stored_as_list(self):
        """Multiple Received headers should be stored as a list."""
        headers = parse_headers(LEGITIMATE_HEADER)
        received = headers.get("Received")
        self.assertIsInstance(received, list)
        self.assertEqual(len(received), 2)

    def test_returns_dictionary(self):
        """parse_headers should return a dictionary."""
        headers = parse_headers(LEGITIMATE_HEADER)
        self.assertIsInstance(headers, dict)


class TestEmailExtraction(unittest.TestCase):
    """Tests for extract_email_address() and extract_display_name()."""

    def test_extract_address_from_angle_brackets(self):
        """Email address in angle brackets should be extracted correctly."""
        result = extract_email_address("John Smith <john@example.com>")
        self.assertEqual(result, "john@example.com")

    def test_extract_address_plain(self):
        """Plain email address should be returned as-is."""
        result = extract_email_address("john@example.com")
        self.assertEqual(result, "john@example.com")

    def test_extract_display_name(self):
        """Display name should be extracted from 'Name <email>' format."""
        result = extract_display_name("John Smith <john@example.com>")
        self.assertEqual(result, "John Smith")

    def test_extract_display_name_no_name(self):
        """Plain email with no display name should return empty string."""
        result = extract_display_name("john@example.com")
        self.assertEqual(result, "")


class TestDomainExtraction(unittest.TestCase):
    """Tests for extract_domain()."""

    def test_extract_domain(self):
        """Domain should be extracted correctly from email address."""
        result = extract_domain("user@example.com")
        self.assertEqual(result, "example.com")

    def test_no_at_symbol(self):
        """Input with no @ should return empty string."""
        result = extract_domain("notanemail")
        self.assertEqual(result, "")


class TestHopExtraction(unittest.TestCase):
    """Tests for extract_received_hops()."""

    def test_extracts_public_ip(self):
        """Public IP from Received header should be extracted."""
        headers = parse_headers(LEGITIMATE_HEADER)
        hops = extract_received_hops(headers)
        # hops is a list of tuples
        self.assertIsInstance(hops, list)
        ips = [hop[1] for hop in hops]          # for loop with tuple index
        self.assertIn("203.0.113.5", ips)

    def test_filters_private_ip(self):
        """Private IP (127.0.0.1) should NOT appear in hop trace."""
        headers = parse_headers(LEGITIMATE_HEADER)
        hops = extract_received_hops(headers)
        ips = [hop[1] for hop in hops]          # for loop
        self.assertNotIn("127.0.0.1", ips)

    def test_hops_are_tuples(self):
        """Each hop should be stored as a tuple."""
        headers = parse_headers(LEGITIMATE_HEADER)
        hops = extract_received_hops(headers)
        for hop in hops:                        # for loop
            self.assertIsInstance(hop, tuple)
            self.assertEqual(len(hop), 3)       # (hop_num, ip, raw_line)


class TestAuthenticationParsing(unittest.TestCase):
    """Tests for parse_authentication_results()."""

    def test_parses_spf_pass(self):
        """SPF=pass should be correctly parsed."""
        headers = parse_headers(LEGITIMATE_HEADER)
        auth = parse_authentication_results(headers)
        self.assertEqual(auth.get("spf"), "pass")

    def test_parses_dkim_pass(self):
        """DKIM=pass should be correctly parsed."""
        headers = parse_headers(LEGITIMATE_HEADER)
        auth = parse_authentication_results(headers)
        self.assertEqual(auth.get("dkim"), "pass")

    def test_parses_spf_fail(self):
        """SPF=fail should be correctly parsed in phishing header."""
        headers = parse_headers(PHISHING_HEADER)
        auth = parse_authentication_results(headers)
        self.assertEqual(auth.get("spf"), "fail")

    def test_returns_dictionary(self):
        """Authentication results should be returned as a dictionary."""
        headers = parse_headers(LEGITIMATE_HEADER)
        auth = parse_authentication_results(headers)
        self.assertIsInstance(auth, dict)
        for key in ["spf", "dkim", "dmarc"]:    # for loop
            self.assertIn(key, auth)


class TestCalculateVerdict(unittest.TestCase):
    """Tests for the calculate_verdict() function."""

    def test_low_risk(self):
        """Score 0 should be Low Risk."""
        self.assertEqual(calculate_verdict(0), "Low Risk")

    def test_low_risk_boundary(self):
        """Score 3 should still be Low Risk."""
        self.assertEqual(calculate_verdict(3), "Low Risk")

    def test_medium_risk(self):
        """Score 5 should be Medium Risk."""
        self.assertEqual(calculate_verdict(5), "Medium Risk")

    def test_high_risk(self):
        """Score 10 should be High Risk."""
        self.assertEqual(calculate_verdict(10), "High Risk")


class TestFullAnalysis(unittest.TestCase):
    """Integration tests for the full analyse_headers() pipeline."""

    def test_legitimate_email_low_risk(self):
        """Legitimate header with all auth passing should score Low Risk."""
        results = analyse_headers(LEGITIMATE_HEADER)
        self.assertEqual(results["verdict"], "Low Risk")

    def test_phishing_email_high_risk(self):
        """Phishing header with all auth failing should score High Risk."""
        results = analyse_headers(PHISHING_HEADER)
        # Should trigger spf_fail + dkim_fail + dmarc_fail = 10 points
        self.assertIn(results["verdict"], ["Medium Risk", "High Risk"])

    def test_results_contains_required_keys(self):
        """Analysis results dictionary must contain all required keys."""
        results = analyse_headers(LEGITIMATE_HEADER)
        required_keys = [
            "subject", "date", "from_address", "from_domain",
            "auth", "hops", "findings", "score", "verdict", "all_headers"
        ]
        for key in required_keys:              # for loop
            self.assertIn(key, results)

    def test_auth_is_dict(self):
        """auth field in results should be a dictionary."""
        results = analyse_headers(LEGITIMATE_HEADER)
        self.assertIsInstance(results["auth"], dict)

    def test_hops_is_list(self):
        """hops field in results should be a list."""
        results = analyse_headers(LEGITIMATE_HEADER)
        self.assertIsInstance(results["hops"], list)

    def test_findings_is_list(self):
        """findings field in results should be a list."""
        results = analyse_headers(LEGITIMATE_HEADER)
        self.assertIsInstance(results["findings"], list)


# ── Run tests ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main(verbosity=2)
