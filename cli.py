"""
cli.py
------
Command Line Interface for the Email Header Analyzer.
Uses: conditional statements, for loops, while loop, dictionaries, lists
"""

import sys
import os

from analyzer import analyse_headers


# ── ANSI colour codes for terminal output ──────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
DIM    = "\033[2m"


def colour_auth(result):
    """
    Return a coloured string for an authentication result.

    Parameters:
        result (str): Authentication result value

    Returns:
        str: ANSI-coloured result string
    """
    # Conditional statements for colour selection
    if result == "pass":
        return f"{GREEN}{BOLD}{result.upper()}{RESET}"
    elif result in ("fail", "permerror"):
        return f"{RED}{BOLD}{result.upper()}{RESET}"
    elif result in ("softfail", "neutral"):
        return f"{YELLOW}{result.upper()}{RESET}"
    else:
        return f"{DIM}{result.upper()}{RESET}"


def colour_verdict(verdict):
    """
    Return a coloured verdict string.

    Parameters:
        verdict (str): The verdict string e.g. 'High Risk'

    Returns:
        str: ANSI-coloured verdict
    """
    if "High" in verdict:
        return f"{RED}{BOLD}{verdict}{RESET}"
    elif "Medium" in verdict:
        return f"{YELLOW}{BOLD}{verdict}{RESET}"
    else:
        return f"{GREEN}{BOLD}{verdict}{RESET}"


def print_banner():
    """Print the application banner."""
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════╗
║       Email Header Analyzer  v1.0        ║
║   Ethical Hacking & Cyber Security       ║
╚══════════════════════════════════════════╝{RESET}
""")


def print_divider():
    """Print a visual divider line."""
    print(f"{DIM}{'─' * 60}{RESET}")


def display_results(results):
    """
    Print the full analysis results to the terminal.

    Parameters:
        results (dict): Analysis results from analyse_headers()
    """
    print_divider()
    print(f"{BOLD}{WHITE}  ANALYSIS RESULTS{RESET}")
    print_divider()

    # ── Key fields ─────────────────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}Key Fields:{RESET}")

    # Dictionary of fields to display — for loop over items
    key_fields = {
        "From":       results["from_raw"],
        "Reply-To":   results["reply_to"] or "—",
        "Subject":    results["subject"],
        "Date":       results["date"],
        "Message-ID": results["message_id"],
        "Domain":     results["from_domain"] or "—",
    }

    for label, value in key_fields.items():                # for loop
        print(f"  {BOLD}{label:<12}{RESET} {value}")

    # ── Authentication results ─────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}Authentication:{RESET}")
    auth = results["auth"]   # dictionary
    for mechanism, result in auth.items():                 # for loop over dict
        print(f"  {BOLD}{mechanism.upper():<8}{RESET} {colour_auth(result)}")

    # ── Hop trace ─────────────────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}Mail Relay Hops:{RESET}")
    hops = results["hops"]   # list of tuples

    if hops:
        for hop_tuple in hops:                             # for loop
            hop_num, ip, raw_line = hop_tuple              # tuple unpacking
            snippet = raw_line[:80] + "..." if len(raw_line) > 80 else raw_line
            print(f"  Hop {hop_num}:  {BOLD}{ip:<18}{RESET}  {DIM}{snippet}{RESET}")
    else:
        print(f"  {DIM}No public IP addresses found in Received headers{RESET}")

    # ── Detection findings ─────────────────────────────────────────────────
    print(f"\n{CYAN}{BOLD}Detection Findings:{RESET}")
    findings = results["findings"]   # list of tuples

    if findings:
        for finding_tuple in findings:                     # for loop
            rule_id, description, weight = finding_tuple  # tuple unpacking
            if weight >= 4:
                icon = f"{RED}⚠{RESET}"
            elif weight >= 3:
                icon = f"{YELLOW}⚠{RESET}"
            else:
                icon = f"{DIM}•{RESET}"
            print(f"  {icon}  [{weight:+d}]  {description}")
    else:
        print(f"  {GREEN}✅  No suspicious indicators detected{RESET}")

    # ── Verdict ────────────────────────────────────────────────────────────
    print_divider()
    verdict = results["verdict"]
    score   = results["score"]
    print(f"  {BOLD}VERDICT:  {colour_verdict(verdict)}   "
          f"{DIM}(Score: {score}){RESET}")
    print_divider()
    print()


def get_header_from_stdin():
    """
    Prompt the user to paste a raw email header in the terminal.
    Uses a while loop to keep reading until the user signals end of input.

    Returns:
        str: The raw header text entered by the user
    """
    print(f"{YELLOW}Paste the raw email header below.")
    print(f"When finished, press Enter then type 'END' on a new line and press Enter:{RESET}\n")

    lines = []
    while True:                                            # while loop
        try:
            line = input()
            if line.strip().upper() == "END":
                break
            lines.append(line)
        except EOFError:
            break

    return "\n".join(lines)


def run_cli():
    """
    Main CLI entry point. Handles file input or interactive paste mode.
    Uses a while loop for the interactive menu.
    """
    print_banner()

    # Check if a file was passed as a command-line argument
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
        if not os.path.exists(filepath):
            print(f"{RED}Error: File '{filepath}' not found.{RESET}")
            sys.exit(1)

        print(f"Loading header from: {filepath}\n")
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw_text = f.read()

        results = analyse_headers(raw_text)
        display_results(results)

    else:
        # Interactive menu — while loop
        while True:                                        # while loop
            print(f"{BOLD}Options:{RESET}")
            print("  1 — Paste a raw email header")
            print("  2 — Load from a file path")
            print("  3 — Exit\n")

            choice = input("Enter choice (1/2/3): ").strip()

            if choice == "1":
                raw_text = get_header_from_stdin()
                if raw_text.strip():
                    results = analyse_headers(raw_text)
                    display_results(results)
                else:
                    print(f"{RED}No header entered.{RESET}\n")

            elif choice == "2":
                filepath = input("Enter file path: ").strip()
                if os.path.exists(filepath):
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        raw_text = f.read()
                    results = analyse_headers(raw_text)
                    display_results(results)
                else:
                    print(f"{RED}File not found: {filepath}{RESET}\n")

            elif choice == "3":
                print("Goodbye.")
                break

            else:
                print(f"{RED}Invalid choice. Please enter 1, 2, or 3.{RESET}\n")
