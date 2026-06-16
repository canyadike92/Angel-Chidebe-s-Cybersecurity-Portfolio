#!/usr/bin/env python3
"""
================================================================
PHISHING ANALYSIS - STEP 3: IOC EXTRACTION PIPELINE
Author: Angel Chidebe
Date: May 2026

WORKFLOW:
  Stage 1 → Scan raw email/text file for all IOCs (regex)
  Stage 2 → Refang & deeply parse any defanged URLs found
================================================================
"""

import re
import sys
from urllib.parse import urlparse

# ══════════════════════════════════════════════════════════════
# STAGE 1 — GENERIC IOC EXTRACTOR (scans any raw text/email)
# ══════════════════════════════════════════════════════════════

def extract_iocs(text: str) -> dict:
    """Scan raw text for all IOC types using regex."""
    patterns = {
        "IPv4 Address" : r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "Domain"       : r'\b[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}\b',
        "URL"          : r'https?://[^\s<>"]+',
        "Email"        : r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "MD5 Hash"     : r'\b[a-fA-F0-9]{32}\b',
        "SHA256 Hash"  : r'\b[a-fA-F0-9]{64}\b',
        "Defanged URL" : r'hxxps?\[://\][^\s<>"]+',
    }
    results = {}
    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        unique  = list(set(matches))
        if unique:
            results[ioc_type] = unique
    return results


# ══════════════════════════════════════════════════════════════
# STAGE 2 — DEFANGED URL PARSER (deep analysis of one URL)
# ══════════════════════════════════════════════════════════════

def refang(url: str) -> str:
    """Convert defanged URL back to active form."""
    url = url.replace("hxxps", "https")
    url = url.replace("hxxp",  "http")
    url = url.replace("[://]", "://")
    url = url.replace("[.]",   ".")
    url = url.replace("(.)",   ".")
    return url

def parse_url_iocs(defanged_url: str) -> dict:
    """Refang and extract all components from a defanged URL."""
    refanged = refang(defanged_url)
    parsed   = urlparse(refanged)

    fqdn     = parsed.netloc
    path     = parsed.path
    filename = path.lstrip("/")
    labels   = fqdn.split(".")

    # Detect hosting platform
    platform = "Unknown"
    if "windows.net"  in fqdn: platform = "Microsoft Azure Blob Storage"
    elif "amazonaws"  in fqdn: platform = "Amazon AWS S3"
    elif "googleapis" in fqdn: platform = "Google Cloud Storage"
    elif "github.io"  in fqdn: platform = "GitHub Pages"

    return {
        "Defanged URL"    : defanged_url,
        "Refanged URL"    : refanged,
        "Scheme"          : parsed.scheme.upper(),
        "FQDN"            : fqdn,
        "Subdomain"       : ".".join(labels[:-3]) if len(labels) > 3 else "N/A",
        "Root Domain"     : ".".join(labels[-3:]) if len(labels) >= 3 else fqdn,
        "TLD"             : labels[-1],
        "Path"            : path,
        "Filename"        : filename,
        "File Extension"  : filename.split(".")[-1].upper() if "." in filename else "N/A",
        "Hosting Platform": platform,
    }

def threat_notes(ioc: dict) -> list:
    """Generate contextual threat intelligence notes."""
    notes = []
    if "Azure" in ioc["Hosting Platform"]:
        notes.append("Attacker abused Microsoft Azure (windows.net) — trusted domain used to bypass spam filters.")
    if ioc["File Extension"] == "HTML":
        notes.append(f"File '{ioc['Filename']}' is likely a phishing landing page.")
    if ioc["Scheme"] == "HTTPS":
        notes.append("HTTPS used — gives false sense of legitimacy to victims.")
    notes.append(f"Attacker-controlled subdomain: {ioc['Subdomain']}")
    return notes


# ══════════════════════════════════════════════════════════════
# MAIN PIPELINE
# ══════════════════════════════════════════════════════════════

def run_pipeline(source_text: str, defanged_urls: list):

    # ── Banner ─────────────────────────────────────────────
    print("\n" + "═" * 65)
    print("        PHISHING IOC EXTRACTION PIPELINE")
    print("═" * 65)

    # ── Stage 1 ────────────────────────────────────────────
    print("\n▶  STAGE 1 — SCANNING RAW TEXT FOR IOCs")
    print("─" * 65)
    stage1 = extract_iocs(source_text)
    if stage1:
        for ioc_type, values in stage1.items():
            print(f"\n  [{ioc_type.upper()}]")
            for v in values:
                print(f"    • {v}")
    else:
        print("  No IOCs found in source text.")

    # ── Stage 2 ────────────────────────────────────────────
    print("\n\n▶  STAGE 2 — DEEP URL ANALYSIS")
    print("─" * 65)

    for url in defanged_urls:
        ioc = parse_url_iocs(url)
        print(f"\n  {'─'*55}")
        for label, value in ioc.items():
            print(f"  {label:<20}: {value}")

        print(f"\n  [!] THREAT INTEL NOTES")
        for note in threat_notes(ioc):
            print(f"    ⚠  {note}")

        print(f"\n  [+] RECOMMENDED LOOKUPS")
        print(f"    → VirusTotal : https://www.virustotal.com/gui/domain/{ioc['FQDN']}")
        print(f"    → urlscan.io : https://urlscan.io/search/#page.domain:{ioc['FQDN']}")
        print(f"    → AbuseIPDB  : https://www.abuseipdb.com/check/{ioc['FQDN']}")

    print("\n" + "═" * 65)
    print("  PIPELINE COMPLETE")
    print("═" * 65 + "\n")


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # Simulated raw phishing email body (Stage 1 input)
    raw_email = """
    From: MAILER-DAEMON@unicode.org
    To: victim@company.com
    Subject: Urgent: Verify your account

    Dear User,

    Please verify your account by clicking the link below:
    hxxps[://]bawafide[.]z27[.]web[.]core[.]windows[.]net/wrza8igw3uko[.]html

    Sender IP: 104.24.17.17
    Reply-To: phishing@evil-domain.ru

    MD5:    d41d8cd98f00b204e9800998ecf8427e
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """

    # Defanged URLs to deep-parse in Stage 2
    targets = [
        "hxxps[://]bawafide[.]z27[.]web[.]core[.]windows[.]net/wrza8igw3uko[.]html"
    ]

    run_pipeline(raw_email, targets)
