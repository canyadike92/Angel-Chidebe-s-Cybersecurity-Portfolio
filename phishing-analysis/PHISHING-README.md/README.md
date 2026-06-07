# Phishing Email Analysis: Credential Harvesting Campaign

> **Analyst:** [Angel Chidebe]
> **Date:** [May 2026]
> **Status:** Complete
> **Severity:** High
> **Disposition:** Malicious, Phishing, Spam — Confirmed credential harvesting attempt
---

## Table of contents

1. [Scenario and objectives](#scenario-and-objectives)
2. [Tools used](#tools-used)
3. [Investigation walkthrough](#investigation-walkthrough)
   - [Step 1: Email header analysis](#step-1-email-header-analysis)
   - [Step 2: URL and domain analysis](#step-2-url-and-domain-analysis)
   - [Step 3: IOC extraction](#step-4-ioc-extraction)
   - [Step 4: SIEM correlation](#step-5-siem-correlation)
   - [Step 5: Threat intel enrichment](#step-6-threat-intel-enrichment)
   - [Step 6: Ticketing and escalation](#step-7-ticketing-and-escalation)
5. [Findings](#findings)
6. [MITRE ATT&CK mapping](#mitre-attck-mapping)
7. [Detection rule](#detection-rule)
8. [Recommendations](#recommendations)
9. [Lessons learned](#lessons-learned)
10. [Artifacts and evidence](#artifacts-and-evidence)

---

## Scenario and Objectives

**Scenario:** A targeted phishing email impersonating Microsoft account team was submitted via the phishing report button by a user. The email claimed there was an unusual sign-in activity in the user's Microsoft 365 account which could lead to account suspension, prompting an immediate reset via an embedded link. The embedded link contained a malicious URL redirecting to a spoofed Microsoft login page hosted on a domain through a malicious URL.

**Objectives:** (WORK ON THIS)
- Determine whether the email is malicious or a false positive
- Extract all indicators of compromise (IOCs)
- Identify any users who may have clicked the link or submitted credentials
- Produce a TheHive ticket with findings and recommended containment actions

**What this project is:** This write-up documents the full investigation from raw email headers to containment and a closed ticket. No credentials were submitted. The sending infrastructure was traced to a known threat actor cluster with medium confidence.

**Source:** Sample .eml - Phishing Pot (github.com/rf-peixoto/phishing_pot/blob/main/email/sample-101.eml) 
            URL         - PhisTank

If you are a hiring manager reading this: I wanted to document not just what I found, but how I thought through each step and where I would do things differently next time.
---

## Tools used

| Tool | Purpose |
|---|---|
| Splunk | Log correlation, identifying other affected users |
| VirusTotal | URL and file hash reputation lookup |
| MISP | Threat intel enrichment, campaign correlation |
| Python | Header parsing script, IOC extraction |
| TheHive | Incident ticketing and case management |
| MXToolbox | SPF, DKIM, DMARC validation |
| URLScan.io | Safe URL detonation and screenshot capture |
| CyberChef | Base64 decoding, URL defanging |

---

## Investigation walkthrough

### Step 1: Email header analysis
The first thing I do with any reported phishing email is pull the raw headers because it tells me where the email actually came from, not just who it claims to be from. The raw headers were extracted from the .eml file and analyzed manually with MXToolbox.

**Key header fields examined:**
Email header analysis showing SPF, DKIM, and DMARC failures
```
From:        Microsoft account team <no-reply@microsoft[.]com>
Subject:     Urgent: Microsoft account unusual sign-in activity. Verify your account
Reply-To:    media-protection@usual-assist[.]com
Return-Path: bounce@nisihfjoz.co[.]uk
Received:    from nisihfjoz.co[.]uk (103.167.154[.]120)
X-Mailer:    PHPMailer 6.6.4
Message-ID:  <ce2fb41e-b910-4df7-bbfb-43b8126ba45c@DM6NAM11FT012.eop-nam11.prod.protection.outlook[.]com>
```
**Authentication results:**

Then the authentication results confirmed it:
| Check | Result | Notes |
|---|---|---|
| SPF | FAIL | protection.outlook.com: nisihfjoz.co[.]uk does not designate permitted sender hosts |
| DKIM | FAIL | Domain dkim:microsoft[.]com:smtp is invalid, No key for signature present |
| DMARC | FAIL | No policy published, nothing to enforce |

---

Observations: Two things jumped out immediately. The Reply-To (@usual-assist[.]com) address differs from the From Microsoft account team <no-reply@microsoft[.]com) address, a common indicator that proves the attacker wants replies to go somewhere they control. The other flag is PHPMailer 6.6.4 in the X-Mailer field indicates bulk sending infrastructure, not a corporate mail server. 

### Step 2: URL and domain analysis

I defanged the embedded link before analyzing it so I did not accidentally click it:
```
Original (defanged): hxxps[://]bawafide[.]z27[.]web[.]core[.]windows[.]net/wrza8igw3uko[.]html
```
**WHOIS lookup:**
```
Domain:       windows.net
Registered:   10-08-1995
Registrar:    MarkMonitor Inc.
Name servers: ns1-39.azure-dns.com, ns2-39.azure-dns.net, ns3-39.azure-dns.org, ns4-39.azure-dns.info
Corporation: Microsoft corporation
```
I ran the domain through CiscoTalos, VirusTotal and URLScan.io seperately for individual analysis. The summary results were pretty definitive:

**VirusTotal result:** The domain had 15 of 92 vendor detections, all categorized as phishing.

**Cisco Talos:** - Web Reputation (Untrusted) - Threat Category (Malware, Phishing, Spam)

**URLScan.io:** - Live Information (Malicious) - 3 HTTP transactions with credentials exfiltrated via HTTPS GET - Current DNS As record: 20.150.1.1 (AS8075 - MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US) Autonomous System 13335 (CLOUDFLARENET - Cloudflare). This website contacted 3 IPs in 2 countries across 3 domains to perform 3 HTTP transactions. The main IP is 20.150.1.1, located in Québec, Canada and belongs to MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US. 

**Red flags:**
- Two separate Autonomous sytem servers with separate IP's 104.17.24.14 IP for (CLOUDFLARENET - Cloudflare) and 20.150.1.1 for (MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation).
- IP 20.150.1.1 was operating from Canada although Microsoft Corporation is a USA company mainly operating in the USA

**Here is a breakdown of my observation:**
- MICROSOFT-CORP-MSN-AS-BLOCK is the name of Microsoft's Autonomous System (AS), which is a block of IP addresses owned and managed by Microsoft Corporation. This likely means that one of the IPs or URLs found in the phishing email resolves to Microsoft's infrastructure, which could indicate:

- The attacker used Microsoft services (like OneDrive, SharePoint, or Outlook) to host malicious content which is a common phishing tactic
- It could be a legitimate Microsoft link being abused to appear trustworthy

Phishers often abuse trusted platforms like Microsoft to bypass spam filters. This is a common red flag in phishing emails — using trusted, legitimate platforms to host malicious content or redirect victims, making it harder for security tools to block them.

### Step 3: IOC extraction

I used the Python script in this repo (tools/ioc_extractor.py) to do the following: 
- parse the all components using Python's urlparse, extract FQDN, subdomain, root domain, path, filename, and hosting platform
- print threat intel notes with direct links to query the IOCs on VirusTotal, urlscan.io, and AbuseIPDB. Then I defanged everything before documenting them.

```
# IOC EXTRACTION AND DEEP URL ANALYSIS REPORT
  Defanged URL          : hxxps[://]bawafide[.]z27[.]web[.]core[.]windows[.]net/wrza8igw3uko[.]html
  Protocol/Scheme       : HTTPS
  FQDN                  : bawafide.z27.web.core.windows.net
  Subdomain             : bawafide.z27.web
  Root Domain           : core.windows.net
  TLD                   : net
  URL Path              : /wrza8igw3uko.html
  Filename              : wrza8igw3uko.html
  File Extension        : HTML
  Hosting Platform      : Microsoft Azure Blob Storage (windows.net)
  MD5                   : [d41d8cd98f00b204e9800998ecf8427e]
  SHA256                : [e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855]
```
How it all connects together

Key finding: The attacker abused Microsoft Azure infrastructure (windows.net) to host a phishing page, exploiting the trusted domain to bypass 
spam filters by doing the following:

STEP 1 → Attacker hosts phishing page on Azure (104.17.24.14)
STEP 2 → Sends phishing email via SMTP (173.66.46.112)
STEP 3 → Mail server blocks it (Frame 156 code 553)
STEP 4 → Python pipeline extracts all IOCs

**IOC extraction screenshots:** [`tools/ioc_extractor.py`](../../tools/ioc_extractor.py)

Full IOC pipeline is in iocs/ioc_extractor.py.

### Step 4: SIEM/Splunk Correlation
Once I had the IOCs, I went into Splunk to figure out the blast radius. Three questions I wanted to answer:

Did anyone else get this email?
Did anyone click the link?
Was there any suspicious auth activity after delivery?
Query 1: who else received it

index=email_logs sourcetype=mail_logs
| search sender_domain="it-helpdeskk.com"
| stats count by recipient, subject, timestamp
| sort -timestamp
Returned two results. The original reporter and one other Finance mailbox.

Query 2: did anyone click

index=proxy_logs sourcetype=squid
| search url="*it-helpdeskk*" OR dest_ip="185.220.101.47"
| stats count by src_ip, url, user, timestamp
| sort -timestamp
Zero results. Neither user accessed the URL.

Query 3: any post-delivery auth anomalies

index=auth_logs sourcetype=o365_audit
| search UserId IN ("jsmith@company.com", "mmurphy@company.com")
| where EventCreationTime > "2024-03-14T09:47:00"
| stats count by UserId, Operation, ClientIP, timestamp
No anomalous logins. No foreign countries. No MFA bypass attempts.

At this point I had high confidence that this was a close call rather than a breach.

Splunk queries showing 2 recipients, 0 clicks, 0 anomalous auth events

### Step 5: MISP threat intel enrichment
I submitted the IOCs to MISP to see if any of them matched prior campaigns.

The IP 185.220.101[.]47 matched MISP Event #4471, which tracks Tor exit nodes used in financially motivated phishing targeting financial services. Fourteen prior events in the cluster.

The domain and URLs did not match anything, which confirms this is fresh infrastructure being stood up for this specific campaign wave.

The infrastructure pattern (Namecheap registrar, self-hosted nameservers, PHPMailer) matched the TTPs of TA2541 across nine prior campaigns. Medium confidence attribution.

I created a new MISP event to document the fresh indicators and linked it to the existing cluster.

MISP enrichment showing IP match to prior campaign cluster and TA2541 attribution

### Step 6: Ticketing and escalation
I opened a TheHive case to document findings and track containment.

 Sending domain it-helpdeskk[.]com blocked at email gateway
 IP 185.220.101[.]47 blocked at perimeter firewall
 IOCs shared to MISP event for cross-org visibility
 Detection rule added to SOC runbook
 Finance team flagged for targeted phishing simulation
 Case closed, no breach confirmed
TheHive case showing completed task checklist and resolution

Tasks completed:

 Email headers analyzed
 URL detonated safely
 IOCs extracted and defanged
 Splunk correlation — no clicks confirmed
 MISP enrichment complete
 Sending domain blocked at email gateway
 IP blocked at perimeter firewall
 Second recipient notified
 Case closed — no breach
## Findings summary
| # | Finding | Severity | Detail |
|---|---|---|---|
| 1 | All email authentication controls failed | High | SPF, DKIM, and DMARC all absent on sending domain |
| 2 | Lookalike domain registered 3 days prior | High | Typosquat of legitimate IT brand |
| 3 | Credential harvesting exfil endpoint identified | High | POST destination is a known malicious Tor exit node |
| 4 | Two recipients identified | Medium | Finance team targeted specifically, not a mass blast |
| 5 | No credential submission confirmed | Informational | No clicks or post-click auth activity detected |
| 6 | Campaign linked to prior activity in MISP | Medium | Medium-confidence attribution based on infrastructure overlap |

## MITRE ATT&CK Mapping
| Technique ID | Technique name | Observed behavior |
|---|---|---|
| T1566.001 | Spearphishing attachment | Targeted phishing delivered via email |
| T1566.002 | Spearphishing link | Malicious URL embedded in email body |
| T1078 | Valid accounts | Objective was to steal M365 credentials |
| T1598.003 | Phishing for information | Credential harvesting form on cloned login page |
| T1071.001 | App layer protocol: web | Exfiltration via HTTPS GET to attacker server |

### T1566.002 — Phishing: Spearphishing Link
The phishing email contained a malicious URL embedded in the body.
The URL was defanged as:
hxxps[://]bawafide[.]z27[.]web[.]core[.]windows[.]net/wrza8igw3uko[.]html
This is consistent with spearphishing via link — a common initial
access technique.

### T1036.005 — Masquerading: Match Legitimate Name
The attacker chose the subdomain 'bawafide' to mimic the English
word 'bona fide', creating a false sense of legitimacy for the victim.

### T1583.001 — Acquire Infrastructure: Domains
The attacker hosted the phishing page on Microsoft Azure (windows.net),
a trusted platform, to bypass email security filters and spam blockers.
The randomized filename (wrza8igw3uko.html) suggests an auto-generated
phishing kit was used.

### T1598.003 — Phishing for Information: Spearphishing Link
The HTML page at the end of the URL is assessed to be a credential
harvesting form — consistent with phishing for information via link.

### T1566.001 — Phishing: Spearphishing Attachment
SMTP session captured in traffic.pcap confirms the email was sent
from IP 173.66.46.112, which was blocked by Spamhaus with code 553
(Frame 156). The sender spoofed MAILER-DAEMON@unicode.org.

## Detection rule
This SPL rule detects emails that fail all three authentication checks.
index=email_logs sourcetype=mail_logs
| eval spf_fail=if(spf_result="fail" OR spf_result="none", 1, 0)
| eval dkim_fail=if(dkim_result="fail" OR dkim_result="none", 1, 0)
| eval dmarc_fail=if(dmarc_result="fail" OR dmarc_result="none", 1, 0)
| eval triple_fail=spf_fail + dkim_fail + dmarc_fail
| where triple_fail=3
| stats count by sender, sender_domain, recipient, subject, timestamp
| sort -timestamp
False positive rate is low. Most legitimate enterprise senders have at least SPF configured. Route these to analyst review rather than auto-block.

Tuning note: allowlist known bulk senders like marketing platforms and ticketing tools that may intentionally send without DKIM.
---
## Recommendations

1. **Enforce DMARC reject policy** on the organization's own sending domains to prevent spoofing of internal addresses (internal spoofing attempts are blocked before delivery)
2. **Block identified IOCs** at email gateway, web proxy, and perimeter firewall
3. **Deploy phishing simulation training** targeting the Finance team specifically so they are proficient in spotting phising tricks
4. **Add the triple-fail detection rule** to the SOC playbook as a tier-1 triage check
5. **Review bulk sender allowlist** so that PHPMailer-based senders with no DKIM should not be whitelisted without review

---

## Lessons learned

**What went well:**
- User reported the email before clicking — security awareness training is working
- Splunk queries confirmed blast radius quickly with no prolonged uncertainty
- MISP correlation added attribution context that a standalone VirusTotal check would have missed

**What I would do differently:**
- Automate IOC extraction at intake rather than doing it manually — the Python script in this repo is the start of that workflow
- Set up URL detonation in a local sandboxed VM rather than relying solely on URLScan.io — some evasive pages detect automated analysis and serve benign content
- Create a structured phishing intake form in TheHive to standardize what gets captured on every case from the start
- The IOC extraction was done manually at first and the Python script came later. In a real SOC environment that should be automated at intake. A few lines in an email parsing pipeline would have saved 10 minutes per case and reduced the chance of missing something.

**Skills gaps identified and addressed:**
- Spent more time than expected on DMARC policy interpretation — added reference notes to `/notes/email-authentication.md`

---
to be edited -I also relied on URLScan.io for detonation. Some evasive pages serve clean content to known analysis infrastructure. A sandboxed VM with a fresh browser profile would give higher confidence results for anything the reputation feeds are not catching yet.

On the MISP side, I created the new event after the investigation. That process should be closer to real-time so other analysts at other orgs benefit from the fresh infrastructure IOCs before the attacker reuses the same nodes.

---

## Artifacts and evidence

```
phishing-analysis/
├── README.md                          <- This file
├── sample/
│   └── phishing_sample.eml            <- Sanitized .eml 
├── iocs/
│   ├── iocs_extractor.py              <- Defanged IOC list
    ├── deep_url_analysis
    ├── PCAP file                      <- smtp_session.pcap
├── screenshots/
│   ├── 01-header-analysis.png         <- MXToolbox header parser output
│   ├── 02-virustotal-url.png          <- VirusTotal URL detection results
│   ├── 03-urlscan-result.png          <- URLScan.io results page screenshot
│   ├── 05-ioc-extractor.png           <- Python script powershell terminal output
│   ├── 06-splunk-correlation.png      <- Splunk SPL query and results table
│   ├── 07-misp-enrichment.png         <- MISP event with IOC attributes
│   └── 08-thehive-case.png            <- TheHive case with tasks and observables

```

---

> **Important Disclosure:** Sample .eml pulled from phishing_pot (github.com/rf-peixoto/phishing_pot/blob/main/email/sample-101.eml) for portfolio demonstration purposes.
All samples, IPs, domains, and usernames are sanitized, fictional, or sourced from publicly available CTF and phishing training platforms. No real incident data is included.

---




























---


---

> #### SCREENSHOT CAPTURE GUIDE 01
> **File:** `screenshots/01-header-analysis.png`
>
> **Where to do this:**
> - Option A (recommended): [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) — paste raw headers from your `.eml` sample
> - Option B: LetsDefend Email Analyzer tab inside any phishing alert
>
> **What your screenshot must show:**
> - The full parsed header view with From, Reply-To, Return-Path, and Received fields visible
> - SPF / DKIM / DMARC result rows, all showing FAIL or NONE
> - The sending IP address visible in the Received chain
> - If using MXToolbox, the color-coded warning flags are especially useful visually
>
> **How to crop:** Results panel only. No need to include the browser address bar.
>
> **Caption to paste below your image once added:**
> `Figure 1: MXToolbox header analysis showing SPF/DKIM/DMARC triple failure and mismatched Reply-To indicating a spoofed sender identity.`

**[ Screenshot 01 — Replace this line with your image once captured ]**

---

**Observations:**

- The `Reply-To` address differs from the `From` address, a common indicator used to route replies to an attacker-controlled mailbox
- `X-Mailer: PHPMailer` indicates bulk sending infrastructure, not a corporate mail server
- The `Received` IP `185.220.101[.]47` does not match the claimed sender organization

---

### Step 2: URL and domain analysis

The embedded link was defanged before analysis:

```
Original (defanged): hxxps://it-helpdeskk[.]com/reset/m365-login[.]php
```

**WHOIS lookup:**

```
Domain:       it-helpdeskk.com
Registered:   [3 days before email delivery]
Registrar:    Namecheap
Name servers: ns1.it-helpdeskk.com / ns2.it-helpdeskk.com
Registrant:   REDACTED FOR PRIVACY
```

**Red flags:**

- Domain registered 3 days before use, typosquat of a legitimate IT service brand
- Self-hosted name servers on a residential/VPS block
- No prior web history or legitimate business presence

**VirusTotal result:** 7/94 vendors flagged as phishing at time of analysis

---

> #### SCREENSHOT CAPTURE GUIDE 02
> **File:** `screenshots/02-virustotal-url.png`
>
> **Where to do this:** [virustotal.com](https://www.virustotal.com) — URL tab
>
> **What your screenshot must show:**
> - The Detection tab with the vendor verdict count (e.g. "7 / 94 security vendors flagged this URL")
> - At least 3 vendor names visible with their Phishing or Malicious labels
> - The full URL being analyzed shown at the top
> - The Community Score section if visible
>
> **Tip:** Use a real phishing URL from [PhishTank](https://phishtank.org) or your TryHackMe / LetsDefend sample. Never submit a live internal URL.
>
> **Caption:** `Figure 2: VirusTotal detection results showing 7/94 vendor flags for phishing on the credential harvesting domain.`

**[ Screenshot 02 — Replace this line with your image once captured ]**

---

> #### SCREENSHOT CAPTURE GUIDE 03
> **File:** `screenshots/03-urlscan-result.png`
>
> **Where to do this:** [urlscan.io](https://urlscan.io) — submit the URL for public scan
>
> **What your screenshot must show:**
> - The Summary tab with the scanned URL and verdict badge
> - The embedded page screenshot thumbnail (the fake login page visual)
> - The HTTP transactions or DOM section showing the POST destination
> - The Malicious or Suspicious verdict tag if present
>
> **Why this screenshot matters:** The page thumbnail is the most visually compelling screenshot in this entire write-up. It shows the cloned login page at a glance. Recruiters who skim will stop here.
>
> **Caption:** `Figure 3: URLScan.io detonation showing cloned Microsoft 365 login page with POST exfiltration to attacker-controlled IP.`

**[ Screenshot 03 — Replace this line with your image once captured ]**

---

### Step 4: IOC extraction

All IOCs were extracted and defanged per TLP:WHITE handling procedures.

```
# Domains
it-helpdeskk[.]com

# IP addresses
185.220.101[.]47

# URLs
hxxps://it-helpdeskk[.]com/reset/m365-login[.]php
hxxps://185.220.101[.]47/collect[.]php

# Email addresses
support@it-helpdeskk[.]com
harvest99@protonmail[.]com
bounce@it-helpdeskk[.]com

# Hashes (if attachment present)
MD5:    [hash]
SHA256: [hash]
```

**Python extraction script:** [`tools/ioc_extractor.py`](../../tools/ioc_extractor.py)

```python
import re

def extract_iocs(text):
    patterns = {
        "ipv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "domain": r'\b[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}\b',
        "url": r'https?://[^\s<>"]+',
        "email": r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
        "md5": r'\b[a-fA-F0-9]{32}\b',
        "sha256": r'\b[a-fA-F0-9]{64}\b',
    }
    results = {}
    for ioc_type, pattern in patterns.items():
        matches = re.findall(pattern, text)
        results[ioc_type] = list(set(matches))
    return results

if __name__ == "__main__":
    import sys
    with open(sys.argv[1], "r", errors="ignore") as f:
        content = f.read()
    iocs = extract_iocs(content)
    for ioc_type, values in iocs.items():
        if values:
            print(f"\n[{ioc_type.upper()}]")
            for v in values:
                print(f"  {v}")
```

---

> #### SCREENSHOT CAPTURE GUIDE 05
> **File:** `screenshots/05-ioc-extractor-output.png`
>
> **Where to do this:** Your local terminal (Mac Terminal, Windows Terminal, or VS Code integrated terminal)
>
> **Steps:**
> 1. Save the script above as `ioc_extractor.py`
> 2. Save your `.eml` sample as `sample.eml` in the same folder
> 3. Run: `python3 ioc_extractor.py sample.eml`
> 4. Screenshot the terminal output
>
> **What your screenshot must show:**
> - The command you ran visible in the terminal
> - The categorized output: [DOMAIN], [IPV4], [URL], [EMAIL] sections
> - The extracted IOC values under each category
>
> **Tip:** Use a dark terminal theme (e.g. Dracula or One Dark). It reads better in a GitHub portfolio than a white terminal.
>
> **Caption:** `Figure 5: Python IOC extractor output showing domains, IPs, URLs, and email addresses parsed from the phishing .eml sample.`

**[ Screenshot 05 — Replace this line with your image once captured ]**

---

### Step 5: SIEM correlation

Splunk was queried to identify any other users who received the same email or clicked the link.

**Query 1 — identify all recipients from sending domain:**

```spl
index=email_logs sourcetype=mail_logs
| search sender_domain="it-helpdeskk.com"
| stats count by recipient, subject, timestamp
| sort -timestamp
```

**Result:** 2 recipients identified

**Query 2 — check proxy/web logs for URL access:**

```spl
index=proxy_logs sourcetype=squid
| search url="*it-helpdeskk.com*" OR dest_ip="185.220.101.47"
| stats count by src_ip, url, user, timestamp
| sort -timestamp
```

**Result:** 0 clicks detected

**Query 3 — check for credential activity post-delivery:**

```spl
index=auth_logs sourcetype=o365_audit
| search UserId IN ("user1@company.com", "user2@company.com")
| where EventCreationTime > "[email delivery time]"
| stats count by UserId, Operation, ClientIP, timestamp
```

**Result:** No anomalous authentication events detected.

---

> #### SCREENSHOT CAPTURE GUIDE 06
> **File:** `screenshots/06-splunk-correlation.png`
>
> **Where to do this:**
> - Option A (recommended): [Splunk BOTS dataset](https://github.com/splunk/botsv3) — free, loaded with phishing scenarios
> - Option B: LetsDefend SIEM tab inside any phishing alert
> - Option C: Splunk free trial with sample data loaded
>
> **What your screenshot must show:**
> - The Splunk search bar with your full SPL query visible
> - The results table with at least 2 rows of data (recipient, sender, timestamp fields)
> - The time range picker showing a specific window, not "All time"
> - The event count in the top-left of the results panel
>
> **Tip:** In Splunk, press Ctrl+\ to format your SPL query onto multiple lines before screenshotting. It looks much more readable than a single-line wall of text.
>
> **Caption:** `Figure 6: Splunk correlation query identifying two recipients of the phishing email and confirming zero URL clicks in proxy logs.`

**[ Screenshot 06 — Replace this line with your image once captured ]**

---

### Step 6: Threat intel enrichment

IOCs were submitted to MISP for cross-correlation against known campaigns.

**MISP results:**

- IP `185.220.101[.]47` matched to a known Tor exit node used in prior credential harvesting campaigns
- Domain infrastructure pattern (Namecheap registration, PHPMailer, self-hosted DNS) matches TTPs of a known financially motivated cluster
- New MISP event created to track this infrastructure node

**MISP event created:** Event #[XXXX] — `Phishing: M365 credential harvesting — Finance targeting — [Date]`

---

> #### SCREENSHOT CAPTURE GUIDE 07
> **File:** `screenshots/07-misp-enrichment.png`
>
> **Where to do this:** Your local MISP instance (Docker install, see platform setup guide below)
>
> **Steps:**
> 1. Log into your MISP instance at `http://localhost`
> 2. Go to Search > Search Attributes and enter one of your IOC values
> 3. If a match exists: screenshot the results list and the event detail panel
> 4. If no match: create a new event, add your IOCs as attributes, apply TLP:WHITE tag, and screenshot the completed event
>
> **What your screenshot must show:**
> - The MISP search or event view with your IOC visible
> - Attribute tags (malicious-activity, phishing, tlp:white)
> - The event title and date
> - At least 3 attributes entered (domain, IP, URL)
>
> **Caption:** `Figure 7: MISP event created for credential harvesting campaign with IOCs tagged and attributed to known infrastructure cluster.`

**[ Screenshot 07 — Replace this line with your image once captured ]**

---

### Step 7: Ticketing and escalation

A TheHive case was created to document findings and track containment.

**Case details:**

```
Case title:   PHI-2024-047 — Phishing: M365 credential harvesting
Severity:     High
TLP:          WHITE
PAP:          GREEN
Tags:         phishing, credential-harvesting, m365, finance
Assignee:     [Your Name]
Status:       Resolved
```

**Tasks completed:**

- [x] Email headers analyzed
- [x] URL detonated safely
- [x] IOCs extracted and defanged
- [x] Splunk correlation — no clicks confirmed
- [x] MISP enrichment complete
- [x] Sending domain blocked at email gateway
- [x] IP blocked at perimeter firewall
- [x] Second recipient notified
- [x] Case closed — no breach

---

> #### SCREENSHOT CAPTURE GUIDE 08
> **File:** `screenshots/08-thehive-case.png`
>
> **Where to do this:** Your local TheHive instance (Docker install, see platform setup guide below)
>
> **Steps:**
> 1. Create a new case in TheHive with the title and fields above
> 2. Add each task from the checklist above to the Tasks section
> 3. Mark all tasks complete
> 4. Go to the Observables tab and add each IOC (ip, domain, url, mail types)
> 5. Tag observables as "phishing" and mark the IP as "sighted"
> 6. Screenshot the completed case
>
> **What your screenshot must show:**
> - The case header: title, High severity badge, TLP:WHITE label, Resolved status
> - The Tasks panel with completed checkmarks visible
> - The Observables tab showing your IOCs with their types and tags
>
> **Tip:** TheHive's Observables tab is what separates a real analyst workflow from someone who just opened a Jira ticket. Make sure it is visible and populated.
>
> **Caption:** `Figure 8: TheHive case PHI-2024-047 showing completed task checklist, IOC observables, and resolved status following confirmed containment.`

**[ Screenshot 08 — Replace this line with your image once captured ]**

---

## Findings

| # | Finding | Severity | Detail |
|---|---|---|---|
| 1 | All email authentication controls failed | High | SPF, DKIM, and DMARC all absent on sending domain |
| 2 | Lookalike domain registered 3 days prior | High | Typosquat of legitimate IT brand |
| 3 | Credential harvesting exfil endpoint identified | High | POST destination is a known malicious Tor exit node |
| 4 | Two recipients identified | Medium | Finance team targeted specifically, not a mass blast |
| 5 | No credential submission confirmed | Informational | No clicks or post-click auth activity detected |
| 6 | Campaign linked to prior activity in MISP | Medium | Medium-confidence attribution based on infrastructure overlap |

**Overall verdict:** Malicious. Confirmed credential harvesting campaign. No breach occurred. Contained.

---

## MITRE ATT&CK mapping

| Technique ID | Technique name | Observed behavior |
|---|---|---|
| T1566.001 | Spearphishing attachment | Targeted phishing delivered via email |
| T1566.002 | Spearphishing link | Malicious URL embedded in email body |
| T1078 | Valid accounts | Objective was to steal M365 credentials |
| T1598.003 | Phishing for information | Credential harvesting form on cloned login page |
| T1071.001 | App layer protocol: web | Exfiltration via HTTPS GET to attacker server |

---

## Detection rule

```spl
index=email_logs sourcetype=mail_logs
| eval spf_fail=if(spf_result="fail" OR spf_result="none", 1, 0)
| eval dkim_fail=if(dkim_result="fail" OR dkim_result="none", 1, 0)
| eval dmarc_fail=if(dmarc_result="fail" OR dmarc_result="none", 1, 0)
| eval triple_fail=spf_fail + dkim_fail + dmarc_fail
| where triple_fail=3
| stats count by sender, sender_domain, recipient, subject, timestamp
| where count >= 1
| sort -timestamp
```

**False positive rate:** Low. Legitimate enterprise senders almost always have at least SPF configured.

**Tuning note:** Allowlist known bulk senders (marketing platforms, ticketing systems) that may intentionally lack DKIM.

---

## Recommendations

1. **Enforce DMARC reject policy** on the organization's sending domains to prevent spoofing of internal addresses
2. **Block identified IOCs** at email gateway, web proxy, and perimeter firewall
3. **Deploy phishing simulation training** targeting the Finance team specifically
4. **Add the detection rule above** to the SOC playbook as a tier-1 triage check
5. **Review bulk sender allowlist** — PHPMailer-based senders with no DKIM should not be whitelisted without review

---

## Lessons learned

**What went well:**
- User reported the email before clicking — security awareness training is working
- Splunk queries confirmed blast radius quickly with no prolonged uncertainty
- MISP correlation added attribution context that a standalone VirusTotal check would have missed

**What I would do differently:**
- Automate IOC extraction at intake rather than doing it manually — the Python script in this repo is the start of that workflow
- Set up URL detonation in a local sandboxed VM rather than relying solely on URLScan.io — some evasive pages detect automated analysis and serve benign content
- Create a structured phishing intake form in TheHive to standardize what gets captured on every case from the start

**Skills gaps identified and addressed:**
- Spent more time than expected on DMARC policy interpretation — added reference notes to `/notes/email-authentication.md`

---

