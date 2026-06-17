# Phishing Email Analysis: Credential Harvesting Campaign

> **Analyst:** [Angel Chidebe]
> **Date:** [May 2026]
> **Severity:** High
> **Disposition:** Malicious, Phishing, Spam — Confirmed credential harvesting attempt
---

## Table of contents

1. [Scenario and objectives](#scenario-and-objectives)
2. [Tools used](#tools-used)
3. [Investigation walkthrough](#investigation-walkthrough)
   - [Step 1: Email header analysis](#step-1-email-header-analysis)
   - [Step 2: URL and domain analysis](#step-2-url-and-domain-analysis)
   - [Step 3: IOC extraction](#step-3-ioc-extraction)
   - [Step 4: SIEM correlation](#step-4-siem-correlation)
   - [Step 5: Threat intel enrichment](#step-5-MISP-threat-intel-enrichment)
   - [Step 6: Ticketing and escalation](#step-6-ticketing-and-escalation)
4. [Findings](#findings-summary)
5. [MITRE ATT&CK mapping](#mitre-attck-mapping)
6. [Detection rule](#detection-rule)
7. [Recommendations](#recommendations)
8. [Lessons learned](#lessons-learned)
19. [Artifacts and evidence](#artifacts-and-evidence)

---
## Scenario and Objectives

**Scenario:** A targeted phishing email impersonating Microsoft account team was reported by a user. The email claimed there was an unusual sign-in activity in the user's Microsoft 365 account which could lead to account suspension, prompting an immediate reset via an embedded link. The embedded link contained a malicious URL redirecting to a spoofed Microsoft login page hosted on a domain through a malicious URL.

**Objectives:**
- Determine whether the email is malicious or a false positive
- Extract all indicators of compromise (IOCs)
- Identify any users who may have clicked the link or submitted credentials
- Produce a TheHive ticket with findings and recommended containment actions

**What this project is:** This write-up documents the full investigation from raw email headers to containment and a closed ticket. No credentials were submitted. The sending infrastructure was traced to a known threat actor cluster with medium confidence. No real incident data is included.

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
From:        Microsoft account team <MAILER-DAEMON@unicode[.]org>
Subject:     Urgent: Microsoft 365 account unusual sign-in activity. Verify your account
Reply-To:    media-protection@usual-assist[.]com
Return-Path: bounce@nisihfjoz.co[.]uk
Received:    from nisihfjoz.co[.]ca (104.17.24[.]14)
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
**Header analysis screenshots:** [`screenshots/header analysis`](../../screenshots/header_analysis.png)

Observations: Two things jumped out immediately. The Reply-To (@usual-assist[.]com) address differs from the From Microsoft account team <MAILER-DAEMON@unicode[.]org) address, a common indicator that proves the attacker wants replies to go somewhere they control. The other flag is PHPMailer 6.6.4 in the X-Mailer field indicates bulk sending infrastructure, not a corporate mail server. 

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

**URLScan.io:** - Live Information (Malicious) - 3 HTTP transactions with credentials exfiltrated via HTTPS GET. This URL contacted 3 IPs in 2 countries across 3 domains to perform 3 HTTP transactions. 

**Red flags:**
- Two separate Autonomous sytem servers with separate IP's 104.17.24.14 IP for (CLOUDFLARENET - Cloudflare) and 20.150.1.1 for (MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation).
- IP 20.150.1.1 was operating from Canada although Microsoft Corporation is a USA company mainly operating in the USA

**Here is a breakdown of my observation:**
- MICROSOFT-CORP-MSN-AS-BLOCK is the name of Microsoft's Autonomous System (AS), which is a block of IP addresses owned and managed by Microsoft Corporation. This likely means that one of the IPs or URLs found in the phishing email resolves to Microsoft's infrastructure, which could indicate:

- The attacker used Microsoft services (like OneDrive, SharePoint, or Outlook) to host malicious content which is a common phishing tactic
- It could be a legitimate Microsoft link being abused to appear trustworthy

Phishers often abuse trusted platforms like Microsoft to bypass spam filters. This is a common red flag in phishing emails — using trusted, legitimate platforms to host malicious content or redirect victims, making it harder for security tools to block them.

**URL scan results screenshots:** [`screenshots/header analysis`](../../screenshots/header_analysis.png)

### Step 3: IOC Extraction

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
→ The attacker hosted a phishing page on Azure (104.17.24.14)
→ Sent phishing email via SMTP (173.66.46.112)
→ Mail server blocks it (Frame 156 code 553)
→ Python pipeline extracts all IOCs

**IOC extraction screenshots:** [`tools/ioc_extractor.py`](../../tools/ioc_extractor.py)

Full IOC pipeline script is in IOCs/ioc_extractor.py.

### Step 4: SIEM Correlation
Once I had the IOCs, I went into Splunk to figure out the blast radius. I used ai to generate sample data (email, proxy, auth logs) to simulate a real-world phishing incident for demonstration purposes. Three questions I wanted to answer:

Who received this email?
Did anyone click the link?
Was there any suspicious auth activity after delivery?

Query 1: who else received it

index=phish_email
| search sender_domain="windows.net"
| stats count by recipient, subject, timestamp
| sort -timestamp
-2 recipients identified: jsmith@company.com and mwilliams@company.com
-Both received the same phishing subject line within 13 seconds of each other, indicating an automated bulk send from the malicious domain.

Query 2: did anyone click

index=proxy_logs sourcetype=squid
| search url="*MAILER-DAEMON@unicode.org*" OR dest_ip="173.17.24.14"
| stats count by src_ip, url, user, timestamp
| sort -timestamp
-Zero clicks detected
-Neither recipient visited the phishing URL or contacted the associated malicious IP

Query 3: any post-delivery auth anomalies

index=phish_auth
| search UserId IN ("jsmith@company.com", "mwilliams@company.com")
| where EventCreationTime > "2024-03-15T09:14:22"
| stats count by UserId, Operation, ClientIP, timestamp
| sort -timestamp

-All activity originates from internal IPs 10.10.1.55 and 10.10.1.88
-Only normal operations, UserLoggedIn and MailboxLogin
-No password changes, no foreign IPs, no anomalous authentication events detectedor MFA changes detected

**Splunk queries showing 2 recipients, 0 clicks, 0 anomalous auth events:** 
[`screenshots/header analysis`](../../screenshots/splunk_query1.png)
[`screenshots/header analysis`](../../screenshots/splunk_query2.png)
[`screenshots/header analysis`](../../screenshots/splunk_query3.png)

### Step 5: MISP threat intel enrichment
I submitted the IOCs to MISP to correlate the threat information. The MISP event created automatically correlated my IOCs against known threat intelligence and flagged all 3 (IP,url,domain) as malicious, confirming malicious infrastructure.

| Attribute | Type | Galaxy Tag |
|---|---|---|
| 104.17.24.14 | ip-dst | Agent Threat Rules - Base64 Encoded Remote Code Execution via Raw IP |
| https://bawafide.z27.web.core.windows.net/wrza8igw3uko.html | url | Agent Threat Rules - Data Exfiltration URL |
| bawafide.z27.web.core.windows.net | domain |  Agent Threat Rules - Browser Credential Harvesting via Session Debug Tool |

**MISP enrichment screenshots:** [`screenshots/header analysis`](../../screenshots/header_analysis.png)

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
 Case closed — no breach
 **TheHive screenshots:** [`screenshots/header analysis`](../../screenshots/header_analysis.png)
 
## Findings Summary
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
| T1566.001 | Phishing: Spearphishing Attachment | Targeted phishing delivered via email |
| T1566.002 | Spearphishing link | Malicious URL embedded in email body |
| T1583.001 | Acquire Infrastructure Domains |  Hosted the phishing page on Microsoft Azure (windows.net), a trusted platform, to bypass email security filters |
| T1598.003 | Phishing for information | HTML page at the end of the URL harvests credentials |

## Detection rule
I built a production-ready detection rule.This SPL rule detects emails that fail all three authentication checks.
index=email_logs
| eval spf_fail=if(spf_result="fail" OR spf_result="none", 1, 0)
| eval dkim_fail=if(dkim_result="fail" OR dkim_result="none", 1, 0)
| eval dmarc_fail=if(dmarc_result="fail" OR dmarc_result="none", 1, 0)
| eval triple_fail=spf_fail + dkim_fail + dmarc_fail
| where triple_fail=3
| stats count by sender, sender_domain, recipient, subject, timestamp
| sort -timestamp

False positive rate is low. Most legitimate enterprise senders have at least SPF configured. Route these to analyst review rather than auto-block.
Tuning note: allowlist known bulk senders like marketing platforms and ticketing tools that may intentionally send without DKIM.

**Detection rule screenshots:** [`screenshots/header analysis`](../../screenshots/header_analysis.png) 
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
- Splunk queries confirmed blast radius quickly with no prolonged uncertainty
- MISP correlation added attribution context that a standalone VirusTotal check would have missed

**What I would do differently:**
- Automate IOC extraction at intake rather than doing it manually — the Python script in this repo is the start of that workflow
- Set up URL detonation in a local sandboxed VM rather than relying solely on URLScan.io — some evasive pages detect automated analysis and serve benign content
- Create a structured phishing intake form in TheHive to standardize what gets captured on every case from the start
- The IOC extraction was done manually at first and the Python script came later. In a real SOC environment that should be automated at intake. A few lines in an email parsing pipeline would have saved 10 minutes per case and reduced the chance of missing something.
- If Splunk Query 2 or 3 returned hits, I would escalate immediately because this shows we've moved from phishing delivery to potential compromise.

**Skills gaps identified and addressed:**
- Spent more time than expected on DMARC policy interpretation — added reference notes to `/notes/email-authentication.md`

---
---

## Artifacts and evidence

```
Phishing-Analysis-M365-Credential-Harvesting-Campaign/
├── iocs/
│   ├── iocs_extractor.py              <- Defanged IOC list
    ├── deep_url_analysis
    ├── PCAP file                      <- smtp_session.pcap
├── Phishing-sample.eml                <- Sanitized .eml 
├── README.md                          <- This file
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

> **Important Disclosure:** All samples, IPs, domains, and usernames are sanitized, fictional, or sourced from publicly available CTF and phishing training platforms. No real incident data is included.

---
