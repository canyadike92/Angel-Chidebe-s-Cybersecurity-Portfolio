# Phishing Email Analysis: M365 Credential Harvesting Campaign

**Analyst:** [Angel Chidebe]
**Date:** May 2026
**Case ID:** PHI-2024-047
**Severity:** High
**Verdict:** Malicious - confirmed credential harvesting, no breach

---

## What this project is

A targeted phishing email impersonating an internal IT help desk was submitted via the phishing report button by a user in the Finance department. The email contained a malicious URL redirecting to a spoofed Microsoft 365 login page hosted on a newly registered domain. No credentials were entered by the recipient. The campaign was attributed with medium confidence to a financially motivated threat actor based on infrastructure overlap with prior campaigns tracked in MISP. 
This write-up documents the full investigation from raw email headers to containment and a closed ticket. No credentials were submitted. The sending infrastructure was traced to a known threat actor cluster with medium confidence.

If you are a hiring manager reading this: I wanted to document not just what I found, but how I thought through each step and where I would do things differently next time.

---

## Tools used

| Tool | What I used it for |
|---|---|
| Splunk | Finding other recipients, confirming no one clicked |
| VirusTotal | Domain and IP reputation checks |
| MISP | Cross-referencing IOCs against prior campaigns |
| Python | Custom IOC extraction script |
| TheHive | Case documentation and task tracking |
| MXToolbox | SPF, DKIM, DMARC validation |
| URLScan.io | Safe URL detonation |
| CyberChef | Base64 decoding, defanging |

---

## Investigation

### Step 1: Email header analysis

The first thing I do with any reported phishing email is pull the raw headers. Headers tell you where the email actually came from, not just who it claims to be from. I copied them out of the `.eml` file and ran them through MXToolbox.

```
From:        Microsoft account team <no-reply@microsoft[.]com>
Subject:     Microsoft account unusual sign-in activity
Reply-To:    media-protection@usual-assist[.]com
Return-Path: bounce@nisihfjoz.co[.]uk
Received:    from nisihfjoz.co[.]uk (103.167.154[.]120)
X-Mailer:    PHPMailer 6.6.4
Message-ID:  <ce2fb41e-b910-4df7-bbfb-43b8126ba45c@DM6NAM11FT012.eop-nam11.prod.protection.outlook[.]com>
```

Two things jumped out immediately. The `Reply-To` is a Usual-assist address that has nothing to do with the supposed Microsoft account team sender. That is a classic setup where the attacker wants replies to go somewhere they control. The other flag is `PHPMailer 6.6.4` in the X-Mailer field. That is bulk sending software, not a corporate mail server.

Then the authentication results confirmed it:

| Check | Result | Why it matters |
|---|---|---|
| SPF | NONE | protection.outlook.com: nisihfjoz.co[.]uk does not designate permitted sender hosts |
| DKIM | FAIL | Domain dkim:microsoft[.]com:smtp is invalid |
| DMARC | FAIL | No policy published, nothing to enforce |

All three failing together is about as clear a signal as you get.

![Email header analysis showing SPF, DKIM, and DMARC failures](screenshots/01-header-analysis.png)

---

### Step 2: URL and domain analysis

I defanged the link before doing anything with it so I did not accidentally click it:

```
hxxps://it-helpdeskk[.]com/reset/m365-login[.]php
```

WHOIS on the domain showed it was registered three days before the email was sent, through Namecheap, with privacy protection. That is a very common pattern for purpose-built phishing infrastructure. Legitimate IT helpdesks do not register throwaway domains three days before emailing employees.

I submitted it to URLScan.io for a safe detonation. The results were pretty definitive:

- The page is a pixel-perfect clone of the Microsoft 365 login portal
- The form POST action sends captured credentials to `hxxps://185.220.101[.]47/collect[.]php`
- VirusTotal had it flagged by 7 of 94 vendors at the time of analysis

![URLScan detonation results showing M365 clone and POST destination](screenshots/02-urlscan-result.png)

---

### Step 3: VirusTotal enrichment

I ran both the domain and the IP through VirusTotal separately.

The domain `it-helpdeskk[.]com` had 7 vendor detections, all categorized as phishing. Low number at that point in time, which is typical for newly registered infrastructure. Most reputation feeds had not caught up yet.

The IP `185.220.101[.]47` was more telling. Multiple vendors flagged it as a known Tor exit node. It also appeared in abuse.ch URLhaus and Feodo Tracker datasets from prior campaigns.

![VirusTotal results for domain and IP lookups](screenshots/03-virustotal-result.png)

---

### Step 4: IOC extraction

I used the Python script in this repo (`tools/ioc_extractor.py`) to parse the raw email and pull all IOCs in one pass. Then I defanged everything manually before documenting them.

```
# Domains
it-helpdeskk[.]com

# IPs
185.220.101[.]47

# URLs
hxxps://it-helpdeskk[.]com/reset/m365-login[.]php
hxxps://185.220.101[.]47/collect[.]php

# Email addresses
support@it-helpdeskk[.]com
harvest99@protonmail[.]com
bounce@it-helpdeskk[.]com
```

Full IOC list is in `iocs/iocs.txt`.

Running the extractor:

```bash
python3 tools/ioc_extractor.py --file sample/phishing_sample.eml --defang
```

---

### Step 5: Splunk correlation

Once I had the IOCs, I went into Splunk to figure out the blast radius. Three questions I wanted to answer:

1. Did anyone else get this email?
2. Did anyone click the link?
3. Was there any suspicious auth activity after delivery?

**Query 1: who else received it**

```spl
index=email_logs sourcetype=mail_logs
| search sender_domain="it-helpdeskk.com"
| stats count by recipient, subject, timestamp
| sort -timestamp
```

Returned two results. The original reporter and one other Finance mailbox.

**Query 2: did anyone click**

```spl
index=proxy_logs sourcetype=squid
| search url="*it-helpdeskk*" OR dest_ip="185.220.101.47"
| stats count by src_ip, url, user, timestamp
| sort -timestamp
```

Zero results. Neither user accessed the URL.

**Query 3: any post-delivery auth anomalies**

```spl
index=auth_logs sourcetype=o365_audit
| search UserId IN ("jsmith@company.com", "mmurphy@company.com")
| where EventCreationTime > "2024-03-14T09:47:00"
| stats count by UserId, Operation, ClientIP, timestamp
```

No anomalous logins. No foreign countries. No MFA bypass attempts.

At this point I had high confidence that this was a close call rather than a breach.

![Splunk queries showing 2 recipients, 0 clicks, 0 anomalous auth events](screenshots/04-splunk-correlation.png)

---

### Step 6: MISP threat intel enrichment

I submitted the IOCs to MISP to see if any of them matched prior campaigns.

The IP `185.220.101[.]47` matched MISP Event #4471, which tracks Tor exit nodes used in financially motivated phishing targeting financial services. Fourteen prior events in the cluster.

The domain and URLs did not match anything, which confirms this is fresh infrastructure being stood up for this specific campaign wave.

The infrastructure pattern (Namecheap registrar, self-hosted nameservers, PHPMailer) matched the TTPs of TA2541 across nine prior campaigns. Medium confidence attribution.

I created a new MISP event to document the fresh indicators and linked it to the existing cluster.

![MISP enrichment showing IP match to prior campaign cluster and TA2541 attribution](screenshots/05-misp-enrichment.png)

---

### Step 7: TheHive case and containment

I opened a TheHive case to track everything formally and document the containment steps.

```
Case:      PHI-2024-047
Severity:  High
TLP:       WHITE
Status:    Resolved
Tags:      phishing, credential-harvesting, m365, finance
```

Containment actions taken:

- [x] Sending domain `it-helpdeskk[.]com` blocked at email gateway
- [x] IP `185.220.101[.]47` blocked at perimeter firewall
- [x] Both recipients notified and briefed
- [x] IOCs shared to MISP event for cross-org visibility
- [x] Detection rule added to SOC runbook
- [x] Finance team flagged for targeted phishing simulation
- [x] Case closed, no breach confirmed

![TheHive case showing completed task checklist and resolution](screenshots/06-thehive-case.png)

---

## Findings summary

| Finding | Severity |
|---|---|
| All three email auth controls failed (SPF, DKIM, DMARC) | High |
| Lookalike domain registered 3 days before delivery | High |
| Credential harvesting POST endpoint identified on known Tor exit node | High |
| Two Finance recipients targeted, not a broad blast | Medium |
| Campaign infrastructure linked to TA2541 cluster with medium confidence | Medium |
| No credential submission or post-click activity confirmed | Informational |

---

## MITRE ATT&CK mapping

| Technique | ID | Observed |
|---|---|---|
| Spearphishing link | T1566.002 | Malicious URL embedded in email body |
| Valid accounts | T1078 | Objective was M365 credential theft |
| Phishing for information | T1598.003 | Credential harvesting via cloned login page |
| Web protocols | T1071.001 | Credentials exfiltrated via HTTPS POST |

---

## Detection rule

This SPL rule detects emails that fail all three authentication checks. Triple failure from a single sender is a strong phishing signal.

```spl
index=email_logs sourcetype=mail_logs
| eval spf_fail=if(spf_result="fail" OR spf_result="none", 1, 0)
| eval dkim_fail=if(dkim_result="fail" OR dkim_result="none", 1, 0)
| eval dmarc_fail=if(dmarc_result="fail" OR dmarc_result="none", 1, 0)
| eval triple_fail=spf_fail + dkim_fail + dmarc_fail
| where triple_fail=3
| stats count by sender, sender_domain, recipient, subject, timestamp
| sort -timestamp
```

False positive rate is low. Most legitimate enterprise senders have at least SPF configured. Route these to analyst review rather than auto-block.

Tuning note: allowlist known bulk senders like marketing platforms and ticketing tools that may intentionally send without DKIM.

---

## Recommendations

1. Publish a DMARC reject policy on the organization's own sending domains so internal spoofing attempts are blocked before delivery
2. Block the confirmed IOCs at email gateway, web proxy, and firewall
3. Run a targeted phishing simulation against the Finance team within 30 days given they were specifically selected by this actor
4. Add the triple-fail detection rule to the SOC playbook as a tier-1 triage check
5. Review the bulk sender allowlist for any entries that lack DKIM

---

## What I would do differently

The IOC extraction was done manually at first and the Python script came later. In a real SOC environment that should be automated at intake. A few lines in an email parsing pipeline would have saved 10 minutes per case and reduced the chance of missing something.

I also relied on URLScan.io for detonation. Some evasive pages serve clean content to known analysis infrastructure. A sandboxed VM with a fresh browser profile would give higher confidence results for anything the reputation feeds are not catching yet.

On the MISP side, I created the new event after the investigation. That process should be closer to real-time so other analysts at other orgs benefit from the fresh infrastructure IOCs before the attacker reuses the same nodes.

---

## Project files

```
phishing-analysis/
├── README.md
├── sample/
│   └── phishing_sample.eml        (sanitized, IOCs defanged)
├── screenshots/
│   ├── 01-header-analysis.png
│   ├── 02-urlscan-result.png
│   ├── 03-virustotal-result.png
│   ├── 04-splunk-correlation.png
│   ├── 05-misp-enrichment.png
│   └── 06-thehive-case.png
├── iocs/
│   └── iocs.txt                   (defanged IOC list, TLP:WHITE)
└── tools/
    └── ioc_extractor.py           (Python IOC parser)
```

---

> All email samples, IP addresses, domains, and usernames are sanitized, fictional, or sourced from publicly available CTF and phishing training platforms. No real incident data or personal information is included.

---

*Part of the [Blue Team Cybersecurity Portfolio](../README.md)*
