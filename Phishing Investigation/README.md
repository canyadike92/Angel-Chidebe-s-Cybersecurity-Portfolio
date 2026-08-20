# Phishing Investigation

## Overview
A Python-based phishing email analyzer that parses raw `.eml` files, extracts key indicators of compromise (IOCs), scores each email's risk, and enriches findings using VirusTotal and AbuseIPDB.

**Skills demonstrated:** email header analysis, IOC extraction, authentication result interpretation (SPF/DKIM/DMARC), API integration, Python scripting, IOC defanging for safe reporting.

**Target roles:** SOC Analyst, Threat Analyst

## Dataset
Emails were sourced from the **Nazario Phishing Corpus**, a public phishing email archive hosted at monkey.org, specifically the 2025 folder: hxxps://monkey[.]org/~jose/phishing/phishing-2025. The full corpus was downloaded and split into 481 individual `.eml` files. Three representative emails were selected for this write-up to keep the report concise; the analyzer itself works against the full set.

## Tools
- Python 3
- `email` (standard library, for parsing `.eml` files)
- `requests`
- [VirusTotal API](https://www.virustotal.com/) (free tier, IP and domain reputation lookups)
- [AbuseIPDB API](https://www.abuseipdb.com/) (free tier, IP abuse confidence scoring)

## How the analyzer works
For each `.eml` file, the script:
1. Parses the `From`, `Return-Path`, `Subject`, and `Date` headers.
2. Reads the `Authentication-Results` header to extract SPF, DKIM, and DMARC outcomes.
3. Extracts the originating IP address from the last `Received` header.
4. Extracts all URLs from the plain-text and HTML body parts.
5. Compares the `From` and `Return-Path` domains for a mismatch (a common spoofing indicator).
6. Calculates a **risk score out of 10**, based on:
   - SPF not passing: +2
   - DKIM not passing: +2
   - DMARC not passing: +2
   - From/Return-Path domain mismatch: +3
   - Presence of URLs in the body: +1
7. Defangs all IPs and URLs in the printed report (e.g. `hxxp://` and `[.]`) so nothing is clickable or auto-linked if pasted elsewhere.
8. Enriches the originating IP against VirusTotal and AbuseIPDB, and enriches every unique URL domain against VirusTotal.

## Bug found and fixed
While enriching URL domains, one lookup returned an unexpected `HTTP 400` error from VirusTotal. Investigation showed the domain-extraction function was grabbing everything between `://` and the next `/` in a URL, for a URL like `hxxp://jose@monkey[.]org/...`, that captured `jose@monkey.org` as the "domain," userinfo included, instead of just the host.

**Fix:** after extracting the substring, the function now splits off anything before an `@` (userinfo) and anything after a `:` (port), leaving only the actual hostname before it's sent to VirusTotal.

```python
def extract_domain_from_url(url):
    match = re.search(r'https?://([^/]+)', url)
    if not match:
        return 'UNKNOWN'
    host = match.group(1).lower()
    if '@' in host:
        host = host.split('@')[-1]
    if ':' in host:
        host = host.split(':')[0]
    return host
```

After the fix, re-running the same email produced a clean domain lookup (`monkey.org`) instead of the HTTP 400 error. See `screenshots/analyzer-output-email0001-fixed.png` for the confirmed before/after behavior.

## Sample results

| File | Risk Score | Key Findings | Verdict |
|---|---|---|---|
| `email_0000.eml` (fake mailbox verification) | 7 / 10 | SPF, DKIM, and DMARC all `none`. 2 URLs in body. Sender: "Monkey-Service" impersonating an account security warning. One linked domain flagged malicious by 9 VirusTotal engines. | **Phishing.** No authenticated sending domain, plus a linked domain independently flagged malicious. |
| `email_0001.eml` (DocuSign spoof) | 7 / 10 | SPF, DKIM, and DMARC all `none`. 3 URLs in body. Sender impersonates DocuSign. One linked domain flagged malicious by 9 VirusTotal engines. This is the email that surfaced the URL-parsing bug above. | **Phishing.** Brand impersonation with no authenticated sending domain and a malicious-flagged link. |
| `email_0002.eml` (fake bank alert) | 1 / 10 | SPF, DKIM, and DMARC all `pass`. 2 URLs in body. Sender header reads "JPMorchan\|Chase Client Support" (misspelled brand name). One linked domain (`boxauth.ru`) flagged malicious by 4 VirusTotal engines and suspicious by 1. | **Phishing.** Authentication passing did not stop this one, the misspelled sender name and a malicious-flagged link both point to spoofing, despite the low automated risk score. |

**Note on `email_0002.eml`:** this is the weakest signal of the three by risk score alone (1/10), because SPF/DKIM/DMARC all passed. That score reflects only sender authentication and does not account for sender name spoofing or link reputation, both of which flagged this email. This is a known limitation of the current scoring model, see below.

## Conclusion
All three emails are confirmed phishing. This is expected, since they were drawn from the Nazario Phishing Corpus, a known, verified collection of real-world phishing samples, not a mix of legitimate and malicious mail. The value of this analysis is in showing *how* each one qualifies as phishing (authentication failures, brand impersonation, malicious-flagged infrastructure), not in discovering *whether* it does.

**Scoring model limitation:** the current risk score weights SPF/DKIM/DMARC heavily but does not factor in sender display-name spoofing or VirusTotal/AbuseIPDB reputation results. `email_0002.eml` shows why this matters: it scored lowest (1/10) despite being a confirmed phishing attempt with a malicious-flagged link, because it passed all three authentication checks. A future improvement would be folding threat-intel findings back into the score itself.

## How to run
```
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
python3 phishing_analyzer.py emails/email_0000.eml emails/email_0001.eml emails/email_0002.eml
```
Note: the VirusTotal free tier is limited to 4 requests/minute, so the script pauses 15 seconds between VirusTotal calls. This is expected and not a hang.

## Files in this repo
- `phishing_analyzer.py` — the analyzer script
- `screenshots/` — labeled terminal output for the three sample emails
- `emails/` — the three sample `.eml` files analyzed in this write-up
