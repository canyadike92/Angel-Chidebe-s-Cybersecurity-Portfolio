import email
from email import policy
import re
import sys
import os
import time
import requests

VT_API_KEY = os.environ.get('VT_API_KEY')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')

def parse_email(filepath):
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    result = {}
    result['file'] = filepath
    result['from'] = msg.get('From', 'MISSING')
    result['return_path'] = msg.get('Return-Path', 'MISSING')
    result['subject'] = msg.get('Subject', 'MISSING')
    result['date'] = msg.get('Date', 'MISSING')

    auth_results = msg.get('Authentication-Results', '')
    result['spf'] = extract_auth_field(auth_results, 'spf')
    result['dkim'] = extract_auth_field(auth_results, 'dkim')
    result['dmarc'] = extract_auth_field(auth_results, 'dmarc')

    received_headers = msg.get_all('Received', [])
    result['originating_ip'] = extract_first_ip(received_headers[-1]) if received_headers else 'MISSING'

    urls = set()
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ('text/plain', 'text/html'):
                try:
                    body = part.get_content()
                    urls.update(re.findall(r'https?://[^\s"\'<>]+', body))
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
            urls.update(re.findall(r'https?://[^\s"\'<>]+', body))
        except Exception:
            pass
    result['urls'] = list(urls)

    from_domain = extract_domain(result['from'])
    return_path_domain = extract_domain(result['return_path'])
    result['from_returnpath_mismatch'] = (
        from_domain != return_path_domain
        and from_domain != 'UNKNOWN'
        and return_path_domain != 'UNKNOWN'
    )
    result['url_domains'] = list(set(extract_domain_from_url(u) for u in result['urls']))

    result['risk_score'] = score_risk(result)

    return result

def extract_auth_field(auth_header, field):
    match = re.search(rf'{field}=(\w+)', auth_header, re.IGNORECASE)
    return match.group(1) if match else 'none'

def extract_first_ip(received_header):
    match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_header)
    return match.group(1) if match else 'MISSING'

def extract_domain(address_field):
    match = re.search(r'@([\w\.-]+)', address_field)
    return match.group(1).lower() if match else 'UNKNOWN'

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

def defang(text):
    if not text or text in ('MISSING', 'UNKNOWN'):
        return text
    text = text.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
    text = text.replace('.', '[.]')
    return text

def score_risk(result):
    score = 0
    reasons = []

    if result['spf'] not in ('pass',):
        score += 2
        reasons.append(f"SPF={result['spf']}")
    if result['dkim'] not in ('pass',):
        score += 2
        reasons.append(f"DKIM={result['dkim']}")
    if result['dmarc'] not in ('pass',):
        score += 2
        reasons.append(f"DMARC={result['dmarc']}")
    if result['from_returnpath_mismatch']:
        score += 3
        reasons.append("From/Return-Path domain mismatch")
    if result['urls']:
        score += 1
        reasons.append(f"{len(result['urls'])} URL(s) in body")

    result['score_reasons'] = reasons
    return score

def check_virustotal_ip(ip):
    if not VT_API_KEY:
        return {'error': 'No VT_API_KEY set'}
    if ip in ('MISSING', 'UNKNOWN'):
        return {'error': 'No valid IP to check'}
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return stats
        else:
            return {'error': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'error': str(e)}

def check_virustotal_domain(domain):
    if not VT_API_KEY:
        return {'error': 'No VT_API_KEY set'}
    if domain in ('MISSING', 'UNKNOWN'):
        return {'error': 'No valid domain to check'}
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()['data']['attributes']['last_analysis_stats']
            return stats
        else:
            return {'error': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'error': str(e)}

def check_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        return {'error': 'No ABUSEIPDB_API_KEY set'}
    if ip in ('MISSING', 'UNKNOWN'):
        return {'error': 'No valid IP to check'}
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 200:
            data = resp.json()['data']
            return {
                'abuseConfidenceScore': data.get('abuseConfidenceScore'),
                'totalReports': data.get('totalReports'),
                'countryCode': data.get('countryCode')
            }
        else:
            return {'error': f'HTTP {resp.status_code}'}
    except Exception as e:
        return {'error': str(e)}

def print_report(result):
    print("=" * 70)
    print(f"File:            {result['file']}")
    print(f"From:            {result['from']}")
    print(f"Return-Path:     {result['return_path']}")
    print(f"Subject:         {result['subject']}")
    print(f"Date:            {result['date']}")
    print(f"Originating IP:  {defang(result['originating_ip'])}")
    print(f"SPF:             {result['spf']}")
    print(f"DKIM:            {result['dkim']}")
    print(f"DMARC:           {result['dmarc']}")
    print(f"From/RP mismatch: {result['from_returnpath_mismatch']}")
    print(f"URLs found:      {len(result['urls'])}")
    for u in result['urls']:
        print(f"  - {defang(u)}")
    print(f"RISK SCORE:      {result['risk_score']} / 10")
    print(f"Reasons:         {', '.join(result['score_reasons'])}")

    print("—— Enrichment ——")
    ip_vt = check_virustotal_ip(result['originating_ip'])
    print(f"VirusTotal (IP {defang(result['originating_ip'])}): {ip_vt}")
    time.sleep(15)  # VirusTotal free tier: 4 requests/minute

    ip_abuse = check_abuseipdb(result['originating_ip'])
    print(f"AbuseIPDB (IP {defang(result['originating_ip'])}): {ip_abuse}")

    for domain in result['url_domains']:
        dom_vt = check_virustotal_domain(domain)
        print(f"VirusTotal (domain {defang(domain)}): {dom_vt}")
        time.sleep(15)

    print("=" * 70)
    print()

if __name__ == '__main__':
    files = sys.argv[1:]
    if not files:
        print("Usage: python3 phishing_analyzer.py <file1.eml> <file2.eml> ...")
        sys.exit(1)

    for f in files:
        result = parse_email(f)
        print_report(result)
