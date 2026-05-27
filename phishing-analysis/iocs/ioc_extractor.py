# ================================================================
# PHISHING ANALYSIS - STEP 3: IOC EXTRACTION
# Description: Extracts Indicators of Compromise (IOCs) from defanged URLs found in phishing emails.
# URL: hxxps[://]bawafide[.]z27[.]web[.]core[.]windows[.]net/wrza8igw3uko[.]html
# ================================================================

import re
from urllib.parse import urlparse

#Defanged URL
defanged_url = "hxxps[://]bawafide[.]z27[.]web[.]core[.]windows[.]net/wrza8igw3uko[.]html"

#Step 1: Refang the URL
def refang(url: str) -> str:
    url = url.replace("hxxps", "https")
    url = url.replace("hxxp", "http")
    url = url.replace("[://]", "://")
    url = url.replace("[.]", ".")
    return url

refanged_url = refang(defanged_url)

#Step 2: Parse components
parsed = urlparse(refanged_url)

scheme   = parsed.scheme
fqdn     = parsed.netloc
path     = parsed.path
filename = path.lstrip("/")

labels        = fqdn.split(".")
subdomain     = ".".join(labels[:-3])
root_domain   = ".".join(labels[-3:])
tld           = labels[-1]

hosting_platform = "Microsoft Azure Blob Storage (windows.net)"

#Step 3: Build IOC dictionary
iocs = {
    "Defanged URL"      : defanged_url,
    "Refanged URL"      : refanged_url,
    "Protocol/Scheme"   : scheme.upper(),
    "FQDN"              : fqdn,
    "Subdomain"         : subdomain,
    "Root Domain"       : root_domain,
    "TLD"               : tld,
    "URL Path"          : path,
    "Filename"          : filename,
    "File Extension"    : filename.split(".")[-1].upper(),
    "Hosting Platform"  : hosting_platform,
}

#Step 4: Print report
print("=" * 65)
print("           IOC EXTRACTION REPORT")
print("=" * 65)

for label, value in iocs.items():
    print(f"  {label:<22}: {value}")

print("=" * 65)

#Step 5: Threat intelligence notes 
print("\n[!] THREAT INTEL NOTES")
print("-" * 65)
print(f"  • URL uses Azure Static Web hosting (windows.net) — a trusted")
print(f"    Microsoft domain commonly abused in phishing to bypass filters.")
print(f"  • Subdomain '{subdomain}' appears to be attacker-controlled.")
print(f"  • The .html file '{filename}' is likely a phishing landing page.")
print(f"  • Recommend querying FQDN and URL in:")
print(f"      - VirusTotal  : https://www.virustotal.com/gui/domain/{fqdn}")
print(f"      - urlscan.io  : https://urlscan.io/search/#page.domain:{fqdn}")
print(f"      - AbuseIPDB   : https://www.abuseipdb.com/check/{fqdn}")
print("=" * 65)
