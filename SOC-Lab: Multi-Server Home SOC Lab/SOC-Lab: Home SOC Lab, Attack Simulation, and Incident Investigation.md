# SOC-Lab: Home SOC Lab, Attack Simulation, and Incident Investigation

A self-built, multi-VM Security Operations Center lab where I simulated attacks against a
monitored Windows endpoint, detected and triaged the activity in Wazuh, and documented a full
incident investigation from evidence to conclusion.

## Overview

I built this lab to develop hands-on SOC analyst skills: standing up a detection stack,
generating realistic attack telemetry, and working an incident end to end using only what the
data confirmed. Every finding in this project is backed by captured evidence rather than
assumption.

## What I built

An isolated lab of four virtual machines on a single Windows host (Intel Core Ultra 7 155U,
32 GB RAM), running on a private NAT network (10.0.0.0/24):

- wazuh-server (10.0.0.5): Wazuh indexer, manager, and dashboard, plus Suricata and Zeek
- bluebox (10.0.0.3): Elasticsearch and Kibana for analysis
- victim-win10 (10.0.0.6): Windows 10 Pro 22H2 endpoint with Sysmon and a Wazuh agent
- kali (10.0.0.7): the attacker

Full build details are in the [architecture README](./README.md).

## What I did

From Kali, I ran reconnaissance (a full Nmap port scan and an MS17-010 EternalBlue check) and an
SMB credential brute force against the Windows endpoint. In Wazuh I reviewed the resulting
telemetry: 517 events and 483 alerts, none above medium severity, mapped to MITRE ATT&CK.

I then investigated the authentication activity rather than trusting the dashboard totals.
Scoping the query to the endpoint and expanding the individual logon events, I confirmed from the
event fields (source IP, logon type, and account SID) that the only successful logons were local
system logons, not the attacker, so no credential compromise occurred. I also found a gap: NTLM
credential validation auditing was disabled on the endpoint.

Finally, I ran a controlled detection validation. After enabling the missing auditing and
creating a test account, I executed a working SMB credential attack with NetExec and confirmed
Wazuh detected the full signature: repeated failed logons followed by a successful remote NTLMv2
logon attributed to the attacker at 10.0.0.7. This closed the audit gap and proved the detection
pipeline works end to end.

The full investigation is in the [incident report](./SOC-Lab-IR-Report.md).

## Skills demonstrated

- SIEM and endpoint monitoring: Wazuh, Sysmon, Elastic and Kibana, Suricata, Zeek
- Attack simulation: Nmap, vulnerability checks, SMB credential attacks (Hydra, NetExec)
- Alert triage and severity assessment against MITRE ATT&CK
- Threat hunting and log analysis using DQL queries in the Wazuh dashboard
- Windows event analysis: logon events 4624, 4625, and 4776, logon types, and account SIDs
- Incident response documentation and evidence handling
- Detection engineering: identifying and closing an audit gap, then validating the fix

## Challenges and lessons

Most of the 517 events were routine Windows activity, so a real lesson was separating background
noise from attack signal. Verifying authentication attribution taught me not to trust a dashboard
count at face value: the "successful logons" turned out to be local, not the attacker. I also
worked through practical lab issues that mirror real environments: a host virtualization conflict
that froze the endpoint, a firewall profile that blocked the attack, an audit policy gap that hid
the credential attempts, and a clock skew that offset the event timestamps and complicated log
correlation. Each of these was diagnosed from confirmed evidence and resolved.

## Documentation and evidence

- Architecture and build notes: [README.md](./README.md)
- Incident report and detection validation: [SOC-Lab-IR-Report.md](./SOC-Lab-IR-Report.md)
- Screenshots, including the MITRE ATT&CK dashboard and framework coverage views, are in the `screenshots/` folder
