# Detection Lab — AD Password Spray Detection

Simulated a password spray attack against Active Directory and detected it in Splunk. Built the full pipeline: domain environment, log forwarding, attack, detection.

**Skills:** Active Directory, Splunk/SIEM, Windows Event Log analysis, attack simulation, detection engineering.

## Lab Topology

| Machine | Role | IP |
|---|---|---|
| WinServer-DC | Domain Controller (Windows Server 2022) | 10.0.0.4 |
| victim-win10 | Domain-joined client | 10.0.0.6 |
| kali | Attacker | 10.0.0.7 |
| Splunk (host) | SIEM | 192.168.56.1 |

VMs run on a shared VirtualBox NAT Network. Splunk runs on the physical host, reached over a separate Host-Only network.

![Lab Topology](screenshots/project1-phase0-01-lab-topology.png)

## Build Steps

**1. Domain Controller** — Windows Server 2022, static IP (10.0.0.4), promoted to DC for a new forest (`detectionlab.local`). Static IP is required since a DC's address can't change without breaking every client pointed at it.

![Static IP](screenshots/project1-phase2-01-static-ip-confirmed.png)
![AD DS Installed](screenshots/project1-phase3-01-adds-installed.png)

**2. Client join** — victim-win10 joined to the domain. Required pointing its DNS at the DC first, since domain join uses DNS to locate the DC by name.

![Domain Join](screenshots/project1-phase4-01-domain-join-success.png)

**3. Test accounts** — 7 domain users created, all sharing one password. Same password across many accounts is what makes it a spray, not a brute force (which is many passwords against one account) — spraying avoids single-account lockout policies.

![Test Accounts](screenshots/project1-phase5-01-test-accounts-created.png)

**4. Log forwarding** — Splunk Universal Forwarder installed on the DC, sends Security/System logs to Splunk on the host. Forwarding off the DC matters because a compromised DC could otherwise have its local logs tampered with.

![Logs Flowing](screenshots/project1-phase6-03-logs-flowing-confirmed.png)

## The Attack

From Kali, using NetExec (current standard AD attack tool, successor to the unmaintained CrackMapExec):

```
nxc smb 10.0.0.4 -u users.txt -p passwords.txt -d detectionlab.local --continue-on-success
```

`--continue-on-success` is required because NetExec stops at the first working credential by default; the flag forces it to try every account. All 7 accounts authenticated successfully.

![Attack Results](screenshots/project1-phase7-02-password-spray-full-results.png)

## The Detection

```
index=main host=WIN-5DMTMCEKM0B EventCode=4624 Source_Network_Address=10.0.0.7
| bucket _time span=1m
| stats dc(Account_Name) as distinct_accounts, values(Account_Name) as accounts by _time, Source_Network_Address
| where distinct_accounts >= 5
```

Detection logic is **distinct accounts per source per minute**, not raw login count, since one account logging in repeatedly isn't suspicious, but 7 different accounts from one source in one minute is. `Source_Network_Address` is the raw Windows Event Log field name (not the common `src_ip`, which required inspecting a raw event to confirm).

Result: 9 distinct accounts from 10.0.0.7 in the same 1-minute window.

![Detection Triggered](screenshots/project1-phase8-02-detection-search-triggered.png)

Saved as a scheduled alert (hourly, triggers on any result > 0). A production environment would run this more frequently to reduce detection latency.

![Alert Configured](screenshots/project1-phase8-03-alert-configured.png)

## Troubleshooting

- **VirtualBox NAT vs. NAT Network:** DC's adapter was on isolated NAT instead of the shared NAT Network, making it unreachable despite a valid IP. Fixed by matching its adapter to the other lab VMs.
- **Mouse capture failures:** VirtualBox lost mouse control on the DC repeatedly. Fixed by switching the VM's Pointing Device from PS/2 Mouse to USB Tablet.
- **Field naming:** initial detection search used `src_ip` and returned nothing; the actual field is `Source_Network_Address`, found by expanding a raw event.

## Tools

VirtualBox, Windows Server 2022, Windows 10, Kali Linux, Splunk Free, NetExec

This project
└── project1-detection-lab/
    ├── README.md                      ← this file
    └── screenshots/
        ├── project1-phase0-01-lab-topology.png
        ├── project1-phase2-01-static-ip-confirmed.png
        └── ... (the other 7)
