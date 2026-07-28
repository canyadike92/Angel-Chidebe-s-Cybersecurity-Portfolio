# SOC-Lab: Multi-Server Home SOC Lab

A multi-server home Security Operations Center (SOC) lab built in VirtualBox on an isolated NAT network. The lab mirrors a real detection pipeline by separating the log aggregation server, the detection stack, the monitored endpoint, and the attacker machine onto their own virtual machines. Attacks are launched from a Kali box against a Windows 10 endpoint, and the resulting activity is detected, mapped to MITRE ATT&CK, and triaged in Wazuh.

> All activity in this lab is performed against machines I own inside an isolated private network.
> No production systems or third-party systems are involved.

---

## Contents

- [Architecture Overview](#architecture-overview)
- [Network Topology](#network-topology)
- [Host Machine Specifications](#host-machine-specifications)
- [Virtual Machine Inventory](#virtual-machine-inventory)
- [Software Stack by Role](#software-stack-by-role)
- [Attack Simulations Performed](#attack-simulations-performed)
- [Detection Results](#detection-results)
- [Evidence and Screenshots](#evidence-and-screenshots)
- [Known Limitations and Lessons Learned](#known-limitations-and-lessons-learned)
- [Credentials](#credentials)
- [Repository Structure](#repository-structure)

---

## Architecture Overview

The lab uses four virtual machines on a single Windows host. Each machine has a dedicated role so the environment reflects how detection components are separated in a production SOC rather than collapsed onto one box.

| VM | IP Address | Role |
|---|---|---|
| bluebox | 10.0.0.3 | Elastic and Kibana analyst server |
| wazuh-server | 10.0.0.5 | Wazuh indexer, manager, and dashboard; Suricata; Zeek |
| victim-win10 | 10.0.0.6 | Monitored Windows 10 endpoint with Sysmon and Wazuh agent |
| kali | 10.0.0.7 | Attacker machine |

All four machines sit on an isolated VirtualBox NAT Network named `SOC-LAB` using the `10.0.0.0/24` subnet. Each VM uses the Intel PRO/1000 MT Desktop virtual network adapter.

---

## Network Topology

```
                      Windows Host (Intel Core Ultra 7 155U, 32 GB RAM)
                                        |
                        VirtualBox NAT Network: SOC-LAB
                                  10.0.0.0/24
                                        |
   +----------------+----------------+----------------+----------------+
   |                |                |                |
bluebox        wazuh-server     victim-win10        kali
10.0.0.3         10.0.0.5         10.0.0.6         10.0.0.7
Elastic +       Wazuh stack      Windows 10       Attacker
Kibana          Suricata         Sysmon +         (Kali Rolling)
(analyst)       Zeek             Wazuh agent
```
---

## Host Machine Specifications

Values below were confirmed from the Windows Task Manager Performance tab.

| Item | Value |
|---|---|
| Operating system | Windows |
| CPU | Intel Core Ultra 7 155U |
| Sockets | 1 |
| Physical cores | 12 |
| Logical processors | 14 |
| Base speed | 1.70 GHz |
| Virtualization | Enabled |
| L1 cache | 1.2 MB |
| L2 cache | 10.0 MB |
| L3 cache | 12.0 MB |
| Installed RAM | 32.0 GB |
| RAM speed | 6400 MT/s |
| Memory slots used | 2 of 2 |

---

## Virtual Machine Inventory

Values below were confirmed from the VirtualBox Details tab for each machine.

### bluebox (Analyst server)

| Setting | Value |
|---|---|
| IP address | 10.0.0.3 |
| Guest OS | Ubuntu (64-bit) |
| Base memory | 8192 MB |
| Processors | 2 |
| Disk | bluebox.vdi, 40.00 GB |
| Video memory | 16 MB |
| Graphics controller | VMSVGA |
| Acceleration | Nested Paging, KVM Paravirtualization |
| Network | Intel PRO/1000 MT Desktop, NAT Network SOC-LAB |

### wazuh-server (Detection stack)

| Setting | Value |
|---|---|
| IP address | 10.0.0.5 |
| Guest OS | Ubuntu (64-bit) |
| Base memory | 6144 MB |
| Processors | 4 |
| Disk | wazuh-server.vdi, 50.00 GB |
| Acceleration | Nested Paging, KVM Paravirtualization |
| Network | Intel PRO/1000 MT Desktop, NAT Network SOC-LAB |

### victim-win10 (Monitored endpoint)

| Setting | Value |
|---|---|
| IP address | 10.0.0.6 |
| Guest OS | Windows 10 (64-bit) |
| Windows edition and build | Windows 10 Pro, version 22H2, build 19045.3803 (confirmed on the guest) |
| Base memory | 6144 MB |
| Processors | 4 |
| Disk | victim-win10.vdi, 50.00 GB |
| Video memory | 128 MB |
| Graphics controller | VBoxSVGA |
| Acceleration | Nested Paging, Hyper-V Paravirtualization |
| Network | Intel PRO/1000 MT Desktop, NAT Network SOC-LAB |

### kali (Attacker)

| Setting | Value |
|---|---|
| IP address | 10.0.0.7 |
| VM name | kali-linux-2026.1-virtualbox-amd64 |
| Distribution | Kali Rolling 2026.1 |
| Guest OS | Debian (64-bit) |
| Base memory | 2048 MB |
| Processors | 2 |
| Disk | kali-linux-2026.1-virtualbox-amd64.vdi, 80.09 GB |
| Acceleration | Nested Paging, PAE/NX, KVM Paravirtualization |
| Network | Intel PRO/1000 MT Desktop, NAT Network SOC-LAB |

### Combined allocation

| Metric | Total across all four VMs | Host total |
|---|---|---|
| RAM requested if all VMs run at once | 22528 MB (about 22 GB) | 32.0 GB |
| vCPU assigned across all VMs | 12 | 14 logical processors |

---

## Software Stack by Role

| Component | Runs on | Purpose |
|---|---|---|
| Elasticsearch | bluebox | Log storage and search |
| Kibana | bluebox | Analyst visualization interface |
| Wazuh indexer | wazuh-server | Alert and event indexing |
| Wazuh manager | wazuh-server | Rule processing and agent management |
| Wazuh dashboard | wazuh-server | Detection and threat hunting interface |
| Suricata | wazuh-server | Network intrusion detection |
| Zeek | wazuh-server | Network metadata logging |
| Sysmon | victim-win10 | Windows endpoint telemetry |
| Wazuh agent | victim-win10 | Forwards endpoint events to the manager |

Access points inside the SOC-LAB network:

- Wazuh dashboard: `https://10.0.0.5`
- Elastic and Kibana: `http://10.0.0.3:5601`

These addresses are reachable only from machines inside the SOC-LAB network. They cannot be reached from the Windows host browser.

---

## Attack Simulations Performed

All attacks were launched from kali (10.0.0.7) against victim-win10 (10.0.0.6).

| Simulation | Description | Result |
|---|---|---|
| Nmap reconnaissance scan | Initial port and service discovery | Open ports and OS fingerprint identified |
| Full port scan | Scan across all 65535 ports | Completed in 194 seconds |
| EternalBlue CVE check | Checked SMB for the EternalBlue vulnerability | Target confirmed patched |
| SMB brute force simulation | Hydra v9.6 against the administrator account over SMB (`hydra -l administrator -P rockyou.txt 10.0.0.6 smb`) | Captured run errored with "invalid reply from target"; the two successful logons on the endpoint were confirmed local, so no attacker credential compromise is confirmed |

### Reconnaissance findings on victim-win10

- Operating system, Nmap estimate: Windows 10, version range 1709 to 21H2
- Operating system, confirmed on the guest: Windows 10 Pro, version 22H2, build 19045.3803
- Hostname: DESKTOP-FBHDPT8
- Open ports: 135, 139, 445, 5040, 7680, 49664, 49665, 49666, 49667, 49668, 49669, 49925
- Ports 49664 to 49669 and 49925 are dynamic RPC (msrpc) ports
- SMB security mode: SMBv3.1.1, message signing enabled but not required
- Recorded SMB clock skew on the target: about -1h58m

The confirmed build (22H2) is newer than the upper bound of the Nmap estimate (21H2). Nmap OS fingerprinting infers a range from network behavior rather than reading the exact build, so the ground-truth value was verified directly on the endpoint.

---

All figures below were read directly from the Wazuh dashboard and threat hunting views.

- Events feed: 517 events recorded over the window Jun 30 2026 05:55 to Jul 1 2026 05:55.
- Threat hunting total alerts: 483.
- Alerts at rule level 12 or above: 0.
- Authentication failures: 1. Authentication successes: 4.
- victim-win10 was the primary agent for the recorded activity. A second agent named angel also appeared in the top agents view as a minor contributor.

### Severity breakdown (dashboard, last 24 hours)

| Severity | Rule level | Count |
|---|---|---|
| Critical | 15 or higher | 0 |
| High | 12 to 14 | 0 |
| Medium | 7 to 11 | 305 |
| Low | 0 to 6 | 177 |

No critical or high severity alerts fired. The recorded activity sat entirely in the medium and low bands, and much of the events feed reflects routine Windows service and software activity rather than attack traffic. Distinguishing that background noise from the attack related detections was part of the analysis.

### MITRE ATT&CK techniques observed

Read from the Top 10 MITRE ATT&CK view. These aggregate across all reporting agents, so some apply to the Linux agent rather than to victim-win10.

- Valid Accounts
- Disable or Modify Tools
- Sudo and Sudo Caching
- Domain Policy Modification
- Password Guessing

---

## Evidence and Screenshots

The following artifacts were captured from the Wazuh dashboard and the Kali terminal.

| File | What it shows |
|---|---|
| screenshots/SOC-Lab-Wazuh-Dashboard-Alerts-Active_png.png | Wazuh overview with active agents and severity counts |
| screenshots/SOC-Lab-Wazuh-ThreatHunting-MITRE-Alerts.png | Threat hunting view of MITRE-mapped alerts |
| screenshots/Get_SOC-Lab-Wazuh-ThreatHunting-Events-Feed.png | Event feed with timestamps and rule descriptions |
| screenshots/SOC-Lab-Wazuh-MITRE-ATTandCK-Dashboard.png | MITRE ATT&CK dashboard with tactics and techniques |
| screenshots/SOC-Lab-Wazuh-MITRE-Framework-Coverage.png | MITRE ATT&CK framework matrix with detected techniques highlighted |
| screenshots/SOC-Lab-Kali-Nmap-FullPortScan-victim-win10.png | Full 65535 port scan output against the victim |
| screenshots/SOC-Lab-Kali-EternalBlue-CVE-Check-Patched.png | MS17-010 (EternalBlue) check returning no vulnerability finding |
| screenshots/SOC-Lab-kali-NetExec-Attack-Output.png | NetExec SMB credential attack: four failures and one success for labuser (detection validation) |
| screenshots/SOC-Lab-Wazuh-BruteForce-Detection-Table.png | Wazuh detection of the credential attack: failed logons and the successful remote logon (detection validation) |
| screenshots/SOC-Lab-Wazuh-BruteForce-Success-92652-Detail.png | Expanded rule 92652 success event showing source 10.0.0.7, logon type 3, and account labuser (detection validation) |
| reports/SOC-Lab-Wazuh-MITRE-ATTandCK-Report.pdf | Wazuh generated MITRE ATT&CK report |

Place the image files under a `screenshots/` folder and the PDF under a `reports/` folder in this repository so the links above resolve.

---

## Known Limitations and Lessons Learned

### Resource contention during simultaneous VM boot

During the build, starting multiple VMs at the same time caused guest machines to freeze, most often when a second VM was booting while a first VM was still initializing. If all four VMs are powered on together they request about 22 GB of the host 32 GB of RAM, which fits on paper, so the freezing was observed as a startup and contention behavior rather than a hard memory ceiling.

Mitigation adopted: run two VMs at a time, matched to the phase of work.

| Phase | VMs running |
|---|---|
| Detection | wazuh-server and victim-win10 |
| Attack | wazuh-server and kali |
| Analysis | bluebox |

Lesson learned: separating components across multiple VMs reflects a realistic SOC architecture, but it raises the coordination cost on a single host. Staging which machines run during each phase kept the lab stable and made each exercise repeatable.

### victim-win10 hard freeze from paravirtualization conflict

Separate from the resource contention above, victim-win10 hard-froze with a completely unresponsive cursor during light interaction, and repeated restarts did not resolve it. The root cause was confirmed as a hypervisor conflict. The VM was set to the Hyper-V paravirtualization interface, while the Windows host runs Virtualization Based Security with Memory Integrity, verified through `msinfo32` which reported VBS as Running, Hypervisor
enforced Code Integrity active, and a hypervisor detected on the host. A Windows guest using the Hyper-V paravirtualization interface while nested under the host's own hypervisor is a known cause of a total guest lockup.

Fix applied: set the victim-win10 paravirtualization interface to Default in VirtualBox (System, Acceleration). This is reversible and touches only the VM. Host VBS and Memory Integrity were left enabled, so host security was not weakened. The VM ran stably afterward.

Lesson learned: on a modern Windows host with VBS or Memory Integrity active, a Windows guest should not use the Hyper-V paravirtualization interface, because the host hypervisor and the guest setting compete for the same layer.

### victim-win10 Windows Firewall Domain profile drift

While preparing the endpoint, the Windows Firewall Domain profile was found disabled while the Private and Public profiles were enabled. `Get-NetFirewallProfile` confirmed Domain False, Private True, and Public True. All three profiles were re-enabled with `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True`. The first attempt failed with an Access Denied error (Windows System Error 5) because the PowerShell window was not elevated; re-running it in an Administrator PowerShell succeeded, and all three profiles were then confirmed as True.

Context: the lab uses an isolated NAT network with no domain controller, so the Domain profile is not active in practice, which is the likely reason only that profile had drifted off. The baseline state for the endpoint is all three profiles enabled, matching how a real Windows machine ships.

---

## Credentials

Credentials for the Wazuh dashboard, Elastic, Kali, and the Windows endpoint are intentionally excluded from this repository. Storing live credentials in a public repository is a security
risk. They are kept outside version control.

---

## Repository Structure

```
.
├── README.md    ---------> This File
├── SOC-Lab-IR-Report.md
├── SOC-Lab-Portfolio.md
├── screenshots/
│   ├── SOC-Lab-Wazuh-Dashboard-Alerts-Active_png.png
│   ├── SOC-Lab-Wazuh-ThreatHunting-MITRE-Alerts.png
│   ├── Get_SOC-Lab-Wazuh-ThreatHunting-Events-Feed.png
│   ├── SOC-Lab-Wazuh-MITRE-ATTandCK-Dashboard.png
│   ├── SOC-Lab-Wazuh-MITRE-Framework-Coverage.png
│   ├── SOC-Lab-Kali-Nmap-FullPortScan-victim-win10.png
│   ├── SOC-Lab-Kali-EternalBlue-CVE-Check-Patched.png
│   ├── SOC-Lab-kali-NetExec-Attack-Output.png
│   ├── SOC-Lab-Wazuh-BruteForce-Detection-Table.png
│   └── SOC-Lab-Wazuh-BruteForce-Success-92652-Detail.png
└── reports/
    └── SOC-Lab-Wazuh-MITRE-ATTandCK-Report.pdf
```
