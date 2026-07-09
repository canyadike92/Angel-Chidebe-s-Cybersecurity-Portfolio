# Security Incident Report: SOC-Lab-03

**Incident ID:** SOC-Lab-IR-001
**Report date:** 2026-07-05
**Environment:** Isolated home SOC lab (SOC-LAB NAT network, 10.0.0.0/24)
**Classification:** Simulated attack, controlled lab environment
**Severity:** Low (see Severity and Rationale)
**Status:** Closed, no confirmed compromise

---
## 1. Executive Summary

On 2026-06-30, a simulated attack was carried out against a monitored Windows 10 endpoint (victim-win10, 10.0.0.6) from a Kali Linux attacker (kali, 10.0.0.7) inside the isolated SOC-LAB network. The campaign consisted of a vulnerability check for EternalBlue,
network reconnaissance, and an SMB credential brute force aimed at the administrator account.

The EternalBlue check returned no vulnerability finding, so that remote code execution path was not available. Wazuh recorded the endpoint activity, and no alert reached high or critical severity. Investigation of the successful authentication events on victim-win10 confirmed they
were local system logons, not attacker logons, so no credential compromise is confirmed in the captured data. One confirmed detection gap was identified: NTLM credential validation auditing was disabled on the endpoint.

---
## 2. Severity and Rationale

**Severity: Low.**

The rationale is drawn from the confirmed evidence:

- The most dangerous vector was neutralized. The MS17-010 script returned no vulnerability
  finding, so the EternalBlue remote code execution path was not exploitable.
- No confirmed compromise. The only two successful logons on victim-win10 were local SYSTEM
  logons from 127.0.0.1, not network logons from the attacker at 10.0.0.7.
- No evidence of code execution or lateral movement in the reviewed data.
- SIEM scoring stayed low. Alerting peaked at medium, with 0 high, 0 critical, and 0 alerts at
  rule level 12 or above.
- Limited scope. A single endpoint in an isolated lab with no production exposure.

Why not Informational: the campaign included an active intrusion attempt, a credential brute force against a privileged account, which is more than passive reconnaissance.

Why not Medium or higher: there is no confirmed compromise and no confirmed foothold, and the primary code execution vector was confirmed unavailable.

**Confidence caveat:** Credential Validation auditing was disabled on the endpoint, so the NTLM credential validation events (Windows event 4776) that a brute force exercises were not captured. This slightly lowers confidence in the no-compromise conclusion. It is a detection
gap to remediate, not evidence of impact, so it does not raise the severity on its own.

---
## 3. Affected Assets

| Asset | IP | Role |
|---|---|---|
| victim-win10 (DESKTOP-FBHDPT8) | 10.0.0.6 | Target endpoint, Windows 10 Pro 22H2 build 19045.3803, Wazuh agent id 001 |
| kali | 10.0.0.7 | Attacker |
| wazuh-server (manager host: angel) | 10.0.0.5 | Detection, alerting, and log aggregation |
| bluebox | 10.0.0.3 | Elastic and Kibana analyst interface |

---
## 4. Timeline

Timestamps are shown as recorded by each source. A clock skew of about -1h58m was measured
between the attacker and the victim's SMB clock, so times across sources do not align exactly.

| Time (source) | Event |
|---|---|
| 2026-06-30 22:02, Kali local (UTC-4) | MS17-010 (EternalBlue) check against 10.0.0.6:445, completed in 1.22s, no vulnerability finding returned |
| 2026-06-30 22:17, Kali local (UTC-4) | Full port scan begins (`nmap -A -T4 -p-`), completes in 194.24s |
| 2026-06-30 23:46:54 and 23:46:55, Wazuh | Two successful logon events recorded on victim-win10, confirmed local |
| 2026-07-01 00:58:30, Kali local (UTC-4) | Hydra SMB brute force launched against administrator on 10.0.0.6; captured run errored with "invalid reply from target" |
| 2026-07-01, after the error, Kali local | Operator pivoted to host discovery (`nmap -sn 10.0.0.0/24`); no working brute force completed in the captured session |
| Jun 30 05:55 to Jul 1 05:55, Wazuh | Events feed window containing the 517 recorded events |

---
## 5. Reconnaissance Findings

From the full Nmap scan of victim-win10 (Nmap 7.98):

- Open ports: 135, 139, 445, 5040, 7680, and dynamic RPC ports 49664 to 49669 and 49925
- OS fingerprint estimate: Windows 10, 1709 to 21H2
- Ground truth, confirmed on the endpoint: Windows 10 Pro, version 22H2, build 19045.3803
- SMB: version 3.1.1, message signing enabled but not required
- NetBIOS name: DESKTOP-FBHDPT8
- Recorded SMB clock skew on the target: about -1h58m

Note on the OS version: the confirmed build (22H2) is newer than the upper bound of the Nmap
estimate (21H2). Nmap infers a range from network behavior rather than reading the exact build,
so the ground truth value was verified directly on the endpoint.

---
## 6. Vulnerability Check: EternalBlue (MS17-010)

- Command: `nmap -p 445 --script smb-vuln-ms17-010 10.0.0.6`
- Run at 2026-06-30 22:02 (Kali local), completed in 1.22 seconds
- Port 445/tcp confirmed open (microsoft-ds)
- Result: the script returned no vulnerability finding. No VULNERABLE result was produced.

The absence of a VULNERABLE result is the standard indicator that the host is not exploitable
via MS17-010. On this basis the endpoint is assessed as not vulnerable to EternalBlue.

---
## 7. Credential Attack: SMB Brute Force

A Hydra SMB brute force against victim-win10 was captured and confirmed from the attacker terminal.

- Command: `hydra -l administrator -P /usr/share/wordlists/rockyou.txt 10.0.0.6 smb -t 4 -W 3`
- Tool: Hydra v9.6
- Target: 10.0.0.6, SMB, port 445
- Username: administrator
- Wordlist: /usr/share/wordlists/rockyou.txt (14,344,399 entries)
- Start time: 2026-07-01 00:58:30 (Kali local)
- Hydra reduced parallelism to 1 task, noting that SMB does not accept parallel connections

Result of the captured run: it errored with "invalid reply from target smb://10.0.0.6:445/" and did not proceed through the wordlist. The cause of the invalid reply is not shown in the output and is not speculated on here.
After this error, no working brute force was completed in the captured session. The operator pivoted to a host-discovery sweep (`nmap -sn 10.0.0.0/24`). No successful attacker authentication is confirmed in the captured data, consistent with the authentication
attribution in section 9.

---
## 8. Detection and Analysis

Figures read from the Wazuh dashboard and threat hunting views:

- Events feed: 517 events over the Jun 30 to Jul 1 window
- Total alerts: 483
- Alerts at rule level 12 or above: 0
- Authentication in the environment aggregate view: 4 successes, 1 failure
- Primary reporting agent: victim-win10 (agent id 001)

### Severity breakdown (dashboard, last 24 hours)

| Severity | Rule level | Count |
|---|---|---|
| Critical | 15 or higher | 0 |
| High | 12 to 14 | 0 |
| Medium | 7 to 11 | 305 |
| Low | 0 to 6 | 177 |

A large share of the 517 events reflects routine Windows service and software activity rather than attack traffic, for example service startup type changes, software protection scheduling, and installation of Microsoft Update Health Tools. Separating that background noise from the
attack related detections was part of the analysis.

---
## 9. Authentication Attribution

The environment aggregate view showed 4 successful authentications. Scoping the query precisely to victim-win10 and Windows event 4624 returned 2 successful logons on the endpoint, both rule id 60118 ("Windows Workstation Logon Success") at 23:46:54 and 23:46:55 on 2026-06-30. Both
events carried identical detail:

| Field | Value |
|---|---|
| Source IP | 127.0.0.1 |
| Logon type | 2 (interactive) |
| Logon process | User32 (C:\Windows\System32\svchost.exe) |
| Account | DESKTOP-FBHDPT8$, SID S-1-5-18 (SYSTEM) |
| Domain | WORKGROUP |

Neither logon originated from 10.0.0.7, and neither was a network logon. Both are local interactive system logons. On this basis, the SMB brute force did not produce a confirmed successful attacker authentication in the captured data.

---
## 10. Impact Assessment

- No confirmed credential compromise
- No high or critical severity alerts
- Endpoint confirmed not vulnerable to EternalBlue (MS17-010)
- No evidence in the reviewed data of attacker code execution or lateral movement

---
## 11. Confirmed Detection Gap

The endpoint audit policy on victim-win10 has Account Logon, Credential Validation set to No Auditing. That subcategory records NTLM credential checks (Windows event 4776), which is the authentication layer an SMB brute force against a local account exercises. With it disabled,
those NTLM validation attempts were not recorded.

The Logon subcategory (events 4624 and 4625) is set to Success and Failure, so successful and failed logons were being audited.

---
## 12. Explanation of the Sparse Authentication Record

Logon failure auditing (event 4625) was enabled, yet the window shows only 1 authentication failure. The confirmed explanation is that the captured Hydra run errored with "invalid reply from target" and did not work through the wordlist, so it delivered essentially no
authentication attempts for Windows to log, and no working brute force followed in the captured session. The single recorded failure cannot be attributed to the brute force with confidence, and its source was not established. Separately, Credential Validation auditing (event 4776) was
disabled, as noted in section 11, so any NTLM validation activity would not have been recorded regardless.

---
## 13. Recommendations

- Enable Account Logon, Credential Validation auditing on the endpoint so NTLM credential
  checks (event 4776) are captured
- Investigate the single recorded failure against the expected brute force volume, per section 12
- Consider requiring SMB signing, currently enabled but not required
- Retain the Nmap output, Wazuh events, and logon event details as evidence for this incident

---
## 14. MITRE ATT&CK Mapping

Techniques observed in the Top 10 MITRE ATT&CK view. This view aggregates across all reporting agents, so some entries apply to the Linux agent rather than to victim-win10.

- Valid Accounts
- Disable or Modify Tools
- Sudo and Sudo Caching
- Domain Policy Modification
- Password Guessing

---
## 15. Evidence

- Kali MS17-010 (EternalBlue) check output
- Kali Nmap full port scan output
- Kali Hydra SMB brute force output (captured run showing the invalid-reply error)
- Wazuh dashboard alert summary
- Wazuh threat hunting MITRE view
- Wazuh events feed (517 events)
- Two expanded event 4624 records showing source IP and logon type
- victim-win10 audit policy output (`auditpol /get /category:*`)

---

# Follow-up: Detection Validation (2026-07-06)

This section is separate from the incident above. It documents a controlled detection test run on the lab, not a new intrusion. The original incident (sections 1 to 15) errored at the SMB layer and produced no compromise, and the Credential Validation audit gap in section 11 meant
the detection pipeline for a credential attack was never exercised end to end. This validation was run to close that gap and prove the pipeline works.

## V1. Objective

Run a working SMB credential attack against a controlled test account and confirm that Wazuh records the failed attempts and the successful attacker logon.

## V2. Prerequisites configured on victim-win10

All of the following were applied and confirmed before the test:

- Enabled Credential Validation auditing: `auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable`, confirmed reading Success and Failure.
- Confirmed Logon auditing set to Success and Failure.
- Created a controlled test account: `net user labuser Passw0rd! /add`, confirmed successful.
- Added an inbound firewall rule for SMB: `netsh advfirewall firewall add rule name="Lab-Allow-SMB-445" dir=in action=allow protocol=TCP localport=445`. Port 445 then confirmed open from Kali with `nmap -p 445 10.0.0.6`.

## V3. Attack executed

- Tool: NetExec (nxc) version 1.5.1, run from kali (10.0.0.7)
- Command: `nxc smb 10.0.0.6 -u labuser -p /home/kali/smb-lab-list.txt`
- Wordlist: five entries (Summer2024, Password123, Welcome1, LetMeIn2024, Passw0rd!), the first four intentionally wrong and the last one matching the test account
- Target banner reported by NetExec: DESKTOP-FBHDPT8, Windows 10 / Server 2019 Build 19041, SMBv1 None, signing False
- Result: four failures marked `[-]` (STATUS_LOGON_FAILURE) for DESKTOP-FBHDPT8\labuser, followed by one success marked `[+]` for Passw0rd!

## V4. Detection confirmed in Wazuh

Recorded under victim-win10, at the endpoint's own clock (about 08:13 on 2026-07-06). Note the events landed on the victim's clock, so the Wazuh time window had to be widened to surface them.

| Wazuh time | Rule description | rule.level | rule.id |
|---|---|---|---|
| 08:13:04.086 | Successful Remote Logon Detected, User labuser, NTLM authentication | 6 | 92652 |
| 08:13:03.9xx to 08:13:04.035 | Logon Failure, Unknown user or bad password | 5 | 60122 |
| 08:13:03.9xx to 08:13:04.001 | Windows audit failure event | 5 | 60104 |

### Confirmed fields on the successful logon (rule 92652)
Read from the expanded event document:

| Field | Value |
|---|---|
| ipAddress | 10.0.0.7 (attacker) |
| ipPort | 59044 |
| lmPackageName | NTLM V2 |
| logonProcessName | NtLmSsp |
| logonType | 3 (network) |
| targetUserName | labuser |
| targetDomainName | DESKTOP-FBHDPT8 |
| channel | Security |

This is a network logon over NTLMv2 from the attacker at 10.0.0.7, succeeding against the local labuser account. Together with the preceding failure events, it is a complete brute force signature: repeated failures followed by one attacker-sourced success, all detected by Wazuh.

## V5. Outcome

The detection pipeline is confirmed working end to end. A credential attack that succeeds at the SMB layer now produces both failed-logon detections and an attacker-attributed success in Wazuh.
This closes the detection gap identified in section 11 of the original incident.

## V6. Cleanup

The test artifacts should be removed to return the endpoint to a clean baseline, since the labuser account carries a weak password:

- Remove the test account: `net user labuser /delete`
- Optionally remove the lab firewall rule: `netsh advfirewall firewall delete rule name="Lab-Allow-SMB-445"`
- Keep Credential Validation auditing enabled. This is a genuine improvement, not a test
  artifact, and it closes the audit gap from the original incident.

## V7. Validation evidence

- NetExec output showing four failures and one success for labuser (`screenshots/SOC-Lab-kali-NetExec-Attack-Output.png`)
- Wazuh threat hunting results table showing the failures and the 92652 success (`screenshots/SOC-Lab-Wazuh-BruteForce-Detection-Table.png`)
- Expanded Wazuh event for rule 92652 showing ipAddress 10.0.0.7, logonType 3, and targetUserName labuser (`screenshots/SOC-Lab-Wazuh-BruteForce-Success-92652-Detail.png`)
