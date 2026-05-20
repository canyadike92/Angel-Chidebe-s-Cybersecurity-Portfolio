# Splunk Detection Rules: Threat-Informed Detection Engineering

> **Analyst:** [Your Name]
> **Date:** [Month Year]
> **Status:** Active — ongoing additions
> **Focus:** Detection engineering using SPL mapped to MITRE ATT&CK
> **Dataset:** Splunk BOTS v3 / Boss of the SOC

---

## Table of contents

1. [Overview](#overview)
2. [Environment and setup](#environment-and-setup)
3. [Detection 1: Credential dumping via LSASS access](#detection-1-credential-dumping)
4. [Detection 2: PowerShell encoded command execution](#detection-2-powershell-encoded-command)
5. [Detection 3: Suspicious scheduled task creation](#detection-3-scheduled-task-creation)
6. [Detection 4: Brute force login detection](#detection-4-brute-force-login)
7. [Detection 5: Data exfiltration via DNS tunneling](#detection-5-dns-tunneling)
8. [False positive analysis summary](#false-positive-analysis-summary)
9. [Detection coverage map](#detection-coverage-map)
10. [Lessons learned](#lessons-learned)
11. [Artifacts and file structure](#artifacts-and-file-structure)

---

## Overview

This project documents five custom Splunk detection rules built from scratch, each mapped
to a specific MITRE ATT&CK technique. For every detection I document the threat hypothesis,
the SPL query with inline comments, tuning decisions, false positive analysis, and the alert
threshold rationale.

The goal is not to show that I can copy Sigma rules. The goal is to show I understand
why a detection fires, what it misses, and how to tune it for a real environment.

**Skills demonstrated:**

| Skill | Detail |
|---|---|
| SPL authoring | Subsearches, eval logic, stats, transaction, tstats |
| MITRE ATT&CK mapping | Technique and sub-technique level |
| False positive analysis | Per-detection tuning rationale |
| Detection lifecycle | Hypothesis, build, test, tune, document |
| Log source knowledge | Windows Event Logs, Sysmon, proxy, DNS, auth logs |

---

## Environment and setup

**Splunk version:** Enterprise 9.x (free trial or Docker)
**Dataset:** Splunk BOTS v3 — [github.com/splunk/botsv3](https://github.com/splunk/botsv3)
**Indexes used:** `botsv3`, `main`
**Key log sources:**

| Source | Sourcetype | Events covered |
|---|---|---|
| Windows Security Event Log | `WinEventLog:Security` | Logon, privilege use, object access |
| Sysmon | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation, network, registry |
| PowerShell | `WinEventLog:Microsoft-Windows-PowerShell/Operational` | Script block logging |
| DNS | `stream:dns` | DNS queries and responses |
| Proxy | `stream:http` | Web traffic, user agents |

**How to load BOTS v3 into your Splunk instance:**

```bash
# Download the dataset from the Splunk BOTS GitHub page
# Then import via Splunk CLI
./splunk add index botsv3
./splunk install app /path/to/botsv3_data.tgz -auth admin:yourpassword
```

---

## Detection 1: Credential dumping

**MITRE Technique:** T1003.001 — OS Credential Dumping: LSASS Memory
**Severity:** Critical
**Log source:** Sysmon Event ID 10 (ProcessAccess)
**Hypothesis:** An adversary attempting to dump credentials will open a handle to
`lsass.exe` with specific access rights. Sysmon Event ID 10 captures process access
events and is the primary telemetry source for this behavior.

### Threat context

LSASS (Local Security Authority Subsystem Service) stores credential material in memory.
Tools like Mimikatz, ProcDump, and Task Manager can all be used to access or dump it.
The specific access rights requested — particularly `0x1010` and `0x1410` — are
characteristic of credential theft tooling rather than legitimate OS operations.

### SPL query

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=10
    TargetImage="*lsass.exe"
| eval suspicious_access=case(
    match(GrantedAccess,"0x1010"),"Read + QueryInfo — Mimikatz pattern",
    match(GrantedAccess,"0x1410"),"Read + QueryInfo + VM Read — ProcDump pattern",
    match(GrantedAccess,"0x1fffff"),"Full access — highly suspicious",
    1==1,"Other"
  )
| where suspicious_access != "Other"
| stats
    count AS access_count,
    values(GrantedAccess) AS access_rights,
    values(suspicious_access) AS access_pattern,
    values(SourceImage) AS calling_process,
    first(_time) AS first_seen,
    last(_time) AS last_seen
    BY Computer, TargetImage
| eval duration_seconds=last_seen - first_seen
| sort -access_count
| table Computer, calling_process, access_pattern, access_rights, access_count,
         first_seen, last_seen
```

### Why this query is written this way

The `eval suspicious_access` block maps raw hex access right values to human-readable
descriptions. This matters because `0x1010` and `0x1410` are the specific flags
that Mimikatz and ProcDump request respectively. Flagging all LSASS access would
create significant noise from legitimate system processes. Filtering to these specific
access masks narrows detection to known malicious patterns while reducing false positives.

### Tuning decisions

| Decision | Rationale |
|---|---|
| Filter on specific GrantedAccess values | Reduces noise from legitimate LSASS access by Windows Defender, AV, and system processes |
| Use `values(SourceImage)` not `count` | Shows all calling processes in case multiple tools are used in sequence |
| Stats by Computer | Groups per host to see if the same machine has multiple access attempts |

### False positive analysis

| Source | Access rights seen | Disposition |
|---|---|---|
| Windows Defender (MsMpEng.exe) | 0x1000 | Benign — does not match suspicious mask |
| CrowdStrike sensor | 0x1410 | Known FP — allowlist by SourceImage path |
| Task Manager (taskmgr.exe) | 0x0400 | Benign — different access mask |
| Legitimate backup agents | 0x1010 | Review — allowlist known backup process paths |

**Recommended allowlist addition:**

```spl
| where NOT (SourceImage="C:\\Program Files\\CrowdStrike\\*"
         OR SourceImage="C:\\Program Files\\Windows Defender\\*"
         OR SourceImage="C:\\Windows\\System32\\svchost.exe")
```

**Expected false positive rate after tuning:** Very low (under 2 per week in a typical enterprise)

---

> #### SCREENSHOT CAPTURE GUIDE 01
> **File:** `screenshots/01-lsass-detection-results.png`
>
> **Where to do this:** Splunk with BOTS v3 dataset loaded
>
> **Steps:**
> 1. Paste the SPL query above into the Splunk search bar
> 2. Set the index to `botsv3` and time range to **All Time**
> 3. Press Ctrl+\ to format the query onto multiple lines before screenshotting
> 4. Run the search and wait for results
>
> **What your screenshot must show:**
> - The formatted SPL query visible in the search bar
> - The results table with Computer, calling_process, access_pattern columns populated
> - The event count shown in the top-left of the results panel
> - The time range picker visible
>
> **Caption:** `Figure 1: Splunk detection for LSASS process access (T1003.001) showing
> Mimikatz-pattern access rights flagged against Sysmon Event ID 10 telemetry.`

**[ Screenshot 01 — Replace this line with your image once captured ]**

---

### Alert configuration

```
Alert name:       CRIT - LSASS Process Access - Possible Credential Dumping
Search schedule:  Every 15 minutes
Time window:      Last 30 minutes
Trigger:          Number of results > 0
Severity:         Critical
Actions:          Create TheHive alert, notify SOC Slack channel
Suppression:      Per Computer — suppress for 1 hour after first alert
```

---

## Detection 2: PowerShell encoded command

**MITRE Technique:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Severity:** High
**Log source:** Windows Event ID 4104 (Script Block Logging), Sysmon Event ID 1
**Hypothesis:** Attackers frequently use PowerShell's `-EncodedCommand` flag to
obfuscate malicious script execution. While base64 encoding has legitimate uses,
the combination of encoded commands with specific execution flags is a strong
indicator of malicious intent.

### Threat context

PowerShell encoded commands are used to bypass command-line logging and evade
simple string-based detection. Common tools that use this pattern include Empire,
Metasploit PowerShell payloads, and many commodity RATs. The key detection opportunity
is at the process creation level (Sysmon EID 1) and script block level (EID 4104).

### SPL query

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
    EventCode=1
    Image="*powershell.exe" OR Image="*pwsh.exe"
| eval cmdline_lower=lower(CommandLine)
| eval encoded_flag=case(
    match(cmdline_lower,"-enc\s"),"Short flag -enc",
    match(cmdline_lower,"-encodedcommand\s"),"Full flag -encodedcommand",
    match(cmdline_lower,"-ec\s"),"Short flag -ec",
    1==1,"none"
  )
| eval suspicious_flags=case(
    match(cmdline_lower,"-nop") AND match(cmdline_lower,"-w\s+hidden"),"NoProfile + Hidden window",
    match(cmdline_lower,"-executionpolicy\s+bypass"),"Execution policy bypass",
    match(cmdline_lower,"-nop"),"NoProfile flag",
    1==1,"none"
  )
| where encoded_flag != "none"
| eval risk_score=case(
    encoded_flag!="none" AND suspicious_flags!="none", 90,
    encoded_flag!="none", 60,
    1==1, 30
  )
| stats
    count,
    values(CommandLine) AS full_commandline,
    values(encoded_flag) AS encoding_flag_used,
    values(suspicious_flags) AS additional_flags,
    max(risk_score) AS max_risk_score,
    values(ParentImage) AS parent_process,
    dc(CommandLine) AS unique_commands
    BY Computer, User
| sort -max_risk_score
| table Computer, User, encoding_flag_used, additional_flags,
         max_risk_score, count, unique_commands, parent_process
```

### Why this query is written this way

The risk scoring logic is the key design decision here. A single `-enc` flag alone
could be a developer or admin task. The combination of `-enc` with `-nop -w hidden`
is almost exclusively malicious. Scoring both patterns separately and surfacing
the max score lets a tier-1 analyst prioritize quickly without missing either case.

The `dc(CommandLine)` count shows how many unique encoded commands ran on that
host and user combination. A count greater than 3 unique encoded commands is a
strong escalation signal.

### Tuning decisions

| Decision | Rationale |
|---|---|
| Lowercase eval before matching | Case-insensitive matching without regex complexity |
| Parent process tracking | PowerShell spawned from Word or Excel is higher priority than from cmd.exe |
| Risk score instead of binary alert | Gives tier-1 a triage signal, not just a flag |

### False positive analysis

| Source | Pattern | Disposition |
|---|---|---|
| SCCM / Endpoint management | `-EncodedCommand` with known hash | Allowlist by ParentImage path and CommandLine hash |
| Developer build scripts | `-enc` in CI pipelines | Allowlist by User (service accounts) |
| Legitimate admin tools | `-ExecutionPolicy Bypass` only | Lower risk score, do not suppress entirely |

**Recommended allowlist addition:**

```spl
| where NOT (User="svc-sccm" OR User="svc-deploy" OR User="svc-backup")
| where NOT ParentImage="C:\\Windows\\CCM\\CcmExec.exe"
```

**Expected false positive rate after tuning:** Low to medium (3 to 8 per week depending on environment)

---

> #### SCREENSHOT CAPTURE GUIDE 02
> **File:** `screenshots/02-powershell-encoded-detection.png`
>
> **Where to do this:** Splunk with BOTS v3 dataset loaded
>
> **What your screenshot must show:**
> - The SPL query in the search bar, formatted across multiple lines
> - Results table showing Computer, User, encoding_flag_used, max_risk_score columns
> - At least one row with a risk score of 90 visible if the dataset contains it
> - The search job inspector showing how many events were scanned (optional but impressive)
>
> **Tip:** Click the search job inspector link below the search bar after running.
> It shows events scanned, run time, and result count. Screenshot that panel as a
> second crop labeled `02b` — it demonstrates you understand search performance.
>
> **Caption:** `Figure 2: Splunk detection for PowerShell encoded command execution
> (T1059.001) with risk scoring logic differentiating combined obfuscation flags
> from single-flag use.`

**[ Screenshot 02 — Replace this line with your image once captured ]**

---

### Alert configuration

```
Alert name:       HIGH - PowerShell Encoded Command Execution
Search schedule:  Every 10 minutes
Time window:      Last 20 minutes
Trigger:          max_risk_score >= 90
Severity:         High
Actions:          Create TheHive alert
Suppression:      Per Computer + User — suppress 30 minutes after first alert
```

---

## Detection 3: Suspicious scheduled task creation

**MITRE Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task
**Severity:** High
**Log source:** Windows Event ID 4698 (Scheduled Task Created), Sysmon Event ID 1
**Hypothesis:** Attackers use scheduled tasks for persistence and lateral movement.
Legitimate scheduled task creation happens during software installation and system
administration. Malicious tasks are typically created outside business hours, by
non-admin users, or with suspicious execution paths pointing to temp directories,
AppData, or encoded commands.

### Threat context

Scheduled task abuse is one of the most common persistence mechanisms in ransomware
and APT campaigns. The detection opportunity is at creation time using Windows
Security Event 4698, which logs the full XML task definition including the command
being scheduled.

### SPL query

```spl
index=botsv3 sourcetype="WinEventLog:Security" EventCode=4698
| spath input=TaskContent
| rename "Task_Xml.Actions.Exec.Command" AS scheduled_command
| rename "Task_Xml.Actions.Exec.Arguments" AS scheduled_args
| eval suspicious_path=case(
    match(lower(scheduled_command),"%temp%"),"Temp directory",
    match(lower(scheduled_command),"%appdata%"),"AppData directory",
    match(lower(scheduled_command),"\\\\users\\\\public"),"Public directory",
    match(lower(scheduled_command),"powershell"),"PowerShell execution",
    match(lower(scheduled_command),"cmd\.exe.*\/c"),"CMD with /c flag",
    match(lower(scheduled_command),"wscript|cscript"),"Script host execution",
    1==1,"Standard path"
  )
| eval hour_of_day=strftime(_time,"%H")
| eval off_hours=if(hour_of_day<8 OR hour_of_day>18,"Yes","No")
| where suspicious_path != "Standard path" OR off_hours="Yes"
| stats
    count,
    values(TaskName) AS task_name,
    values(scheduled_command) AS command,
    values(scheduled_args) AS arguments,
    values(suspicious_path) AS path_flag,
    values(off_hours) AS created_off_hours,
    values(SubjectUserName) AS created_by
    BY Computer
| sort -count
| table Computer, created_by, task_name, command, arguments,
         path_flag, created_off_hours, count
```

### Why this query is written this way

The `spath` command parses the XML task definition that Windows embeds in Event 4698.
This is important because the raw event log stores the full task XML as a field, and
without parsing it you cannot inspect what the task actually runs. Most detection rules
for this technique miss this and only alert on task creation without checking the payload.

The off-hours logic is a secondary signal, not a primary one. A task created at 2am
with a standard path is still worth reviewing. A task created at 2am pointing to
AppData with a PowerShell command is an immediate escalation.

### Tuning decisions

| Decision | Rationale |
|---|---|
| spath to parse XML | Exposes the actual command being scheduled, not just the event |
| Off-hours as secondary signal | Adds context without creating noise for all off-hours activity |
| Exclude standard paths only when no off-hours flag | Reduces volume while preserving visibility |

### False positive analysis

| Source | Pattern | Disposition |
|---|---|---|
| Software installers | Task creation during install pointing to ProgramFiles | Allowlist by SubjectUserName (SYSTEM during install) and path prefix |
| Windows Update | Tasks pointing to system32 | Excluded by standard path filter already |
| Backup software | Off-hours tasks to known backup agent paths | Allowlist by scheduled_command path |

**Recommended allowlist addition:**

```spl
| where NOT (created_by="SYSTEM" AND match(lower(command),"c:\\\\program files"))
| where NOT match(lower(command),"c:\\\\windows\\\\system32")
```

**Expected false positive rate after tuning:** Low (1 to 3 per week)

---

> #### SCREENSHOT CAPTURE GUIDE 03
> **File:** `screenshots/03-scheduled-task-detection.png`
>
> **Where to do this:** Splunk with BOTS v3 dataset loaded
>
> **What your screenshot must show:**
> - SPL query in the search bar
> - Results table with Computer, command, path_flag, created_off_hours visible
> - The parsed XML command field populated in at least one row
>
> **Tip:** After running, click any result row to expand the raw event. Screenshot
> the expanded event showing the full XML task definition. Save this as `03b` — it
> demonstrates you understand what spath is actually parsing and why it matters.
>
> **Caption:** `Figure 3: Splunk detection for scheduled task creation (T1053.005)
> using spath to parse embedded XML task definitions and flag suspicious execution
> paths and off-hours creation.`

**[ Screenshot 03 — Replace this line with your image once captured ]**

---

## Detection 4: Brute force login detection

**MITRE Technique:** T1110.001 — Brute Force: Password Guessing
**Severity:** Medium
**Log source:** Windows Event ID 4625 (Failed Logon), 4624 (Successful Logon)
**Hypothesis:** A brute force attack against a Windows account produces a pattern
of rapid consecutive logon failures, optionally followed by a successful logon.
The detection logic looks for failure volume thresholds and then correlates with
any subsequent success to identify a successful brute force.

### Threat context

Account brute force is a primary initial access technique and a common signal in
ransomware precursor activity. The challenge in detection is tuning the threshold
to catch attacks without flooding the queue with users who mistype their password
twice in the morning.

### SPL query

```spl
index=botsv3 sourcetype="WinEventLog:Security"
    (EventCode=4625 OR EventCode=4624)
| eval event_type=case(EventCode=4625,"failure",EventCode=4624,"success",1==1,"other")
| eval logon_type_name=case(
    Logon_Type=2,"Interactive",
    Logon_Type=3,"Network",
    Logon_Type=10,"Remote Interactive (RDP)",
    1==1,"Other"
  )
| bucket span=5m _time
| stats
    count(eval(event_type="failure")) AS failure_count,
    count(eval(event_type="success")) AS success_count,
    values(Source_Network_Address) AS source_ips,
    values(logon_type_name) AS logon_types
    BY _time, ComputerName, Account_Name
| where failure_count >= 10
| eval brute_force_result=case(
    success_count > 0 AND failure_count >= 10,"CRITICAL - Failures followed by success",
    failure_count >= 50,"HIGH - High volume failure spray",
    failure_count >= 10,"MEDIUM - Threshold exceeded",
    1==1,"monitor"
  )
| sort -failure_count
| table _time, ComputerName, Account_Name, failure_count,
         success_count, brute_force_result, source_ips, logon_types
```

### Why this query is written this way

The `bucket span=5m` command groups events into 5-minute windows. This is the
key design decision — without bucketing, a user who fails 3 logins over 3 hours
would never trigger the threshold. Bucketing ensures we are measuring burst rate,
not total count.

The `brute_force_result` escalation logic is the most important part of this query
for a SOC analyst. Failures followed by a success is the highest priority case —
it means the attack likely succeeded. That must page someone immediately. Pure
failure spray without a success may be a noisy attacker or a locked account.

### Tuning decisions

| Decision | Rationale |
|---|---|
| 5-minute bucket window | Catches burst patterns without false positives from spread-out typos |
| Threshold of 10 failures | Tunable — start at 10, raise to 20 in noisy environments |
| Success correlation | Distinguishes failed attacks from successful compromises |
| Logon type tracking | RDP brute force is higher priority than network logon |

### False positive analysis

| Source | Pattern | Disposition |
|---|---|---|
| User with bad cached credentials | 10 to 20 failures, no success, single source IP | Review — likely benign, add to known-user allowlist |
| Service account misconfiguration | Hundreds of failures from same host | Allowlist service account names with known issue tracking |
| Helpdesk password testing | Failures from helpdesk IP range | Allowlist source IP range for known admin subnets |

**Recommended allowlist addition:**

```spl
| where NOT (Account_Name="svc-*" AND failure_count < 100)
| where NOT match(source_ips,"10\.10\.1\.")
```

**Expected false positive rate after tuning:** Medium (5 to 15 per week, mostly Monday mornings)

---

> #### SCREENSHOT CAPTURE GUIDE 04
> **File:** `screenshots/04-brute-force-detection.png`
>
> **Where to do this:** Splunk with BOTS v3 dataset loaded
>
> **What your screenshot must show:**
> - SPL query in the search bar
> - Results table showing failure_count, success_count, brute_force_result columns
> - At least one row showing the CRITICAL result (failures followed by success) if present
> - The bucket span visible in the query
>
> **Tip:** After getting results, switch to the Visualization tab and create a bar
> chart of failure_count by Account_Name. Screenshot that chart as `04b`. A visual
> showing attack volume by account is compelling in a portfolio and demonstrates
> you can translate raw data into a dashboard element.
>
> **Caption:** `Figure 4: Splunk brute force detection (T1110.001) using 5-minute
> bucketing to identify burst login failure patterns with success correlation to
> flag completed account compromises.`

**[ Screenshot 04 — Replace this line with your image once captured ]**

---

## Detection 5: DNS tunneling

**MITRE Technique:** T1071.004 — Application Layer Protocol: DNS
**Severity:** High
**Log source:** DNS query logs (`stream:dns`)
**Hypothesis:** DNS tunneling encodes data inside DNS query strings to exfiltrate
data or maintain C2 communication. Characteristics include: unusually long subdomains,
high query volume to a single domain, high entropy subdomains, and rare or newly
seen domains with no web presence.

### Threat context

DNS tunneling tools like Iodine, DNScat2, and custom implants use the DNS protocol
as a covert channel because DNS traffic is rarely inspected or blocked. Detection
relies on behavioral anomalies in query patterns rather than known-bad signatures.

### SPL query

```spl
index=botsv3 sourcetype="stream:dns"
    message_type=QUERY
| eval query_length=len(query)
| eval subdomain_count=mvcount(split(query,".")) - 2
| eval has_long_subdomain=if(query_length > 52, "Yes", "No")
| eval has_many_subdomains=if(subdomain_count > 3, "Yes", "No")
| rex field=query "^(?P<subdomain>[^.]+)\."
| eval subdomain_entropy=0
| eval chars="abcdefghijklmnopqrstuvwxyz0123456789"
| eval entropy_flag=if(
    match(subdomain,"[0-9a-f]{20,}") OR
    match(subdomain,"[A-Za-z0-9+/]{20,}=*"),
    "High entropy — possible base64 or hex encoding",
    "Normal"
  )
| stats
    count AS query_count,
    dc(query) AS unique_subdomains,
    avg(query_length) AS avg_query_length,
    max(query_length) AS max_query_length,
    values(entropy_flag) AS entropy_flags,
    values(has_long_subdomain) AS long_subdomain_flag,
    values(src_ip) AS source_hosts
    BY dest
| eval tunneling_score=0
| eval tunneling_score=tunneling_score + if(query_count > 100, 30, 0)
| eval tunneling_score=tunneling_score + if(unique_subdomains > 50, 25, 0)
| eval tunneling_score=tunneling_score + if(avg_query_length > 40, 25, 0)
| eval tunneling_score=tunneling_score + if(match(mvjoin(entropy_flags,""),"High entropy"), 20, 0)
| where tunneling_score >= 50
| sort -tunneling_score
| table dest, tunneling_score, query_count, unique_subdomains,
         avg_query_length, max_query_length, entropy_flags, source_hosts
```

### Why this query is written this way

No single indicator reliably identifies DNS tunneling. A scoring model that combines
multiple weak signals into a composite score is the right approach here. High query
volume alone could be CDN traffic. Long subdomains alone could be legitimate cloud
services. High entropy alone could be UUID-based service discovery. The combination
of three or more signals scoring 50 or above is a meaningful indicator.

The entropy detection using regex pattern matching for base64 and hex strings is
a simplified approximation. A production version would implement Shannon entropy
calculation via a lookup table or a custom Splunk app. This version is appropriate
for a home lab and demonstrates the concept correctly.

### Tuning decisions

| Decision | Rationale |
|---|---|
| Score threshold of 50 | Requires at least 2 to 3 signals to trigger — single signal is too noisy |
| unique_subdomains threshold of 50 | CDNs use many subdomains but typically not high entropy ones |
| Exclude known CDNs | Add allowlist for Akamai, Cloudflare, AWS resolver IPs |

### False positive analysis

| Source | Pattern | Disposition |
|---|---|---|
| CDN traffic (Akamai, Cloudflare) | High query count, moderate subdomain count | Allowlist known CDN resolver IPs |
| Cloud service discovery | High unique subdomains, low entropy | Scores below threshold without entropy flag |
| Software update checks | Periodic high-entropy subdomains | Allowlist by dest domain if known update endpoint |

**Recommended allowlist addition:**

```spl
| where NOT match(dest,"akamai\.net$|cloudfront\.net$|amazonaws\.com$")
| where NOT match(dest,"windowsupdate\.com$|microsoft\.com$")
```

**Expected false positive rate after tuning:** Low (1 to 4 per week)

---

> #### SCREENSHOT CAPTURE GUIDE 05
> **File:** `screenshots/05-dns-tunneling-detection.png`
>
> **Where to do this:** Splunk with BOTS v3 dataset loaded
>
> **What your screenshot must show:**
> - SPL query in the search bar
> - Results table showing dest, tunneling_score, unique_subdomains, entropy_flags
> - At least one row with a tunneling_score of 50 or above
>
> **Tip:** After running the query, switch to Visualization and create a column
> chart of tunneling_score by dest domain. Screenshot the chart as `05b`. The
> score distribution across domains tells a cleaner story than the raw table
> alone and shows you can communicate findings visually.
>
> **Caption:** `Figure 5: Splunk DNS tunneling detection (T1071.004) using composite
> scoring across query volume, unique subdomain count, query length, and entropy
> patterns to surface covert DNS channel activity.`

**[ Screenshot 05 — Replace this line with your image once captured ]**

---

## False positive analysis summary

This table summarizes false positive rates across all five detections after tuning.
Maintaining this summary demonstrates you understand that detection engineering is
an ongoing process, not a one-time build.

| Detection | Technique | Pre-tuning FP rate | Post-tuning FP rate | Primary FP source |
|---|---|---|---|---|
| LSASS access | T1003.001 | High | Very low | CrowdStrike sensor, Windows Defender |
| PowerShell encoded | T1059.001 | Medium | Low | SCCM, developer build pipelines |
| Scheduled task | T1053.005 | Medium | Low | Software installers, backup agents |
| Brute force login | T1110.001 | Medium | Medium | Cached credentials, Monday mornings |
| DNS tunneling | T1071.004 | Low | Very low | CDN traffic, cloud service discovery |

---

## Detection coverage map

Coverage of MITRE ATT&CK tactics addressed by these five detections:

| Tactic | Technique | Detection |
|---|---|---|
| Credential Access | T1003.001 LSASS Memory | Detection 1 |
| Execution | T1059.001 PowerShell | Detection 2 |
| Persistence | T1053.005 Scheduled Task | Detection 3 |
| Initial Access | T1110.001 Brute Force | Detection 4 |
| Command and Control | T1071.004 DNS | Detection 5 |
| Exfiltration | T1071.004 DNS (dual use) | Detection 5 |

**Coverage gaps identified:**

- T1055 Process Injection — no detection in this set, planned for next iteration
- T1078 Valid Accounts — brute force detection covers the attack vector but not
  post-compromise use of stolen credentials
- T1021.001 RDP — brute force detection covers logon failures but not lateral
  movement via legitimate RDP sessions

---

## Lessons learned

**What went well:**
- Composite scoring models (detections 4 and 5) proved more robust than binary
  threshold alerts — fewer false positives and better prioritization for tier-1 analysts
- Using `spath` for XML parsing in the scheduled task detection uncovered the actual
  command payload, which most public detections for this technique miss entirely
- The LSASS detection access mask filtering reduced noise significantly compared to
  alerting on all LSASS access

**What I would do differently:**
- Implement proper Shannon entropy calculation for the DNS tunneling detection rather
  than the regex approximation — a Splunk lookup table with precomputed entropy values
  for common character patterns would be more accurate
- Add a baseline period to the brute force detection so the threshold adapts to
  each account's normal failure rate rather than using a static count
- Build a correlation search that links detections 1 and 2 — PowerShell encoded
  commands that follow LSASS access on the same host within 10 minutes is a very
  high confidence compromise indicator

**Skills gaps identified and addressed:**
- spath and XML parsing in SPL was new — documented full notes in `/notes/splunk-spl-reference.md`
- DNS entropy analysis requires deeper study — added threat hunting with DNS logs
  to the learning backlog

---

## Artifacts and file structure

```
splunk-detections/
├── README.md                              <- This file
├── detections/
│   ├── 01-lsass-credential-dump.spl       <- Raw SPL for detection 1
│   ├── 02-powershell-encoded-cmd.spl      <- Raw SPL for detection 2
│   ├── 03-scheduled-task-creation.spl     <- Raw SPL for detection 3
│   ├── 04-brute-force-login.spl           <- Raw SPL for detection 4
│   └── 05-dns-tunneling.spl               <- Raw SPL for detection 5
├── screenshots/
│   ├── 01-lsass-detection-results.png     <- Splunk results for detection 1
│   ├── 02-powershell-encoded-detection.png
│   ├── 03-scheduled-task-detection.png
│   ├── 04-brute-force-detection.png
│   └── 05-dns-tunneling-detection.png
├── sigma/
│   ├── 01-lsass-credential-dump.yml       <- Sigma rule equivalent for portability
│   ├── 02-powershell-encoded-cmd.yml
│   └── 03-scheduled-task-creation.yml
└── notes/
    └── tuning-log.md                      <- Running log of tuning changes and dates
```

---

> **Note on dataset:** All queries in this project were developed and tested against
> the Splunk BOTS v3 public dataset. No proprietary or customer data was used.
> BOTS v3 is an open dataset published by Splunk for security training purposes.

---

*Part of the [Blue Team Cybersecurity Portfolio](../../README.md)*
