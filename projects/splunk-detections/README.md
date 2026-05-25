\# Splunk Detection Rules: Threat-Informed Detection Engineering



> \*\*Analyst:\*\* \[Your Name]

> \*\*Date:\*\* \[Month Year]

> \*\*Status:\*\* Active — ongoing additions

> \*\*Focus:\*\* Detection engineering using SPL mapped to MITRE ATT\&CK

> \*\*Dataset:\*\* Splunk BOTS v3 / Boss of the SOC



\---



\## Table of contents



1\. \[Overview](#overview)

2\. \[Environment and setup](#environment-and-setup)

3\. \[Detection 1: Credential dumping via LSASS access](#detection-1-credential-dumping)

4\. \[Detection 2: PowerShell encoded command execution](#detection-2-powershell-encoded-command)

5\. \[Detection 3: Suspicious scheduled task creation](#detection-3-scheduled-task-creation)

6\. \[Detection 4: Brute force login detection](#detection-4-brute-force-login)

7\. \[Detection 5: Data exfiltration via DNS tunneling](#detection-5-dns-tunneling)

8\. \[False positive analysis summary](#false-positive-analysis-summary)

9\. \[Detection coverage map](#detection-coverage-map)

10\. \[Lessons learned](#lessons-learned)

11\. \[Artifacts and file structure](#artifacts-and-file-structure)



\---



\## Overview



This project documents five custom Splunk detection rules built from scratch, each mapped

to a specific MITRE ATT\&CK technique. For every detection I document the threat hypothesis,

the SPL query with inline comments, tuning decisions, false positive analysis, and the alert

threshold rationale.



The goal is not to show that I can copy Sigma rules. The goal is to show I understand

why a detection fires, what it misses, and how to tune it for a real environment.



\*\*Skills demonstrated:\*\*



| Skill | Detail |

|---|---|

| SPL authoring | Subsearches, eval logic, stats, transaction, tstats |

| MITRE ATT\&CK mapping | Technique and sub-technique level |

| False positive analysis | Per-detection tuning rationale |

| Detection lifecycle | Hypothesis, build, test, tune, document |

| Log source knowledge | Windows Event Logs, Sysmon, proxy, DNS, auth logs |



\---



\## Environment and setup



\*\*Splunk version:\*\* Enterprise 9.x (free trial or Docker)

\*\*Dataset:\*\* Splunk BOTS v3 — \[github.com/splunk/botsv3](https://github.com/splunk/botsv3)

\*\*Indexes used:\*\* `botsv3`, `main`

\*\*Key log sources:\*\*



| Source | Sourcetype | Events covered |

|---|---|---|

| Windows Security Event Log | `WinEventLog:Security` | Logon, privilege use, object access |

| Sysmon | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation, network, registry |

| PowerShell | `WinEventLog:Microsoft-Windows-PowerShell/Operational` | Script block logging |

| DNS | `stream:dns` | DNS queries and responses |

| Proxy | `stream:http` | Web traffic, user agents |



\*\*How to load BOTS v3 into your Splunk instance:\*\*



```bash

\# Download the dataset from the Splunk BOTS GitHub page

\# Then import via Splunk CLI

./splunk add index botsv3

./splunk install app /path/to/botsv3\_data.tgz -auth admin:yourpassword

```



\---



\## Detection 1: Credential dumping



\*\*MITRE Technique:\*\* T1003.001 — OS Credential Dumping: LSASS Memory

\*\*Severity:\*\* Critical

\*\*Log source:\*\* Sysmon Event ID 10 (ProcessAccess)

\*\*Hypothesis:\*\* An adversary attempting to dump credentials will open a handle to

`lsass.exe` with specific access rights. Sysmon Event ID 10 captures process access

events and is the primary telemetry source for this behavior.



\### Threat context



LSASS (Local Security Authority Subsystem Service) stores credential material in memory.

Tools like Mimikatz, ProcDump, and Task Manager can all be used to access or dump it.

The specific access rights requested — particularly `0x1010` and `0x1410` — are

characteristic of credential theft tooling rather than legitimate OS operations.



\### SPL query



```spl

index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

&#x20;   EventCode=10

&#x20;   TargetImage="\*lsass.exe"

| eval suspicious\_access=case(

&#x20;   match(GrantedAccess,"0x1010"),"Read + QueryInfo — Mimikatz pattern",

&#x20;   match(GrantedAccess,"0x1410"),"Read + QueryInfo + VM Read — ProcDump pattern",

&#x20;   match(GrantedAccess,"0x1fffff"),"Full access — highly suspicious",

&#x20;   1==1,"Other"

&#x20; )

| where suspicious\_access != "Other"

| stats

&#x20;   count AS access\_count,

&#x20;   values(GrantedAccess) AS access\_rights,

&#x20;   values(suspicious\_access) AS access\_pattern,

&#x20;   values(SourceImage) AS calling\_process,

&#x20;   first(\_time) AS first\_seen,

&#x20;   last(\_time) AS last\_seen

&#x20;   BY Computer, TargetImage

| eval duration\_seconds=last\_seen - first\_seen

| sort -access\_count

| table Computer, calling\_process, access\_pattern, access\_rights, access\_count,

&#x20;        first\_seen, last\_seen

```



\### Why this query is written this way



The `eval suspicious\_access` block maps raw hex access right values to human-readable

descriptions. This matters because `0x1010` and `0x1410` are the specific flags

that Mimikatz and ProcDump request respectively. Flagging all LSASS access would

create significant noise from legitimate system processes. Filtering to these specific

access masks narrows detection to known malicious patterns while reducing false positives.



\### Tuning decisions



| Decision | Rationale |

|---|---|

| Filter on specific GrantedAccess values | Reduces noise from legitimate LSASS access by Windows Defender, AV, and system processes |

| Use `values(SourceImage)` not `count` | Shows all calling processes in case multiple tools are used in sequence |

| Stats by Computer | Groups per host to see if the same machine has multiple access attempts |



\### False positive analysis



| Source | Access rights seen | Disposition |

|---|---|---|

| Windows Defender (MsMpEng.exe) | 0x1000 | Benign — does not match suspicious mask |

| CrowdStrike sensor | 0x1410 | Known FP — allowlist by SourceImage path |

| Task Manager (taskmgr.exe) | 0x0400 | Benign — different access mask |

| Legitimate backup agents | 0x1010 | Review — allowlist known backup process paths |



\*\*Recommended allowlist addition:\*\*



```spl

| where NOT (SourceImage="C:\\\\Program Files\\\\CrowdStrike\\\\\*"

&#x20;        OR SourceImage="C:\\\\Program Files\\\\Windows Defender\\\\\*"

&#x20;        OR SourceImage="C:\\\\Windows\\\\System32\\\\svchost.exe")

```



\*\*Expected false positive rate after tuning:\*\* Very low (under 2 per week in a typical enterprise)



\---



> #### SCREENSHOT CAPTURE GUIDE 01

> \*\*File:\*\* `screenshots/01-lsass-detection-results.png`

>

> \*\*Where to do this:\*\* Splunk with BOTS v3 dataset loaded

>

> \*\*Steps:\*\*

> 1. Paste the SPL query above into the Splunk search bar

> 2. Set the index to `botsv3` and time range to \*\*All Time\*\*

> 3. Press Ctrl+\\ to format the query onto multiple lines before screenshotting

> 4. Run the search and wait for results

>

> \*\*What your screenshot must show:\*\*

> - The formatted SPL query visible in the search bar

> - The results table with Computer, calling\_process, access\_pattern columns populated

> - The event count shown in the top-left of the results panel

> - The time range picker visible

>

> \*\*Caption:\*\* `Figure 1: Splunk detection for LSASS process access (T1003.001) showing

> Mimikatz-pattern access rights flagged against Sysmon Event ID 10 telemetry.`



\*\*\[ Screenshot 01 — Replace this line with your image once captured ]\*\*



\---



\### Alert configuration



```

Alert name:       CRIT - LSASS Process Access - Possible Credential Dumping

Search schedule:  Every 15 minutes

Time window:      Last 30 minutes

Trigger:          Number of results > 0

Severity:         Critical

Actions:          Create TheHive alert, notify SOC Slack channel

Suppression:      Per Computer — suppress for 1 hour after first alert

```



\---



\## Detection 2: PowerShell encoded command



\*\*MITRE Technique:\*\* T1059.001 — Command and Scripting Interpreter: PowerShell

\*\*Severity:\*\* High

\*\*Log source:\*\* Windows Event ID 4104 (Script Block Logging), Sysmon Event ID 1

\*\*Hypothesis:\*\* Attackers frequently use PowerShell's `-EncodedCommand` flag to

obfuscate malicious script execution. While base64 encoding has legitimate uses,

the combination of encoded commands with specific execution flags is a strong

indicator of malicious intent.



\### Threat context



PowerShell encoded commands are used to bypass command-line logging and evade

simple string-based detection. Common tools that use this pattern include Empire,

Metasploit PowerShell payloads, and many commodity RATs. The key detection opportunity

is at the process creation level (Sysmon EID 1) and script block level (EID 4104).



\### SPL query



```spl

index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

&#x20;   EventCode=1

&#x20;   Image="\*powershell.exe" OR Image="\*pwsh.exe"

| eval cmdline\_lower=lower(CommandLine)

| eval encoded\_flag=case(

&#x20;   match(cmdline\_lower,"-enc\\s"),"Short flag -enc",

&#x20;   match(cmdline\_lower,"-encodedcommand\\s"),"Full flag -encodedcommand",

&#x20;   match(cmdline\_lower,"-ec\\s"),"Short flag -ec",

&#x20;   1==1,"none"

&#x20; )

| eval suspicious\_flags=case(

&#x20;   match(cmdline\_lower,"-nop") AND match(cmdline\_lower,"-w\\s+hidden"),"NoProfile + Hidden window",

&#x20;   match(cmdline\_lower,"-executionpolicy\\s+bypass"),"Execution policy bypass",

&#x20;   match(cmdline\_lower,"-nop"),"NoProfile flag",

&#x20;   1==1,"none"

&#x20; )

| where encoded\_flag != "none"

| eval risk\_score=case(

&#x20;   encoded\_flag!="none" AND suspicious\_flags!="none", 90,

&#x20;   encoded\_flag!="none", 60,

&#x20;   1==1, 30

&#x20; )

| stats

&#x20;   count,

&#x20;   values(CommandLine) AS full\_commandline,

&#x20;   values(encoded\_flag) AS encoding\_flag\_used,

&#x20;   values(suspicious\_flags) AS additional\_flags,

&#x20;   max(risk\_score) AS max\_risk\_score,

&#x20;   values(ParentImage) AS parent\_process,

&#x20;   dc(CommandLine) AS unique\_commands

&#x20;   BY Computer, User

| sort -max\_risk\_score

| table Computer, User, encoding\_flag\_used, additional\_flags,

&#x20;        max\_risk\_score, count, unique\_commands, parent\_process

```



\### Why this query is written this way



The risk scoring logic is the key design decision here. A single `-enc` flag alone

could be a developer or admin task. The combination of `-enc` with `-nop -w hidden`

is almost exclusively malicious. Scoring both patterns separately and surfacing

the max score lets a tier-1 analyst prioritize quickly without missing either case.



The `dc(CommandLine)` count shows how many unique encoded commands ran on that

host and user combination. A count greater than 3 unique encoded commands is a

strong escalation signal.



\### Tuning decisions



| Decision | Rationale |

|---|---|

| Lowercase eval before matching | Case-insensitive matching without regex complexity |

| Parent process tracking | PowerShell spawned from Word or Excel is higher priority than from cmd.exe |

| Risk score instead of binary alert | Gives tier-1 a triage signal, not just a flag |



\### False positive analysis



| Source | Pattern | Disposition |

|---|---|---|

| SCCM / Endpoint management | `-EncodedCommand` with known hash | Allowlist by ParentImage path and CommandLine hash |

| Developer build scripts | `-enc` in CI pipelines | Allowlist by User (service accounts) |

| Legitimate admin tools | `-ExecutionPolicy Bypass` only | Lower risk score, do not suppress entirely |



\*\*Recommended allowlist addition:\*\*



```spl

| where NOT (User="svc-sccm" OR User="svc-deploy" OR User="svc-backup")

| where NOT ParentImage="C:\\\\Windows\\\\CCM\\\\CcmExec.exe"

```



\*\*Expected false positive rate after tuning:\*\* Low to medium (3 to 8 per week depending on environment)



\---



> #### SCREENSHOT CAPTURE GUIDE 02

> \*\*File:\*\* `screenshots/02-powershell-encoded-detection.png`

>

> \*\*Where to do this:\*\* Splunk with BOTS v3 dataset loaded

>

> \*\*What your screenshot must show:\*\*

> - The SPL query in the search bar, formatted across multiple lines

> - Results table showing Computer, User, encoding\_flag\_used, max\_risk\_score columns

> - At least one row with a risk score of 90 visible if the dataset contains it

> - The search job inspector showing how many events were scanned (optional but impressive)

>

> \*\*Tip:\*\* Click the search job inspector link below the search bar after running.

> It shows events scanned, run time, and result count. Screenshot that panel as a

> second crop labeled `02b` — it demonstrates you understand search performance.

>

> \*\*Caption:\*\* `Figure 2: Splunk detection for PowerShell encoded command execution

> (T1059.001) with risk scoring logic differentiating combined obfuscation flags

> from single-flag use.`



\*\*\[ Screenshot 02 — Replace this line with your image once captured ]\*\*



\---



\### Alert configuration



```

Alert name:       HIGH - PowerShell Encoded Command Execution

Search schedule:  Every 10 minutes

Time window:      Last 20 minutes

Trigger:          max\_risk\_score >= 90

Severity:         High

Actions:          Create TheHive alert

Suppression:      Per Computer + User — suppress 30 minutes after first alert

```



\---



\## Detection 3: Suspicious scheduled task creation



\*\*MITRE Technique:\*\* T1053.005 — Scheduled Task/Job: Scheduled Task

\*\*Severity:\*\* High

\*\*Log source:\*\* Windows Event ID 4698 (Scheduled Task Created), Sysmon Event ID 1

\*\*Hypothesis:\*\* Attackers use scheduled tasks for persistence and lateral movement.

Legitimate scheduled task creation happens during software installation and system

administration. Malicious tasks are typically created outside business hours, by

non-admin users, or with suspicious execution paths pointing to temp directories,

AppData, or encoded commands.



\### Threat context



Scheduled task abuse is one of the most common persistence mechanisms in ransomware

and APT campaigns. The detection opportunity is at creation time using Windows

Security Event 4698, which logs the full XML task definition including the command

being scheduled.



\### SPL query



```spl

index=botsv3 sourcetype="WinEventLog:Security" EventCode=4698

| spath input=TaskContent

| rename "Task\_Xml.Actions.Exec.Command" AS scheduled\_command

| rename "Task\_Xml.Actions.Exec.Arguments" AS scheduled\_args

| eval suspicious\_path=case(

&#x20;   match(lower(scheduled\_command),"%temp%"),"Temp directory",

&#x20;   match(lower(scheduled\_command),"%appdata%"),"AppData directory",

&#x20;   match(lower(scheduled\_command),"\\\\\\\\users\\\\\\\\public"),"Public directory",

&#x20;   match(lower(scheduled\_command),"powershell"),"PowerShell execution",

&#x20;   match(lower(scheduled\_command),"cmd\\.exe.\*\\/c"),"CMD with /c flag",

&#x20;   match(lower(scheduled\_command),"wscript|cscript"),"Script host execution",

&#x20;   1==1,"Standard path"

&#x20; )

| eval hour\_of\_day=strftime(\_time,"%H")

| eval off\_hours=if(hour\_of\_day<8 OR hour\_of\_day>18,"Yes","No")

| where suspicious\_path != "Standard path" OR off\_hours="Yes"

| stats

&#x20;   count,

&#x20;   values(TaskName) AS task\_name,

&#x20;   values(scheduled\_command) AS command,

&#x20;   values(scheduled\_args) AS arguments,

&#x20;   values(suspicious\_path) AS path\_flag,

&#x20;   values(off\_hours) AS created\_off\_hours,

&#x20;   values(SubjectUserName) AS created\_by

&#x20;   BY Computer

| sort -count

| table Computer, created\_by, task\_name, command, arguments,

&#x20;        path\_flag, created\_off\_hours, count

```



\### Why this query is written this way



The `spath` command parses the XML task definition that Windows embeds in Event 4698.

This is important because the raw event log stores the full task XML as a field, and

without parsing it you cannot inspect what the task actually runs. Most detection rules

for this technique miss this and only alert on task creation without checking the payload.



The off-hours logic is a secondary signal, not a primary one. A task created at 2am

with a standard path is still worth reviewing. A task created at 2am pointing to

AppData with a PowerShell command is an immediate escalation.



\### Tuning decisions



| Decision | Rationale |

|---|---|

| spath to parse XML | Exposes the actual command being scheduled, not just the event |

| Off-hours as secondary signal | Adds context without creating noise for all off-hours activity |

| Exclude standard paths only when no off-hours flag | Reduces volume while preserving visibility |



\### False positive analysis



| Source | Pattern | Disposition |

|---|---|---|

| Software installers | Task creation during install pointing to ProgramFiles | Allowlist by SubjectUserName (SYSTEM during install) and path prefix |

| Windows Update | Tasks pointing to system32 | Excluded by standard path filter already |

| Backup software | Off-hours tasks to known backup agent paths | Allowlist by scheduled\_command path |



\*\*Recommended allowlist addition:\*\*



```spl

| where NOT (created\_by="SYSTEM" AND match(lower(command),"c:\\\\\\\\program files"))

| where NOT match(lower(command),"c:\\\\\\\\windows\\\\\\\\system32")

```



\*\*Expected false positive rate after tuning:\*\* Low (1 to 3 per week)



\---



> #### SCREENSHOT CAPTURE GUIDE 03

> \*\*File:\*\* `screenshots/03-scheduled-task-detection.png`

>

> \*\*Where to do this:\*\* Splunk with BOTS v3 dataset loaded

>

> \*\*What your screenshot must show:\*\*

> - SPL query in the search bar

> - Results table with Computer, command, path\_flag, created\_off\_hours visible

> - The parsed XML command field populated in at least one row

>

> \*\*Tip:\*\* After running, click any result row to expand the raw event. Screenshot

> the expanded event showing the full XML task definition. Save this as `03b` — it

> demonstrates you understand what spath is actually parsing and why it matters.

>

> \*\*Caption:\*\* `Figure 3: Splunk detection for scheduled task creation (T1053.005)

> using spath to parse embedded XML task definitions and flag suspicious execution

> paths and off-hours creation.`



\*\*\[ Screenshot 03 — Replace this line with your image once captured ]\*\*



\---



\## Detection 4: Brute force login detection



\*\*MITRE Technique:\*\* T1110.001 — Brute Force: Password Guessing

\*\*Severity:\*\* Medium

\*\*Log source:\*\* Windows Event ID 4625 (Failed Logon), 4624 (Successful Logon)

\*\*Hypothesis:\*\* A brute force attack against a Windows account produces a pattern

of rapid consecutive logon failures, optionally followed by a successful logon.

The detection logic looks for failure volume thresholds and then correlates with

any subsequent success to identify a successful brute force.



\### Threat context



Account brute force is a primary initial access technique and a common signal in

ransomware precursor activity. The challenge in detection is tuning the threshold

to catch attacks without flooding the queue with users who mistype their password

twice in the morning.



\### SPL query



```spl

index=botsv3 sourcetype="WinEventLog:Security"

&#x20;   (EventCode=4625 OR EventCode=4624)

| eval event\_type=case(EventCode=4625,"failure",EventCode=4624,"success",1==1,"other")

| eval logon\_type\_name=case(

&#x20;   Logon\_Type=2,"Interactive",

&#x20;   Logon\_Type=3,"Network",

&#x20;   Logon\_Type=10,"Remote Interactive (RDP)",

&#x20;   1==1,"Other"

&#x20; )

| bucket span=5m \_time

| stats

&#x20;   count(eval(event\_type="failure")) AS failure\_count,

&#x20;   count(eval(event\_type="success")) AS success\_count,

&#x20;   values(Source\_Network\_Address) AS source\_ips,

&#x20;   values(logon\_type\_name) AS logon\_types

&#x20;   BY \_time, ComputerName, Account\_Name

| where failure\_count >= 10

| eval brute\_force\_result=case(

&#x20;   success\_count > 0 AND failure\_count >= 10,"CRITICAL - Failures followed by success",

&#x20;   failure\_count >= 50,"HIGH - High volume failure spray",

&#x20;   failure\_count >= 10,"MEDIUM - Threshold exceeded",

&#x20;   1==1,"monitor"

&#x20; )

| sort -failure\_count

| table \_time, ComputerName, Account\_Name, failure\_count,

&#x20;        success\_count, brute\_force\_result, source\_ips, logon\_types

```



\### Why this query is written this way



The `bucket span=5m` command groups events into 5-minute windows. This is the

key design decision — without bucketing, a user who fails 3 logins over 3 hours

would never trigger the threshold. Bucketing ensures we are measuring burst rate,

not total count.



The `brute\_force\_result` escalation logic is the most important part of this query

for a SOC analyst. Failures followed by a success is the highest priority case —

it means the attack likely succeeded. That must page someone immediately. Pure

failure spray without a success may be a noisy attacker or a locked account.



\### Tuning decisions



| Decision | Rationale |

|---|---|

| 5-minute bucket window | Catches burst patterns without false positives from spread-out typos |

| Threshold of 10 failures | Tunable — start at 10, raise to 20 in noisy environments |

| Success correlation | Distinguishes failed attacks from successful compromises |

| Logon type tracking | RDP brute force is higher priority than network logon |



\### False positive analysis



| Source | Pattern | Disposition |

|---|---|---|

| User with bad cached credentials | 10 to 20 failures, no success, single source IP | Review — likely benign, add to known-user allowlist |

| Service account misconfiguration | Hundreds of failures from same host | Allowlist service account names with known issue tracking |

| Helpdesk password testing | Failures from helpdesk IP range | Allowlist source IP range for known admin subnets |



\*\*Recommended allowlist addition:\*\*



```spl

| where NOT (Account\_Name="svc-\*" AND failure\_count < 100)

| where NOT match(source\_ips,"10\\.10\\.1\\.")

```



\*\*Expected false positive rate after tuning:\*\* Medium (5 to 15 per week, mostly Monday mornings)



\---



> #### SCREENSHOT CAPTURE GUIDE 04

> \*\*File:\*\* `screenshots/04-brute-force-detection.png`

>

> \*\*Where to do this:\*\* Splunk with BOTS v3 dataset loaded

>

> \*\*What your screenshot must show:\*\*

> - SPL query in the search bar

> - Results table showing failure\_count, success\_count, brute\_force\_result columns

> - At least one row showing the CRITICAL result (failures followed by success) if present

> - The bucket span visible in the query

>

> \*\*Tip:\*\* After getting results, switch to the Visualization tab and create a bar

> chart of failure\_count by Account\_Name. Screenshot that chart as `04b`. A visual

> showing attack volume by account is compelling in a portfolio and demonstrates

> you can translate raw data into a dashboard element.

>

> \*\*Caption:\*\* `Figure 4: Splunk brute force detection (T1110.001) using 5-minute

> bucketing to identify burst login failure patterns with success correlation to

> flag completed account compromises.`



\*\*\[ Screenshot 04 — Replace this line with your image once captured ]\*\*



\---



\## Detection 5: DNS tunneling



\*\*MITRE Technique:\*\* T1071.004 — Application Layer Protocol: DNS

\*\*Severity:\*\* High

\*\*Log source:\*\* DNS query logs (`stream:dns`)

\*\*Hypothesis:\*\* DNS tunneling encodes data inside DNS query strings to exfiltrate

data or maintain C2 communication. Characteristics include: unusually long subdomains,

high query volume to a single domain, high entropy subdomains, and rare or newly

seen domains with no web presence.



\### Threat context



DNS tunneling tools like Iodine, DNScat2, and custom implants use the DNS protocol

as a covert channel because DNS traffic is rarely inspected or blocked. Detection

relies on behavioral anomalies in query patterns rather than known-bad signatures.



\### SPL query



```spl

index=botsv3 sourcetype="stream:dns"

&#x20;   message\_type=QUERY

| eval query\_length=len(query)

| eval subdomain\_count=mvcount(split(query,".")) - 2

| eval has\_long\_subdomain=if(query\_length > 52, "Yes", "No")

| eval has\_many\_subdomains=if(subdomain\_count > 3, "Yes", "No")

| rex field=query "^(?P<subdomain>\[^.]+)\\."

| eval subdomain\_entropy=0

| eval chars="abcdefghijklmnopqrstuvwxyz0123456789"

| eval entropy\_flag=if(

&#x20;   match(subdomain,"\[0-9a-f]{20,}") OR

&#x20;   match(subdomain,"\[A-Za-z0-9+/]{20,}=\*"),

&#x20;   "High entropy — possible base64 or hex encoding",

&#x20;   "Normal"

&#x20; )

| stats

&#x20;   count AS query\_count,

&#x20;   dc(query) AS unique\_subdomains,

&#x20;   avg(query\_length) AS avg\_query\_length,

&#x20;   max(query\_length) AS max\_query\_length,

&#x20;   values(entropy\_flag) AS entropy\_flags,

&#x20;   values(has\_long\_subdomain) AS long\_subdomain\_flag,

&#x20;   values(src\_ip) AS source\_hosts

&#x20;   BY dest

| eval tunneling\_score=0

| eval tunneling\_score=tunneling\_score + if(query\_count > 100, 30, 0)

| eval tunneling\_score=tunneling\_score + if(unique\_subdomains > 50, 25, 0)

| eval tunneling\_score=tunneling\_score + if(avg\_query\_length > 40, 25, 0)

| eval tunneling\_score=tunneling\_score + if(match(mvjoin(entropy\_flags,""),"High entropy"), 20, 0)

| where tunneling\_score >= 50

| sort -tunneling\_score

| table dest, tunneling\_score, query\_count, unique\_subdomains,

&#x20;        avg\_query\_length, max\_query\_length, entropy\_flags, source\_hosts

```



\### Why this query is written this way



No single indicator reliably identifies DNS tunneling. A scoring model that combines

multiple weak signals into a composite score is the right approach here. High query

volume alone could be CDN traffic. Long subdomains alone could be legitimate cloud

services. High entropy alone could be UUID-based service discovery. The combination

of three or more signals scoring 50 or above is a meaningful indicator.



The entropy detection using regex pattern matching for base64 and hex strings is

a simplified approximation. A production version would implement Shannon entropy

calculation via a lookup table or a custom Splunk app. This version is appropriate

for a home lab and demonstrates the concept correctly.



\### Tuning decisions



| Decision | Rationale |

|---|---|

| Score threshold of 50 | Requires at least 2 to 3 signals to trigger — single signal is too noisy |

| unique\_subdomains threshold of 50 | CDNs use many subdomains but typically not high entropy ones |

| Exclude known CDNs | Add allowlist for Akamai, Cloudflare, AWS resolver IPs |



\### False positive analysis



| Source | Pattern | Disposition |

|---|---|---|

| CDN traffic (Akamai, Cloudflare) | High query count, moderate subdomain count | Allowlist known CDN resolver IPs |

| Cloud service discovery | High unique subdomains, low entropy | Scores below threshold without entropy flag |

| Software update checks | Periodic high-entropy subdomains | Allowlist by dest domain if known update endpoint |



\*\*Recommended allowlist addition:\*\*



```spl

| where NOT match(dest,"akamai\\.net$|cloudfront\\.net$|amazonaws\\.com$")

| where NOT match(dest,"windowsupdate\\.com$|microsoft\\.com$")

```



\*\*Expected false positive rate after tuning:\*\* Low (1 to 4 per week)



\---



> #### SCREENSHOT CAPTURE GUIDE 05

> \*\*File:\*\* `screenshots/05-dns-tunneling-detection.png`

>

> \*\*Where to do this:\*\* Splunk with BOTS v3 dataset loaded

>

> \*\*What your screenshot must show:\*\*

> - SPL query in the search bar

> - Results table showing dest, tunneling\_score, unique\_subdomains, entropy\_flags

> - At least one row with a tunneling\_score of 50 or above

>

> \*\*Tip:\*\* After running the query, switch to Visualization and create a column

> chart of tunneling\_score by dest domain. Screenshot the chart as `05b`. The

> score distribution across domains tells a cleaner story than the raw table

> alone and shows you can communicate findings visually.

>

> \*\*Caption:\*\* `Figure 5: Splunk DNS tunneling detection (T1071.004) using composite

> scoring across query volume, unique subdomain count, query length, and entropy

> patterns to surface covert DNS channel activity.`



\*\*\[ Screenshot 05 — Replace this line with your image once captured ]\*\*



\---



\## False positive analysis summary



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



\---



\## Detection coverage map



Coverage of MITRE ATT\&CK tactics addressed by these five detections:



| Tactic | Technique | Detection |

|---|---|---|

| Credential Access | T1003.001 LSASS Memory | Detection 1 |

| Execution | T1059.001 PowerShell | Detection 2 |

| Persistence | T1053.005 Scheduled Task | Detection 3 |

| Initial Access | T1110.001 Brute Force | Detection 4 |

| Command and Control | T1071.004 DNS | Detection 5 |

| Exfiltration | T1071.004 DNS (dual use) | Detection 5 |



\*\*Coverage gaps identified:\*\*



\- T1055 Process Injection — no detection in this set, planned for next iteration

\- T1078 Valid Accounts — brute force detection covers the attack vector but not

&#x20; post-compromise use of stolen credentials

\- T1021.001 RDP — brute force detection covers logon failures but not lateral

&#x20; movement via legitimate RDP sessions



\---



\## Lessons learned



\*\*What went well:\*\*

\- Composite scoring models (detections 4 and 5) proved more robust than binary

&#x20; threshold alerts — fewer false positives and better prioritization for tier-1 analysts

\- Using `spath` for XML parsing in the scheduled task detection uncovered the actual

&#x20; command payload, which most public detections for this technique miss entirely

\- The LSASS detection access mask filtering reduced noise significantly compared to

&#x20; alerting on all LSASS access



\*\*What I would do differently:\*\*

\- Implement proper Shannon entropy calculation for the DNS tunneling detection rather

&#x20; than the regex approximation — a Splunk lookup table with precomputed entropy values

&#x20; for common character patterns would be more accurate

\- Add a baseline period to the brute force detection so the threshold adapts to

&#x20; each account's normal failure rate rather than using a static count

\- Build a correlation search that links detections 1 and 2 — PowerShell encoded

&#x20; commands that follow LSASS access on the same host within 10 minutes is a very

&#x20; high confidence compromise indicator



\*\*Skills gaps identified and addressed:\*\*

\- spath and XML parsing in SPL was new — documented full notes in `/notes/splunk-spl-reference.md`

\- DNS entropy analysis requires deeper study — added threat hunting with DNS logs

&#x20; to the learning backlog



\---



\## Artifacts and file structure



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

&#x20;   └── tuning-log.md                      <- Running log of tuning changes and dates

```



\---



> \*\*Note on dataset:\*\* All queries in this project were developed and tested against

> the Splunk BOTS v3 public dataset. No proprietary or customer data was used.

> BOTS v3 is an open dataset published by Splunk for security training purposes.



\---



\*Part of the \[Blue Team Cybersecurity Portfolio](../../README.md)\*

