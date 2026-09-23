# Incident Response Playbook
**Organization:** Meridian Health Partners (fictional healthcare organization, built for portfolio purposes)
**Framework:** NIST SP 800-61 Revision 3, *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile* (April 2025)
**Regulatory Overlay:** HIPAA Privacy Rule and Breach Notification Rule (45 CFR Part 164, Subpart D)
**Document Owner:** Security Operations / GRC (fictional role, portfolio project)
**Status:** v1.1, revised after tabletop testing. Changes are marked inline as *(v1.1)*. See `02-tabletop-exercise.md` for the full gap analysis behind each change.

---

## 1. Purpose and Scope

This playbook defines how Meridian Health Partners prepares for, detects, responds to, and recovers from cybersecurity incidents involving its systems, networks, and electronic protected health information (ePHI).

A note on why this is built on Rev 3 instead of the more commonly cited Rev 2: NIST officially withdrew SP 800-61 Revision 2, the four-phase "Preparation / Detection & Analysis / Containment-Eradication-Recovery / Post-Incident Activity" model that most beginner material still references, on April 3, 2025. Revision 3 replaced it. Building on the current standard rather than the older one that's still floating around online was a deliberate choice. Source: NIST CSRC, "Incident Response" project page (https://csrc.nist.gov/projects/incident-response).

The scope covers any suspected or confirmed event that could put the confidentiality, integrity, or availability of Meridian's information systems, or the ePHI they process, at risk.

---

## 2. Framework Model: NIST SP 800-61 Rev 3

Rev 3 doesn't use a linear lifecycle. It maps incident response onto the six functions of the NIST Cybersecurity Framework (CSF) 2.0:

| Function | Role in Incident Response |
|---|---|
| **Govern** | Sets policy, roles, risk tolerance, and oversight. This is the foundation everything else depends on. |
| **Identify** | Asset inventory, risk assessment, and the Improvement category, where lessons learned get analyzed and fed back into the program. |
| **Protect** | Preventive controls (access control, encryption, training) that reduce how likely an incident is and how bad it gets. |
| **Detect** | Continuous monitoring for anomalous or malicious activity. This is where incident response actually begins. |
| **Respond** | Triage, analysis, containment, eradication, and communication, including HIPAA breach notification obligations. |
| **Recover** | Restoring systems and data, validating that restoration, and returning to normal operations. |

Govern, Identify, and Protect are ongoing risk management work, not something a responder does in the middle of an incident. They're the preparation layer everything else sits on. The part that actually plays out during a live incident is Detect, Respond, Recover, and Improvement runs continuously underneath all of it, feeding lessons learned back into the other five functions. Section 3 below covers preparation. Section 4 covers the live incident lifecycle.

---

## 3. Preparation (Govern, Identify, Protect)

### 3.1 Governance
- The Incident Response Policy is approved by executive leadership and reviewed annually.
- The HIPAA Security Officer and Privacy Officer are designated roles with defined authority to make breach determination decisions (see Section 6).
- Business Associate Agreements (BAAs) with any third party handling ePHI include incident notification obligations.

### 3.2 Roles and Responsibilities

| Role | Responsibility During an Incident |
|---|---|
| Incident Commander (IC) | Owns the response, makes containment decisions, coordinates the team |
| SOC Analyst / First Responder | Detects, triages, and escalates the incident |
| HIPAA Security Officer | Runs the four-factor risk assessment (Section 6.1) to determine whether the incident meets the definition of a reportable breach |
| HIPAA Privacy Officer | Manages individual and HHS notification if a breach is confirmed |
| Legal / Compliance | Advises on regulatory, contractual, and law enforcement questions |
| IT/Systems Owner | Executes technical containment and recovery on affected systems |
| Communications Lead | Manages internal updates and, if required, media notification |
| Executive Sponsor | Approves major decisions, like taking systems offline or public disclosure |

**Standing containment authority** *(v1.1, added after the tabletop exercise, see `02-tabletop-exercise.md`)*: The Incident Commander has standing authority to suspend account access for any account under active investigation, without waiting for HR or Legal sign-off. This is limited to suspension, not deleting the account or terminating employment. HR/Legal approval is still required before any employment action is taken.

### 3.3 Asset Inventory and Risk Assessment
Every system that stores, processes, or transmits ePHI is inventoried and classified by criticality. Meridian's annual HIPAA Security Risk Assessment identifies the threat scenarios most likely to happen (ransomware, insider misuse, cloud misconfiguration), which is what the incident-specific sections in Section 5 are built around.

### 3.4 Protective Controls
A few examples of the controls this playbook assumes are already in place:
- Role-based access control and least privilege for systems containing ePHI
- Data Loss Prevention (DLP) monitoring on egress channels like email, cloud storage, and removable media
- Multi-factor authentication on remote and cloud administrative access
- Security awareness training, including annual HIPAA training for the whole workforce
- Logging and centralized log retention that's actually sufficient to reconstruct an incident timeline, not just check a box

---

## 4. Incident Response Life Cycle (Detect, Respond, Recover)

### 4.1 Detect
1. An alert or report comes in, whether that's a SIEM/DLP alert, a help desk ticket, an employee report, or a third-party notification.
2. The SOC Analyst does initial triage: what system or data is involved, what's the suspected activity, and could ePHI be involved.
3. The analyst assigns a severity level using the matrix below and escalates to the Incident Commander at Severity 2 or higher.

**Severity Classification**

| Severity | Definition | Example |
|---|---|---|
| Sev 1, Critical | Confirmed or highly likely exposure of ePHI, or loss of availability to critical clinical systems. This also includes any DLP-confirmed transfer of PHI-containing data to a non-corporate destination, even before actual data misuse is confirmed. *(v1.1, added after tabletop exercise)* The confirmed transfer itself is the trigger, not confirmed misuse. | Ransomware encrypting EHR-adjacent systems; confirmed large-scale data exfiltration; DLP-confirmed upload of patient records to a personal cloud account |
| Sev 2, High | Suspected unauthorized access to ePHI or a system that stores it, where the transfer or access itself isn't confirmed yet | An anomalous access pattern gets flagged but nothing's confirmed transferred |
| Sev 3, Moderate | A security event with no evidence of ePHI involvement | Isolated malware on a non-clinical workstation, contained quickly |
| Sev 4, Low | Policy violation or informational event | Failed login attempts, a minor phishing report with no click-through |

### 4.2 Respond
1. **Contain.** Isolate the affected systems or accounts to stop further damage or data loss (disable the account, network-isolate the host, revoke cloud session tokens, whatever fits).
2. **Analyze.** Figure out the scope: what data, how many records, which individuals, what time window.
3. **Notify internally.** The Incident Commander briefs the HIPAA Security Officer, Privacy Officer, and Legal as soon as ePHI involvement is suspected. Don't wait for full confirmation to loop them in.
4. **Determine breach status.** The HIPAA Security Officer applies the four-factor risk assessment (Section 6.1) to determine whether this counts as a reportable breach.
5. **Eradicate.** Remove the threat, whether that's malware, unauthorized access, or malicious insider access, from the environment.
6. **External notification**, if it's required. The Privacy Officer runs the HIPAA breach notification process (Section 6).

**HR/Legal handoff timing** *(v1.1, added after tabletop exercise)*: For insider-related incidents, HR and Legal are notified in parallel with the Incident Commander at the point of initial escalation, not after technical containment has already started. These cases are dual-track from the first minute: technical and personnel at the same time, not one after the other.

### 4.3 Recover
1. Restore affected systems from clean backups, or rebuild as needed.
2. Validate the integrity of restored systems before putting them back into production.
3. Re-enable accounts and access only once the root cause has actually been addressed.
4. Keep affected systems under heightened monitoring for a defined period after recovery.

---

## 5. Incident-Specific Response Sections

### 5.1 Ransomware
**Detect:** EDR or antivirus alert, unusual file encryption activity, a ransom note, backup jobs failing unexpectedly.

**Contain:** Isolate affected hosts from the network immediately. Don't power them off if it can be helped, since that destroys volatile memory that forensics might need. Disable affected user or service accounts if compromised credentials are suspected.

**HIPAA consideration:** HHS guidance treats ePHI that's been encrypted by ransomware as presumed to have been acquired by an unauthorized party unless the four-factor risk assessment can show a low probability of compromise. In practice, that means most ransomware incidents touching ePHI systems default toward being treated as reportable breaches until proven otherwise.

**Eradicate/Recover:** Rebuild from known-clean backups. Don't restore from a backup that might itself be compromised without validating it first, and don't assume paying a ransom means data wasn't already exfiltrated.

### 5.2 Insider Threat / Data Exfiltration
**Detect:** A DLP alert on a large or unusual data transfer, an anomalous access pattern (access outside a person's role, an access spike right before a resignation or termination), or a report from a user or manager.

**Contain:** Disable account access and revoke active sessions, but preserve device and account activity logs before doing any remote wipe or account deletion.

**HIPAA consideration:** An insider accessing more PHI than their role requires can itself be a reportable breach, even without confirmed external exfiltration. The four-factor test still applies.

**Eradicate/Recover:** This is coordinated with HR and Legal on any personnel action. It's as much a human-process incident as a technical one.

### 5.3 Cloud Account Compromise
**Detect:** An impossible-travel or anomalous sign-in alert from the cloud identity provider, unauthorized MFA registration, unexpected mail forwarding rules, or unexpected cloud storage sharing changes.

**Contain:** Revoke active sessions and tokens, force a password reset, remove any unauthorized MFA devices, and review and remove unauthorized OAuth app grants.

**HIPAA consideration:** If the compromised account had access to any ePHI-containing cloud resource (email, an EHR portal, cloud storage), scope has to cover everything that account touched during the compromise window, not just what the attacker is confirmed to have looked at.

**Eradicate/Recover:** Rotate credentials for any service accounts or integrations tied to the compromised identity, and review conditional access policies for whatever gap let the compromise happen.

---

## 6. HIPAA Breach Notification Procedure

### 6.1 Four-Factor Risk Assessment (45 CFR §164.402)
An impermissible use or disclosure of PHI is presumed to be a breach unless the covered entity can show a low probability that PHI was compromised, based on assessing:
1. The nature and extent of PHI involved, meaning the types of identifiers and how likely re-identification is
2. Who the unauthorized person is, or who the PHI was disclosed to
3. Whether the PHI was actually acquired or viewed
4. How much the risk to the PHI has been mitigated

This assessment is documented and owned by the HIPAA Security Officer, in consultation with Legal.

**Four-Factor Risk Assessment Worksheet** *(v1.1, added after tabletop exercise)*

| # | Question | Findings |
|---|---|---|
| 1 | Nature and extent of PHI involved: what identifiers, and how sensitive or re-identifiable are they? | |
| 2 | Who received or could access the PHI: internal party, unknown third party, another covered entity? | |
| 3 | Was the PHI actually acquired or viewed, or only potentially exposed? | |
| 4 | How much has the risk been mitigated (data recovered/destroyed, confidentiality agreement obtained, etc.)? | |
| - | **Conclusion:** low probability of compromise (not a reportable breach), or breach confirmed, proceed to Section 6.2 | |

### 6.2 Notification Timelines
- **Individual notification:** without unreasonable delay, and no later than 60 calendar days after the breach is discovered.
- **HHS notification, 500+ individuals affected:** no later than 60 days after discovery, submitted through the HHS breach reporting portal.
- **Media notification:** required if 500 or more residents of a single state or jurisdiction are affected, on that same 60-day timeline.
- **HHS notification, fewer than 500 individuals affected:** can be logged and reported annually, no later than 60 days after the end of the calendar year in which the breach was discovered.

Source: HHS.gov, "Breach Notification Rule" (https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html).

### 6.3 Business Associate Obligations
If a business associate is the one who discovers a breach, they have to notify Meridian without unreasonable delay so Meridian can still meet its own notification clock. That obligation comes from the BAA itself, it isn't assumed.

---

## 7. Continuous Improvement

Under NIST SP 800-61 Rev 3, Improvement isn't a one-time lessons-learned meeting tacked onto the end of an incident. It's continuous, and it feeds back into Govern, Identify, Protect, Detect, Respond, and Recover the whole way through, not just after the incident is closed.

Every incident of Severity 2 or higher triggers a post-incident review that answers:
- What happened, and when?
- Were the documented procedures actually followed? If not, why not?
- What would the team do differently next time?
- What corrective actions prevent this from happening again, and who owns them?

Findings get logged in the change log below, and where they change this playbook, that results in a version update.

See `02-tabletop-exercise.md` for a worked example of this whole process, using a tabletop exercise instead of a real incident.

---

## 8. Change Log

| Version | Date | Change | Trigger |
|---|---|---|---|
| 1.0 | Baseline | Initial playbook published | Program build-out |
| 1.1 | See tabletop doc | Added the Sev 1 trigger for DLP-confirmed transfers, standing IC containment authority, the four-factor risk assessment worksheet, and parallel HR/Legal handoff timing | Section 7's continuous improvement process, applied to a simulated insider threat incident |
