# Security Risk Assessment Report

**Riverside Family Health Clinic (Fictional Organization)**

A NIST Risk Management Framework (SP 800-37 Rev. 2) assessment, completed as part of my GRC portfolio.

📄 [Download the full report (Word document)](./Riverside-Clinic-Risk-Assessment-Report.docx) | 📊 [Risk Register workbook](./Riverside-Clinic-Risk-Assessment.xlsx)

---

## 1. Prepare

I built this assessment around Riverside Family Health Clinic, a fictional outpatient clinic with about 60 employees. Since it's a healthcare provider, it falls under HIPAA and handles Protected Health Information (PHI) for patients, which shaped a lot of the risk decisions below.

My goal was to identify and evaluate risks to the confidentiality, integrity, and availability of patient data and clinic operations, then give leadership a clear basis for deciding what to fix and in what order.

This report is written for clinic leadership and the board, since they're the ones who'd ultimately sign off on funding fixes or accepting risk.

I scoped the assessment to five systems a clinic this size would realistically run day to day:
- Electronic Health Records (EHR) system
- Front-desk scheduling system
- Employee laptops
- On-site server room
- Firewall / network perimeter

---

## 2. Categorize

Before I could assess any risk, I needed to understand how much each system actually matters if something goes wrong. I rated each one for Confidentiality, Integrity, and Availability (CIA) impact as Low, Moderate, or High, using a NIST SP 800-60 style approach.

| System | Confidentiality | Integrity | Availability | Why |
|---|---|---|---|---|
| EHR System | High | High | Moderate | Holds PHI for every patient, so a leak or corruption is a direct HIPAA violation. Rated Moderate for availability since the clinic could fall back to paper charts for a short stretch if it went down. |
| Front-desk Scheduling | Moderate | Moderate | Moderate | Holds patient names and appointment details. Less sensitive than the EHR, and if something breaks here it's inconvenient but recoverable. |
| Employee Laptops | High | Moderate | Low | Staff use these to access PHI, so a lost or stolen laptop is a real exposure risk. Losing one laptop doesn't take down clinic operations, hence the Low availability rating. |
| On-site Server Room | High | High | High | This is where the core infrastructure lives. Physical access here could hit confidentiality, integrity, and availability all at once. |
| Firewall / Network | Moderate | High | High | Every system's traffic runs through here. An outage or compromise doesn't expose data directly, but it can take down or corrupt everything connected to it. |

---

## 3. Select

With the impact levels set, I picked a baseline of controls from the NIST SP 800-53 catalog, keeping the list realistic for what a small clinic could actually implement rather than pulling the entire catalog.

| Control Family | What This Looks Like Here | Related System(s) |
|---|---|---|
| Access Control (AC) | Give every EHR and scheduling user their own login, tied to their role. No shared accounts. | EHR, Scheduling |
| Audit and Accountability (AU) | Log EHR access and login attempts, and review the logs periodically. | EHR System |
| Awareness and Training (AT) | Run HIPAA security awareness training for all staff, at least once a year. | Organization-wide |
| System and Communications Protection (SC) | Encrypt PHI both at rest and in transit. | Laptops, EHR |
| Contingency Planning (CP) | Write and test a backup and disaster recovery plan. | EHR, Server Room |
| Physical and Environmental Protection (PE) | Add badge or lock-based access control to the server room. | Server Room |
| System and Information Integrity (SI) | Keep the firewall firmware current with vendor patches. | Firewall / Network |

---

## 4. Assess

From there, I walked through the environment and identified seven specific findings across the five systems in scope. I scored each one using a simple Likelihood x Impact matrix (1-3 each), so a Risk Score of 1-2 is Low, 3-5 is Medium, and 6-9 is High. Full scoring detail and formulas live in the companion Risk Register workbook (`Riverside-Clinic-Risk-Assessment.xlsx`).

| ID | Finding | System | Likelihood | Impact | Rating | Recommended Control |
|---|---|---|---|---|---|---|
| RA-01 | No MFA enabled for remote access to the EHR system | EHR System | High | High | High | Enable multi-factor authentication (authenticator app or hardware token) for all remote and VPN access to the EHR system. |
| RA-02 | Employee laptops are not encrypted at rest | Employee Laptops | Medium | High | Medium | Turn on full-disk encryption (e.g., BitLocker or FileVault) on every laptop and enforce it through IT policy. |
| RA-03 | No formal HIPAA security awareness training program | Organization-wide | High | Medium | Medium | Stand up a mandatory annual HIPAA security awareness training program, with completion tracked per employee. |
| RA-04 | Server room lacks physical access controls | Server Room | Medium | High | Medium | Install a badge or keyed lock on the server room door and keep an access log. |
| RA-05 | No documented backup or disaster recovery plan | EHR / Server Room | Medium | High | Medium | Document a formal backup and disaster recovery plan, including backup frequency, offsite/cloud storage, and recovery time targets. |
| RA-06 | Front-desk staff share a single login | Scheduling System | High | Medium | Medium | Issue each front-desk employee their own login and retire the shared account. |
| RA-07 | Firewall firmware has not been updated in 12+ months | Firewall / Network | Medium | Medium | Medium | Set a recurring patch schedule (at least quarterly, or on vendor release) for firewall firmware updates. |

---

## 5. Authorize

Every finding here gets a Mitigate recommendation, since PHI and HIPAA obligations don't leave much room for accepting these risks as-is:

- **RA-01:** MFA closes off one of the easiest paths an attacker has into PHI, compromised credentials.
- **RA-02:** Encryption means a lost or stolen laptop doesn't automatically become a data breach.
- **RA-03:** Untrained staff are one of the most common ways phishing and social engineering succeed.
- **RA-04:** Without any barrier to entry, anyone who gets inside the building can walk into the server room.
- **RA-05:** No backup plan means ransomware or a hardware failure could wipe out patient data for good.
- **RA-06:** Shared logins make it impossible to know who actually did what.
- **RA-07:** Old firmware can carry known, unpatched vulnerabilities that are exploitable from outside the network.

**My authorization decision:** with one High-rated finding (RA-01) and six Medium-rated findings still open, I wouldn't recommend authorizing this environment to operate as-is. RA-01 should be fixed first, since it has the broadest exposure, remote attackers can attempt it from anywhere, and it ties directly to how ransomware incidents typically start in healthcare. The remaining Medium findings should follow on a defined timeline before I'd sign off on full authorization.

---

## 6. Monitor

Fixing these findings is only half the job. Here's how I'd keep an eye on things going forward:

- **Access Reviews:** Check EHR and scheduling system access quarterly against who's actually still on staff.
- **Risk Reassessment:** Redo this assessment every year, or sooner if something major changes (new system, new vendor, an incident).
- **Patch Management:** Keep firewall and server updates on a set schedule and track anything that gets skipped.
- **Log Review:** Check EHR access logs periodically for anything that looks off.
- **Training Refresh:** Repeat HIPAA training every year and for anyone newly hired.
- **Backup Testing:** Actually test restoring from backup on a regular basis, not just assume it works.

---

## References

- NIST SP 800-37 Rev. 2, *Risk Management Framework for Information Systems and Organizations*
- NIST SP 800-53, *Security and Privacy Controls for Information Systems and Organizations*
- NIST SP 800-60, *Guide for Mapping Types of Information and Information Systems to Security Categories*

> Heads up: I referenced NIST publication titles and structure here as general guidance. If you're using this for anything beyond a portfolio project, confirm the current control numbering and text directly at [nist.gov](https://www.nist.gov).
