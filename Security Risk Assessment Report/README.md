# Security Risk Assessment Report

**Riverside Family Health Clinic (Fictional Organization)**

Prepared using the NIST Risk Management Framework (SP 800-37 Rev. 2)

📄 [Download the full report (Word document)](./Riverside-Clinic-Risk-Assessment-Report.docx) | 📊 [Risk Register workbook](./Riverside-Clinic-Risk-Assessment.xlsx)

---

## 1. Prepare

This assessment evaluates security risk for Riverside Family Health Clinic, a fictional outpatient medical clinic with approximately 60 employees. As a healthcare provider, the clinic is subject to the Health Insurance Portability and Accountability Act (HIPAA) and handles Protected Health Information (PHI) for its patients.

**Purpose:** identify and evaluate risks to the confidentiality, integrity, and availability of patient data and clinic operations, and provide leadership with a basis for risk treatment decisions.

**Intended audience:** clinic leadership and board, for risk acceptance and remediation planning.

**Systems in Scope:**
- Electronic Health Records (EHR) system
- Front-desk scheduling system
- Employee laptops
- On-site server room
- Firewall / network perimeter

---

## 2. Categorize

Each in-scope system was rated for Confidentiality, Integrity, and Availability (CIA) impact as Low, Moderate, or High, following a NIST SP 800-60 style approach.

| System | Confidentiality | Integrity | Availability | Justification |
|---|---|---|---|---|
| EHR System | High | High | Moderate | Contains PHI for all patients; unauthorized disclosure or corruption is a direct HIPAA violation. Clinic can operate briefly on paper if unavailable. |
| Front-desk Scheduling | Moderate | Moderate | Moderate | Contains patient names and appointment data; errors disrupt operations but are recoverable. |
| Employee Laptops | High | Moderate | Low | May store or access PHI; loss or theft risks data exposure. Limited effect on overall availability. |
| On-site Server Room | High | High | High | Hosts core infrastructure; physical compromise affects all connected systems. |
| Firewall / Network | Moderate | High | High | Protects all traffic; compromise or outage affects every connected system. |

---

## 3. Select

A baseline set of controls was selected from the NIST SP 800-53 control catalog, scoped to what is realistic for a small clinic.

| Control Family | Example Control Applied | Related System(s) |
|---|---|---|
| Access Control (AC) | Unique logins and role-based access to the EHR system; no shared accounts | EHR, Scheduling |
| Audit and Accountability (AU) | Logging of EHR access and login attempts, reviewed periodically | EHR System |
| Awareness and Training (AT) | Annual HIPAA security awareness training for all staff | Organization-wide |
| System and Communications Protection (SC) | Encryption of PHI at rest and in transit | Laptops, EHR |
| Contingency Planning (CP) | Documented, tested backup and disaster recovery plan | EHR, Server Room |
| Physical and Environmental Protection (PE) | Badge or lock access control on the server room | Server Room |
| System and Information Integrity (SI) | Firewall firmware kept current with vendor patches | Firewall / Network |

---

## 4. Assess

Seven findings were identified across the five in-scope systems. Full likelihood, impact, and scoring detail (including formulas) is maintained in the companion Risk Register workbook (`Riverside-Clinic-Risk-Assessment.xlsx`).

**Scoring method:** Risk Score = Likelihood Score x Impact Score (1-3 each). Rating bands: 1-2 Low, 3-5 Medium, 6-9 High.

| ID | Finding | System | Likelihood | Impact | Rating |
|---|---|---|---|---|---|
| RA-01 | No MFA enabled for remote access to the EHR system | EHR System | High | High | High |
| RA-02 | Employee laptops are not encrypted at rest | Employee Laptops | Medium | High | Medium |
| RA-03 | No formal HIPAA security awareness training program | Organization-wide | High | Medium | Medium |
| RA-04 | Server room lacks physical access controls | Server Room | Medium | High | Medium |
| RA-05 | No documented backup or disaster recovery plan | EHR / Server Room | Medium | High | Medium |
| RA-06 | Front-desk staff share a single login | Scheduling System | High | Medium | Medium |
| RA-07 | Firewall firmware has not been updated in 12+ months | Firewall / Network | Medium | Medium | Medium |

---

## 5. Authorize

Recommended treatment for each finding, all rated **Mitigate** given the presence of PHI and HIPAA obligations:

- **RA-01:** Mitigate - MFA significantly reduces risk of unauthorized PHI access via compromised credentials.
- **RA-02:** Mitigate - Encryption protects PHI if a laptop is lost or stolen.
- **RA-03:** Mitigate - Untrained staff are a common vector for phishing and social engineering.
- **RA-04:** Mitigate - Unrestricted physical access could allow theft, tampering, or destruction of equipment.
- **RA-05:** Mitigate - Without backups, ransomware or hardware failure could cause permanent data loss.
- **RA-06:** Mitigate - Shared logins prevent accountability and accurate audit trails.
- **RA-07:** Mitigate - Outdated firmware may contain unpatched, externally exploitable vulnerabilities.

**Authorization Decision:** Given one High-rated finding (RA-01) and six Medium-rated findings, this assessment does not recommend authorizing the current environment to operate as-is. Remediation of RA-01 (MFA on EHR remote access) should be prioritized first, followed by the remaining Medium findings on a defined timeline, before full authorization is granted.

---

## 6. Monitor

- **Access Reviews:** review EHR and scheduling system access quarterly against current staff and roles.
- **Risk Reassessment:** repeat this assessment annually, or after any significant change (new system, vendor, or incident).
- **Patch Management:** apply firewall and server updates on a defined schedule and track exceptions.
- **Log Review:** periodically review EHR access logs for unusual or unauthorized activity.
- **Training Refresh:** repeat HIPAA security awareness training annually and for new hires.
- **Backup Testing:** regularly test data restoration to confirm the disaster recovery plan works as documented.

---

## References

- NIST SP 800-37 Rev. 2, *Risk Management Framework for Information Systems and Organizations*
- NIST SP 800-53, *Security and Privacy Controls for Information Systems and Organizations*
- NIST SP 800-60, *Guide for Mapping Types of Information and Information Systems to Security Categories*

> **Note:** This report references NIST publication titles and structure as general guidance. Readers should confirm current control numbering and text directly at [nist.gov](https://www.nist.gov) before relying on this document for a real compliance decision.
