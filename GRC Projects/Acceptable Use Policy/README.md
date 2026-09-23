# Acceptable Use Policy (ISO/IEC 27001:2022)

## Project Overview

For this project I wrote a formal Acceptable Use Policy (AUP) for an IT company and aligned every requirement to ISO/IEC 27001:2022 Annex A. I built it as a reusable template, using placeholders like `[Organization Name]` so any IT services company could adopt it.

📄 **Read the full policy here:** [acceptable-use-policy.md](acceptable-use-policy.md)

![AUP title block](screenshots/03-aup-title-block-rendered.png)

## Why I Built This

An AUP is usually the first security policy a new hire signs, so it has to be clear to everyone, not only the security team. I wanted to show I can:

- Turn security controls into plain rules that any employee can follow
- Write for the specific risks of an IT company, where staff often have administrator access, source code, and access to customer systems
- Tie every rule back to a recognized standard so it holds up in an audit

## Why I Chose ISO/IEC 27001:2022

ISO/IEC 27001:2022 is an international standard for information security management, and its Annex A includes a control written specifically for this topic: **A.5.10 Acceptable use of information and other associated assets**. That gave my policy a direct anchor. I then mapped the rest of my rules to related Annex A controls covering authentication, endpoint devices, remote working, and more.

![ISO/IEC 27001:2022](screenshots/01-iso-27001-2022-official-page.png)

## How I Built It

1. **Identified the anchor control.** I started with A.5.10 because it is the control an auditor would check first for an AUP.
2. **Thought about what makes an IT company different.** Most AUP templates are written for general office staff. I added sections for privileged access, customer data, and generative AI tools, since those are real risks for IT workers.
3. **Wrote each rule in plain language.** I used "must" for every requirement so there is no confusion about what is optional.
4. **Numbered every rule (AUP-01 to AUP-34)** so each one can be tracked, audited, and mapped.
5. **Mapped every rule to an Annex A control** in Appendix A.
6. **Added an acknowledgment form** in Appendix B, since an AUP only works if people sign that they have read it.

![Project folder on GitHub](screenshots/02-github-project-folder.png)

## What the Policy Covers

| Section | What It Does |
|---|---|
| Purpose and Scope | Explains why the policy exists and who and what it covers, including customer systems and personal devices |
| Roles and Responsibilities | Assigns ownership from leadership to every workforce member |
| Policy Statements (AUP-01 to AUP-34) | Rules for accounts, devices, email, data handling, remote work, personal devices, privileged access, AI tools, and more |
| Prohibited Activities | A clear list of what is never allowed without written approval |
| Monitoring | Sets expectations that company assets may be monitored |
| Enforcement, Exceptions, Review | Governance rules that keep the policy enforceable and current |
| Appendix A | Maps every rule to an ISO/IEC 27001:2022 Annex A control |
| Appendix B | Employee acknowledgment form |

![Roles and Responsibilities](screenshots/04-roles-responsibilities-rendered.png)

![Prohibited Activities](screenshots/05-prohibited-activities-rendered.png)

## Standard Mapping

Every rule traces back to an Annex A control. This is the part an auditor would review first, so I made it its own appendix.

![Annex A mapping table](screenshots/06-annex-a-mapping-rendered.png)

![Acknowledgment form](screenshots/07-acknowledgment-form-rendered.png)

## Key Decisions I Made

- **Separate accounts for privileged work.** IT staff with administrator rights must use a standard account for email and browsing. This limits the damage if someone clicks a phishing link.
- **Generative AI rules.** I added a section because entering customer data or source code into an unapproved AI tool is a real data leak risk for an IT company.
- **Security testing is prohibited unless authorized in writing.** IT staff often have the skills and tools to scan networks, so the policy makes clear that doing it without approval is a violation.
- **Good-faith reporting is protected.** Staff will not be disciplined for reporting something that turns out to be harmless, because people who fear being wrong tend not to report at all.
- **Monitoring language is limited by law.** Monitoring rules vary by location, so I wrote the section to apply "to the extent permitted by applicable law" instead of guessing at specific legal requirements.

## Skills Demonstrated

- Security policy writing
- Standards alignment (ISO/IEC 27001:2022 Annex A)
- Translating technical controls into plain language for non-technical staff
- Tailoring a policy to an industry's specific risks
- Control mapping and audit readiness

## References

- ISO/IEC 27001:2022, *Information security, cybersecurity and privacy protection: Information security management systems: Requirements*. Annex A.
- ISO/IEC 27002:2022, *Information security, cybersecurity and privacy protection: Information security controls*.
