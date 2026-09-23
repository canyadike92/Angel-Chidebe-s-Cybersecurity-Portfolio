# Project 3: IR Playbook - NIST-Based Incident Response Playbook + Tabletop Exercise

## What this is

A written incident response playbook for a fictional HIPAA-regulated healthcare organization, built on NIST SP 800-61 Revision 3, then tested against a simulated insider threat scenario in a tabletop exercise. The tabletop found real gaps in the first draft. Those gaps got fixed, and both the "before" (what broke) and "after" (the revised playbook) are documented here, not just the final clean version.

## Why this project

A lot of portfolio IR playbooks are static documents that read well but were never actually tested. The point of this one is the opposite: write the playbook, then prove it holds up (or doesn't) against a simulated incident, and show the iteration honestly instead of hiding it. That's closer to how real IR programs actually mature, and it gives an interviewer something to ask about beyond "did you write a document."

This project targets SOC and GRC roles on purpose, because it touches both sides of that split. The technical response steps (detect, contain, eradicate, recover) are what a SOC analyst executes. The compliance layer (HIPAA breach notification, the four-factor risk assessment, the documentation requirements) is what GRC owns.

## Files in this project

| File | What it is |
|---|---|
| `01-incident-response-playbook.md` | The playbook itself, v1.1, post-tabletop. Revisions from the tabletop are marked inline. |
| `02-tabletop-exercise.md` | The tabletop scenario, the timeline of injects, the gaps it exposed, and exactly which playbook sections changed because of it. |

## Key decisions, and why (for an interview walkthrough)

**Why NIST SP 800-61 Rev 3 instead of the more commonly referenced Rev 2 model?**
NIST withdrew Rev 2 in April 2025 and replaced it with Rev 3, which restructures incident response around the six CSF 2.0 functions instead of a linear lifecycle. A lot of online IR tutorials and templates still use the old Rev 2 four-phase language, because they just haven't been updated. Building this on Rev 3 instead was a deliberate choice, working from the current standard rather than the one that's easiest to find copies of. Source: the NIST CSRC Incident Response project page.

**Why the HIPAA overlay specifically?**
A generic IR playbook shows process knowledge. Tying it to a real regulatory framework, HIPAA's Breach Notification Rule, the four-factor risk assessment, the 60-day notification clock, shows the compliance layer that GRC and healthcare-sector SOC roles actually operate in day to day. The notification timelines and thresholds here come from HHS.gov, not from memory or assumption.

**Why an insider threat scenario for the tabletop, out of the three incident types the playbook covers?**
Insider threat is the one scenario where the technical response and the HR/Legal/personnel response have to happen at the same time, and where "who actually has the authority to act" is genuinely unclear in a way ransomware and cloud compromise usually aren't (those are more straightforward "isolate the technical asset now" calls). That ambiguity is exactly what a tabletop is supposed to surface, and it did. The exercise found a real gap in containment authority that never would have shown up just from reading the document.

**Why document the gaps instead of just publishing the clean final version?**
Because "found a gap and fixed it" is a much stronger interview answer than "wrote a playbook." The tabletop document keeps the exact timeline of where the room actually got stuck, so every revision traces back to a specific moment in the exercise instead of just being asserted after the fact.

## How to walk an interviewer through this

1. Start with the playbook's framework section and explain the Rev 2 to Rev 3 shift, and why that mattered for how the document is structured (Govern/Identify/Protect as preparation, Detect/Respond/Recover as the live lifecycle).
2. Move to the tabletop document and walk the scenario timeline, stopping at the two points where the room got stuck: severity classification, and containment authority.
3. Point back at the playbook and show the specific inline changes those two stuck points led to.
4. Close on the HIPAA section. That's the part that separates this from a generic technical IR playbook and signals GRC-relevant knowledge.

## Sources used

- NIST SP 800-61 Revision 3 overview: https://csrc.nist.gov/projects/incident-response
- HHS.gov, HIPAA Breach Notification Rule: https://www.hhs.gov/hipaa/for-professionals/breach-notification/index.html
- HHS.gov, Submitting Notice of a Breach to the Secretary: https://www.hhs.gov/hipaa/for-professionals/breach-notification/breach-reporting/index.html

## Related projects in this portfolio

Project 2 (Phishing Investigation) covers detection and analysis of a specific attack vector. This project picks up where that leaves off: once something's confirmed as an incident, this playbook governs what happens next.
