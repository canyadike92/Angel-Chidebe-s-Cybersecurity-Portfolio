# Tabletop Exercise: Insider Threat / Data Exfiltration

A playbook that's never been tested is really just a guess written down nicely. This exercise runs `01-incident-response-playbook.md` against a simulated insider threat scenario to see where it actually breaks, before a real incident finds the cracks for us. The scenario itself isn't really the point. The point is what it exposed, and what changed as a result.

**Scenario type:** Insider Threat / Data Exfiltration (Section 5.2 of the playbook)
**Format:** Discussion-based tabletop, single session, played out as a timeline of injects
**Fictional organization:** Meridian Health Partners

---

## 1. Scenario Narrative

Dana, a billing department employee with legitimate access to the patient billing system, resigns with two weeks' notice. During those two weeks, Dana's account starts accessing significantly more patient records than the role normally requires, and a DLP alert fires for a large upload from Dana's workstation to a personal cloud storage account. Dana's last day is three days away.

## 2. Injects (Timeline)

| Time | Inject |
|---|---|
| Day 1, 9:14 AM | Dana submits two weeks' notice to their manager. |
| Day 3, 2:40 PM | DLP alert fires: about 4,200 patient billing records uploaded from Dana's workstation to a personal cloud storage domain that isn't on the approved vendor list. |
| Day 3, 2:55 PM | The SOC Analyst reviews the alert and confirms the destination is a personal, non-corporate cloud account. |
| Day 3, 3:10 PM | The analyst escalates. This is where the room stalls for a minute: is this Sev 2 or Sev 1? The playbook's matrix calls "suspected unauthorized access, not confirmed" a Sev 2, but this looks a lot closer to confirmed exfiltration than that. |
| Day 3, 3:20 PM | The Incident Commander gets paged. The IC's first question: can we disable Dana's account right now, given Dana is still an active employee for three more days? |
| Day 3, 3:35 PM | HR gets looped in. HR asks whether Legal needs to approve suspending an active employee's account before IT acts. |
| Day 3, 4:00 PM | The HIPAA Security Officer starts the four-factor risk assessment, but there's no template or prior example to work from. |
| Day 4, 10:00 AM | Scope review shows the 4,200 records include full patient names, dates of birth, and insurance ID numbers. No clinical notes. |

## 3. Playbook Walkthrough

Mapping the injects onto the playbook's Detect, Respond, Recover structure:

**Detect (4.1):** This part worked as designed. The DLP alert fired, and the SOC Analyst triaged it correctly, catching that the destination was non-corporate right away.

**Respond, Contain (4.2.1):** This is where the exercise found its first real gap. The playbook assumes containment authority is obvious, and in this scenario it wasn't, at all.

**Respond, Determine breach status (4.2.4):** The four-factor assessment is referenced in Section 6.1, but the playbook doesn't actually give a working template for it, so the HIPAA Security Officer ended up building one live, during the incident, which is not a great time to be building a form.

**Recover:** Never reached. The team ran out of session time still stuck in Respond, which is itself worth noting as a finding.

## 4. Gaps Identified

**1. Severity classification gap.** The Sev 1 versus Sev 2 line in Section 4.1 assumes a clean split between "confirmed" and "suspected" unauthorized access. A large, DLP-confirmed upload to a personal account sits right in between those two, and it caused a real argument in the room about which severity, and therefore which escalation path, actually applied.

**2. Containment authority gap.** The roles table in Section 3.2 never says who has the authority to disable an active employee's account before HR or Legal sign off, especially when that employee already has a known end date. This cost the exercise more than 15 minutes while the room worked out who could actually make that call.

**3. No four-factor risk assessment template.** Section 6.1 mentions the four-factor test but doesn't hand anyone a usable worksheet. The HIPAA Security Officer had to improvise the format on the spot instead of pulling up something pre-built.

**4. No defined handoff point to HR/Legal.** Section 5.2 says to coordinate with HR and Legal on insider incidents, but never says when that handoff should happen relative to technical containment. In the exercise, HR wasn't looped in until after the SOC had already escalated to the IC, and that gap cost time.

## 5. Playbook Revisions (v1.0 to v1.1)

Each gap above maps to a specific change made in `01-incident-response-playbook.md`:

| Gap | Revision |
|---|---|
| Severity classification gap | Section 4.1 now says a DLP-confirmed transfer to a non-corporate destination is treated as Sev 1 regardless of whether full data misuse is confirmed. Confirmed transfer is the trigger, not confirmed misuse. |
| Containment authority gap | Section 3.2 now gives the Incident Commander standing authority to suspend account access, not delete the account or end employment, for any account under active investigation, without waiting on HR or Legal first. HR/Legal approval is still required for actual employment action. |
| No risk assessment template | Section 6.1 now includes a four-factor risk assessment worksheet with the four questions already laid out as fillable fields, so the HIPAA Security Officer starts with a form instead of a blank page. |
| No defined HR/Legal handoff point | Section 5.2 now specifies that HR and Legal are notified in parallel with the Incident Commander at initial escalation, not afterward. Insider cases are treated as dual-track, technical and personnel, from the first minute. |

## 6. Lessons Learned Summary

The exercise didn't really show that the playbook was wrong. It showed the playbook was written for a cleaner version of an incident than the ones that actually happen. Every gap it found was in the messy middle: a severity level that assumes a neat line between "confirmed" and "suspected," and a containment step that assumes someone obviously has the authority to act when, in the moment, nobody was sure who did.

That's also the argument for why tabletop testing has to be part of an IR program and not just optional paperwork. A static playbook could pass a compliance review while still hiding a 15-minute authority gap that only shows up once you actually put people under simulated pressure.
