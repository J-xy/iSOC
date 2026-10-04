---
name: soc-triage
description: Triage a single security alert and produce an analyst handoff with a verdict, independently scored confidence and severity, competing benign and malicious hypotheses, and a prioritized evidence-request plan. Use whenever an alert, finding, or detection is pasted or referenced — AWS GuardDuty or CloudTrail, EDR detections (CrowdStrike, Defender, SentinelOne), CSPM findings (Wiz, Prisma, Orca, Security Hub), or SaaS identity alerts (Entra ID, Okta) — and whenever the user asks to triage, investigate, assess, scope, or write up an alert. Reason-only: it queries nothing and confirms nothing, and instead names the evidence that would resolve each hypothesis and what each answer would change.
---

# SOC Alert Triage

## What this does
One paragraph. Reason-only tier-1/tier-2 triage over a single alert from AWS,
EDR, CSPM, or SaaS identity. Output is exactly one artifact: the handoff.

## Workflow
1. Normalize — thin common core (who/what/when/source/vendor severity) plus
   an unmodified source-specific payload block.
2. Identify source class, read the matching file in references/.
3. Run the five-question frame.
4. Score verdict / confidence / severity against references/verdict-rubric.md.
5. Build evidence requests, ordered by uncertainty resolved.
6. Emit assets/handoff.md. Nothing else. No chat commentary alongside it.

## The five-question frame
Run these in order. Each one feeds a specific section of the handoff.

1. **What did the detection actually observe, and what did it infer?**
   Separate the observed field values from the vendor's characterization of
   them. "Anomalous" and "malicious" are the vendor's conclusions, not
   observations. Carry the observations forward; treat the conclusions as one
   input among several.
2. **What is the mechanism, in this alert's own identifiers?**
   Name the principal, resource, process, app, or account; the specific API,
   command, or scope; and the timestamps. If the answer is a technique name or
   a MITRE ID, it is not yet an answer.
3. **What are the competing explanations, and what would confirm each?**
   At least one benign and one malicious. Each gets a "Confirmed if" clause
   that survives the substitution test in Filling rules.
4. **What is reachable if the malicious branch is true?**
   Privilege, data, and blast radius beyond the initial entity. This scores
   severity, and it is independent of how confident you are.
5. **What is still unknown, what would resolve it, and does that telemetry
   exist?**
   Order the unknowns by how much of the verdict each one moves. For each,
   name the source and state whether it is on by default. An unknown you
   cannot query is a stated limitation, not an evidence request.

## Filling rules

### Mechanism, not category
Every claim names the specific thing that happened in this alert. A category
describes a class of alerts; a mechanism describes this one.

Apply the substitution test to every hypothesis, evidence request, and
"what would change this verdict" line: paste it into a different alert of the
same source class. If it still reads correctly, it is a category — rewrite it
until it breaks when moved.

Category: "the role performed unusual API activity."
Mechanism: "ci-deploy-role called CreateAccessKey on svc-backup at 18:43:02Z
from 10.4.11.87, then attached AdministratorAccess 38 seconds later."

The same discipline applies to containment. "Isolate the host" is a category.
"Delete the svc-backup access key created at 18:43:02Z, then detach
AdministratorAccess, then revoke the role's sessions" is a mechanism, and it is
also the only form that can be checked against what containment leaves behind.

### Citation
Every finding traces to something. Mark each statement as one of:

- **Observed** — a field value present in the alert payload. Quote the field
  and the value. This is the only category that supports a Malicious verdict.
- **Derived** — a conclusion from two or more observed values. Show the
  values it rests on, so the analyst can see it collapse if one is wrong.
- **Assumed** — everything else, including anything a person asserted, any
  vendor characterization taken at face value, and any environment fact not in
  the payload. Assumptions go in the Assumptions section, not inline as
  findings.

Never introduce an identifier that is not in the payload. If the alert does not
contain the instance's IP, the user's role, or the bucket's data
classification, that absence is itself a finding — name it as an evidence
request rather than filling the gap with a plausible value.

Vendor severity is an input, not a finding. Record it in the normalized core
and score severity independently against the rubric.

### Windows
Every evidence request carries an explicit window with a bound at each end,
written as absolute timestamps from the alert, not relative language.

- Anchor to an event in the payload, not to the alert's fire time, when the two
  differ. Detection lag is routine and often large.
- Look back far enough to cover the baseline the detection claims. When a
  finding says "not seen in 90 days," the query that tests it is 90 days.
- Look forward to now for anything that establishes whether activity is
  ongoing. An unbounded forward window is correct here; say "to now."
- For conditions rather than events, the window is the exposure window —
  introduction to remediation — which may be months. Use it even when you
  expect retention to fall short, and say that you expect it to.
- State the source's delivery lag when a null result near the alert time would
  otherwise read as absence.

### Output discipline
The handoff is the entire output. No preamble, no summary alongside it, no
offer to investigate further. Where a section has nothing to put in it, write
what is missing and why rather than deleting the section or padding it.

## Guardrails

**Containment does not clear persistence.**
Before recommending any containment action, name what it does NOT touch.
State the gap explicitly in Recommended action, then order the steps so the
persistence artifact is removed first.
Attackers routinely establish persistence that outlives the obvious response,
so an analyst who acts on the obvious step alone believes they are contained
when they are not.
Examples: terminating a compromised EC2 instance does not delete the IAM
access key created from it; a password reset does not invalidate an OAuth
refresh token granted with offline_access; killing a malicious process does
not remove the scheduled task that respawns it.

**Absent telemetry is not a negative finding.**
When an evidence request depends on optional telemetry, state the dependency
in the request. When a query returns nothing, do not treat it as a negative
finding — treat it as unresolved until collection status is confirmed.
An empty result from disabled collection is indistinguishable from an empty
result from a clean environment.
Example: S3 object-level events are not ingested by CloudTrail by default.
A request for them must say so, and a null result means unresolved, not
"no activity," until collection status is confirmed.


**Indicators are not corroboration.**
Reserve a malicious verdict for observed activity. When indicators are strong
but no activity has been observed, call it Suspicious — unresolved and name
the single evidence request that would resolve it.
An indicator describes a property of the entity; corroboration shows what it
did. Overcalling on properties alone produces confident verdicts that collapse
under the first real query.
Example: an unverified publisher, a 29-hour-old app registration, and a 03:14
consent are three indicators. None of them shows the token was ever exercised
— that requires service principal sign-in logs.

**A hypothesis you cannot query is not a hypothesis.**
Every "Confirmed if" clause names a specific log source, a specific field or
operation, and a specific value or timestamp. Test it: paste the clause into
a different alert of the same type. If it still fits, it is a category —
rewrite it.
Vague clauses give the analyst nothing to query, and the evidence requests
built on them come out empty too.
Vague: "Confirmed if email logs show malicious actions."
Specific: "Confirmed if the Exchange unified audit log shows New-InboxRule
attributed to the app's service principal after 03:13:58Z, or message trace
shows outbound mail with no corresponding Sent Items entry."

**Self-attestation is not evidence.**
Label human assertions as assumptions by default. Convert to a finding only
when an artifact supports it, and name the artifact required.
The person asserting may be the compromised account or the insider — and
contacting them before insider threat is ruled out can tip off the subject.
Example: an engineer says the sensitive IAM grant was them. That closes
nothing until there is a change ticket naming that grant, an approver, and a
timestamp preceding the activity.

**Do not tip off the subject.**
Do not contact the account holder until account compromise and insider threat
are ruled out. Once ruled out, contact is a legitimate and fast evidence
source — the gate is the ruling-out, not the contact.
If the acting party is the account holder, contact gives them time to delete
inbox rules, remove keys, or clear history before you have a record of it.
Example: on a suspicious IAM grant, pull CloudTrail and check for other
affected principals first. Ask the engineer after the log shows the activity
is isolated to their session — not before.

## Reference map

Read exactly one source file per alert, chosen at workflow step 2. Read the
rubric on every alert.

| Read | When the alert is |
| --- | --- |
| `references/verdict-rubric.md` | Always, at step 4. Defines verdict states, confidence, and severity as independent dimensions. |
| `references/aws-identity.md` | GuardDuty findings on IAM principals, CloudTrail-derived detections, STS session anomalies, S3 access alerts. |
| `references/edr.md` | Endpoint detections — CrowdStrike Falcon, Defender for Endpoint, SentinelOne, and equivalents. |
| `references/cspm.md` | Cloud posture findings — Wiz, Prisma Cloud, Orca, Defender for Cloud, Security Hub. Conditions rather than events. |
| `references/saas-identity.md` | Entra ID and Okta — risky sign-ins, OAuth consent grants, MFA anomalies, password spray, privileged role changes. |

Each source file carries the same sections: alert types, log sources and fields
to name, time windows, telemetry that is not on by default, what containment
clears and what it leaves, common false positives, hypothesis clauses, and
severity. Pull field names and log source names from the file rather than from
memory — an evidence request naming a field that does not exist is worse than
one that is vague, because the analyst will run it.

When an alert spans two classes, read both and say which one you scored
against. An instance-credential exfiltration finding is AWS identity; the host
compromise that produced it is EDR.

For the shape and depth of the output, follow the worked examples in `assets/`:
`oauth_handoff.md` (Entra illicit OAuth consent) and `aws_handoff.md`
(GuardDuty IAM privilege escalation). A blank template at `assets/handoff.md`
is referenced by workflow step 6 but is not yet written; until it is, the
examples define the section order.
