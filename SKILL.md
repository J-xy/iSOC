---
name: soc-triage
description: <pushy — you'll draft this last, once the body exists>
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

## Filling rules
<the mechanism-vs-category discipline, citation rules, window rules>

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
Which file to read when.