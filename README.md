# soc-triage

A Claude Skill that runs tier-1/tier-2 triage reasoning over a single security
alert and produces an analyst handoff.

## What it does

Takes a raw alert from AWS, EDR, CSPM, or SaaS identity and produces one
artifact: a handoff document with a verdict, separately scored confidence and
severity, competing benign and malicious explanations, and a prioritized
evidence-request plan.

## Reason-only by design

The skill has no credentials and queries nothing. It cannot confirm a verdict,
and it says so.

That constraint is the point. Most alert-triage automation produces a confident
verdict from data it never verified. This produces a structured, cited
assessment and hands the analyst a prioritized evidence plan instead — naming
the log source, the query, the time window, and what each answer would change.
The evidence-request section is the primary output, not a fallback.

## Structure

```
soc-triage/
├── SKILL.md                       # workflow, five-question frame, filling rules, guardrails
├── references/
│   ├── verdict-rubric.md          # verdict, confidence, severity definitions
│   ├── aws-identity.md            # GuardDuty / CloudTrail / STS / S3
│   ├── edr.md                     # CrowdStrike, Defender, SentinelOne
│   ├── cspm.md                    # Wiz, Prisma, Orca, Security Hub
│   └── saas-identity.md           # Entra ID, Okta
└── assets/                        # worked triage output
    ├── aws_handoff.md             # GuardDuty IAM privilege escalation
    └── oauth_handoff.md           # Entra ID illicit OAuth consent
```

## Status

SKILL.md is complete: workflow, the five-question frame, filling rules,
guardrails, and the reference map. The verdict rubric and all four source
reference files are written.

Each reference file carries the same sections — alert types, log sources and
fields to name, time windows, telemetry that is not on by default, what
containment clears and what it leaves, common false positives, hypothesis
clauses, and severity — so the skill can rely on consistent structure whatever
the source class.

Outstanding: a blank output template at `assets/handoff.md`, referenced by
workflow step 6 and not yet written. Until it exists the two worked examples
define the section order.

The output structure has been stress-tested against two structurally different
alerts — a GuardDuty IAM privilege-escalation sequence and an Entra ID illicit
OAuth consent grant — both under `assets/`.

## Design notes

Three guardrails drive most of the output quality:

- **Containment does not clear persistence.** Terminating an instance does not
  delete a key created from it; a password reset does not invalidate an OAuth
  refresh token granted with `offline_access`.
- **Absent telemetry is not a negative finding.** S3 object-level events are
  off by default. A null result is unresolved, not "no activity."
- **A hypothesis you cannot query is not a hypothesis.** Every "Confirmed if"
  clause names a log source, a field, and a value. If the clause would fit a
  different alert of the same type, it is a category and gets rewritten.