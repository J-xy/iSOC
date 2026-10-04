# Alert Triage Handoff

**Alert:** {vendor title} · **Source:** {vendor (product / detection type)} · **ID:** {alert ID}
**Fired:** {ISO-8601 UTC} · **Event time:** {earliest payload event, ISO-8601 UTC}
**Entity:** {primary principal / host / resource / account, verbatim}
**Mode:** Reason-only — no evidence retrieved. All findings derive from the alert payload.

---

## Verdict
**Call:** {Malicious | Benign | False positive | Suspicious — unresolved}
**Confidence:** {High | Medium | Low} — {the finding that sets it; for High, the finding that rules out the alternative}
**Severity:** {High | Medium | Low} — {what is reachable if the malicious branch is true}

## Recommended action
{What the obvious containment step does NOT clear, named.}
1. {Remove the persistence artifact first — exact identifier and timestamp.}
2. {...}

---

## What fired and why
{Observed field values, quoted. Vendor characterization labeled as such.}

## Competing explanations

**Benign — {named scenario in this alert's identifiers}.**
{One to three sentences.}
Confirmed if: {log source} shows {field / operation} = {value} in {window}.
Argued against by: {observed values}.

**Malicious — {named scenario in this alert's identifiers}.**
{One to three sentences.}
Confirmed if: {log source} shows {field / operation} = {value} in {window}.
Argued against by: {observed values, or "nothing in the payload"}.

## Evidence requests
Ordered by how much uncertainty each item resolves.

1. **{Imperative: what to find.}**
   Source: {log source, operation / field}. {Not on by default: {dependency}. Omit if on by default.}
   Window: {absolute start} to {absolute end | now}.
   Resolves: {which hypothesis moves, and in which direction for each answer}.

## What would change this verdict
- {Specific finding} → {new verdict / severity / containment scope}.

## Assumptions
Asserted without evidence.
- {Each assumption, including vendor characterizations and human assertions.}

## Raw
**Normalized core:** who / what / when / source / vendor severity
{source-specific payload, verbatim}
