# Verdict Rubric

## Verdict states
**Malicious** — observed activity confirms compromise or abuse.
Requires: Active connections to known malicious IP address
Process spawned by a parent that shouldnt spawn it, or a persistence mechanism created by a process with no change record
Service principal sign-in from a hosting ASN outside corporate ranges
key created on a dormant principal followed by a privilege attachment, with no corresponding change record
Confirmed exfiltration of data/artifacts

**Benign** — activity is real and authorized.
Requires: Confirmed tickets/messages of planned infrastructure change
confirmed sheduled IAM role/permission grants
Break glass exception of third party integration
planned data transfer and export

**False positive** — detection logic misfired; the described activity did not occur
as characterized.
Requires: Inregular but benigh IAM role grants that attributed to the wrong principal
EDR sensors misclassified a benign command line
Incorrect IP threat intel flagged malicious IP
Action: Provide the suspicious false positives verdict to analyst which triggers a detection-tuning ticket.

**Suspicious — unresolved** — Alerts that have no concrete findings, agents do not have enough evidence to make a declarative verdict
Default state when There are no actual logs supporting the verdict, and no concrete information to label the alert as either malicious/benign or false positive

## Confidence
**High** — evidence rules out the other explanation. Name the finding that did it.
**Medium** — indicators favor one explanation but the other remains viable.
**Low** —  both explanations still fit the evidence, or the deciding telemetry are inference.

Confidence and severity move independently. High severity with low confidence escalates immediately, it does noyt wait for confidence to rise.

## Severity
Impact if malicious branch is true, independent of vendor rating
**High** — Admin or org-wide privilege, sensitive or regulated data in scope, or production systmes affected. Blast radius extends beyond the initial principal
**Medium** — Scoped privilege on production, or non-sensitive data in scope. Contained to the initial principal or a limited set
**Low** —  Non-production, no sensitive data, no privilege escalation avaialble from what was reached

for CSPM findings, which are conditions rather than events, score what an attacker could reach if the condition were exploited.