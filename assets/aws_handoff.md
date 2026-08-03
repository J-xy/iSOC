# Alert Triage Handoff

**Alert:** Anomalous IAM user in AWS · **Source:** AWS GuardDuty(CLoudTrail-derived) · **ID:** 6cb8f4e2-1a09-4d77-b3e1-92f04c8a7d5e
**Fired:** 2026-07-31T18:42:11Z UTC · **Entity:** arn:aws:sts::471829336104:assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0
**Mode:** Reason-only — no evidence retrieved. All findings derive from the alert payload.

---

## Verdict
**Call:** likely malicious/suspicious
**Confidence:** medium, since its a public facing instances, it was likely compromised by malicious user and then the user attempted to create persistence by creating access key to svc-backup account to probe resources and attach permissions, then it tried to probe data stored in production buckets(indicated by name)
**Severity:** High, admins permission policy on svc-backup role can lead to exposure of sensitive data.

## Recommended action
Terminating i-0a3f7c91e4b28d5a0 and revoking ci-deploy-role does NOT contain this. The attacker created a long-lived access key on svc-backup at 18:43:02 and attached AdministratorAccess at 18:43:40. That key is independent of the instance and the role, and it persists after both are gone.
1. delete svc-backup access key created at 18:43:02
2. detach AdministratorAccess from svc-backup
3. isolate the instance and revoke the role's session

---

## What fired and why
IAM role made an unusual API call that was not seen in prior 90 days
No scheduled pipeline execution


## Competing explanations

**Benign — {named scenario}**
Real scheduled infrastructure change. for example, this could be an ad-hoc audit request that requested visibility into the backup data.
This could also be an off-record backup that was made without sheduled change request


**Malicious — {named scenario}**
Initial access through public facing instace, then privilege escalation through IAM policy grants, then data exfiltration attempt through loosely hardened data buckets.
Source IP is instance's own IP and user agent is aws-cli, meaning that this was ran on the host instead of remotely ran via IMDS SSRF indicating this either is someone without approved access or malicious user compromising at the host level.

## Evidence requests
Ordered by how much uncertainty each item resolves.

1. cloudtrail logs on svc-backup, anything that were called after 18:43:02 could indicate malicious attempts
2.Source: cloudtrail logs. queries whether other public facing instances had similar unschduled policy grants. this resolves scope, determine whether it was a single attempt or mass compromise campaign  time window: backtrack 30 days from time of incident
3. cloudtrail logs on whether IAM roles were continuely being used outside the incident window, this resovles whether the incident is ongoing or not time window: after 2026-07-31T18:47:03Z

4.Source: cloudtrail: data enumeration attempts on S3 buckets, make sure s3 data events are enabled and look for any exfiltration attempts on probed S3 buckets time window: after 2026-07-31T18:47:03Z
5.VPC flow logs, look for it internal ec2 instances are connecting to rogue IPs and unknown hosts. time window: after 2026-07-31T18:47:03Z


## What would change this verdict
- approved breakglass or ad hoc tickets indicating the IAM grant or buckets backup actions
- No further actions done by the IAM role concludes incident is not on going
- No other instances affected confirms that this is not a mass campaign

## Assumptions
Public facing: assumed breach from outside, however, this could also be a malicious insider trying to exfiltrate data
Privilege escalation: Instance could already have the permission to assume sensitive roles. This would be a process failure

## Raw
{normalized core: who, what, when, source, vendor severity}
{source-specific payload, unmodified}