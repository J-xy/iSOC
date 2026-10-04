# AWS Identity

Read this for GuardDuty findings on IAM principals, CloudTrail-derived
detections, STS session anomalies, and S3 access alerts.

## Alert types you will see

**GuardDuty, anomaly-driven.** `PrivilegeEscalation:IAMUser/AnomalousBehavior`,
`Discovery:IAMUser/AnomalousBehavior`, `CredentialAccess:IAMUser/AnomalousBehavior`,
`Exfiltration:IAMUser/AnomalousBehavior`, `InitialAccess:IAMUser/AnomalousBehavior`,
`Impact:IAMUser/AnomalousBehavior`. These fire off a per-principal behavioral
baseline. The baseline needs roughly 7 days of history, so a principal created
last week has no meaningful baseline and the finding carries far less weight.
Check principal age before you weight "never seen before."

**GuardDuty, signature-driven.** `CredentialAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`
and `.InsideAWS`, `UnauthorizedAccess:IAMUser/MaliciousIPCaller`,
`UnauthorizedAccess:IAMUser/TorIPCaller`, `Policy:IAMUser/RootCredentialUsage`,
`Stealth:IAMUser/CloudTrailLoggingDisabled`, `Discovery:S3/MaliciousIPCaller`,
`Exfiltration:S3/ObjectRead.Unusual`. These assert a fact about the call, not a
deviation from a baseline, and are worth more confidence.

**The instance-credential discriminator.** When `userIdentity.arn` is
`assumed-role/<role>/i-0abc...`, compare `sourceIPAddress` against that
instance's own public and private IP:
- Source IP equals the instance IP → the call ran on the host. Host compromise,
  or an authorized process on the host.
- Source IP is anything else → the role's temporary credentials left the
  instance. That is credential theft, usually via SSRF against IMDSv1 or via
  code execution, and it does not require the attacker to still hold the host.
Never state one of these without checking the field. It changes containment.

## Log sources and fields to name

**CloudTrail management events** — the default source for every IAM question.
Name these fields explicitly in evidence requests:
`eventTime`, `eventName`, `eventSource`, `awsRegion`, `sourceIPAddress`,
`userAgent`, `userIdentity.type`, `userIdentity.arn`, `userIdentity.principalId`,
`userIdentity.accessKeyId`, `userIdentity.sessionContext.attributes.mfaAuthenticated`,
`userIdentity.sessionContext.sessionIssuer.arn`, `requestParameters`,
`responseElements`, `errorCode`, `errorMessage`, `readOnly`, `eventType`,
`recipientAccountId`, `tlsDetails.clientProvidedHostHeader`, `vpcEndpointId`.

**The session pivot.** `userIdentity.accessKeyId` is the strongest join key in
CloudTrail. `ASIA...` is a temporary STS credential and scopes to one session;
`AKIA...` is a long-lived IAM user key and scopes to every use of that key
until deletion. Pivot on the accessKeyId to reconstruct the full session rather
than on the ARN, which collapses many sessions together.

**IAM global events land in us-east-1.** IAM, STS (non-regional endpoints),
CloudFront, and Organizations write to `us-east-1` regardless of where the
caller was. A region-scoped query for IAM activity in the alert's region
returns nothing and that nothing means nothing.

**Other sources.** VPC flow logs (egress from a suspect instance), S3 server
access logs, ALB/CloudFront access logs (initial access vector for a public
instance), AWS Config configuration item history (what changed and when),
IAM credential report and `GetServiceLastAccessedDetails` (whether a principal
was dormant before the alert), EC2 instance metadata about IMDSv2 enforcement
(`HttpTokens`, `HttpPutResponseHopLimit`).

## Privilege escalation sequences

Recognize these as sequences. A single event in isolation is weaker than the
same event in order:

- `CreateAccessKey` on a principal other than the caller, then any use of the
  new `AKIA` key. Long-lived persistence independent of the original session.
- `AttachUserPolicy` / `AttachRolePolicy` / `PutUserPolicy` / `PutRolePolicy`
  with `AdministratorAccess` or a wildcard action.
- `CreatePolicyVersion` + `SetDefaultPolicyVersion` — escalation without
  attaching anything new, so an attach-only detection misses it.
- `UpdateAssumeRolePolicy` — adds an external account or `*` to a role trust
  policy. This is the persistence that survives deleting every principal.
- `CreateLoginProfile` / `UpdateLoginProfile` — console access on a service
  principal that never had it.
- `AddUserToGroup`, `CreateServiceLinkedRole`, `CreateRole` + `PassRole`.
- `DeactivateMFADevice`, `DeleteVirtualMFADevice`, `UpdateAccountPasswordPolicy`.
- `CreateOpenIDConnectProvider` / `CreateSAMLProvider` — a new federation trust
  mints valid principals forever and survives all principal-side cleanup.
- Anti-forensics: `StopLogging`, `DeleteTrail`, `PutEventSelectors` narrowed,
  `DeleteFlowLogs`, `LeaveOrganization`, `DisassociateKmsKey`.
- Discovery preceding all of it: `GetCallerIdentity`, `ListRoles`, `ListUsers`,
  `GetAccountAuthorizationDetails`, `ListAttachedUserPolicies`, `ListBuckets`,
  `ListSecrets` / `GetSecretValue`, `DescribeInstances`.

## Time windows

- **Is this normal for this principal:** T-90d on `userIdentity.principalId`.
  Matches GuardDuty's own baseline language and covers quarterly jobs.
- **Session reconstruction:** first `AssumeRole` for the `accessKeyId` through
  the last event on it. Do not bound this by the alert window; sessions run up
  to 12 hours.
- **Scope / campaign:** T-30d across all principals for the same API pattern
  and the same `sourceIPAddress` or ASN.
- **Ongoing activity:** T to now, same `accessKeyId` and same principal.
- **Initial access for a public workload:** T-24h to T on ALB, CloudFront, WAF,
  and VPC flow logs for the instance.
- **Delivery latency:** CloudTrail delivers to S3 in about 5 to 15 minutes.
  An empty result for the last 15 minutes is latency, not absence.

## Telemetry that is not on by default

State the dependency in the evidence request whenever you rely on these:

- **CloudTrail data events** (S3 object-level, Lambda invoke, DynamoDB) are
  off by default and cost extra. Without them there is no record of which
  objects were read. A null `GetObject` result is unresolved, not "no
  exfiltration."
- **VPC flow logs** are off by default, capture metadata only, and aggregate on
  a 1-minute or 10-minute interval, so timestamps are coarse and short
  connections may be merged.
- **S3 server access logging** is off by default and best-effort, with delivery
  delays measured in hours.
- **AWS Config** is off by default. Without it there is no configuration
  timeline for "when was this trust policy changed."
- **CloudTrail Insights**, **GuardDuty Malware/RDS/EKS/Lambda Protection**, and
  **IAM Access Analyzer** are separately enabled.
- **Console Event history** covers only 90 days and only management events;
  anything older requires a configured trail with S3 retention.
- **Organization trails.** A single-account query misses cross-account activity.
  Confirm whether the trail is org-wide before treating scope as resolved.
- **IAM last-accessed data** lags by up to 4 hours and is region- and
  service-level, not action-level.

## What containment clears and what it leaves

**Terminating the instance** ends the process and the source of new calls. It
does not delete access keys created during the session, does not detach
policies, does not undo trust policy edits, does not invalidate STS credentials
already issued (they live to expiry, up to 12 hours), and destroys volatile
memory if you did not snapshot first.

**Revoking role sessions** (an inline deny on `aws:TokenIssueTime`) invalidates
outstanding temporary credentials for that role. It does not touch long-lived
`AKIA` keys, policy attachments, or anything on a different principal.

**Deleting an access key** stops new authentication with that key. It does not
invalidate STS sessions already minted from it, and does not remove the user.

**Detaching a managed policy** does not remove inline policies, group
membership, or a permissions boundary change.

**Nothing principal-side clears resource-based policy.** A bucket policy, KMS
key policy, ECR policy, Lambda resource policy, or role trust policy that
grants an external account survives deleting every user, key, role, and
instance in the account. Check for these before calling containment complete.

**Also outlives principal cleanup:** EC2 user data, SSM documents and State
Manager associations, EventBridge scheduled rules, Lambda functions, launch
templates and AMIs baked with a backdoor, CloudFormation stacks, and new
identity providers.

## Common false positives

- **IaC and CI.** Terraform, CloudFormation, and CDK produce burst sequences of
  privileged calls in seconds. Check `userAgent` for `Terraform`,
  `aws-sdk-go`, `APN/1.0 HashiCorp`, or `cloudformation.amazonaws.com`, and
  correlate the burst to a pipeline run ID.
- **No baseline.** Anomaly findings on a principal younger than 7 days, or one
  used only quarterly.
- **Scanners.** Prowler, ScoutSuite, Wiz, Security Hub, and Config rules
  generate large `Describe*`/`List*`/`Get*` volumes. Filter `readOnly=true`.
- **Identity Center.** The assumed-role ARN rotates per session for the same
  human. Pivot on the SSO user name in `sessionContext`, not the role ARN.
- **Tor / anonymizer callers** from a corporate VPN egress or a researcher's
  exit node.
- **Authorized testing.** Check for an approved pentest window before scoring.

## Hypothesis clauses

Too generic — would fit any GuardDuty IAM finding:
> Confirmed if CloudTrail shows malicious API activity by the role.

Specific enough to query:
> Confirmed if CloudTrail in us-east-1 shows `CreateAccessKey` with
> `requestParameters.userName=svc-backup` at 18:43:02Z from
> `sourceIPAddress` 10.4.11.87, followed by `AttachUserPolicy` with
> `policyArn=arn:aws:iam::aws:policy/AdministratorAccess`, and no Jira change
> record references svc-backup in the preceding 7 days.

Benign clauses need the same treatment. Name the ticketing system, the field
that would carry the reference, and the window it must precede the activity by.

## Severity

Score the malicious branch. Escalate to High when the reached privilege is
account-wide (`AdministratorAccess`, `iam:*`, `sts:AssumeRole` into a prod
role), when the principal can read a bucket or secret holding regulated data,
or when a trust policy or federation change extends access to an external
account. Blast radius beyond the initial principal is the deciding factor, not
the vendor severity on the finding.
