# CSPM

Read this for cloud posture findings from Wiz, Prisma Cloud, Orca, Defender for
Cloud, and Security Hub.

## A CSPM finding is a condition, not an event

Every other source in this skill reports something that happened at a
timestamp. A CSPM finding reports something that is true right now. That
changes the entire frame:

- There is no "when did this happen." There is **when it was introduced**, and
  **when it was detected**, and those can be months apart.
- The finding is not evidence that anyone exploited it. It is not evidence that
  nobody did either — that requires event telemetry the finding does not
  contain.
- The default verdict for a CSPM finding with no corroborating event data is
  **Suspicious — unresolved** or a benign misconfiguration, never Malicious.
  Malicious requires observed activity against the condition.

Say this explicitly in the handoff. An analyst who reads a posture finding as
an incident will burn hours; one who reads a genuinely exploited condition as
"just a misconfiguration" will miss a breach.

## Alert types you will see

Public storage (S3 bucket, blob container, GCS bucket); security group or
firewall rule open to `0.0.0.0/0` on 22, 3389, 3306, 5432, 6379, 27017;
publicly accessible database, snapshot, or AMI; overly permissive IAM
(wildcard action or resource, trust policy admitting `*` or an unknown
external account, unused privileged principal); disabled logging (CloudTrail
off, flow logs off, audit logging off); unencrypted volume, snapshot, or
bucket; secret in environment variable, user data, or a repository; container
and host CVEs on running workloads; Kubernetes RBAC `cluster-admin` binding,
privileged pod, `hostPath` mount; IMDSv1 permitted; public Lambda function URL;
and KMS or resource policy granting `*`.

**Attack path / toxic combination findings** are the ones worth real attention.
A CVE alone is a condition. A CVE on an internet-reachable workload, with an
attached identity that holds privilege, that can reach data of consequence, is
an attack path. Score the path, and name every link in it — if you cannot name
all the links, say which one you could not verify.

## Configured exposure versus effective exposure

This is the largest false-positive class in CSPM, and the first thing to
resolve. A security group allowing `0.0.0.0/0` is only reachable if **all** of
the following hold:

1. The resource has a public IP or sits behind a public load balancer.
2. Its subnet has a route to an internet gateway.
3. The network ACL permits the traffic in both directions.
4. The security group permits it.
5. The host firewall permits it.
6. A service is actually listening on that port.

Wiz and comparable tools model most of this and will say whether the resource
is externally exposed; where the tool only reports the rule, treat exposure as
unverified and make it an evidence request rather than an assumption.

The identity-side equivalent: a permissive role only matters to the degree
something can assume it. Check the trust policy, whether any principal actually
holds `sts:AssumeRole` on it, and whether the role has been used at all.

## Log sources and fields to name

**Provenance — who introduced the condition and when.**
CloudTrail management events for the configuring API:
`AuthorizeSecurityGroupIngress`, `PutBucketPolicy`, `PutBucketAcl`,
`DeletePublicAccessBlock`, `PutPublicAccessBlock`, `ModifySnapshotAttribute`,
`ModifyImageAttribute`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`,
`UpdateAssumeRolePolicy`, `ModifyDBInstance`, `CreateFunctionUrlConfig`.
Fields: `userIdentity.arn`, `userAgent`, `sourceIPAddress`, `eventTime`,
`requestParameters`. Azure: Activity Log, `operationName` plus `caller`.
GCP: Cloud Audit Logs, `protoPayload.methodName` plus
`authenticationInfo.principalEmail`.

Also: AWS Config configuration item history, the IaC repository (git blame on
the module that owns the resource), and drift between committed IaC and the
live resource. A condition introduced by a Terraform apply from a CI role is a
different story from the same condition introduced by a human principal at
03:00 from an unrecognized IP — and the second is an incident, not a posture
finding.

**Exploitation — was the condition ever used.**
For storage: CloudTrail S3 data events, S3 server access logs, and the bucket's
own `GetObject` records. For network exposure: VPC flow logs filtered to the
resource ENI and the exposed port, ALB/NLB access logs, WAF logs. For
databases: the engine's audit log. For identity: CloudTrail on the role's
`AssumeRole` and subsequent session activity. Plus any GuardDuty or runtime
sensor finding scoped to the same resource ID.

## Time windows

The window for every exploitation question is **the exposure window** —
introduction time through remediation time — not a fixed lookback from the
alert. A bucket public since March needs a March-to-now query, and you should
say so even when you expect the log retention to fall short.

- **Provenance:** back to resource creation, or as far as Config and CloudTrail
  retention allow.
- **Exploitation:** the full exposure window.
- **Scan staleness:** agentless scanners snapshot on an interval, commonly
  around 24 hours. The finding reflects state as of the last scan, so it may
  already be remediated, and a resource created after the last scan is not in
  the results at all.

## Telemetry that is not on by default

CSPM is where absent telemetry bites hardest, because the exposure window is
long and the logs that would cover it were usually never enabled.

- CloudTrail **data events** are off by default. For a public bucket this is
  the difference between "nobody read it" and "we have no idea."
- **VPC flow logs**, **S3 server access logs**, **ALB access logs**, and
  **RDS / Aurora audit logs** are all off by default.
- **AWS Config** is off by default, which removes the configuration timeline.
- **GuardDuty** may not be enabled in the account or region holding the
  resource.
- **Data classification** (Macie, or the CSPM's own scanner) may not have run,
  so "sensitive data in scope" may be an inference from bucket naming rather
  than a finding. Label it as such.
- **Runtime visibility.** Agentless scanning sees the disk, not the process
  table. Whether a vulnerable package is actually loaded and reachable requires
  a runtime sensor.

When exploitation telemetry does not exist for the exposure window, the honest
output is that the question is unanswerable and the verdict rests on exposure
and blast radius alone. Write it that way rather than implying the resource was
clean.

## What remediation clears and what it leaves

**Closing the security group rule or removing public access** stops future
access. It does not end sessions already established, does not revoke data
already copied, and does not remove anything an attacker left behind during the
exposure window. If the condition was reachable and exploitable, closing it is
the start of an investigation, not the end of one.

**Patching the CVE** does not remove a webshell, a cron job, an added SSH key,
or a credential harvested from the instance metadata service during the
vulnerable period. Where an attached role's credentials could have been reached
through the finding, those credentials must be treated as exposed and rotated —
closing the port does not do that.

**Deleting the resource** does not remove IAM roles, resource policies,
snapshots, or AMIs derived from it, and destroys the evidence needed to
determine whether it was exploited. Snapshot first when the exposure window is
long.

**Fixing the live resource without fixing the IaC** means the next apply
reintroduces the condition. Name the module and the repository in the
recommended action.

## Common false positives

- **Intentional public.** Static website buckets, CDN origins, public
  container images, and public documentation endpoints. Look for an exception
  tag, an approval ticket, or a documented pattern before scoring exposure.
- **Not effectively exposed.** The rule is open but there is no public IP, no
  IGW route, a restrictive NACL, or nothing listening.
- **Distribution backports.** RHEL, Ubuntu, and Amazon Linux backport security
  fixes without changing the upstream version string, so version-only matching
  reports fixed packages as vulnerable. Check the distro package version and
  advisory, not just the upstream version.
- **Package present but unreachable.** A vulnerable library in the image that
  no running code imports, or a CVE that requires a configuration the workload
  does not use.
- **Stale scan.** Resource deleted or remediated since the last snapshot.
- **Duplicate findings** across every instance in an autoscaling group or every
  replica of one image, presented as many findings of one underlying issue.
- **Sandbox and isolated accounts** with no data and an SCP boundary.
- **Vendor CVSS without environment.** A base score of 9.8 on a host with no
  network path is not a 9.8 in this environment.

## Hypothesis clauses

Too generic — fits any public-bucket finding:
> Confirmed if logs show unauthorized access to the bucket.

Specific enough to query:
> Confirmed if CloudTrail S3 data events for `acme-prod-exports` show
> `GetObject` or `ListBucket` from a `sourceIPAddress` outside the corporate
> and AWS service ranges between 2026-03-14T09:22Z (when
> `DeletePublicAccessBlock` was called by `arn:aws:iam::4718...:user/dmartin`)
> and remediation — noting that data events must be confirmed enabled on this
> trail before a null result means anything.

Note how the second clause carries its own telemetry caveat. For CSPM that is
usually mandatory, not optional.

## Severity

Score what an attacker could reach if the condition were exploited, independent
of whether anyone did and independent of the vendor rating. Weigh, in order:
whether the resource is effectively internet-reachable; what identity is
attached to it and what that identity can reach; whether data of consequence is
in scope; and whether the account is production. High requires a plausible path
from an unauthenticated position to privilege or regulated data. An open rule
in an empty sandbox account is Low no matter what the tool called it.
