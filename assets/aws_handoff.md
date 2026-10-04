# Alert Triage Handoff

**Alert:** Anomalous privilege-escalation APIs invoked by ci-deploy-role · **Source:** AWS GuardDuty (PrivilegeEscalation:IAMUser/AnomalousBehavior) · **ID:** 6cb8f4e2-1a09-4d77-b3e1-92f04c8a7d5e
**Fired:** 2026-07-31T18:42:11Z · **Event time:** 2026-07-31T18:40:52Z (first) to 2026-07-31T18:47:03Z (last)
**Entity:** arn:aws:sts::471829336104:assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0
**Mode:** Reason-only — no evidence retrieved. All findings derive from the alert payload.

---

## Verdict
**Call:** Suspicious — unresolved
**Confidence:** Medium — the escalation sequence is observed (`CreateAccessKey` on svc-backup at 18:43:02Z, `AttachUserPolicy` AdministratorAccess at 18:43:40Z), run interactively via `aws-cli` from the instance's own IP. The rubric's Malicious criterion also requires the absence of a change record, and that is not in the payload. Single resolving request: Evidence request 2 (change record), read together with 1 (use of the new key).
**Severity:** High — the malicious branch leaves a long-lived `AKIA` key with AdministratorAccess: account-wide privilege that outlives the instance and the role session. Per the rubric, High severity escalates now rather than waiting for confidence.

## Recommended action
Terminating i-0a3f7c91e4b28d5a0 and revoking ci-deploy-role sessions does NOT contain this. Neither touches access key AKIAEXAMPLESVCBKUP01 on svc-backup or the AdministratorAccess attachment, and neither touches a resource-based policy changed during the session. The steps below are reversible and should be taken now, given High severity.
1. Deactivate access key AKIAEXAMPLESVCBKUP01 on svc-backup (created 2026-07-31T18:43:02Z). Deactivate rather than delete until Evidence request 1 is answered, so the key's CloudTrail history stays attributable.
2. Detach `arn:aws:iam::aws:policy/AdministratorAccess` from svc-backup (attached 2026-07-31T18:43:40Z).
3. Snapshot the EBS volumes and capture memory on i-0a3f7c91e4b28d5a0, then isolate it with a deny-all security group. Do not terminate it before the snapshot.
4. Revoke ci-deploy-role sessions issued before now (inline deny on `aws:TokenIssueTime`). STS credentials already issued otherwise stay valid for up to 12 hours.
5. Hold before calling containment complete: Evidence request 3 must show no `PutBucketPolicy`, `UpdateAssumeRolePolicy`, or identity-provider creation in the session. Principal-side cleanup clears none of those.

---

## What fired and why
Observed in CloudTrail (all records `userIdentity.accessKeyId` = `ASIAEXAMPLECIDEPLOY0`, `sourceIPAddress` = `54.198.37.112`):

| eventTime | eventName | requestParameters |
| --- | --- | --- |
| 18:40:52Z | `GetAccountAuthorizationDetails` | `filter: User, Role, LocalManagedPolicy` |
| 18:41:30Z | `ListUsers` | — |
| 18:43:02Z | `CreateAccessKey` | `userName: svc-backup` → `AKIAEXAMPLESVCBKUP01` |
| 18:43:40Z | `AttachUserPolicy` | `userName: svc-backup`, `policyArn: …/AdministratorAccess` |
| 18:45:18Z | `ListBuckets` | — |
| 18:47:03Z | `GetBucketPolicy` | `bucketName: prod-customer-exports` |

Derived: `sourceIPAddress` 54.198.37.112 equals the instance's `publicIpAddress` in the attached enrichment, so the calls ran on the host. These are not instance credentials used off-host after IMDS theft.
Derived: every `userAgent` is `aws-cli/2.17.20 … command/<api>`, an interactive CLI, not Terraform, CloudFormation, or a pipeline SDK.
Vendor characterization: "not seen for this principal in the prior 90 days" (GuardDuty baseline, not verified here). Vendor severity 8.0.

## Competing explanations

**Benign — an engineer with shell access on ci-runner-03 manually set up svc-backup access outside the pipeline.**
Someone fixing a broken backup job used the runner's role to mint a key for svc-backup and over-granted it.
Confirmed if: a change record in the change-management system names svc-backup and AdministratorAccess, with approval timestamped before 2026-07-31T18:43:02Z, and CloudTrail shows `AKIAEXAMPLESVCBKUP01` used only from the backup system's known source IP.
Argued against by: discovery (`GetAccountAuthorizationDetails` at 18:40:52Z) preceding the change; a CI deploy role creating credentials for a different principal; AdministratorAccess far exceeding what a backup principal needs; interactive `aws-cli` rather than IaC.

**Malicious — compromise of the internet-exposed ci-runner-03, used to plant a long-lived admin key on svc-backup.**
An attacker with code execution on the host used the instance role on-host to enumerate IAM, mint persistence on a second principal, escalate it, then enumerate S3.
Confirmed if: CloudTrail in any region shows a call with `userIdentity.accessKeyId` = `AKIAEXAMPLESVCBKUP01` from a `sourceIPAddress` other than the backup system after 2026-07-31T18:43:02Z, or no change record exists for the svc-backup grant.
Argued against by: nothing in the payload. Use of the new key is not observed.

## Evidence requests
Ordered by how much uncertainty each item resolves.

1. **Find any use of the new key.**
   Source: CloudTrail management events, all regions, `userIdentity.accessKeyId` = `AKIAEXAMPLESVCBKUP01`.
   Window: 2026-07-31T18:43:02Z to now. CloudTrail delivery lags 5–15 minutes; an empty last 15 minutes is latency.
   Resolves: any use from an unknown source → Malicious, High confidence. No use → still unresolved; the key may be dormant persistence.

2. **Look for a change record covering the grant.**
   Source: change-management system, records referencing svc-backup, AdministratorAccess, or ci-runner-03.
   Window: 2026-07-24T18:43:02Z to 2026-07-31T18:43:02Z.
   Resolves: an approved record → Benign path, still requiring AdministratorAccess to be removed as over-privilege. No record → meets the rubric's Malicious criterion.

3. **Reconstruct the full role session.**
   Source: CloudTrail management events, all regions, `userIdentity.accessKeyId` = `ASIAEXAMPLECIDEPLOY0`.
   Window: 2026-07-31T14:05:17Z (`sessionContext.attributes.creationDate`) to now.
   Resolves: whether the session did more than the six calls in the finding, especially `PutBucketPolicy`, `UpdateAssumeRolePolicy`, `CreateOpenIDConnectProvider`, or `CreateLoginProfile`. Any of those expands containment beyond svc-backup.

4. **Check for object reads on prod-customer-exports.**
   Source: CloudTrail data events, `GetObject` / `ListObjectsV2` on `prod-customer-exports`. Not on by default; S3 server access logs are the fallback, also off by default and delayed by hours.
   Window: 2026-07-31T18:45:18Z to now.
   Resolves: exfiltration. A null result is unresolved until data-event collection on this bucket is confirmed.

5. **Correlate with the CI system.**
   Source: CI pipeline run log for ci-runner-03; CloudTrail on `userIdentity.principalId` = `AROAEXAMPLECIDEPLOY:i-0a3f7c91e4b28d5a0` for IAM write calls.
   Window: 2026-05-02T18:42:11Z to 2026-07-31T18:47:03Z (90-day baseline the finding claims).
   Resolves: whether any pipeline job ran at 18:40–18:47Z, and whether this role has ever made IAM write calls. A matching job → Benign path.

6. **Find the initial access vector on ci-runner-03.**
   Source: ALB / WAF logs fronting the instance; VPC flow logs for i-0a3f7c91e4b28d5a0 (not on by default; 1- or 10-minute aggregation); EDR telemetry on the host if a sensor is installed.
   Window: 2026-07-30T18:40:52Z to 2026-07-31T18:40:52Z.
   Resolves: how execution was obtained; changes containment from one host to the exposed application.

7. **Check for the same pattern elsewhere.**
   Source: CloudTrail, all principals, `CreateAccessKey` where `requestParameters.userName` differs from the caller, or `AttachUserPolicy` with AdministratorAccess. Confirm the trail is organization-wide; a single-account trail leaves cross-account scope unresolved.
   Window: 2026-07-01T18:42:11Z to now.
   Resolves: single host vs. campaign.

## What would change this verdict
- Approved change record predating 18:43:02Z naming svc-backup, plus a matching CI job at 18:40–18:47Z → Benign; AdministratorAccess on svc-backup is still removed as over-privilege.
- Any call by `AKIAEXAMPLESVCBKUP01` from a source other than the backup system → Malicious, High confidence.
- `PutBucketPolicy`, `UpdateAssumeRolePolicy`, or a new identity provider in session `ASIAEXAMPLECIDEPLOY0` → Malicious; containment expands to resource-based policies and federation.
- The same `CreateAccessKey` / `AttachUserPolicy` pattern on another principal → campaign; containment becomes account-wide.
- No use of `AKIAEXAMPLESVCBKUP01` found does NOT clear this. The key may be held in reserve, and the result means nothing until an all-region trail is confirmed.

## Assumptions
Asserted without evidence.
- Instance IPs and tags come from the SOAR enrichment attached to the alert, not from GuardDuty; taken as accurate.
- `Exposure: internet` tag taken at face value; security groups and load balancer exposure not verified.
- prod-customer-exports is assumed to hold customer data based on its name only.
- svc-backup's normal usage, and whether it was dormant before 18:43:02Z, are unknown.
- The change-management system is assumed to exist and be the authoritative record for IAM changes.
- An insider with shell access on ci-runner-03 is not ruled out. Do not contact the CI owners or ci-runner-03 users until Evidence requests 1–3 return.

## Raw
**Normalized core:** who `assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0` · what `PrivilegeEscalation:IAMUser/AnomalousBehavior` · when 2026-07-31T18:40:52Z–18:47:03Z (fired 18:42:11Z) · source AWS GuardDuty + CloudTrail, account 471829336104, us-east-1 · vendor severity 8.0

Synthetic payload; identical to `tests/aws_alert.json`.

```json
{
  "_note": "Synthetic payload built for the aws_handoff.md worked example. All identifiers are fictional.",
  "guardDutyFinding": {
    "schemaVersion": "2.0",
    "accountId": "471829336104",
    "region": "us-east-1",
    "id": "6cb8f4e2-1a09-4d77-b3e1-92f04c8a7d5e",
    "type": "PrivilegeEscalation:IAMUser/AnomalousBehavior",
    "title": "Anomalous privilege-escalation APIs invoked by ci-deploy-role",
    "description": "APIs commonly used in privilege escalation tactics were invoked by principal ci-deploy-role. This activity has not been seen for this principal in the prior 90 days.",
    "severity": 8.0,
    "createdAt": "2026-07-31T18:42:11Z",
    "updatedAt": "2026-07-31T18:49:30Z",
    "resource": {
      "resourceType": "AccessKey",
      "accessKeyDetails": {
        "accessKeyId": "ASIAEXAMPLECIDEPLOY0",
        "principalId": "AROAEXAMPLECIDEPLOY:i-0a3f7c91e4b28d5a0",
        "userName": "ci-deploy-role",
        "userType": "AssumedRole"
      }
    },
    "service": {
      "serviceName": "guardduty",
      "eventFirstSeen": "2026-07-31T18:40:52Z",
      "eventLastSeen": "2026-07-31T18:47:03Z",
      "count": 6,
      "action": {
        "actionType": "AWS_API_CALL",
        "awsApiCallAction": {
          "api": "AttachUserPolicy",
          "serviceName": "iam.amazonaws.com",
          "callerType": "Remote IP",
          "remoteIpDetails": {
            "ipAddressV4": "54.198.37.112",
            "organization": { "asn": "14618", "asnOrg": "AMAZON-AES" }
          }
        }
      },
      "additionalInfo": {
        "anomalies": {
          "anomalousAPIs": {
            "iam.amazonaws.com": [
              "GetAccountAuthorizationDetails",
              "ListUsers",
              "CreateAccessKey",
              "AttachUserPolicy"
            ],
            "s3.amazonaws.com": ["ListBuckets", "GetBucketPolicy"]
          }
        },
        "profiledBehavior": {
          "rareProfiledAPIsAccountProfiling": "CreateAccessKey,AttachUserPolicy",
          "rareProfiledAPIsUserIdentityProfiling": "CreateAccessKey,AttachUserPolicy,GetAccountAuthorizationDetails"
        }
      }
    }
  },
  "cloudTrailRecords": [
    {
      "eventTime": "2026-07-31T18:40:52Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "GetAccountAuthorizationDetails",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "54.198.37.112",
      "userAgent": "aws-cli/2.17.20 Python/3.11.9 Linux/5.10.219-208.866.amzn2.x86_64 exe/x86_64.amzn.2 prompt/off command/iam.get-account-authorization-details",
      "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::471829336104:assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0",
        "accessKeyId": "ASIAEXAMPLECIDEPLOY0",
        "sessionContext": {
          "sessionIssuer": { "arn": "arn:aws:iam::471829336104:role/ci-deploy-role" },
          "attributes": { "mfaAuthenticated": "false", "creationDate": "2026-07-31T14:05:17Z" }
        }
      },
      "requestParameters": { "filter": ["User", "Role", "LocalManagedPolicy"] },
      "readOnly": true
    },
    {
      "eventTime": "2026-07-31T18:41:30Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "ListUsers",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "54.198.37.112",
      "userAgent": "aws-cli/2.17.20 Python/3.11.9 Linux/5.10.219-208.866.amzn2.x86_64 exe/x86_64.amzn.2 prompt/off command/iam.list-users",
      "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::471829336104:assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0",
        "accessKeyId": "ASIAEXAMPLECIDEPLOY0"
      },
      "requestParameters": null,
      "readOnly": true
    },
    {
      "eventTime": "2026-07-31T18:43:02Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "CreateAccessKey",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "54.198.37.112",
      "userAgent": "aws-cli/2.17.20 Python/3.11.9 Linux/5.10.219-208.866.amzn2.x86_64 exe/x86_64.amzn.2 prompt/off command/iam.create-access-key",
      "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::471829336104:assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0",
        "accessKeyId": "ASIAEXAMPLECIDEPLOY0"
      },
      "requestParameters": { "userName": "svc-backup" },
      "responseElements": {
        "accessKey": {
          "userName": "svc-backup",
          "accessKeyId": "AKIAEXAMPLESVCBKUP01",
          "status": "Active",
          "createDate": "Jul 31, 2026 6:43:02 PM"
        }
      },
      "readOnly": false
    },
    {
      "eventTime": "2026-07-31T18:43:40Z",
      "eventSource": "iam.amazonaws.com",
      "eventName": "AttachUserPolicy",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "54.198.37.112",
      "userAgent": "aws-cli/2.17.20 Python/3.11.9 Linux/5.10.219-208.866.amzn2.x86_64 exe/x86_64.amzn.2 prompt/off command/iam.attach-user-policy",
      "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::471829336104:assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0",
        "accessKeyId": "ASIAEXAMPLECIDEPLOY0"
      },
      "requestParameters": {
        "userName": "svc-backup",
        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
      },
      "readOnly": false
    },
    {
      "eventTime": "2026-07-31T18:45:18Z",
      "eventSource": "s3.amazonaws.com",
      "eventName": "ListBuckets",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "54.198.37.112",
      "userAgent": "aws-cli/2.17.20 Python/3.11.9 Linux/5.10.219-208.866.amzn2.x86_64 exe/x86_64.amzn.2 prompt/off command/s3api.list-buckets",
      "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::471829336104:assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0",
        "accessKeyId": "ASIAEXAMPLECIDEPLOY0"
      },
      "requestParameters": null,
      "readOnly": true
    },
    {
      "eventTime": "2026-07-31T18:47:03Z",
      "eventSource": "s3.amazonaws.com",
      "eventName": "GetBucketPolicy",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "54.198.37.112",
      "userAgent": "aws-cli/2.17.20 Python/3.11.9 Linux/5.10.219-208.866.amzn2.x86_64 exe/x86_64.amzn.2 prompt/off command/s3api.get-bucket-policy",
      "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::471829336104:assumed-role/ci-deploy-role/i-0a3f7c91e4b28d5a0",
        "accessKeyId": "ASIAEXAMPLECIDEPLOY0"
      },
      "requestParameters": { "bucketName": "prod-customer-exports" },
      "readOnly": true
    }
  ],
  "enrichment": {
    "_source": "SOAR instance lookup attached to the alert",
    "instanceId": "i-0a3f7c91e4b28d5a0",
    "publicIpAddress": "54.198.37.112",
    "privateIpAddress": "10.4.11.87",
    "iamInstanceProfile": "arn:aws:iam::471829336104:instance-profile/ci-deploy-role",
    "tags": { "Name": "ci-runner-03", "Exposure": "internet" }
  }
}
```
