# Alert Triage Handoff

**Alert:** Consent granted to untrusted application · **Source:** Microsoft Entra ID (audit: Consent to application) · **ID:** c3a91f07-5e2d-4b8a-a6f4-1d9e8b27c450
**Fired:** 2026-08-01T03:19:44Z · **Event time:** 2026-08-01T03:13:58Z
**Entity:** m.reyes@acmecorp.com → App ID 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1 (QuarterlyReports Connector)
**Mode:** Reason-only — no evidence retrieved. All findings derive from the alert payload.

---

## Verdict
**Call:** Suspicious — unresolved
**Confidence:** Medium — three indicators favor the malicious branch (unverified publisher, registration 29h before consent, consent from a hosting-provider ASN), but no use of the granted token is observed. Indicators are not corroboration. Single resolving request: Evidence request 2 (token exercise).
**Severity:** High — the malicious branch holds delegated `Mail.Read` and `Mail.Send` on m.reyes' mailbox with `offline_access`: mail read plus send-as reaching external parties, persisting through a password reset. Per the rubric, High severity escalates now rather than waiting for confidence.

## Recommended action
Resetting m.reyes' password does NOT contain this. The `oauth2PermissionGrant` for App ID 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1 and its service principal survive a reset, and any inbox rule already created keeps working after the grant is gone.
1. Remove the delegated `oauth2PermissionGrant` for App ID 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1 on m.reyes@acmecorp.com (consented 2026-08-01T03:13:58Z).
2. Disable service principal e81c4a52-0b6f-4d39-9a17-3f6d2c8b5e04 (`accountEnabled = false`). Disable rather than delete until Evidence requests 1–2 are answered.
3. Remove any inbox rules, forwarding, or mailbox permissions found by Evidence request 3.
4. Revoke m.reyes' sign-in sessions, then reset the password.
5. If Evidence request 1 finds other consents to this App ID, block the app tenant-wide.

Hold contact with m.reyes until Evidence request 5 returns. The consent came from a hosting-provider IP, so the account itself may be compromised.

---

## What fired and why
Observed in the Entra audit event (`correlationId` 9f2b6c1e-7a44-4e0d-8b3a-52c1d7e9f018):
- `activityDisplayName`: "Consent to application", `activityDateTime` 2026-08-01T03:13:58Z, `result` success.
- `initiatedBy.user.userPrincipalName`: m.reyes@acmecorp.com, `ipAddress` 45.83.x.x.
- `ConsentAction.Permissions`: `Mail.Read Mail.Send offline_access User.Read`.
- `ConsentContext.IsAdminConsent`: False; `OnBehalfOfAll`: False — delegated consent, one user.

Observed on the application: `createdDateTime` 2026-07-30T22:10:04Z; `verifiedPublisher` empty; `signInAudience` AzureADMultipleOrgs.
Derived: registration preceded consent by 29h04m (2026-07-30T22:10:04Z → 2026-08-01T03:13:58Z).
Vendor characterization: "untrusted application"; IP 45.83.x.x described as a hosting-provider ASN outside corporate ranges. Vendor severity medium.

## Competing explanations

**Benign — real third-party reporting tool, self-onboarded by the user.**
Small vendors frequently skip publisher verification, and users self-onboard
SaaS tools without IT involvement.
Confirmed if: an approved vendor-onboarding or software-request ticket names
App ID 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1, and a matching vendor record
exists in the tenant app inventory.
Argued against by: registration 29h before consent (2026-07-30T22:10:04Z),
unverified publisher, and consent at 03:13:58Z from a hosting-provider ASN
outside corporate ranges.

**Malicious — illicit consent grant for persistent mailbox access, staged for BEC.**
Attacker holds refresh-token-backed read and send-as surviving credential reset.
Confirmed if: Exchange unified audit log shows New-InboxRule attributed to the
app's service principal after 03:13:58Z, or message trace shows outbound mail
from m.reyes@acmecorp.com with no corresponding Sent Items entry.

## Evidence requests
Ordered by how much uncertainty each item resolves.

1. **Enumerate all consents to App ID 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1.**
   Source: Entra ID audit log, "Consent to application" events.
   Window: 2026-07-30T22:10:04Z (app registered) to now.
   Resolves: scope. A single grant is targeted or opportunistic phishing;
   multiple grants indicate a campaign and change containment from one
   revocation to a tenant-wide app block.

2. **Check whether the refresh token has been exercised.**
   Source: Entra ID non-interactive user sign-in logs for
   m.reyes@acmecorp.com, filtered to `appId` 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1.
   This is a delegated consent, so refresh-token use lands here, not in
   service principal sign-ins; check those second. Both are separate
   diagnostic categories and may not be collected.
   Window: 2026-08-01T03:13:58Z to now.
   Resolves: active vs. dormant. Token use makes this an active incident
   with data exposure. No token use means revoke and close only once
   collection of non-interactive sign-ins is confirmed.

3. **Search for inbox rule creation attributed to the service principal.**
   Source: Exchange unified audit log, New-InboxRule / Set-InboxRule.
   Window: 2026-08-01T03:13:58Z to now.
   Resolves: BEC staging. A keyword-filtered delete or move rule is
   near-conclusive for fraud setup rather than collection.

4. **Message trace for outbound mail from m.reyes@acmecorp.com.**
   Source: Exchange message trace, compared against mailbox Sent Items.
   Window: 2026-08-01T03:13:58Z to now.
   Resolves: whether send-as was used. Outbound mail absent from Sent Items
   confirms Graph-based sending and identifies fraud recipients.

5. **Reconstruct the consent session.**
   Source: Entra ID sign-in logs for m.reyes@acmecorp.com around 03:13:58Z,
   plus email gateway logs.
   Window: 2026-07-31T03:13:58Z to 2026-08-01T03:19:44Z.
   Resolves: initial access vector. A session from 45.83.x.x indicates
   token theft or session hijack; a corporate-IP session with a consent
   redirect indicates a phishing lure and implies other recipients.

## What would change this verdict
- Approved onboarding ticket naming this App ID, plus consent-session origin
  from a corporate IP → benign, close with justification.
- Non-interactive sign-in logs showing zero token use, with collection
  confirmed → severity holds, but this becomes revoke-and-close rather than
  an active incident.
- Additional users consenting to the same App ID → escalate to campaign;
  containment moves to tenant-wide app block.
- Prior legitimate use history does NOT clear this. A 29-hour-old registration
  cannot have it, and a compromised legitimate app would.

## Assumptions
Asserted without evidence.
- "Untrusted application" — publisher is unverified, which is not the same as
  known-malicious. No threat intel lookup performed on the App ID.
- m.reyes' role and whether mailbox-integration tooling is expected for it.
- No evidence the grant has been exercised; malicious branch is inferred from
  scope combination and registration timing, not observed activity.
- Source IP 45.83.x.x characterized as hosting-provider ASN per the alert;
  not independently verified.
## Raw
**Normalized core:** who m.reyes@acmecorp.com · what Consent to application (App ID 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1) · when 2026-08-01T03:13:58Z (fired 03:19:44Z) · source Microsoft Entra ID audit log · vendor severity medium

Synthetic payload; identical to `tests/oauth_alert.json`.

```json
{
  "_note": "Synthetic payload built for the oauth_handoff.md worked example. All identifiers are fictional.",
  "alert": {
    "id": "c3a91f07-5e2d-4b8a-a6f4-1d9e8b27c450",
    "title": "Consent granted to untrusted application",
    "productName": "Microsoft Entra ID",
    "severity": "medium",
    "category": "InitialAccess",
    "createdDateTime": "2026-08-01T03:19:44Z",
    "evidence": {
      "ipAddress": "45.83.x.x",
      "ipCategory": "hosting provider ASN, outside corporate ranges"
    }
  },
  "auditEvent": {
    "category": "ApplicationManagement",
    "activityDisplayName": "Consent to application",
    "activityDateTime": "2026-08-01T03:13:58Z",
    "correlationId": "9f2b6c1e-7a44-4e0d-8b3a-52c1d7e9f018",
    "result": "success",
    "initiatedBy": {
      "user": {
        "userPrincipalName": "m.reyes@acmecorp.com",
        "ipAddress": "45.83.x.x"
      }
    },
    "targetResources": [
      {
        "type": "ServicePrincipal",
        "displayName": "QuarterlyReports Connector",
        "id": "e81c4a52-0b6f-4d39-9a17-3f6d2c8b5e04",
        "modifiedProperties": [
          { "displayName": "ConsentContext.IsAdminConsent", "newValue": "\"False\"" },
          { "displayName": "ConsentContext.OnBehalfOfAll", "newValue": "\"False\"" },
          { "displayName": "ConsentAction.Permissions", "newValue": "\"Scope: Mail.Read Mail.Send offline_access User.Read\"" },
          { "displayName": "TargetId.ServicePrincipalNames", "newValue": "\"7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1\"" }
        ]
      }
    ]
  },
  "application": {
    "appId": "7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1",
    "displayName": "QuarterlyReports Connector",
    "createdDateTime": "2026-07-30T22:10:04Z",
    "publisherDomain": "quarterlyreportsconnector.onmicrosoft.com",
    "verifiedPublisher": {},
    "signInAudience": "AzureADMultipleOrgs"
  }
}
```
