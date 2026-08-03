## Competing explanations

**Benign — real third-party reporting tool, self-onboarded by the user.**
Small vendors frequently skip publisher verification, and users self-onboard
SaaS tools without IT involvement.
Confirmed if: an approved vendor-onboarding or software-request ticket names
App ID 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1, and a matching vendor record
exists in the tenant app inventory.
Argued against by: registration 29h before consent (2026-07-29T22:10:04Z),
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
   Window: T-72h (app registered 2026-07-29T22:10:04Z) to T.
   Resolves: scope. A single grant is targeted or opportunistic phishing;
   multiple grants indicate a campaign and change containment from one
   revocation to a tenant-wide app block.

2. **Check whether the refresh token has been exercised.**
   Source: Entra ID service principal sign-in logs, filtered to the App ID.
   Window: 2026-08-01T03:13:58Z to T.
   Resolves: active vs. dormant. No token use means revoke and close;
   token use makes this an active incident with data exposure.

3. **Search for inbox rule creation attributed to the service principal.**
   Source: Exchange unified audit log, New-InboxRule / Set-InboxRule.
   Window: 2026-08-01T03:13:58Z to T.
   Resolves: BEC staging. A keyword-filtered delete or move rule is
   near-conclusive for fraud setup rather than collection.

4. **Message trace for outbound mail from m.reyes@acmecorp.com.**
   Source: Exchange message trace, compared against mailbox Sent Items.
   Window: 2026-08-01T03:13:58Z to T.
   Resolves: whether send-as was used. Outbound mail absent from Sent Items
   confirms Graph-based sending and identifies fraud recipients.

5. **Reconstruct the consent session.**
   Source: Entra ID sign-in logs for m.reyes@acmecorp.com around 03:13:58Z,
   plus email gateway logs T-24h.
   Window: T-24h to T.
   Resolves: initial access vector. A session from 45.83.x.x indicates
   token theft or session hijack; a corporate-IP session with a consent
   redirect indicates a phishing lure and implies other recipients.

## What would change this verdict
- Approved onboarding ticket naming this App ID, plus consent-session origin
  from a corporate IP → benign, close with justification.
- Service principal sign-in logs showing zero token use → severity holds,
  but this becomes revoke-and-close rather than an active incident.
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