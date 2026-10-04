# SaaS Identity

Read this for Entra ID and Okta alerts: risky sign-ins, OAuth consent grants,
MFA anomalies, password spray, and privileged role changes.

## Alert types you will see

**Entra ID.** Identity Protection risk detections (anonymous IP, atypical
travel, unfamiliar sign-in properties, malicious IP, leaked credentials,
password spray, anomalous token, token issuer anomaly); illicit consent grant;
new service principal or added service principal credential; directory role
assignment or PIM activation; federation / domain authentication change;
Conditional Access policy modification; MFA method registration or removal; and
Defender for Cloud Apps alerts such as mass download or inbox rule creation.

**Okta.** Suspicious activity reported by user; repeated `user.session.start`
failures; MFA factor reset or deactivation; admin role or admin-group
membership grant; API token creation; new device or new geography;
ThreatInsight detections; push-notification fatigue; and impersonation session
start.

**Two flows worth recognizing on sight.** *Illicit consent grant* — the
attacker never obtains the password, so credential remediation is irrelevant to
their access. *Device code phishing* — the victim enters a real code on a real
Microsoft page, so the sign-in looks legitimate; the tell is
`authenticationProtocol` of `deviceCode` in a context where no device
enrollment was expected.

## Log sources and fields to name

**Entra sign-in logs are four separate collections.** Interactive user
sign-ins, non-interactive user sign-ins, service principal sign-ins, and
managed identity sign-ins. Refresh-token use appears in the non-interactive
collection, and an app acting on its own appears only in the service principal
collection. Querying interactive sign-ins alone and finding nothing is the most
common false negative in this source class. Always name which collection.

Fields: `userPrincipalName`, `appId`, `appDisplayName`, `resourceDisplayName`,
`ipAddress`, `autonomousSystemNumber`, `location`, `clientAppUsed`,
`authenticationProtocol`, `incomingTokenType`, `deviceDetail.deviceId`,
`deviceDetail.isCompliant`, `deviceDetail.isManaged`, `deviceDetail.trustType`,
`conditionalAccessStatus`, `appliedConditionalAccessPolicies`,
`authenticationRequirement`, `authenticationDetails`, `riskLevelDuringSignIn`,
`riskEventTypes`, `resultType`, `resultDescription`, `correlationId`,
`uniqueTokenIdentifier`, `servicePrincipalId`, `crossTenantAccessType`.

**Entra audit logs.** `activityDisplayName` values that matter: "Consent to
application", "Add app role assignment to service principal", "Add service
principal", "Add service principal credentials", "Update application –
Certificates and secrets management", "Add member to role", "Add owner to
application", "Update domain", "Add unverified domain", "Disable Strong
Authentication", "User registered security info", "Update conditional access
policy". Fields: `initiatedBy`, `targetResources`, and
`targetResources.modifiedProperties`, which carries the actual before and after
values — ask for that field by name, not for "the audit log entry."

**Exchange unified audit log.** `New-InboxRule`, `Set-InboxRule`,
`Set-Mailbox` (forwarding), `Add-MailboxPermission`,
`Add-RecipientPermission` (send-as), `UpdateInboxRules`, `MailItemsAccessed`,
`Send`, `SendAs`. Plus message trace, compared against Sent Items.

**Okta System Log.** `eventType`, `actor.alternateId`, `target[]`,
`client.ipAddress`, `client.userAgent`, `client.geographicalContext`,
`client.zone`, `securityContext.asNumber`, `securityContext.isp`,
`securityContext.isProxy`, `outcome.result`, `outcome.reason`,
`authenticationContext.externalSessionId`, `debugContext.debugData.dtHash`,
`debugContext.debugData.threatSuspected`, `debugContext.debugData.riskLevel`.
Event types worth naming: `user.session.start`, `user.authentication.auth_via_mfa`,
`system.push.send_factor_verify_push`, `user.mfa.factor.deactivate`,
`user.mfa.factor.reset_all`, `system.api_token.create`,
`group.user_membership.add`, `user.session.impersonation.initiate`,
`application.user_membership.add`.

**Pivot keys.** Entra: `correlationId` for one authentication, plus
`uniqueTokenIdentifier` to follow one token. Okta: `externalSessionId` to
follow one session across events, plus `dtHash` to follow one device across
sessions and accounts.

## Tokens: what exists and what survives

This is where most SaaS identity triage goes wrong. Be precise.

**Access token.** A signed bearer JWT, typically valid 60 to 90 minutes. It is
validated by signature, not by a lookup, so **nothing revokes it** — a disabled
account with a live access token keeps working until expiry. Continuous Access
Evaluation closes this for CAE-aware resources (Exchange Online, SharePoint,
Graph) by having the resource evaluate critical events in near real time.
Whether CAE is enforced in the tenant is an evidence request, not an
assumption.

**Refresh token.** Long-lived, sliding, and the actual persistence mechanism.
`offline_access` in a consent grant is what mints one for a third-party app.

**Password reset does not remove an application's authorization.** Resetting or
changing the user's password stamps `refreshTokensValidFromDateTime` and
invalidates that user's own refresh tokens, but:

- The `oauth2PermissionGrant` and the service principal remain. The app's
  standing authorization is unchanged.
- For **application permissions** (app-only, client-credentials), the app
  authenticates with its own secret or certificate and never touched the user's
  password. A reset is entirely irrelevant to that access.
- Any credential the attacker added to the service principal — a client secret
  or certificate — survives every action taken against the user.
- Access tokens already issued remain valid to expiry without CAE.

To actually contain an illicit consent grant: remove the OAuth2 permission
grant and app role assignments, delete or disable the service principal, remove
attacker-added service principal credentials, then revoke the user's sessions,
then reset the password. Order matters, and a handoff that lists only the reset
is wrong.

**Okta.** Clearing user sessions ends the Okta session but does not revoke
OAuth refresh tokens issued to applications; those require revoking the grant.
API tokens (SSWS) are independent of the user's password and MFA entirely and
expire only after 30 days of inactivity — an attacker-created API token
survives a full account remediation.

**IdP revocation does not terminate downstream sessions.** After a SAML or OIDC
assertion is consumed, the service provider maintains its own session on its
own lifetime. Revoking at Entra or Okta does not sign the attacker out of
Salesforce, AWS, Workday, or the VPN. Each downstream application needs its own
session revocation, and each has its own log to check.

## Persistence that survives account remediation

Name these explicitly before calling containment complete:

- Inbox rules and mailbox forwarding — these keep exfiltrating mail after the
  password, tokens, and sessions are all cleared.
- Mailbox delegation, full-access permissions, and send-as grants.
- An MFA method the attacker registered. Left in place, it lets them
  self-service the password back.
- Registered or Entra-joined devices, and the primary refresh token on them.
- Attacker-added service principals, app credentials, and app owners.
- Directory role assignments and admin group memberships.
- Federation and domain-authentication changes, which mint valid assertions for
  any user in the tenant and are unaffected by anything done to one account.
- Okta API tokens, admin role grants, and inline hooks.

## Consent scopes worth escalating

`Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `MailboxSettings.ReadWrite` (inbox
rules), `Files.Read.All`, `Sites.Read.All`, `User.Read.All`,
`Directory.Read.All` — data access. `Directory.ReadWrite.All`,
`Application.ReadWrite.All` (add credentials to any app in the tenant), and
`RoleManagement.ReadWrite.Directory` (grant Global Administrator) are tenant
takeover, and admin consent means the grant applies tenant-wide rather than to
one user. `offline_access` alongside any of these converts a session into
persistence.

Distinguish delegated consent (acts as the user, within the user's own
permissions) from application permission (acts as itself, tenant-wide, requires
admin consent). Say which one the alert is.

## Result codes that change the reading

Entra `resultType`: `50126` invalid credentials; `50053` smart lockout or
account locked; `50055` expired password; `50158` external challenge failed.
Critically, `50076`, `50079`, and `50074` mean **the password was correct** and
only MFA stopped the sign-in — in a spray alert, these are the accounts that
matter. `500121` is an MFA request denied or timed out, and a run of them
followed by a `0` is the push-fatigue signature.

`clientAppUsed` of "Other clients", IMAP, POP, SMTP, or Exchange ActiveSync
indicates legacy authentication, which bypasses MFA-based Conditional Access
unless explicitly blocked.

Okta: `outcome.reason` of `INVALID_CREDENTIALS` across many accounts from one
`securityContext.asNumber`, at low volume per account, is spray rather than
brute force.

## Time windows

- **Consent grant:** app registration time through T for scope (who else
  consented), and T through now for exercise (was the token used).
- **User baseline:** T-30d on that user's normal ASN, device IDs, client apps,
  and resource access, to judge whether "unfamiliar" is meaningful.
- **Post-compromise sweep:** T through now for inbox rules, forwarding,
  MFA registration, new consents, role assignments, device joins, and API
  tokens.
- **Spray or stuffing:** T-7d tenant-wide for the same source ASN, looking
  specifically for successes among the failures.
- **Delivery vector:** T-24h on the email gateway for a consent or device-code
  lure, which also identifies other recipients.
- **Downstream:** T through now in each federated application's own logs.

## Telemetry that is not on by default

- **Entra log retention is 7 days without a licence and 30 days with Entra ID
  P1 or P2.** Anything longer requires a diagnostic setting exporting to Log
  Analytics, storage, or Event Hub, which is not configured by default. A
  90-day question is unanswerable in most tenants — say so rather than assuming
  the query will run.
- **Non-interactive sign-in logs and service principal sign-in logs** are
  separate diagnostic categories and separate licence tiers. They are the
  collections that show token use, so confirm they are being collected before
  treating "no token use" as a finding.
- **Identity Protection detail** (risk event types, risk history) needs P2.
- **`MailItemsAccessed`** — the record that proves which mail was actually read
  — requires E5 or the Advanced Audit add-on. On E3 you cannot establish what
  was read, only what was configured. This distinction belongs in the handoff.
- **Unified audit log retention** is 90 days on E3 and 1 year on E5. **Message
  trace** is 10 days detailed, 90 days summary.
- **Okta System Log** is 90 days rolling; longer needs SIEM export.
  **ThreatInsight** must be enabled, and can be in log-only mode rather than
  blocking.

## Common false positives

- **Impossible travel** from a corporate VPN or proxy egressing in another
  region, a mobile carrier CGNAT, split tunnelling, cloud VDI, or a phone
  roaming while the laptop stays put.
- **Anonymous IP** from a consumer VPN or iCloud Private Relay. Extremely
  common and not by itself suspicious.
- **Unfamiliar sign-in properties** on a genuinely new device, a first trip, or
  after a browser reinstall.
- **Password spray alerts caused by a stale credential.** A service account,
  a phone mail client, or a scheduled job holding an old password will
  loop failures across a tenant and look like spray. The tell is a single
  account, a stable source IP, and a fixed retry interval.
- **Legitimate consent** granted by an admin during a rollout, or an app the
  business genuinely onboarded without IT involvement.
- **Push fatigue that is a stale session** on a forgotten device re-prompting.
- **Okta impersonation** by support with an approved ticket.
- **Mass download by a departing employee** — often real, but insider rather
  than external, which changes the handling path entirely and engages the
  do-not-tip-off rule.

## Hypothesis clauses

Too generic — fits any consent-grant alert:
> Confirmed if audit logs show the application was used maliciously.

Specific enough to query:
> Confirmed if Entra **non-interactive user** sign-in logs for the
> consenting user, filtered to App ID 7d1e9a3f-2b88-4c10-9f55-c0aa41e2b6d1,
> show at least one token issuance after 2026-08-01T03:13:58Z (delegated
> consent; for application permissions, use service principal sign-ins), and the Exchange unified audit log shows
> `New-InboxRule` attributed to that service principal — noting that
> `MailItemsAccessed` is unavailable on E3, so read activity cannot be
> established from this tenant's licence tier.

For the benign branch, name the onboarding system, the field carrying the App
ID, and the tenant app inventory record that would have to exist.

## Severity

Score the malicious branch. High when the grant or account reaches mailboxes,
files, or directory data at tenant scope; when the scopes permit privilege
change (`Application.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`);
when the account holds a directory role; when federation or domain
authentication was modified; or when the identity federates into production
cloud accounts. Confidence stays separate: an unexercised grant with strong
indicators is High severity and Low or Medium confidence, and per the rubric
that escalates now rather than waiting for confidence to rise.
