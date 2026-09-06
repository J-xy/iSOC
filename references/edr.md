# EDR

Read this for endpoint detections from CrowdStrike Falcon, Defender for
Endpoint, SentinelOne, and equivalents.

## Read the disposition before anything else

An EDR alert says two separate things: what was observed, and whether it was
stopped. In Falcon this is `PatternDispositionDescription`; elsewhere it is a
blocked / detected / audit-only field.

- **Prevented / blocked** — the specific action was stopped. The delivery chain
  that produced it was not. A blocked payload still means something executed
  far enough to drop it.
- **Detected only** — it ran. Everything downstream of it should be assumed to
  have run too.
- **Audit / informational** — the sensor was in a policy mode that observes
  without acting.

Never write "the threat was blocked" as if it closed the alert. Name the stage
that was blocked and the stages before it that were not.

## Alert types you will see

Malware / ML detection on a file write or execution; suspicious process
lineage; credential access (LSASS handle open, `comsvcs.dll MiniDump`,
registry SAM/SECURITY hive save); persistence creation; script-based execution
(PowerShell, WScript, `mshta`, macro); living-off-the-land binary abuse;
lateral movement (remote service creation, WMI/WinRM exec, SMB admin share
write); C2 / network detection; ransomware behavioral (shadow copy deletion,
mass file rename); and tamper events (sensor stop, uninstall attempt).

Each carries a MITRE tactic and technique. Use the technique as a starting
point, not as the verdict — technique mapping is assigned by the vendor from
the pattern that fired, not from what actually happened.

## Log sources and fields to name

**Sensor process telemetry.** `aid` (agent ID), `ComputerName`, `UserName` /
`UserSid`, `ProcessStartTime`, `TargetProcessId`, `ParentProcessId`,
`ParentBaseFileName`, `GrandparentBaseFileName`, `ImageFileName`,
`CommandLine`, `SHA256HashData`, `MD5HashData`, `SignInfoFlags` /
signer status, `RemoteIP`, `RemotePort`, `DomainName` (DNS request),
`RegObjectName` / `RegValueName`, `FileName` / `FilePath`.

**Windows event logs**, when available: 4688 process creation, 4624 / 4625
logon with `LogonType` (3 network, 10 RDP, 9 explicit-cred), 4672 special
privileges, 4697 service install, 7045 service install (System), 4698 /
4702 scheduled task create/update, 5140 / 5145 share access, 4104 PowerShell
script block, 4103 module logging, 1102 log cleared.

**Linux:** auditd, `/var/log/auth.log`, `journalctl -u`, shell history, and
the sensor's own process events. **macOS:** Endpoint Security framework events
via the sensor, `log show`, and Unified Log.

**Corroborating sources outside the endpoint:** proxy / DNS logs for the C2
domain, email gateway for the delivery, identity logs for what the stolen
credential did next, and NetFlow for hosts the sensor does not cover.

## Process lineage that is worth escalating

- Office (`winword.exe`, `excel.exe`, `outlook.exe`) → `cmd.exe`,
  `powershell.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe`.
- Web server (`w3wp.exe`, `httpd`, `nginx`, `java`, `php-fpm`, `tomcat`) →
  any shell. This is a webshell until proven otherwise, and it means the
  initial access vector is remote and unauthenticated.
- Anything → `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`,
  `msiexec`, `installutil`, `msbuild`, `wmic`, `odbcconf`, `forfiles` with a
  remote URL or an unusual path in the command line.
- Non-system process opening a handle to `lsass.exe`.
- `services.exe` → a binary in `C:\Users\`, `%TEMP%`, `%PROGRAMDATA%`, or a
  path with a random name.
- Linux: `curl` or `wget` piped to a shell, writes to `/tmp` or `/dev/shm`
  followed by `chmod +x`, `bash -i >& /dev/tcp/`, `nohup` from a web process.
- macOS: `osascript` with a remote URL, `curl` into `~/Library`, `launchctl
  load` of a plist written seconds earlier.

Walk the tree up to the first ancestor that is a legitimate service or logon
session, and record where in that chain the disposition applied.

## Persistence, by OS

Killing a process does not remove any of these. Name the specific artifact
class in the evidence request rather than asking for "persistence."

**Windows:** `Run` / `RunOnce` keys (HKLM and HKCU), scheduled tasks
(`\Windows\System32\Tasks\` XML on disk, plus 4698), services
(`HKLM\SYSTEM\CurrentControlSet\Services`, 7045), WMI event subscription
(`root\subscription`: `__EventFilter`, `CommandLineEventConsumer`,
`__FilterToConsumerBinding`), Startup folder, `Winlogon` Shell/Userinit,
Image File Execution Options debugger, `AppInit_DLLs`, COM hijack
(`HKCU\Software\Classes\CLSID\...\InprocServer32`), DLL search-order
hijack and sideloading, BITS jobs, netsh helper DLL, LSA security package,
accessibility binary replacement, Office add-ins and templates, local account
creation plus privileged group add, and GPO / scheduled task pushed from a DC.

**Linux:** crontab and `/etc/cron.d`, systemd units and timers, `~/.bashrc`
and `/etc/profile.d`, `~/.ssh/authorized_keys`, `/etc/ld.so.preload` and
`LD_PRELOAD`, `rc.local`, udev rules, `at` jobs, kernel modules, PAM modules,
setuid binaries, and MOTD scripts.

**macOS:** `LaunchAgents` and `LaunchDaemons` plists in `~/Library`,
`/Library`, and `/System/Library`; login items; configuration profiles; cron;
`~/.zshrc`; system extensions; and TCC database modification.

## Time windows

- **Process tree:** back to the start time of the topmost ancestor, not a
  fixed window. A service-hosted implant may have started weeks ago.
- **Initial access:** T-24h to T-7d on email gateway, browser download history,
  removable media, and VPN or RDP logon events for that host.
- **Lateral movement:** T to now, plus outbound 4624 type 3 and type 10 from
  this host, and inbound to hosts sharing the same credential.
- **Persistence sweep:** unbounded. The artifact may predate the detection by
  months, so ask for the artifact's own creation timestamp.
- **Beaconing:** T-30d on proxy and DNS for the C2 indicator, looking for
  regular intervals rather than volume.
- **Credential lifetime after theft:** Kerberos TGT default 10 hours with a
  7-day renewal window; NTLM hashes valid until the password changes; browser
  session cookies until their own expiry.

## Telemetry that is not on by default

- **PowerShell script block logging (4104)**, module logging (4103), and
  transcription are all off unless enabled by policy. Without them you have the
  command line but not what an encoded or downloaded script actually did.
- **Process creation auditing (4688)** is off by default, and the command-line
  field within it requires a second, separate policy setting.
- **Sysmon** is not present unless deployed.
- **Sensor telemetry retention is shorter than detection retention.** Raw
  events are commonly held 7 to 90 days depending on license tier while the
  detection record persists much longer. A T-90d telemetry question may be
  unanswerable even though the alert is visible.
- **Reduced Functionality Mode.** After a kernel or OS update the sensor can
  run degraded, with prevention off and telemetry incomplete. Check the
  sensor's health state for the alert window before treating a gap as absence.
- **Coverage gaps:** the host may have been offline, the sensor may have been
  stopped or uninstalled, and Linux and macOS sensors see substantially less
  than Windows. Servers, appliances, contractor laptops, and OT hosts often
  have no sensor at all.
- File content, full packet capture, and most USB payload detail are not
  captured.

## What containment clears and what it leaves

**Network containment / host isolation** cuts the host off from everything
except the management console. It does not kill running processes, does not
remove persistence, does not undo lateral movement already completed, and does
not revoke credentials already stolen from the host. Persistence fires again
the moment the host is released.

**Killing the process** does not remove the scheduled task, service, WMI
subscription, or Run key that respawns it.

**Reimaging** clears the host and nothing else: domain credentials harvested
from it remain valid until rotated, and the initial access vector is still
open.

**A password reset does not invalidate a certificate.** If the attacker
enrolled a certificate for the user through ADCS, PKINIT authentication with
that certificate continues to work until the certificate is revoked or
expires. Same for a Kerberos ticket already issued, until its lifetime ends.

**Domain-side artifacts survive every host action:** added privileged accounts,
delegated permissions, ADCS template changes, GPO edits, and DCSync-derived
credentials including `krbtgt`.

Order the steps so the persistence artifact is removed before the host is
released, and say plainly what remains after each step.

## Common false positives

- **Administrative tooling.** PsExec, PDQ Deploy, SCCM (`ccmexec`), Tanium,
  Intune, Ansible, and remote support agents all produce remote execution that
  looks like lateral movement. Confirm the source host is a known management
  server.
- **Credentialed vulnerability scans.** Nessus and Qualys authenticate, spawn
  processes, and touch credential stores across many hosts at once.
- **Installers and updaters** legitimately use `msiexec`, `rundll32`, and
  `regsvr32`, and legitimately write to `%TEMP%`.
- **Backup and DLP agents** read enormous numbers of files, which resembles
  collection or ransomware staging.
- **Developer workstations.** Compilers, debuggers, `msbuild`, unsigned
  self-built binaries, and package managers pulling scripts.
- **Encoded PowerShell is not itself malicious.** Plenty of management tooling
  base64-encodes commands. Decode it before scoring.
- **Authorized red team.** Check for an active engagement window and a
  documented source host before scoring a textbook attack chain.

## Hypothesis clauses

Too generic — fits any suspicious-process detection:
> Confirmed if the process tree shows malicious activity after execution.

Specific enough to query:
> Confirmed if sensor telemetry for `aid` 4f2c...9b shows `w3wp.exe` as the
> `ParentBaseFileName` of the `cmd.exe` at 14:07:22Z, and IIS logs for that
> host show a POST to a `.aspx` path first requested within the preceding
> 10 minutes with no matching entry in the deployment manifest.

For the benign branch, name the management server, the deployment job ID, and
the field that would carry it.

## Severity

Score the malicious branch. High when the host holds or can reach domain
privilege, when credential access occurred (LSASS, hive dump, ticket
extraction), when the account is a service or admin account usable elsewhere,
or when the host is a server, DC, jump box, or build system. A single
workstation with a blocked commodity payload and no credential access is Low to
Medium even when the vendor rates it Critical.
