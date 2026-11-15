# CyberPatriot Windows Hardening — 2026 Edition

Hardening for **Windows 10 / 11** and **Windows Server 2019 / 2022 / 2025** CyberPatriot
images. Rebuilt from the 2019 Sharon High School script (teams 14-3178 / 15-3557)
around one rule: **reduce risk while gaining points** — audit first, back up always,
protect whatever the scenario needs, and never reboot automatically. No script can
guarantee a score or eliminate all risk.

## The 30-second version

```text
1. Drag this folder into the VM. Open the Scoring Report. Note your starting score.
2. Answer ALL Forensic Questions. (Hardening first can destroy the evidence.)
3. Read the README on the image desktop. Fill in, from that README:
     keep_services.txt      authorizedusers.txt      admins.txt      rdpusers.txt
   ...and delete the EDIT_ME line in each file you finish.
4. secure.bat -Mode Audit      (system audit; writes local reports and logs)
5. secure.bat                  (interactive hardening, step by step)
6. Work CHECKLIST.md, watch the Scoring Report, use -Rollback if a change costs points.
```

**First run only**, `secure.bat` prints the paragraph in [`AI_PROMPT.txt`](AI_PROMPT.txt)
before anything else: paste it into an AI model, paste the image README immediately after
it, to request critical/necessary services that must **not** be disabled (with
Windows service names, ports and dependencies) plus paste-ready contents for the four
`.txt` files. **Verify every line yourself** against the README.

## What it does, in run order

| Step | Module | Scoring categories it targets | Point-safety |
|---|---|---|---|
| 0 | Critical-services AI paragraph | — (scenario preparation) | Prints once per fresh folder copy |
| 1 | Preflight: OS/role detection, forensics gate, README-file gate | — | Apply modes stop until required gates pass |
| 2 | Backup: secedit, auditpol, firewall, services, selected registry keys, hosts, LGPO `/b` | — | Stops if core exports fail; recovery is partial |
| 3 | Recon reports: users/groups, shares, listeners, services, persistence (Run keys, tasks, IFEO debuggers, Winlogon, hosts, DNS, WMI), software | Malware, Misc, hints for Forensics | Read-only always |
| 4 | Passwords: one strong team-chosen password (never hard-coded) | User Policy, Password Policy | Skips you, built-ins, service-logon accounts; runs *before* password-age policy |
| 5 | Password + lockout policy (14 / 24 / 60d / 1d / 5·15·15) + conservative User Rights | Password Policy, Login Policy, Access Control | CIS/Microsoft-baseline values; lockout set *after* password changes |
| 6 | Security options (LSA/NTLMv2, UAC, logon, SMB signing…) + advanced audit policy & log sizes | Access Control, Login Policy, Misc | Role-aware (e.g. null-session pipes untouched on DCs) |
| 7/7B | Defender: remove planted exclusions, enable cloud/PUA, ASR (3 Standard Protection rules Block, rest Audit), signatures, quick scan; then **running-process triage** for backdoors/malware (Defender verdicts, path, signature, command line, parent, listeners/connections, persistence, service hosting) | Antivirus, Malware | Scoring-folder exclusions are **kept**; risky ASR/CFA stay in Audit. Process containment is evidence- and threshold-based: core/protected/scoring/AV/VM/kept-service processes and shared service hosts are never killed directly; a lone suspicious service goes through the normal dependency check; executables are hashed/reported, not deleted by the triage step |
| 8 | Firewall: all profiles on, inbound Block, **outbound Allow**, logging; risky multi-port/range inbound rules reported with program & remote address + per-rule disable choice | Firewall | Never blocks outbound (scoring + updates); never bulk-deletes rules; keeps critical-service ports |
| 9 | Insecure services, Remote Desktop (disable *or* secure-with-NLA), WinRM, then **automatic hardening of every service that must stay** (9C: RDP extras, IIS/Apache, FTP, DNS, DHCP, SMB, print, SSH, WinRM, SNMP, AD/LDAP, databases), SMBv1 (+ optional feature), LLMNR/mDNS, NetBIOS, old TLS, hosts, shares | Insecure Services, File Sharing & Permissions | `keep_services.txt` + **dependency shield** (every service a kept service needs is protected transitively and kept running; a candidate with running/auto-start/kept dependents is never disabled) + hard-coded protection for scoring/VM/core services; hardening never disables a kept service, changes its account, or forces certificate-based modes |
| 10 | Users & groups from your lists (create/add/remove **with previews**) + existing-user password hygiene (`PasswordNeverExpires`, `UserMayNotChangePassword`, `PasswordRequired`) | User Policy | Never you, never built-ins, never the last admin, never service accounts, never domain users on a DC; Delete needs `DELETE` typed per account |
| 11 | Prohibited Win32 & Microsoft Store (`Appx`) software (report + per-app uninstaller), **automated search for suspicious `.exe`/scripts, `.zip`/archives (with inner-content inspection), double-extension payloads, hacking tools, sensitive `.txt` files (content-scanned for plaintext passwords/keys/tokens/PII), & credential/dump artifacts** (`suspicious-files.csv`), and media files (reparse-point-safe **quarantine**, never bulk-delete) | Policy Violations (files/services), Malware | Excludes `C:\CyberPatriot`, `\Forensic`, `Windows\System32`, `WinSxS`, and `Program Files`; reads `.zip` headers without extracting; flags `.txt` secrets without echoing secret values or auto-quarantining; `C:\CP-Quarantine` is reversible until you choose otherwise |
| 12 | **Auto-updating necessary apps & dependencies (12A):** repairs Windows Update / Store / AppInstaller / Office C2R / Chrome / Edge / Firefox / Adobe updater services, tasks & blocking policies; ensures WinGet is ready; updates **platform/runtime dependencies first** (WinGet, VC++, .NET, WebView2, Java, Python, Node, Git, OpenSSL, pwsh), then **necessary apps** (`necessary_apps.txt`, curated essentials, service-derived tools), then Store/PowerShell/`pip`/`npm` dependencies + `.NET` EOL check; optional/auto Windows Update API install & recurring task; records `app-updates.txt`, `dependency-updates.txt`, `app-versions.txt`; legacy 2018 GPOs (12B, optional, default skip) | Updates | `prohibited_software.txt` and `!` version pins override updates; paid Acrobat edition mismatch guarded; exact WinGet ID/source only, never `--allow-reboot` or `--force`; never force-closes apps; re-verifies kept critical services running afterward |
| ✓ | Verification pass/fail table + summary of every change and warning | All | Tells you exactly what to undo if the score drops |

## Ways to run it

| Command | Effect |
|---|---|
| `secure.bat -Mode Audit` | **Dry-run.** Reports system state and proposed changes; writes local reports, logs and a prompt marker, but does not harden system settings. |
| `secure.bat` | Interactive (normal). Each module and each risky item asks first. Defaults are the safe/scoring choice. |
| `secure.bat -Mode ApplySafe -ForensicsDone -ReadmeConfigured` | Unattended-safe subset for *practice reruns only*. Refuses to start without both gate switches; passwords, account/group changes and share changes require an interactive run. Add `-AutoUpdate` (and optionally `-SkipWindowsUpdates`) to auto-run Step 12A updates too. |
| `secure.bat -Mode Update` | **Auto-update mode.** Unattended repair of update infrastructure + dependency-first updates for necessary apps, runtime dependencies, Store/PS/`pip`/`npm`, and Windows Updates (add `-SkipWindowsUpdates` to update apps/dependencies only; add `-ScanFiles` to also run the `.exe`/`.zip`/vulnerability file search). |
| `secure.bat -Rollback` | Restore the newest backup (policy, audit, firewall, service start-types, registry exports, hosts). |
| `secure.ps1 -ShowAIPrompt` | Show the Step-0 AI paragraph again, then continue with the selected mode. |

Settings you may tune without editing code (defaults are the documented baseline values):
`-MinPasswordLength`, `-PasswordHistorySize`, `-MaxPasswordAgeDays`, `-MinPasswordAgeDays`,
`-LockoutThreshold`, `-LockoutDurationMin`, `-LockoutResetMin`.

Run the non-destructive regression checks on Windows with
`powershell.exe -NoProfile -File tests\regression.ps1`. They do not replace VM testing.

## Configuration files (fill in from the image README)

| File | Contents |
|---|---|
| `keep_services.txt` | Critical services to **never** disable — and to **harden automatically in place** (Step 9C) — service names, display names, or plain words (`RDP`, `IIS`, `FTP`, `DNS`, `SMB`, `PRINT`, `SQL`/`DATABASE`, `SSH`, `WEBDAV`, `ANONYMOUSFTP` only if anonymous FTP is required, …). One per line. Whatever they depend on is protected too. |
| `authorizedusers.txt` | Every account allowed to exist. Keep the 4 built-ins. |
| `admins.txt` | Everyone allowed in **Administrators**. Keep `Administrator`. |
| `rdpusers.txt` | Non-admins allowed in **Remote Desktop Users** (only if RDP is critical). |
| `necessary_apps.txt` | Optional scenario list of required apps/runtimes to keep updated (only when already installed; never installs unrequested software). Prefix any line with `!` (e.g. `!Python`) to pin/skip updating it. |
| `prohibited_software.txt` | Name fragments to flag in installed programs. Edit per scenario — “prohibited” is scenario-specific. |
| `AI_PROMPT.txt` | The exact Step-0 paragraph printed on first run. |

Before applying changes, the three required configuration files must exist and have their
active `EDIT_ME` line removed. Comment lines may still mention it. `-ReadmeConfigured`
confirms the review for unattended mode; it does not bypass these checks. The RDP list
must also be edited before its group membership is changed. Audit can run before setup.

## Safety measures and limitations

- The **CyberPatriot/CCS scoring service, Defender, Firewall, Windows Update, Event Log,
  VM guest tools** and Windows core services are hard-protected; so are the account you're
  signed in as, built-in accounts, and any account a service signs in with.
- On a **domain controller**, domain users are report-only and AD/DNS/Kerberos/Netlogon/
  SYSVOL are protected; password policy warns that the real control is the Default Domain Policy.
- **Dependencies are never removed:** a service is only disabled if it is not needed by any
  kept/protected service (checked transitively) and nothing that depends on it is running,
  set to auto-start, or kept; stops are graceful (never force-cascaded), a failed stop leaves
  the startup type untouched, and services are never deleted. Disabled *dependencies* of a
  critical service are repaired to Manual so the critical service can always start, and the
  final verification FAILs loudly if any critical service — or anything it depends on — is down.
- No bulk anything: services stop only after dependency + keep-list checks; users delete only
  per-account with a typed confirmation; shares, firewall rules and uninstalls are per-item;
  media files are *moved to quarantine*, not deleted.
- Ordering matters: passwords change **before** the max-password-age policy (nobody is
  instantly expired), and the account-lockout policy is applied after resets, with accounts
  unlocked afterwards. Your *own* password and AutoAdminLogon are handled **last**, with a
  Win+L lock/unlock test before auto-logon can be turned off.
- The script **never reboots, logs you off, disables IPv6, blocks outbound traffic, enables
  BitLocker/Credential Guard, or touches `C:\CyberPatriot`** — each of those has cost real
  teams real points (see `docs/RESEARCH_AND_SAFETY.md` for the reasoning on every control,
  including the ones deliberately *not* automated).

## Repository map

| Path | Purpose |
|---|---|
| `secure.bat` / `secure.ps1` | Launcher / main hardening entrypoint (Windows PowerShell 5.1 compatible) |
| `modules/*.ps1` | Modular hardening components (`Common`, `BackupAndPreflight`, `ServiceShield`, `ReconAndPolicy`, `ProcessTriage`, `NetworkAndAccess`, `ServiceHardening`, `FileScanner`, `Updates`, `Verification`) |
| `.PSScriptAnalyzerSettings.psd1` | `PSScriptAnalyzer` rules enforced alongside `tests\regression.ps1` in CI |
| `CHECKLIST.md` | Printable manual lap: everything automation must not decide for you |
| `docs/RESEARCH_AND_SAFETY.md` | 2019 bug audit, source + risk analysis for **every** fix, validation method |
| `docs/UPDATE_BASELINES_2026.md` | Getting current Microsoft baselines/LGPO and applying them *by role* |
| `Policies/` | Unchanged 2018 MSFT baseline GPO backups (legacy Step 12B fallback only; see the role table before use) |
| `legacy/` | Archived 2019 script (`secure-2019-original.bat.txt`) and deprecated helpers (`admins.bat`, `GetLocalUsers.vbs`) |
| `LGPO.exe` | Microsoft Local GPO tool (update it per `docs/UPDATE_BASELINES_2026.md`) |

Runtime output (`Backups\`, `Reports\`, `Logs\`) is created next to the script and is
git-ignored — it contains machine state and must never be committed or shared.

## Honest limits

No script can promise 100/100: CyberPatriot scores image-specific vulnerabilities and
forensic answers that only a human reading *that* README can decide. This toolkit is built
to (a) cover every recurring scored category, (b) surface the image-specific findings in
reports instead of guessing, and (c) provide backups and recovery guidance where possible.
Rollback is partial: it does
not restore passwords, deleted users, group membership, removed shares, software updates,
or all registry values. Registry imports do not remove newly created values. Keep a VM
snapshot and recover individual changes manually where necessary. Rehearse on practice
images for your exact Windows builds before you trust it under time pressure.

*Original work by the Sharon High School CyberPatriot teams 14-3178 / 15-3557. See
`LICENSE.md`. Competition use is governed by the current CyberPatriot Rules Book.*
