# Research & Safety Audit — why every change exists (and what was wrong before)

Researched October 2026 against: the CyberPatriot 18 Rules Book (2025–26, Change 2) and
CP-19 (2026–27) public schedule/coverage, Microsoft Security Baselines and the Security
Compliance Toolkit (Windows 11 24H2/25H2, Windows Server 2025 v2506/v2602), Microsoft
Learn (Defender ASR reference — including the exact rule GUIDs used in `secure.ps1`),
CIS Benchmarks for Windows 11 / Server 2022 (v3–v5 family), and DISA STIG concepts.
Primary links are collected at the end. Baselines differ in a few values; where they
differ, the script picks the value that (1) satisfies the most scoring-style range checks,
then (2) carries the least lockout/breakage risk in a timed VM. Each such choice is
flagged below and exposed as a parameter when it matters.

---

## 1. How CyberPatriot scoring punishes scripts (the design constraints)

From the CP-18 Rules Book scoring/penalty sections and years of round instructions:

- CCS re-checks the image continuously. **Undoing a fix, or doing anything that "conflicts
  with the scenario," loses points** — deleting a needed user or stopping a required
  service are the canonical examples. Penalty points are recoverable by correcting the
  action. *Design consequence:* backups before changes, quarantine-instead-of-delete,
  per-item confirmations, and a verification pass whose job is to point at rollbacks.
- **Not all vulnerabilities in an image are scored.** A fix that earns nothing is not
  proof of error. *Consequence:* apply the full recurring-category control set; don't
  chase a single missing point by breaking invariants.
- **Never delete/disable/tamper with `C:\CyberPatriot` or the Scoring Service**, keep AV
  from interfering with it, and keep the image able to reach the scoring server
  (outbound port 80 historically; 443 as well). The Scoring Report also needs JavaScript.
  *Consequence:* hard-coded protected services/paths, outbound firewall pinned to Allow,
  Defender exclusions for the scoring folder preserved, no JS-killing browser policy.
- Round vulnerability categories published by CPOC: *Access control & settings, Insecure
  services, Policy violations (files/services), Antivirus, File sharing & permissions,
  Login Policy, Malware, Password Policy, Firewall, Updates, User Policy, Forensics
  Questions, Miscellaneous.* The module table in `README.md` maps 1:1 onto these.

## 2. Rules audit (2025–2027) — read this before trusting any public toolkit

- **Scripts:** allowed in online rounds *at your own risk* (no score appeals for script
  failures), must be created by **your own team's competitors** — not other teams,
  coaches, mentors or team assistants; teams from the same school may not collaborate on
  or share scripts; pre-written scripts are prohibited at **National Finals**.
  (CP-18 §3011.4; carried forward in CP-19 coverage.)
- **AI:** CP-19 §3010.4, as reported by multiple 2026 season sources, prohibits AI tools
  (including chatbots and AI-generated scripts) **during competition rounds** and paid AI
  products in connection with the competition at any time; free AI tools remain usable
  for **training outside rounds**. This is why the Step-0 AI paragraph in this repo is
  labelled training-only and has a manual equivalent. **Verify against the signed Rules
  Book for your season** — this document summarizes secondary reporting where the CP-19
  book itself was not publicly fetchable.
- **Sharing:** publicly posting/distributing scripts or resources created for CyberPatriot
  is prohibited (§3011.5 family). Keep your team's operational copy private.
- **Outside assistance / staging** (§3010–3011): no outside advice during rounds, no
  staged internet resources/tool transfers into the image beyond what the rules allow.
  Bring tools the allowed way, and do your rehearsing before the round.

Net effect on this repo: it is positioned, labelled and structured as **training
material** a team studies, rehearses with on practice images, and re-authors — not as a
drop-in competition download. The `LICENSE.md` team restriction from the original authors
is retained.

## 3. Bugs found in the 2019 script (all fixed or removed; original archived in `legacy/`)

1. **Automatic service mode guaranteed penalties.** One flat list disabled — among others —
   `DNS`, `W3SVC`/`IISADMIN`, FTP (three names for it), SMTP, `Dfs`, `NtFrs`, `MSDTC`,
   `Spooler`, `VSS`, `PolicyAgent`, `SharedAccess`, `Themes`. On any image where DNS/AD,
   a website, FTP, mail or printing was the scenario, automatic mode broke the critical
   service. Several names no longer exist (`ERSVC`, `helpsvc`, `SZCSVC`); `seclogon`
   disabling breaks *Run as*, which competitors themselves need.
   Also, `sc config <svc> start=disabled` omits the space `sc.exe` requires after `=`,
   so disables could silently fail. → Curated two-group list, keep-list + dependency
   checks, `Set-Service`, per-service judgement group.
2. **Applied all eleven 2018 GPO backups to every machine** (`LGPO /g .\Policies`):
   Windows 10 *and* Member Server *and* Domain Controller *and* BitLocker *and*
   Credential Guard *and* DC-VBS baselines simultaneously. VBS/Credential Guard in a
   VMware guest risks unbootable or driver-broken VMs; DC user-rights on a workstation
   sharing files breaks network logon for its own users. → GPOs now optional, role-picked,
   staged, backed up; equivalent settings applied directly and auditable in `secure.ps1`.
3. **Published password.** Every account was set to one password committed to a public
   repository (so "everyone knows it"), including — via `GetLocalUsers.vbs` enumerating
   *all* SAM accounts — `WDAGUtilityAccount` and any **service-logon account** (changing
   those breaks their services on next start: a self-inflicted critical-service penalty).
   The string also contained a batch `^` escape, so the *typed* password in the old
   README didn't match what batch actually set. → SecureString prompt, strength-checked,
   never stored in the repo; built-ins, current user and detected service accounts skipped.
4. **`net user administrator /active:no` unconditionally.** If you were signed in *as*
   the built-in Administrator (common on images), the next reboot is a lockout. The GPO
   half repeated it. → SID-500 detection, refuse when it's you or the only admin, warn
   about knowing the surviving admin's password first.
5. **Registry values that were wrong or self-contradicting:**
   - SMB server signing set to `0` ("pursuant to checklist") while its own GPO set `1`;
     whichever ran last won. → Both now `1` (require behind a prompt for legacy devices).
   - `DisablePasswordChange=1` + `MaximumPasswordAge=15` for Netlogon (domain secure
     channel rot; GPO said `0`/`30`). → `0`/`30`.
   - `auditbaseobjects=1` and `fullprivilegeauditing=1` — CIS recommends **Disabled**
     for both (log flooding). → Explicitly `0` (also heals machines the old script touched).
   - IE `RunInvalidSignatures=1` (*allows* running invalidly-signed downloads) and
     `LOCALMACHINE_CD_UNLOCK=1` (*unlocks* the lockdown) — both backwards; IE is retired
     in Windows 11 anyway. → Removed; Edge SmartScreen policies instead.
   - CD-ROM AutoRun written under `HKCU\SYSTEM\...` (wrong hive) with value `1`
     (enables). → `HKLM\...\CDROM AutoRun=0` + `NoDriveTypeAutoRun=255`.
   - `AllocateCDRoms`/`AllocateFloppies` written as `REG_DWORD`; Windows expects
     `REG_SZ`. → Written as strings (matching the secedit template form).
   - `UseMachineId=0` at the LSA root; the real policy value is `MSV1_0\UseMachineId=1`.
   - SMB idle disconnect `45` minutes (CIS ceiling is 15). → `15`.
   - `ClearPageFileAtShutdown=1` by default — minutes of extra shutdown inside a timed
     round. → Not automated; documented as a conscious end-of-round choice.
   - Dozens of `HKCU` values that only affect the signed-in competitor, not the machine
     policy scoring engines read. → Machine policy keys used; HKCU retained only for
     Explorer hunting aids (show hidden files/extensions).
6. **User-audit logic bugs:** the `seen[…]` array was shared between the users pass and the
   admins pass (so "missing admins" detection was wrong); `admins.bat` parsed the first
   token of `net localgroup` output (breaks names with spaces, `DOMAIN\user`, nested
   groups — and can eject `Domain Admins`); comparisons were brittle with case/spaces and
   gave no preview before deleting accounts (and their profile evidence, before forensics).
   → `Get-LocalUser`/`Get-LocalGroupMember`, full preview table, per-account choices,
   delete requires typing `DELETE`, account details exported to Backups first.
7. **Media "automatic mode" deleted `.jpg/.png/.gif` across `C:\Users`** — i.e. work
   product on photography/media scenarios, program assets under AppData, and potential
   forensic evidence — irreversibly. → Report → per-extension **quarantine to
   `C:\CP-Quarantine`** with a restore log; images scanned only on opt-in; CyberPatriot
   and Forensics paths excluded; forensics gate precedes everything.
8. **Fragile plumbing:** located itself by recursively searching `C:\Users` for
   `LGPO.exe`; `net sessions` admin test fails when the Server service is off; `cd
   C:\Users` mid-script broke later relative paths; no logging, no backups, no audit
   mode, single failure could derail the run. → `%~dp0`/`$PSScriptRoot`, token-based
   elevation with self-relaunch, transcript + summary, per-setting try/catch.

## 4. Control-by-control: source, scoring logic, risk, guard

Values cite CIS Benchmark (Windows 11 Enterprise / Server 2022) and Microsoft baselines
unless noted. "Range-safe" means the value satisfies typical CCS-style checks that test
thresholds (≥/≤/enabled) across the previous CyberPatriot checklist generations.

| Control | Value chosen | Source / why it scores | Risk → guard |
|---|---|---|---|
| Min password length | 14 | CIS L1 = 14; MSFT domain baseline = 14 | Exactly 14 avoids the pre-2004 `RelaxMinimumPasswordLengthLimits` requirement for >14 |
| Password history | 24 | CIS = 24 | Admin resets are exempt; no lockout risk |
| Max password age | 60 days | MSFT baseline = 60; CIS allows ≤365 ≠0; older CP checks expect ≤90 | Instant-expiry → passwords rotated in Step 4 *before* this applies; `-MaxPasswordAgeDays` tunable |
| Min password age | 1 day | CIS/STIG = 1 | Prevents history-cycling; admin resets exempt |
| Complexity / reversible encryption | On / Off | CIS L1 | Team password is strength-validated first |
| Lockout threshold | 5 | CIS "5 or fewer, not 0"; Server-2025 baseline moved to 3 | 3 is a self-lockout trap mid-round → 5, applied after resets, accounts then unlocked; tunable |
| Lockout duration / reset | 15 / 15 min | CIS ≥15; MSFT 15/15 | — |
| User rights | Deny-Guests-*; empty `SeCreateToken/SeTcb/SeCreatePermanent/SeTrustedCredMan/SeLockMemory/SeEnableDelegation`; admin-only backup/restore/debug/load-driver/security/take-ownership/pagefile/profile/sysenv/volume/remote-shutdown | CIS 2.2 family; assignments mirror the repo's 2018 GptTmpl SIDs | `SeImpersonate/SeCreateGlobal/SeIncreaseQuota` keep Local/Network Service (removing breaks IIS/SQL); "access from network / log on locally" **not** reassigned (lockout); Local-account deny added only when SMB/RDP aren't critical |
| UAC suite | EnableLUA=1, Admin consent-on-secure-desktop=2, User deny=0, PromptOnSecureDesktop=1, installer detection, secure UIA paths, virtualization, FilterAdministratorToken=1, LocalAccountTokenFilterPolicy=0 | CIS 2.3.17 | `ValidateAdminCodeSignatures=0` per CIS, so unsigned competition tools still elevate |
| Interactive logon | hide last user, hide lock-screen identity (3), require CAD, 900 s inactivity lock | CIS 2.3.7 | Banner only if the README dictates text (prompted, default no) |
| LSA/NTLM | LmCompatibilityLevel=5, NoLMHash=1, NTLMMin*Sec=537395200 (NTLMv2 + 128-bit), WDigest UseLogonCredential=0, RestrictRemoteSAM=admins-only SDDL, RunAsPPL=1, LSASS IFEO AuditLevel=8 | CIS 2.3.11; MSFT (WDigest policy removed from Server-2025 baseline as deprecated — the registry value remains harmless where honored); repo GptTmpl values reused where confirmed | NTLMv1-dependent ancient devices would break — acceptable on images, noted in docs; RunAsPPL takes effect at reboot (score checks the setting) |
| Anonymous/null sessions | RestrictAnonymous(SAM)=1, EveryoneIncludesAnonymous=0, LimitBlankPasswordUse=1, RestrictNullSessAccess=1, empty NullSessionPipes/Shares | CIS 2.3.10/2.3.11 | **Skipped on DCs** (domain functions use those pipes) |
| Domain member / Netlogon | MaxPwAge=30, DisablePasswordChange=0, RequireStrongKey/SignOrSeal/Sign/Seal=1, RefusePasswordChange=0 | CIS 2.3.5–2.3.6 | Registry-only on standalone machines (service absent = harmless) |
| SMB | Server+client signing enabled; required behind a prompt; insecure guest logons off; SMB1 server off + `mrxsmb10` start=4; plaintext-passwords off | CIS 2.3.8/2.3.9; SMB1 deprecation; Server 2025/Win11 24H2 remove NetBIOS SMB ports & NTLMv1 | Prompt covers prehistoric NAS scenarios; feature-uninstall not forced (service state is what scores) |
| AutoPlay/AutoRun | NoDriveTypeAutoRun=255, NoAutoRun=1, CDROM AutoRun=0 | CIS 18.9 AutoPlay | — |
| Remote Assistance / WinRM | RA solicited+unsolicited off; WinRM Basic & unencrypted off (client+service policy) | CIS 18.9 RA, 18.10 WinRM | Kerberos WinRM still works if the scenario needs it; service stop is a separate prompt |
| CredSSP | AllowEncryptionOracle=0 | MSFT (CVE-2018-0886) | Breaks RDP only to *unpatched pre-2018* hosts |
| PowerShell | ScriptBlockLogging on | MSFT baseline | Transcription left off (secrets in logs, slow) |
| SmartScreen | System on at **Warn**; Edge SmartScreen + PUA on | CIS Edge / MSFT | Block-level would hard-stop legitimate downloaded tools mid-round → Warn |
| DEP/SEHOP | bcdedit nx OptOut; DisableExceptionChainValidation=0 | STIG | Applies at reboot; prompted |
| Advanced audit | All subcategories Success+Failure; SCENoApplyLegacyAuditPolicy=1; cmdline in process-creation | MSFT (2025 baseline enables cmdline logging; audit.csv subcategories in repo) | Log flooding → logs enlarged *first* (Security 192 MB, others 32 MB, policy + wevtutil); superset satisfies Success-only/Failure-only checks |
| Defender core | Real-time/behavior/IOAV/script/archive/removable/mapped-drive scanning on; MAPS Advanced; SendSafeSamples; PUA Enabled; CloudBlockLevel High; CFA **Audit**; NetworkProtection **Audit** | MSFT Defender baseline (repo GPO family) + current Learn docs | Block modes for CFA/NP can sever required apps/sites → Audit during rounds; Tamper Protection caveat printed with the manual toggle path |
| Defender exclusions | List all; remove per-item (auto in ApplySafe); **keep** CyberPatriot/CCS paths | Planted-exclusion vuln pattern; CPOC "AV must not interfere with scoring" | Removing an exclusion an app *legitimately* needs → per-item prompt + transcript |
| Running-process triage (7B) | Scores live `Win32_Process` evidence: active `Get-MpThreat`/`Get-MpThreatDetection` path match, system-name impersonation, remote-shell/credential-tool names, user-writable or deleted executable, Authenticode status/signer, LOLBin command line, Office/browser parent, listening/public-IP activity, exact Run/task persistence and service hosting. Saves SHA-256/command/network evidence to `suspicious-processes.csv`. Only the exact non-service PID is stopped (graceful main-window close attempted first), never a name sweep or process tree; Defender CustomScan is then offered/run for that one file. A lone suspicious service is routed through `Disable-ServiceSafe`; shared/kept service hosts are report-only | Microsoft Defender threat cmdlets (`IsActive`, resources), `Win32_Process`, Authenticode and `Start-MpScan CustomScan` are built-in, local evidence sources; no executable/hash leaves the machine for a third-party verdict | Heuristics cannot prove malware and can miss rootkits, code injection, or a malicious DLL in genuine `svchost`. Automatic stopping in ApplySafe is limited to Defender-confirmed standalone processes or >=90-score standalone processes, and to Defender-confirmed lone services only; visible-window and child-process cases are not auto-killed without a Defender verdict; Interactive mode defaults high scores to stop but shows every reason first. Core/wrong-path system processes, scoring/Defender/VM tools, this script's family, kept-service hosts and their descendants are shielded. Stopping is containment only—persistence and the file must still be investigated |
| ASR rules | 3 Standard Protection **Block** (vulnerable signed drivers `56a863a9…`, LSASS theft `9e6c4e1f…`, WMI persistence `e6db77e5…`); 15 others **Audit**; Exchange webshell rule intentionally unset | Microsoft Learn ASR reference (all 19 GUIDs verified there in Oct 2026) | Audit cannot break critical apps/scoring client; MS designates the 3 as safe-to-Block without extensive testing |
| Firewall | All profiles on; inbound Block, **outbound Allow**; log allowed+blocked @16 MB/profile | CIS 9.1–9.3 + CP scoring connectivity | Existing rules never bulk-deleted; risky inbound allows reported with keep-list/port awareness for manual triage |
| Services Group 1 | Telnet/FTP/IIS/SMTP/SNMP/RemoteRegistry/RpcLocator/SSDP/UPnP/Fax/Bluetooth/RRAS/simptcp/Computer Browser/Xbox ×4/OpenSSH-Server | CIS §5 + CP "insecure services" history (e.g. CP-18 key: "FTP stopped and disabled") | Keep-list tokens (IIS, FTP, SSH…) + display-name match + dependency check + protected core set; unedited keep-list forces per-service questions |
| Services Group 2 | Spooler, LanmanServer, FD×2, ICS, RasMan/RasAuto, SCardSvr, seclogon, TrkWks, lmhosts, ssh-agent | PrintNightmare/STIG spooler-on-DC guidance; the rest are genuine judgement calls | Asked one-by-one, default **keep** (Spooler-on-DC defaults to disable); ApplySafe keeps them |
| Features | PowerShell v2, TelnetClient, TFTP offered per-feature | PSv2 has no AMSI/logging (downgrade attack) — CIS 18.10 | Only offered when currently Enabled; -NoRestart |
| RDP | Critical → on + NLA=1 + SecurityLayer=2 + MinEncryption=3 + password prompt + group cleanup via rdpusers.txt; else deny + stop 3 services + kill FW group | CIS 18.9 Terminal Services; CP-18 key lists both "RDP NLA enabled" *and* "Remote Desktop Users updated" as scored items | The fork is driven by `keep_services.txt` first, direct question second |
| Protocols | LLMNR off (EnableMulticast=0); NetBIOS-per-adapter prompted (default no); SSL2/3+TLS1.0/1.1 off, TLS1.2 on; .NET SchUseStrongCrypto/SystemDefaultTlsVersions | CIS LLMNR; MS NetBIOS/LLMNR phase-out (2022→, 24H2/2025 SMB changes); TLS hardening staples | Cipher-suite **order untouched** (can sever Update/scoring); WPAD report-only (school proxies); IPv6 & Windows Time never touched |
| Hosts file | List active lines; offer default reset | Planted-redirect classic | Original backed up; requires your confirmation |
| Shares | Per-share Remove / revoke-Everyone / Keep; SYSVOL/NETLOGON & admin shares protected/reported | CP "File sharing & permissions" | Removing a share never deletes the folder |
| Users/groups | Create missing authorized (with team password), add missing admins, strip unauthorised admins, disable Guest, conditional SID-500 disable, RDP-group sync, delete unauthorised users **per-account with typed confirmation** | CP "User Policy" (per-user points in published keys) | Forensics gate + edited-lists gate + current-user/built-in/service-account/last-admin guards; DC = report-only |
| Software/files | Registry-uninstall scan vs editable prohibited list (never `Win32_Product` — it triggers MSI self-repair); per-app own uninstaller; media scan → **quarantine** per extension | CP "Policy violations"; CP-18 key examples (Wireshark/CCleaner removed; Chrome/Notepad++ updated) | No silent/bulk uninstall; no deletion path for files at all |
| Updates | AU policy (auto, scheduled, **NoAutoRebootWithLoggedOnUsers=1**); documented Microsoft Update COM opt-in (`AddService2(...,7,"")`, skipped when `UseWUServer=1`); un-disable WU/BITS/UsoSvc; UsoClient scan; optional Update-API install; supported Office Automatic Updates 2.0 task repair/start (not unsupported `OfficeC2RClient.exe` switches); disabled Chrome/Edge/Firefox/Adobe updater-service repair; curated WinGet upgrades by exact ID/source (`winget list --upgrade-available`, then silent upgrade) for Chrome/Firefox/Edge/Notepad++/Adobe Reader/VLC/7-Zip; bulk `--all` is a separate default-No opt-in with a critical-app retest warning | CP "majority of updates installed" and named app/browser updates are scored; Microsoft Learn WinGet list/upgrade docs + official winget-pkgs IDs; Microsoft WUA opt-in and Microsoft 365 update-process docs | Script never passes WinGet `--allow-reboot`/`--force`, never force-closes running apps, skips apps matching `prohibited_software.txt`, treats WinGet `0x8A15002B` as already-current, and reports MSI 3010 as an operator-timed pending reboot. Installed updates are not rollback-able, which is why the candidates are displayed before the curated prompt and bulk upgrade defaults to No |
| Legacy GPOs | Not applied by default; optional role-staged LGPO import | 2018 baselines superseded by Win11 25H2 / Server 2025 2602 | Double confirmation + rollback warning; BitLocker/Credential Guard/VBS GUIDs never staged |

| Dependency shield (2026 hardening update) | Transitive closure over `ServicesDependedOn`: kept/protected services protect everything they need; a disable candidate is refused while any transitive dependent is Running, auto-starting, or kept (state read fresh per candidate, so W3SVC-then-WAS in one run still works); graceful stop before `Disabled`, never `-Force`, services never deleted | Scoring engines award points per *check* on the critical service itself; a running required service whose dependency was killed scores as a penalty every cycle, and at the next boot the dependent fails to start at all | Over-protection bias: an insecure service may survive one pass if an auto-start dependent exists; the log says exactly which dependent to review, so the fix costs a re-run, never points |
| Kept-service availability | Scenario-kept services are verified Running (Disabled repaired to Automatic, or Manual for on-demand helpers; Disabled *dependencies* repaired to Manual - never removed); restart-on-failure recovery on critical services; Manual/trigger-start helpers are protected but never force-started (e.g. Remote Registry riding the RDP token) | Same logic: a stopped critical service bleeds points every scoring cycle; recovery actions convert crashes into restarts | Only keep-list/operator-kept names become seeds - protected *core* services are never force-started; failure to start is reported as CRITICAL with full dependency state |
| Kept-service hardening (9C) | RDP: CIS L1 already in 9B; opt-in L2 redirection/session block (`fDisableClip/Cdm/Ccm/LPT/PNPRedir`, `MaxIdleTime` 900000, `MaxDisconnectionTime` 60000, `fSingleSessionPerUser`) - **IIS**: directoryBrowse off, logging on, app-pool LocalSystem report/opt-in least privilege, WebDAV warning (backup first via `Backup-WebConfiguration`) - **Apache**: ServerTokens/ServerSignature/TraceEnable/FileETag with backup + `httpd -t` + auto-restore - **FTP**: anonymous off + Basic on per site unless `ANONYMOUSFTP` - **DNS**: cache pollution protection (`Set-DnsServerCache -PollutionProtection`); `TransferAnyServer` -> `TransferToZoneNameServer` (official enum spelling is singular); secure-only dynamic updates opt-in and AD-integrated only; recursion untouched - **DHCP**: `Set-DhcpServerAuditLog -Enable`, conflict detection opt-in, restart opt-in - **SMB**: SMB2 ensured, SMB1/guest *auditing* only; encryption opt-in in transition mode (`RejectUnencryptedAccess:$false` set with it) - **Print**: KB5005010 PointAndPrint trio; `RegisterSpoolerRemoteRpcEndPoint=2` only when local-only AND no shared printers exist - **SSH**: safe `sshd_config` subset inserted before any `Match` block, `sshd -t` gate, restore-on-failure; password auth untouched - **WinRM**: Service `AllowBasic=0` policy; listeners reported, HTTPS never forced - **SNMP**: write communities (rights >= 8) reduced to ReadOnly (4), names never changed; empty `PermittedManagers` warned - **DC**: `LdapEnforceChannelBinding=1` (audit-only, rejects nobody); required LDAP signing opt-in, Interactive-only - **DB/SMTP/VPN/Telnet**: account/listener reports + precise manual guidance; SQLBrowser disable opt-in and only when not keep-protected | Microsoft Learn cmdlet docs (DnsServer/DhcpServer/SmbShare/WebAdministration), MS KB5005010, ADMX CSP references for every registry value, CIS RDS/IIS values - each setting individually verified against a primary or official source before inclusion | The pattern everywhere: *harden the service that stays, never make it unreachable.* Nothing changes a kept service's account, port, shares/zones/sites, community/user names, or forces cert-based encryption; every config-file edit is backup -> syntax-test -> auto-restore; anything that can cut off legitimate users (RDP redirection, DNS secure updates, LDAP signing, FTPS, SMB reject-unencrypted, SSH password auth off) is opt-in with the consequence printed in the question, or report-only |

### Deliberate non-automations (each is a researched decision, see CHECKLIST for the manual path)

BitLocker enablement, Credential Guard/VBS, Windows LAPS policy, domain-wide AD changes,
ClearPageFileAtShutdown, Controlled Folder Access in Block, Network Protection in Block,
cipher-suite reordering, IPv6 disabling, admin-share removal, account renames for
Administrator/Guest (breaks name-based lists and tasks for at most a cosmetic check),
Kerberos encryption-type forcing on DCs, and any change inside a *critical* application
(IIS sites, FTP auth, DNS zones, SQL logins) — the script protects those services and
tells the human exactly where to look instead.

## 5. Validation performed in this environment (no Windows host available)

- **Full-grammar parse** of `secure.ps1` with `tree-sitter-powershell` (PyPI):
  final result **0 error nodes** on a validation copy. Getting there surfaced three
  *grammar* limitations, verified with minimal repros: (a) bareword comma lists
  (`Select-Object Name, Status` — valid PowerShell) are rejected; the code was
  normalized to quoted property lists, which are equally valid and unambiguous;
  (b) digits inside parameter names (`-EnableSMB1Protocol`) are rejected; the
  validation copy renames that single real parameter to parse the rest — the shipped
  file keeps the true Microsoft parameter name; (c) boolean arguments were normalized
  to the `-Parameter:$false` form.
- **Structural checks:** string/comment-aware brace accounting balances at every
  function boundary; file is pure ASCII (Windows PowerShell 5.1 reads BOM-less files as
  ANSI — non-ASCII in string literals is a classic silent-corruption trap); no
  PS7-only syntax (`??`, `?.`, `&&`/`||`, ternary) — 5.1 ships on the images.
- **Static danger sweep:** every `Remove-*`/`Disable-*`/`Stop-*` call site traced to its
  guard (keep-list/protected set/confirmation/audit early-return); no reboot, logoff,
  file-deletion, or format calls; the old hard-coded password no longer exists outside
  the archived legacy file; Audit mode audited to guarantee **zero writes** (including
  a caught bug where `Set-RegValue` created missing keys before its audit check — fixed).
- **What still requires your rehearsal:** runtime behaviour on real Windows images
  (cmdlet availability across SKUs/Core, Tamper Protection interactions, DC behaviours),
  and how CCS thresholds on *your* season's images score the chosen values. Run
  `-Mode Audit` on each practice image first and diff the verification table against the
  practice answer key — that is the intended tuning loop, and the account-policy knobs
  are command-line parameters for exactly that reason.

## 6. Sources (accessed October 2026)

- CyberPatriot 18 Rules Book (FINAL, Change 2) — uscyberpatriot.org (scoring/penalties,
  §3009–3014 resources/scripts/assistance, §4002–4003).
- CyberPatriot 19 competition timeline & challenges — uscyberpatriot.org; 2026 season
  coverage summarising CP-19 §3010.4 (AI) / §3011.5 (publication ban), e.g.
  hackerdna.com "CyberPatriot Guide 2026".
- Microsoft, *Security baseline for Windows Server 2025* (v2506 Jun 2025; v2602 Feb 2026)
  — Tech Community / Security Compliance Toolkit download (details?id=55319): lockout
  threshold change, WDigest removal rationale, NTLM auditing, sudo/IE-COM/print changes.
- Microsoft Learn, *ASR rules reference* (updated 2026-09-09) — all rule GUIDs, Standard
  Protection designation, per-rule caveats (LSASS noise, WMI-persistence ConfigMgr note,
  webshell "leave Not Configured" guidance → rule left unset).
- Microsoft Learn, *SMB security hardening*; *Features removed/deprecated in Windows
  Server* (SMB1, Computer Browser, NTLMv1 removed in 24H2/2025).
- CIS Benchmarks: Microsoft Windows 11 Enterprise (v3–v5) and Windows Server 2022
  (v3–v5) — §1 account policy, §2 user rights/security options, §5 services,
  §9 firewall, §17 advanced audit, §18 administrative templates. (CIS current versions:
  check CIS WorkBench; values used here are stable across those revisions.)
- Microsoft Security Compliance Toolkit 1.0 package listing (Oct 2026): Windows 11
  v24H2/v25H2/v26H2, Windows Server 2022, Windows Server 2025 2602 baselines,
  LGPO, Policy Analyzer, Microsoft Edge & Microsoft 365 Apps baselines.
