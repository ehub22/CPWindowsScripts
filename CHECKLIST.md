# Competition Checklist — the manual lap (print this)

The script automates the repeatable 80%. The last points — and most penalties — are
human decisions. Work this list top to bottom. Times assume the current **4-hour** round.

## Before the round (host machine)

- [ ] Coach has the Unique Identifier(s) printed/screenshotted; checksums verified.
- [ ] Host meets current CyberPatriot Technical Specifications; VM player is the required one.
- [ ] You have rehearsed this runbook on a **practice image of the same OS** at least once.
- [ ] You have read the **current Rules Book** sections on resources/scripts/AI/outside help.
- [ ] Backup internet plan (hotspot) and a paper copy of this checklist.

## First 15 minutes on the image (change NOTHING yet)

- [ ] Enter the Unique Identifier **first**, exactly as issued. Confirm the Scoring Report loads.
- [ ] Write down: starting score, image OS/role, the exact time your 4 hours end.
- [ ] Read the **entire README/scenario** twice. Highlight: critical services, authorized
      users/admins, prohibited software/files, required software, every "do not" sentence.
- [ ] Open **every Forensic Question file**. Answer them now; note any you must research
      *before* hardening (file contents, hashes, user activity, deleted-file questions).
- [ ] Fill in `keep_services.txt`, `authorizedusers.txt`, `admins.txt`, `rdpusers.txt`
      from the README; delete each `EDIT_ME` line. (Training: the `AI_PROMPT.txt`
      paragraph + README produces these lists — then verify them by eye, line by line.)
- [ ] Optional but smart: `secure.bat -Mode Audit` and skim `Reports\…\recon.txt` —
      listeners, Run keys, scheduled tasks and IFEO debuggers often *answer* forensics.
- [ ] Start **Settings → Windows Update → Check for updates** in the background now.
      It is the slowest scoring category; never leave it for the last hour.

## Hardening lap (`secure.bat`, interactively)

- [ ] Keep the Scoring Report visible. After each module, refresh it. **Any drop = stop,
      read the penalty text, undo that one change first** (penalties are recoverable).
- [ ] Password step: write the team password on paper. Test it (Win+L) for any account
      you will actually sign in with — *before* any reboot.
- [ ] Services: every "PROTECTED" line should make sense against the README. If the
      script protects something you expected to disable, your keep-list is doing its job —
      re-read the README before overriding it by hand.
- [ ] Remote Desktop: if critical, confirm you can still explain *who* may use it, and
      that `rdpusers.txt` matches. If not critical, confirm the module disabled it.
- [ ] Users: be able to say, for every remaining account, which README line authorizes it.
      Check **all** privileged groups the script prints (Backup Operators, Hyper-V
      Administrators, Remote Management Users, Print/Server/Account Operators, Guests)
      in `lusrmgr.msc` — group nesting wins and loses quiet points.
- [ ] Defender: open Windows Security once. Real-time on, cloud on, no surprise
      exclusions, protection history reviewed. If a setting "didn't stick," Tamper
      Protection is why: toggle it off, re-apply that one setting, toggle it back **on**.
- [ ] Shares: open `fsmgmt.msc`. Every remaining share needs a README reason and a
      named audience (`Everyone: Full` is never the answer unless the README demands it).

## Things the script deliberately does NOT decide (your call, per image)

- [ ] **Domain controllers:** set domain password/lockout policy in the *Default Domain
      Policy* GPO (`gpmc.msc`) — local policy alone may not score. Review AD users,
      Domain Admins / Enterprise Admins, DNS zones, and DHCP scopes against the README.
- [ ] **Browsers & apps:** Step 12A auto-checks/updates the curated WinGet set; still update
      any app the README specifically names from Help → About, and **normally close/reopen
      browsers after their updates** (running copies keep the old version). Check
      `Reports\…\app-updates.txt` and `app-versions.txt`. Remove browser toolbars/
      extensions nobody can justify. **Never disable JavaScript** — the Scoring Report needs it.
- [ ] **IIS/FTP/DNS/DHCP/SMB/print/SSH/WinRM/SNMP/SQL that ARE critical:** Step 9C already
      hardens them in place and protects everything they depend on; finish the inside jobs it
      deliberately won't force (FTP: FTPS cert, no anonymous writes; IIS: remove sample
      sites, per-site auth; DNS: recursion audience; SQL: sa/root passwords, xp_cmdshell;
      SMTP: relay list; read `Reports\…\hardened-services.txt`).
- [ ] **BitLocker:** do not enable it inside a timed VM without TPM/recovery planning.
      Policy settings are not worth a recovery lockout. Report-only is intentional.
- [ ] **Credential Guard / VBS / Windows LAPS:** do not force-enable mid-round
      (UEFI, reboots, nested-virtualization and lockout risks). LSA Protection
      (`RunAsPPL`) *is* set by the script and takes effect at reboot.
- [ ] **Clear pagefile at shutdown:** left off — it can add many minutes to shutdown
      inside the round. Only enable late, only if you are confident about end-of-round timing.
- [ ] **Default admin shares (`C$`, `ADMIN$`, `IPC$`):** left alone. Touch them only if
      the scenario explicitly forbids administrative shares.
- [ ] **Per-user settings** (screensaver lock/timeout, Office macro policy, browser
      settings for *other* users): set via `gpedit.msc` User Configuration when the
      README points at user behavior; machine policy can't cover every profile.
- [ ] **Running malware/backdoors:** check Step 7B's `suspicious-processes.csv` and
      Defender Protection history. The script only directly stops evidence-backed,
      non-service processes under its thresholds; finish the job by removing the
      matching persistence (service/task/Run/WMI/startup entry) one item at a time.
- [ ] **Persistence sweep by eye:** walk `recon.txt` — unknown listening ports,
      scheduled-task *actions*, Run/RunOnce values, Startup folders, IFEO `Debugger`
      values (Sticky-Keys backdoor), `Winlogon Shell/Userinit`, WMI subscriptions,
      services running from `Temp`/user folders, unquoted service paths. Remove only
      what you can explain, after forensics, one item at a time, checking the score.
- [ ] **Event Viewer sanity:** Security log is actually recording logons; no service is
      crash-looping after your changes (`services.msc` + System log quick scan).
- [ ] **Time & date:** VM clock sane (Kerberos, certificates and updates care).
      Do not stop the Windows Time service.

## Final 30 minutes

- [ ] Re-read the README **top to bottom, once more, out loud**. Check off every sentence.
- [ ] Re-answer/re-save every Forensic Question; confirm the points registered.
- [ ] Confirm every critical service is **Running** (`services.msc`), every authorized
      user can sign in, and you know the password for the account you'll leave signed in.
- [ ] Finish updates. Reboot **once** only if updates demand it and time remains —
      passwords written down, lock/unlock tested first. After reboot, re-check:
      scoring service running, critical services running, score held or improved.
- [ ] Decide on quarantined files (`C:\CP-Quarantine`): leave quarantined (safe default)
      unless you are certain deletion is required and safe. Never empty it blindly.
- [ ] Final Scoring Report screenshot/notes: score, penalties (should be none), anything
      still red and why. Shut the image down **properly** (or per current round
      instructions) well before your period expires — then delete images as the rules require.

## If something breaks (in order)

1. Read the Scoring Report penalty text — it usually names the service/user/share.
2. Re-enable/re-create just that one thing (`services.msc`, Start, Automatic; etc.).
   Penalty points return when the conflict is corrected.
3. `secure.bat -Rollback` restores policy/audit/firewall/service start-types/registry/hosts.
4. Quarantined files: move back per `Reports\…\quarantine-log.csv`.
5. Locked-out account: sign in as another admin → `lusrmgr.msc` → unlock / reset.
   No other admin? That's why the script refuses to disable the last one — don't undo that protection by hand.
6. Scoring Report stale/grey: check the image still has internet (port 80/443 out),
   the **CyberPatriot Scoring** service is Running, and nothing quarantined
   `C:\CyberPatriot`. Never reinstall/move the scoring client; contact CPOC support per the round instructions.
