# Updating to the 2026 Microsoft security baselines (do this on a prep machine)

The `Policies/` folder in this repo is Microsoft's **November 2018** baseline set for
Windows 10 1809 / Server 2019. `secure.ps1` no longer depends on it (the same controls
are applied directly, role-aware, and logged). If you want Microsoft's own current GPO
backups — for studying with Policy Analyzer, or for a role-specific LGPO import on a
practice image — get them from the source. **Do not** scrape baselines from random
mirrors, and do not download tools onto a live competition image outside what the current
Rules Book allows.

## 1. Download (official)

Microsoft Security Compliance Toolkit 1.0:
<https://www.microsoft.com/en-us/download/details.aspx?id=55319>

As listed in October 2026, the relevant files are:

| File | Use for |
|---|---|
| `Windows 11 v25H2 Security Baseline.zip` (and newer when posted) | Windows 11 images |
| `Windows 10 version 22H2 Security Baseline.zip` | Late Windows 10 images |
| `Windows Server 2025 Security Baseline - 2602.zip` | Server 2025 images (supersedes 2506) |
| `Windows Server 2022 Security Baseline.zip` | Server 2022 images |
| `Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip` | The vintage of this repo's `Policies/` folder |
| `Microsoft Edge vXXX Security Baseline.zip` | Browser policy reference |
| `LGPO.zip` | Current LGPO.exe (replaces the vintage copy beside this script) |
| `PolicyAnalyzer.zip` | Diff baselines and export Excel reports before touching a VM |

Each baseline zip contains GPO backups, `GP Reports` (HTML), an Excel listing of every
setting, a Policy Analyzer rules file, `Local_Script` helpers, and the SecGuide ADMX.
**Verify provenance:** download only over HTTPS from microsoft.com, check the file's
digital signature/hashes as published, and scan the extract with Defender on the prep
machine before it goes anywhere near a team VM.

## 2. Study before you apply

1. Open the Excel/HTML reports for the exact role you face (Computer vs User;
   Member Server vs Domain Controller). Skim for settings that assume enterprise
   infrastructure you don't have in a VM (BitLocker escrow to AD, Credential Guard
   hardware, LAPS-to-AD, WDAC/App Control, TLS-inspecting proxies).
2. Load your current local policy into Policy Analyzer (`LGPO /b` a *practice* VM first,
   or Policy Analyzer's "Add → local policy") and compare against the baseline. The
   delta list is the safest possible preview of what an import would change.
3. Cross-check any value you plan to adopt against `secure.ps1` and
   `docs/RESEARCH_AND_SAFETY.md` — where this repo differs from a baseline (lockout 5
   not 3, SmartScreen Warn, ASR Audit for non-standard rules, no ClearPageFile), the
   difference is a competition-safety decision, not an oversight.

## 3. Apply by role — never "all of them"

The 2019 script's failure mode was `LGPO /g Policies` over **eleven** mixed baselines.
Correct usage on a *practice* image:

```text
1. Snapshot the practice VM.  Run:  secure.bat -Mode Audit   (record the start state)
2. Back up local policy:            LGPO.exe /b C:\GP-Backup-Before /n "Before baseline"
3. Create a staging folder containing ONLY the GPO backups for this machine's role, e.g.
   workstation:  "MSFT Windows 11 v25H2 - Computer" + "- User" + "Defender Antivirus"
                 (+ "Domain Security" only if you intentionally want its password/Kerberos policy)
   member server:"MSFT Windows Server 2025 - Member Server" + "Defender Antivirus"
   DC (rare in CP): the Domain Controller GPOs — and expect domain GPOs to override
                 local policy anyway; prefer editing the Default Domain Policy in GPMC.
4. NEVER stage in a VM round: BitLocker, Credential Guard / VBS GPOs (UEFI/nested-virt/
   reboot hazards), and skip IE 11 baselines entirely (retired).
5. Import:                          LGPO.exe /g C:\Stage
6. gpupdate /force, then RE-RUN secure.bat -Mode Audit and the practice Scoring Report.
   Any score drop → restore your /b backup (LGPO can re-import it the same way) and
   bisect the staged set. That rehearsal loop is how a baseline becomes team knowledge.
```

Keep the machine/role mapping next to any staged folder you keep. The GUID → baseline
name table for this repo's legacy `Policies/` set is printed at runtime by
`secure.ps1` (Step 12B) and was recovered from each folder's `bkupInfo.xml`.

## 4. Keeping current each season

- Baselines now rev roughly with feature updates (e.g. Server 2025 **2602** = Feb 2026).
  Re-check the toolkit page every pre-season; note the changelog posts on the
  *Microsoft Security Baselines* Tech Community blog (recent themes: NTLM auditing
  ahead of deprecation, account-lockout tightening, Windows Protected Print, sudo
  policy, IE COM-automation lockdown).
- CIS Benchmarks rev on a similar cadence (Windows 11 / Server 2022 / Server 2025;
  March 2026 saw Server 2022 v5.0.0). Free PDFs require a CIS WorkBench account; use
  them to sanity-check values, especially where CIS and Microsoft differ (password-age
  ceilings are the recurring example).
- Re-verify the CyberPatriot image list for your season (CP-17/18/19 era: Windows 10,
  Windows 11, Server 2019, Server 2022 — with Server 2025 the logical next addition;
  dates: rounds are now **4-hour** periods). `secure.ps1` detects workstation vs
  member-server vs DC at runtime, so a new server vintage needs no code change — but
  rehearse on it anyway, and watch for newly-defaulted platform changes (e.g. Server
  2025 requires SMB signing outbound by default; NTLMv1 is removed in 24H2/2025).
