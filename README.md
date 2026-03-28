# GPO Overlap Analyzer

A PowerShell script that connects to an authoritative domain controller, analyzes every GPO in your domain, and reports on redundant, conflicting, and fully duplicated policy settings — giving administrators clear intelligence for GPO consolidation without making any changes to your environment.

---

## Prerequisites

| Requirement | Details |
|---|---|
| **PowerShell** | 5.1 or later |
| **RSAT Module** | `GroupPolicy` module — *RSAT: Group Policy Management Tools* |
| **Permissions** | Read access to all GPOs and SYSVOL on the target domain |

Install RSAT if needed:
```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

# Windows Server
Install-WindowsFeature -Name GPMC
```

---

## Usage

```powershell
# Auto-discovers your domain and PDC emulator
.\Analyze-GPOOverlap.ps1

# Target a specific DC with output folder
.\Analyze-GPOOverlap.ps1 -DomainController dc01.corp.local -Domain corp.local -ReportPath C:\GPO_Reports

# Exclude specific GPOs (wildcards supported)
.\Analyze-GPOOverlap.ps1 -ExcludeGPO "Default Domain Policy", "Legacy*"

# Include fully-disabled GPOs
.\Analyze-GPOOverlap.ps1 -IncludeDisabledGPOs
```

| Parameter | Default | Description |
|---|---|---|
| `-DomainController` | PDC emulator | FQDN or hostname of the DC to query |
| `-Domain` | Current user's domain | Target domain name |
| `-ReportPath` | Script directory | Folder where output files are written |
| `-IncludeDisabledGPOs` | Off | Include fully disabled GPOs in analysis |
| `-ExcludeGPO` | None | GPO display names to skip (wildcards supported) |

---

## What It Analyzes

**Exact Duplicates** — Same policy name and value in two or more GPOs. One is doing work already done elsewhere and is a clear consolidation candidate.

**Value Conflicts** — Same policy name, different values across GPOs. Active Directory resolves these silently via link order precedence; unintentional conflicts can cause unpredictable effective settings.

**Redundant GPOs** — Every setting in a GPO is already present with the same value in another GPO. The redundant GPO contributes nothing and is a candidate for unlinking. This is the most powerful finding but requires the most caution — see tips below.

---

## Output Files

All files are timestamped so successive runs don't overwrite each other.

| File | Contents | Key Nuance |
|---|---|---|
| `GPO_Summary_*.txt` | Human-readable narrative of all findings | Best starting point; use CSVs for systematic remediation work |
| `GPO_ExactDuplicates_*.csv` | One row per duplicated policy with GPO list | GPOs are listed alphabetically, **not** by link precedence — confirm link order in GPMC before removing anything |
| `GPO_ValueConflicts_*.csv` | Conflicting policies with each value and its source GPO | Not all conflicts are errors; some are intentional overrides — check modification dates and intent before acting |
| `GPO_RedundantGPOs_*.csv` | GPO pairs where one is fully subsumed by another | Analysis is **scope-blind** — a "redundant" GPO may be the only one applying those settings to a specific OU or security group |
| `GPO_AllSettings_*.csv` | Flat export of every setting from every GPO | Useful for ad-hoc queries and diffing between runs to detect policy drift |

---

## Tips

- **Unlink before deleting.** Remove all OU links, wait a full GPO refresh cycle, verify no clients report missing settings, then delete. Unlinking is reversible; deletion requires a backup to undo.
- **Diff `GPO_AllSettings` between runs.** Running on a schedule and diffing the flat export turns this into lightweight change detection over time.
- **Exclude known-intentional GPOs.** The Default Domain Policy and any deliberately scoped GPOs will generate noise. Use `-ExcludeGPO` to keep findings focused.
- **Validate redundant GPOs on three axes before acting:** link scope (same OUs?), security/WMI filtering (same target population?), and link order (does the covering GPO actually win in every linked OU?).
- **Parse errors are their own finding.** GPOs that fail XML export appear in the summary under *Parse Errors*. A GPO the tooling can't read often can't be reliably applied by clients either.

---

## Limitations

- **Scope-blind.** Settings are compared across all GPOs regardless of where they are linked. Apparent duplicates may be intentionally applied to different OUs or populations.
- **WMI and security filtering not evaluated.** Two GPOs defining the same policy with different filters are not truly equivalent — the script cannot account for this.
- **Complex Preferences may have reduced fidelity.** Preference items like mapped drives or scheduled tasks may not be fully represented in the `ExtraInfo` field.
- **Read-only.** No changes are made to your environment. All remediation requires manual action.
