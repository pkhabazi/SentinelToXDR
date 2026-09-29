# Run it with PowerShell

The full workflow from a PowerShell prompt: read, assess, convert, validate, deploy. If you
have not installed the module yet, start with [Getting started](Getting-Started.md). If you
would rather ask for an assessment in plain language, see
[Run it with Claude Code](Run-With-Claude-Code.md).

Everything up to and including step 3 runs offline. Nothing touches a tenant until step 4,
and nothing is written to one without `-Deploy` or a `New-`/`Set-`/`Remove-` cmdlet.

## 1. Read your rules

`Get-SentinelAnalyticsRule` is the single way rules get in. Whatever the source, it emits
the same normalized rule object, so nothing downstream needs to know where a rule came from.

| Source | How |
|---|---|
| Community / Content Hub YAML | `-Path ./Detections -Recurse` |
| ARM template JSON (single resource) | `-Path ./rule.json` |
| ARM deployment template with `resources[]` | `-Path ./mainTemplate.json` |
| Content Hub `mainTemplate.json` (rules nested under a content template) | same, found recursively |
| REST list response, or a bare array of rules | `-Path ./export.json` |
| Live Sentinel workspace | `-SubscriptionId <id> -ResourceGroupName <rg> -WorkspaceName <ws>` |

```powershell
# How many rules, and of what kind?
Get-SentinelAnalyticsRule -Path ./my-rules -Recurse | Group-Object Kind -NoElement

# Straight from a workspace (needs a sign-in, see Authentication below)
Get-SentinelAnalyticsRule -SubscriptionId $sub -ResourceGroupName rg-soc -WorkspaceName law-soc
```

Files that are not rules (data connectors, DCR templates, workbooks, solution metadata) are
skipped with a warning, not reported as broken rules.

## 2. Assess them

```powershell
# The verdict split
Test-XDRMigrationReadiness -Path ./my-rules -Recurse | Group-Object Verdict -NoElement

# What needs a decision, and why
Test-XDRMigrationReadiness -Path ./my-rules -Recurse |
    Where-Object Verdict -eq 'NeedsWork' |
    Select-Object RuleName -ExpandProperty Headline

# A report for the team: CSV, Markdown or one self-contained HTML page
Test-XDRMigrationReadiness -Path ./my-rules -Recurse |
    Export-XDRMigrationReport -Path ./readiness.html
```

Or read, assess, report and convert in one call:

```powershell
Invoke-SentinelToXDRMigration -Path ./my-rules -Recurse -ReportPath ./readiness.html -OutputFolder ./out
```

What each verdict means and what to do about it is in the
[README](../README.md#reading-the-verdicts). Every gap behind a verdict is explained in
[Migration-Gaps.md](Migration-Gaps.md).

## 3. Convert them

```powershell
# One rule, look at the result
ConvertTo-XDRCustomDetection -InputFile ./MyRule.yaml

# A whole tree, written as YAML (one file per rule) for review
Get-SentinelAnalyticsRule -Path ./Solutions -Recurse |
    ConvertTo-XDRCustomDetection -As Object -Force |
    Export-XDRCustomDetection -Path ./out

# Straight from a live workspace
Get-SentinelAnalyticsRule -SubscriptionId $sub -ResourceGroupName rg-soc -WorkspaceName law-soc |
    ConvertTo-XDRCustomDetection -As Object -Force |
    Export-XDRCustomDetection -Path ./out
```

The default output is
[`microsoft.graph.security.detectionRule`](https://learn.microsoft.com/graph/api/resources/security-detectionrule?view=graph-rest-beta),
which is exactly what `POST /security/rules/detectionRules` accepts. This is
[`Examples/community-yaml-example.yaml`](../Examples/community-yaml-example.yaml) after
conversion (description trimmed):

```yaml
id: r-11111111-aaaa-bbbb-cccc-222222222222
displayName: Multiple Failed Logins from Single IP
status: enabled
queryCondition:
  queryText: |
    SecurityEvent
    | where EventID == 4625
    | summarize FailedCount = count() by IpAddress, Computer
    | where FailedCount > 10
schedule:
  frequency: PT1H
detectionAction:
  alertTemplate:
    title: Multiple Failed Logins from Single IP
    severity: medium
    tactics:
    - tactic: CredentialAccess
      techniques:
      - technique: T1110
        subTechniques:
        - T1110.001
    entityMappings:
      hosts:
      - nameColumn: Computer
      ips:
      - addressColumn: IpAddress
```

`-As` picks the serialization: `Yaml` (default), `Json`, or `Object`. The object form carries
the detection, its diagnostics and the source rule together, which is what you want when
you are assessing an estate rather than writing files.

`-Format XDRConverter` still produces the flat shape used by Fabian Bader's
[XDRConverter](https://github.com/f-bader/XDRConverter), if you already have pipelines built
on it. It cannot express typed entity columns.

### Rules that cannot convert

These produce a **Blocking** diagnostic and no output. They are reported, never turned into
an empty detection.

| Rule kind | Why not |
|---|---|
| `Fusion` | Microsoft managed multistage correlation, no query to carry. Defender XDR correlates natively. |
| `MLBehaviorAnalytics` | Microsoft managed model, no query. |
| `ThreatIntelligence` | Server side indicator matching, no query. |
| `MicrosoftSecurityIncidentCreation` | Only forwards another product's alerts. In the Defender portal they arrive natively. |
| `Anomaly` | Tunable managed model, not a portable query. |
| `HuntingQuery` | Has a query but no schedule, severity or entity mappings. Promote it to a scheduled rule first. |

### Every compromise is a diagnostic

Every conversion decision is a structured record: `Feature`, `Capability`, `Severity`
(Info, Warning, Blocking), `Action` (Mapped, Rounded, Dropped, Constrained, Unsupported,
RequiresReview), `SourceValue`, `TargetValue`, `Reason`, and a `DocReference` back to the
Microsoft parity doc row it came from.

```powershell
# What did this rule lose?
$d = ConvertTo-XDRCustomDetection -InputFile ./MyRule.yaml -As Object -Force
$d.Diagnostics | Where-Object Action -in 'Dropped','Unsupported' | Format-Table Capability, Reason

# Across an estate
Get-SentinelAnalyticsRule -Path ./rules -Recurse |
    ConvertTo-XDRCustomDetection -As Object -Force -WarningAction SilentlyContinue |
    ForEach-Object Diagnostics | Group-Object Action
```

---

## 4. Validate and deploy

Start in a dev tenant. Always preview first. Land detections disabled, look at them in the
portal, then turn them on.

```powershell
Connect-SentinelToXDR

# Does the KQL actually run in this tenant? Read-only, safe against production.
Test-XDRMigrationReadiness -Path ./rules -PassThruDetection |
    Where-Object Verdict -in 'Ready','Review' |
    ForEach-Object Detection |
    Test-XDRDetectionQuery |
    Where-Object { -not $_.QueryValid }

# The whole run as a dry run
Invoke-SentinelToXDRMigration -Path ./rules -Recurse -ValidateQuery -Deploy -DeployDisabled -WhatIf

# The real one: only Ready and Review rules (the default), landed disabled
Invoke-SentinelToXDRMigration -Path ./rules -Recurse -ValidateQuery -Deploy -DeployDisabled
```

A Graph sign-in does not survive the PowerShell process, so connect and run in the same
session.

### Deploying from a reviewed file

Converting and deploying in one pipeline leaves nothing for a reviewer to approve. When
someone has to sign off on what ships, export first:

```powershell
# One JSON file a reviewer can read, diff and approve
Get-SentinelAnalyticsRule -Path ./rules -Recurse |
    ConvertTo-XDRCustomDetection -As Object -Force |
    Export-XDRCustomDetection -Path ./out -Format Json -Combine

# ...then deploy exactly that file
New-XDRCustomDetection -Path ./out/customDetections.json -Disabled -Force
```

### Managing what is deployed

| Cmdlet | Does |
|---|---|
| `Get-XDRCustomDetection` | List or read deployed detections (paging is handled) |
| `New-XDRCustomDetection` | Create. `-Update` patches on conflict, `-Disabled` lands them off |
| `Set-XDRCustomDetection` | Update a detection, or just flip its status |
| `Remove-XDRCustomDetection` | Delete |

All four prompt before writing (`ConfirmImpact = High`) and support `-WhatIf`. One failed
rule does not stop the batch. Each result carries a `Status`, an `Error`, and the service's
own `ServiceMessage` when the API refuses something.

```powershell
# Turn one on once you are happy with it
Set-XDRCustomDetection -Id r-11111111-aaaa-bbbb-cccc-222222222222 -Status enabled -Force

# Clean up a lab run. There is no undo in the product, so -WhatIf first.
Get-XDRCustomDetection |
    Where-Object { $_.displayName -like 'TEST-*' } |
    Remove-XDRCustomDetection -WhatIf
```

---

## Authentication

**Permissions.** Deploying needs `CustomDetection.ReadWrite.All` plus a Defender XDR role that
allows detection tuning (Detection tuning (Manage), Security Administrator or Security
Operator). Validating queries needs only `ThreatHunting.Read.All`. Reading rules from a
workspace needs Microsoft Sentinel Reader on it.

**The one that trips everyone.** A plain `Connect-AzAccount` works for reading Sentinel over
ARM, but not for these Graph calls. The Az PowerShell client has a fixed set of Graph
permissions, `ThreatHunting.Read.All` and `CustomDetection.ReadWrite.All` are not among
them, and no amount of re-acquiring the token changes that. You get a 403
`Missing application scopes`. So sign in with something that can hold the scopes:

```powershell
# Interactive, everything the module can use
Connect-SentinelToXDR

# Read only: enough to assess and validate queries, cannot write a detection
Connect-SentinelToXDR -Scopes ThreatHunting.Read.All -TenantId $devTenant

# Device code, for a machine without a browser
Connect-SentinelToXDR -UseDeviceCode -TenantId $tenant

# A pipeline, with an app registration and a certificate
Connect-SentinelToXDR -TenantId $tenant -ClientId $app -CertificateThumbprint $thumb

# A token you already hold
Connect-SentinelToXDR -GraphAccessToken $token

# Check before running anything long
Get-SentinelToXDRContext | Format-List Account, CanValidateQueries, CanManageDetections
```

Interactive sign-in goes through `Microsoft.Graph.Authentication`, and the module uses that
session directly, so it never handles a raw token. Nothing is written to disk.
`Get-SentinelToXDRContext` reports audience, scopes and expiry, never a token value.

---

Next: [Run it with Claude Code](Run-With-Claude-Code.md) for the plain language version of
step 2, or [Validation.md](Validation.md) for how the verdicts are proven.
