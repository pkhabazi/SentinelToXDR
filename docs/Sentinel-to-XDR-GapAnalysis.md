# Sentinel to XDR Custom Detection — Gap Analysis

This document describes every field mapping gap between a Microsoft Sentinel Scheduled/NRT analytics rule and an XDR custom detection rule, explains the default behaviour of `ConvertTo-XDRCustomDetection`, lists the warning messages you will see, and shows practical examples for each gap.

> **Superseded.** This document describes v1 behaviour and the legacy
> `-Format XDRConverter` output shape. The current reference is
> **[Migration-Gaps.md](Migration-Gaps.md)**, which covers every gap the module detects, what
> it costs, and what to do about it.
>
> Kept for the field-by-field mapping detail and the worked examples, which are still
> broadly accurate. Where the two disagree, Migration-Gaps.md is right.

---

## Overview

The converter handles two Sentinel rule formats:

| Format | Extension | Structure |
|---|---|---|
| Community / content-hub YAML | `.yaml` / `.yml` | Flat object (`name`, `query`, `tactics`, …) |
| ARM template JSON | `.json` | `kind` + `properties` sub-object (`Microsoft.SecurityInsights/alertRules`) |

In either case, the output is an XDR custom detection **YAML** file that conforms to the `CustomDetection.schema.json` schema.

For a quick conversion:

```powershell
ConvertTo-XDRCustomDetection -InputFile .\MySentinelRule.yaml -OutputFile .\MyXdrRule.yaml
```

Use `ConvertTo-XDRCustomDetection | ConvertTo-CustomDetectionJson` to go straight to the XDR Graph API JSON format.

---

## Field Mapping Table

| Sentinel field | XDR field | Notes |
|---|---|---|
| `id` / `name` (GUID) | `guid` | See [Gap 7 – Missing GUID](#gap-7--missing-guid) |
| `name` / `properties.displayName` | `ruleName`, `alertTitle` | See [Gap 5 – No dedicated alert title](#gap-5--no-dedicated-alert-title) |
| `description` / `properties.description` | `alertDescription` | Direct copy |
| `severity` / `properties.severity` | `alertSeverity` | Direct match (both Title Case) |
| `status` (`Deprecated` → `false`) | `isEnabled` | `Deprecated` → `false`; all others → `true` |
| `enabled` (ARM) | `isEnabled` | Direct bool copy |
| `queryFrequency` / `properties.queryFrequency` | `frequency` | See [Gap 3 – Frequency rounding](#gap-3--frequency-rounding) |
| `kind: NRT` | `frequency: "0"` | Exact match |
| `tactics[0]` | `alertCategory` | See [Gap 1 – Multiple tactics](#gap-1--multiple-tactics) |
| `relevantTechniques` / `properties.techniques` | `mitreTechniques` | Direct copy |
| `query` / `properties.query` | `queryText` | See [Gap 2 – KQL query compatibility](#gap-2--kql-query-compatibility) |
| `entityMappings` | `impactedEntities` | See [Gap 4 – Entity type mapping](#gap-4--entity-type-mapping) |
| `queryPeriod` | `lookbackPeriod` | Carried as an ISO 8601 duration (clamped to parity limits); see Stage 2 notes in `CustomDetection.schema.json` |
| `triggerOperator` / `triggerThreshold` | *(dropped)* | See [Gap 6 – Trigger threshold](#gap-6--trigger-threshold) |
| `alertDetailsOverride` | *(dropped)* | Sentinel-specific |
| `customDetails` | *(dropped)* | Sentinel-specific |
| `incidentConfiguration` | *(dropped)* | Sentinel-specific |
| `eventGroupingSettings` | *(dropped)* | Sentinel-specific |
| `requiredDataConnectors` | *(dropped)* | Sentinel-specific |

---

## Gap 1 — Multiple Tactics

### Background

Sentinel analytics rules support an array of MITRE ATT&CK tactics (e.g. `['InitialAccess', 'Persistence', 'DefenseEvasion']`). XDR custom detections support exactly **one** `alertCategory` per rule.

### Default behaviour

The converter picks the **first** tactic in the array that maps to a valid XDR category. When multiple tactics are present, a `ShouldContinue` prompt is shown interactively (suppressed by `-Force`).

### Warning message

```
Rule 'My Rule' has 3 tactics: [InitialAccess, Persistence, DefenseEvasion].
XDR only supports one alertCategory. Using 'InitialAccess'.
Use -AlertCategory to override.
```

### Tactic → alertCategory mapping

| Sentinel tactic | XDR alertCategory |
|---|---|
| Collection | Collection |
| CommandAndControl | CommandAndControl |
| CredentialAccess | CredentialAccess |
| DefenseEvasion | DefenseEvasion |
| Discovery | Discovery |
| Execution | Execution |
| Exfiltration | Exfiltration |
| Impact | Impact |
| InitialAccess | InitialAccess |
| LateralMovement | LateralMovement |
| Persistence | Persistence |
| PrivilegeEscalation | PrivilegeEscalation |
| PreAttack | **SuspiciousActivity** *(no direct XDR equivalent)* |
| Reconnaissance | **SuspiciousActivity** *(no direct XDR equivalent)* |
| ResourceDevelopment | **SuspiciousActivity** *(no direct XDR equivalent)* |
| ImpairProcessControl | **SuspiciousActivity** *(no direct XDR equivalent)* |
| InhibitResponseFunction | **SuspiciousActivity** *(no direct XDR equivalent)* |

Sentinel-only tactics that map to `SuspiciousActivity` emit an additional warning:

```
Tactics [PreAttack, Reconnaissance] are not natively supported in XDR
and have been mapped to 'SuspiciousActivity'.
```

### How to override

```powershell
# Accept the auto-selected first tactic without prompt (CI/CD usage)
ConvertTo-XDRCustomDetection -InputFile rule.yaml -Force

# Specify the category explicitly
ConvertTo-XDRCustomDetection -InputFile rule.yaml -AlertCategory DefenseEvasion
```

---

## Gap 2 — KQL Query Compatibility

### Background

Sentinel analytics rules query tables in the **Log Analytics workspace** that backs the Sentinel instance. XDR custom detections query advanced hunting tables in the **Defender portal**.

When **Microsoft Sentinel Unified SOC** (the Defender portal integration) is enabled, Sentinel workspace tables (e.g. `SigninLogs`, `SecurityEvent`, `AuditLogs`) **are available** in the Defender advanced hunting experience alongside the native XDR tables. In that case the query may work without modification.

If Unified SOC is **not** enabled, Sentinel-specific tables are not present and the query will fail. Common mismatches:

| Sentinel table | XDR equivalent (if any) |
|---|---|
| `SigninLogs` | Available via Unified SOC only |
| `SecurityEvent` | Available via Unified SOC only |
| `AuditLogs` | Available via Unified SOC only |
| `OfficeActivity` | Available via Unified SOC only |
| `Syslog` | Available via Unified SOC only |
| `DeviceEvents` | Native XDR table (direct match) |
| `DeviceProcessEvents` | Native XDR table (direct match) |
| `IdentityLogonEvents` | Native XDR table (direct match) |

### Default behaviour

The query is **always carried over as-is** regardless of the tables used. A warning is always emitted to prompt review.

### Warning message

```
The KQL query in rule 'My Rule' may reference Sentinel-specific tables
(e.g. SigninLogs, SecurityEvent, AuditLogs). These tables are available
in XDR only when Microsoft Sentinel Unified SOC (the Defender portal
integration) is enabled. If Unified SOC is not enabled, review and adapt
the query before deploying to XDR.
```

### Examples

```powershell
# Suppress the query warning when you have already reviewed it (redirect warning stream)
ConvertTo-XDRCustomDetection -InputFile rule.yaml -Force 3>$null

# Or capture warnings and filter only the ones you care about
ConvertTo-XDRCustomDetection -InputFile rule.yaml -Force -WarningVariable wv -WarningAction SilentlyContinue
$wv | Where-Object { $_ -notmatch 'KQL|tables' }
```

---

## Gap 3 — Query Frequency Rounding

### Background

Sentinel `queryFrequency` accepts arbitrary ISO 8601 durations (e.g. `PT15M`, `PT6H`, `P3D`, `P1W`) or community shorthand (e.g. `15m`, `6h`, `1d`). XDR custom detections support only five discrete values:

| XDR period | Meaning |
|---|---|
| `"0"` | Near Real Time (NRT) |
| `"1H"` | Every 1 hour |
| `"3H"` | Every 3 hours |
| `"12H"` | Every 12 hours |
| `"24H"` | Every 24 hours |

### Default behaviour

The Sentinel frequency is parsed to **total hours** and rounded to the nearest supported XDR value using these midpoints:

| Input range | Rounded to |
|---|---|
| < 2 hours | `1H` |
| 2 h – 7.5 h | `3H` |
| 7.5 h – 18 h | `12H` |
| ≥ 18 hours | `24H` |

`kind: NRT` always maps to `"0"` regardless of `queryFrequency`.

### Warning message (only when value is imprecise)

```
Query frequency 'PT30M' (~0.5h) was rounded to '1H' — the nearest
supported XDR frequency. Supported values are: 0 (NRT), 1H, 3H, 12H, 24H.
```

No warning is emitted for exact matches (e.g. `PT1H`, `PT3H`, `PT12H`, `PT24H`, `1h`, `3h`, `12h`, `24h`, `1d`).

### Examples

| Sentinel `queryFrequency` | Total hours | XDR `frequency` | Warning? |
|---|---|---|---|
| `PT15M` / `15m` | 0.25 h | `1H` | Yes |
| `PT1H` / `1h` | 1 h | `1H` | No |
| `PT2H` / `2h` | 2 h | `3H` | Yes |
| `PT3H` / `3h` | 3 h | `3H` | No |
| `PT6H` / `6h` | 6 h | `3H` | Yes |
| `PT12H` / `12h` | 12 h | `12H` | No |
| `P1D` / `1d` | 24 h | `24H` | No |
| `P2D` / `2d` | 48 h | `24H` | Yes |
| `P7D` / `1w` | 168 h | `24H` | Yes |
| `kind: NRT` | N/A | `"0"` | No |

```powershell
# Convert a rule with a 15-minute frequency — frequency becomes 1H with a warning
ConvertTo-XDRCustomDetection -InputFile rule.yaml -Force
# WARNING: Query frequency 'PT15M' (~0.25h) was rounded to '1H' ...
```

---

## Gap 4 — Entity Type Mapping

### Background

Sentinel entity mappings use the `entityMappings` array. Each entry has an `entityType` (Sentinel's vocabulary) and one or more `fieldMappings` that link entity-specific identifiers to KQL result columns.

XDR `impactedEntities` uses a different vocabulary and does not have a concept of the Sentinel-specific entity `identifier` field — only the **column name** (`columnName`) is used as `entityIdentifier`.

### Default behaviour

Each `fieldMapping` entry becomes a separate `impactedEntity` row in the output. The `identifier` field from Sentinel (e.g. `FullName`, `Address`) is **silently discarded**; only `columnName` is carried over.

#### Entity type translation

| Sentinel `entityType` | XDR `entityType` | Notes |
|---|---|---|
| `Host` | `Machine` | Renamed to match XDR schema |
| `Account` | `User` | Renamed to match XDR schema |
| `IP` | `IP` | Direct match |
| `URL` | `URL` | Direct match |
| `Process` | `Process` | Direct match |
| `Mailbox` | `Mailbox` | Direct match |
| `RegistryKey` | `RegistryKey` | Direct match |
| `RegistryValue` | `RegistryValue` | Direct match |
| `FileHash` | `FileHash` | Direct match |
| `File` | *(skipped)* | No XDR equivalent |
| `MailMessage` | *(skipped)* | No XDR equivalent |
| `AzureResource` | *(skipped)* | No XDR equivalent |
| `CloudApplication` | *(skipped)* | No XDR equivalent |
| `DNS` | *(skipped)* | No XDR equivalent |
| `IoTDevice` | *(skipped)* | No XDR equivalent |
| `SecurityGroup` | *(skipped)* | No XDR equivalent |
| `SubmissionMail` | *(skipped)* | No XDR equivalent |
| `MailCluster` | *(skipped)* | No XDR equivalent |
| `Malware` | *(skipped)* | No XDR equivalent |

### Warning message (skipped entity types)

```
Sentinel entity type 'AzureResource' has no equivalent in XDR custom
detections and will be skipped. Review impactedEntities in the output manually.
```

### Example

Sentinel input:
```yaml
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: HostCustomEntity
  - entityType: Account
    fieldMappings:
      - identifier: FullName
        columnName: AccountCustomEntity
  - entityType: AzureResource
    fieldMappings:
      - identifier: ResourceId
        columnName: ResourceCustomEntity
```

XDR output (note: `AzureResource` is dropped, `Host` → `Machine`, `Account` → `User`):
```yaml
impactedEntities:
  - entityType: Machine
    entityIdentifier: HostCustomEntity
  - entityType: User
    entityIdentifier: AccountCustomEntity
```

Note that `entityIdentifier` values from Sentinel (like `HostCustomEntity`) are KQL column names and **may need to be updated** to match the XDR-supported identifier list (e.g. `deviceId`, `accountUpn`). The converter carries them over as-is since only the source rule author knows which column maps to which identifier.

---

## Gap 5 — No Dedicated Alert Title

### Background

Sentinel analytics rules have a single `name` field used both as the rule's display name and as the alert title. XDR custom detections have separate `displayName` (rule name) and `alertTitle` (alert heading shown to analysts) fields.

### Default behaviour

Both `ruleName` and `alertTitle` are set to the Sentinel rule's `name`. A warning is emitted to suggest providing an explicit title.

### Warning message

```
Sentinel analytics rules do not have a dedicated alert title.
Using the rule name 'My Sentinel Rule' as alertTitle. Use -AlertTitle to override.
```

### How to override

```powershell
ConvertTo-XDRCustomDetection -InputFile rule.yaml -AlertTitle 'Suspicious Sign-in Detected'
```

---

## Gap 6 — Trigger Threshold / Operator

### Background

Sentinel analytics rules fire based on a `triggerOperator` + `triggerThreshold` combination, for example:

```yaml
triggerOperator: gt
triggerThreshold: 5
```

This means the alert triggers only when the query returns **more than 5** rows. XDR custom detections have no threshold concept — they trigger on **every row** returned by the query, which is functionally equivalent to `triggerOperator: gt, triggerThreshold: 0`.

### Default behaviour

The threshold and operator are **dropped** from the output. A warning is emitted only when the combination is anything other than `gt 0` (the XDR default).

### Warning message

```
Sentinel trigger condition 'gt 5' is not supported in XDR.
XDR custom detections trigger on every row returned by the query.
```

### Implications

If you rely on a threshold (e.g. `gt 10` to reduce noise), the converted XDR rule will be **more noisy** than the original. You should adapt the KQL to embed the threshold logic directly:

```kql
// Original Sentinel query (implicitly filtered by triggerThreshold: 10)
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by Computer

// Adapted XDR query (threshold embedded in KQL)
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedLogins = count() by DeviceName
| where FailedLogins > 10
```

---

## Gap 7 — Missing GUID

### Background

The XDR custom detection schema requires a `guid` field (used as `detectorId`). Sentinel community YAML rules have an `id` field, but ARM templates use the ARM resource `name` as the GUID.

### Default behaviour

The converter looks for a GUID-shaped value in this order:
1. The `-Guid` parameter (if supplied)
2. `id` on the root object (community YAML)
3. `name` on the root object (ARM resource name when it is a GUID-shaped value)

If none of these yield a valid UUID, a **new GUID is generated automatically** and a warning is emitted.

### Warning message

```
No UUID found in Sentinel rule 'My Rule'. A new GUID has been generated:
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx. Use -Guid to specify one explicitly.
```

### Recommendation

Always store a stable GUID in your Sentinel rule's `id` field (community YAML) so the converted XDR rule can be updated idempotently in a CI/CD pipeline.

```powershell
# Override with a known GUID
ConvertTo-XDRCustomDetection -InputFile rule.yaml `
    -Guid 'aaaaaaaa-0000-0000-0000-bbbbbbbbbbbb'
```

---

## Warnings Reference

The table below lists every warning that `ConvertTo-XDRCustomDetection` (and its private helper `ConvertFrom-SentinelToCustomDetection`) can emit, along with the default action taken.

| # | Warning keywords | When emitted | Default action |
|---|---|---|---|
| 1 | `"has N tactics"` | Rule has more than one tactic | Use first mappable tactic |
| 1b | `"not natively supported in XDR"` | One or more Sentinel-only tactics present | Map to `SuspiciousActivity` |
| 1c | `"Unknown tactic(s)"` | Tactic not in the known list | Skip the tactic |
| 1d | `"no tactics defined"` | `tactics` array is absent or empty | `alertCategory = SuspiciousActivity` |
| 2 | `"Sentinel-specific tables"` | Always | Carry query as-is |
| 3 | `"was rounded to"` | `queryFrequency` does not map exactly | Use nearest supported XDR period |
| 3b | `"Unable to parse query frequency"` | Unparseable frequency string | Default to `1H` |
| 3c | `"No queryFrequency found"` | Field absent (non-NRT rule) | Default to `1H` |
| 4 | `"has no equivalent in XDR"` | Unsupported Sentinel entity type | Skip entity |
| 4b | `"Unknown Sentinel entity type"` | Entity type not in known list | Skip entity |
| 5 | `"does not have a dedicated alert title"` | `-AlertTitle` not specified | Use rule name as `alertTitle` |
| 6 | `"trigger condition"` | `triggerThreshold > 0` or operator ≠ `gt` | Drop threshold |
| 7 | `"No UUID found"` | No GUID-shaped value in source rule | Generate new GUID |
| 8 | `"Isolation type"` | Invalid `isolationType` on response action | Default to `Full` |

---

## Complete Example

### Input — Sentinel community YAML (`SentinelRule.yaml`)

```yaml
id: 11111111-aaaa-bbbb-cccc-222222222222
name: Multiple Failed Logins from Single IP
description: Detects brute-force login attempts from a single source IP.
severity: Medium
status: Available
queryFrequency: PT15M
queryPeriod: PT1H
triggerOperator: gt
triggerThreshold: 10
tactics:
  - CredentialAccess
  - InitialAccess
relevantTechniques:
  - T1110
  - T1110.001
query: |
  SecurityEvent
  | where EventID == 4625
  | summarize FailedCount = count() by IpAddress, Computer
  | where FailedCount > 10
entityMappings:
  - entityType: Host
    fieldMappings:
      - identifier: FullName
        columnName: Computer
  - entityType: IP
    fieldMappings:
      - identifier: Address
        columnName: IpAddress
  - entityType: AzureResource
    fieldMappings:
      - identifier: ResourceId
        columnName: ResourceId
kind: Scheduled
version: 1.2.0
```

### Conversion command

```powershell
ConvertTo-XDRCustomDetection `
    -InputFile .\SentinelRule.yaml `
    -AlertTitle 'Brute-Force: Multiple Failed Logins from Single IP' `
    -AlertCategory CredentialAccess `
    -OutputFile .\XdrRule.yaml `
    -Force
```

### Warnings emitted

```
WARNING: The KQL query in rule 'Multiple Failed Logins from Single IP' may reference
Sentinel-specific tables (e.g. SigninLogs, SecurityEvent, AuditLogs). These tables are
available in XDR only when Microsoft Sentinel Unified SOC (the Defender portal
integration) is enabled. If Unified SOC is not enabled, review and adapt the query
before deploying to XDR.

WARNING: Query frequency 'PT15M' (~0.25h) was rounded to '1H' — the nearest supported
XDR frequency. Supported values are: 0 (NRT), 1H, 3H, 12H, 24H.

WARNING: Sentinel trigger condition 'gt 10' is not supported in XDR.
XDR custom detections trigger on every row returned by the query.

WARNING: Sentinel entity type 'AzureResource' has no equivalent in XDR custom
detections and will be skipped. Review impactedEntities in the output manually.
```

*(No multi-tactic or alert-title warning because `-AlertCategory` and `-AlertTitle` were provided explicitly.)*

### Output — XDR detection YAML (`XdrRule.yaml`)

```yaml
guid: 11111111-aaaa-bbbb-cccc-222222222222
isEnabled: true
ruleName: Multiple Failed Logins from Single IP
alertTitle: Brute-Force: Multiple Failed Logins from Single IP
alertCategory: CredentialAccess
alertDescription: Detects brute-force login attempts from a single source IP.
frequency: 1H
alertSeverity: Medium
mitreTechniques:
  - T1110
  - T1110.001
impactedEntities:
  - entityType: Machine
    entityIdentifier: Computer
  - entityType: IP
    entityIdentifier: IpAddress
queryText: |
  SecurityEvent
  | where EventID == 4625
  | summarize FailedCount = count() by IpAddress, Computer
  | where FailedCount > 10
```

### What to review before deploying

1. **Query** — `SecurityEvent` requires Unified SOC to be enabled. If not, replace with `DeviceLogonEvents` or an equivalent XDR table.
2. **Frequency** — The original ran every 15 minutes; the XDR rule will run every hour. The `where FailedCount > 10` in the KQL mitigates noise.
3. **entityIdentifier values** — `Computer` and `IpAddress` are raw KQL column names. For the `Machine` entity, XDR expects an identifier like `deviceId` or `deviceName`; `Computer` may not be recognised. Validate against the [XDR impacted asset identifiers documentation](https://learn.microsoft.com/en-us/graph/api/resources/security-impactedasset).

---

## Pipeline / Batch Conversion

```powershell
# Convert all Sentinel YAML rules in a folder to XDR YAML files
Get-ChildItem .\SentinelRules\*.yaml | ForEach-Object {
    ConvertTo-XDRCustomDetection `
        -InputFile $_.FullName `
        -UseDisplayNameAsFilename `
        -OutputFolder .\XdrRules `
        -Force `
        -WarningAction SilentlyContinue
}

# Convert and go straight to XDR JSON (ready for Graph API)
Get-ChildItem .\SentinelRules\*.yaml | ForEach-Object {
    ConvertTo-XDRCustomDetection -InputFile $_.FullName -Force -WarningAction SilentlyContinue |
        ConvertTo-CustomDetectionJson -UseDisplayNameAsFilename -OutputFolder .\XdrJson
}
```
