---
name: Bug report
about: A rule converted wrong, a verdict looks wrong, or a cmdlet failed
labels: bug
---

**What happened**
<!-- One or two sentences. What did you run, what came back? -->

**What you expected**

**The rule**
<!-- The smallest rule file that shows it. Strip anything from your own tenant:
     workspace names, IP ranges, user names, internal hostnames. A rule from
     Azure/Azure-Sentinel is ideal if it reproduces there. -->

```yaml

```

**The command and the output**

```powershell

```

**Environment**
- SentinelToXDR version: <!-- (Get-Module SentinelToXDR).Version -->
- PowerShell version: <!-- $PSVersionTable.PSVersion -->
- OS:
- Did the tenant reject it? If so, paste the `ServiceMessage`:
