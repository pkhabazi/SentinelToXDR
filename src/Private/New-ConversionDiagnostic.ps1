function New-ConversionDiagnostic {
    <#
    .SYNOPSIS
        Creates a structured conversion diagnostic record.

    .DESCRIPTION
        Builds a single PSCustomObject describing one Sentinel→XDR mapping decision
        (a gap that was mapped, rounded, dropped, constrained, etc.). The converter
        accumulates these records and attaches them to its result; back-compat
        Write-Warning calls are emitted alongside them. The report writer and batch
        summary consume the collection.

        Severity / Action / (optionally) Feature+Capability tie the record back to the
        capability matrix and compare doc via DocReference.

    .PARAMETER Feature
        Compare-doc Feature column (e.g. 'Rule frequency').

    .PARAMETER Capability
        Compare-doc Capability column (e.g. 'Link multiple MITRE tactics').

    .PARAMETER Severity
        Info | Warning | Blocking.

    .PARAMETER Action
        What the converter did: Mapped | Rounded | Dropped | Unsupported | RequiresReview | Constrained.

    .PARAMETER SourceValue
        What the Sentinel rule had (optional).

    .PARAMETER TargetValue
        What the XDR detection received, or $null when dropped (optional).

    .PARAMETER Reason
        Human-readable explanation. For refactored Write-Warning sites this holds the
        exact original warning string so it can be re-emitted verbatim.

    .PARAMETER DocReference
        Link/anchor into the compare doc (optional).
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [string]$Feature,

        [Parameter(Mandatory)]
        [string]$Capability,

        [Parameter(Mandatory)]
        [ValidateSet('Info', 'Warning', 'Blocking')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet('Mapped', 'Rounded', 'Dropped', 'Unsupported', 'RequiresReview', 'Constrained')]
        [string]$Action,

        [Parameter()]
        [AllowNull()]
        [object]$SourceValue = $null,

        [Parameter()]
        [AllowNull()]
        [object]$TargetValue = $null,

        [Parameter(Mandatory)]
        [string]$Reason,

        [Parameter()]
        [AllowNull()]
        [string]$DocReference = $null
    )

    [PSCustomObject][ordered]@{
        Feature      = $Feature
        Capability   = $Capability
        Severity     = $Severity
        Action       = $Action
        SourceValue  = $SourceValue
        TargetValue  = $TargetValue
        Reason       = $Reason
        DocReference = $DocReference
    }
}
