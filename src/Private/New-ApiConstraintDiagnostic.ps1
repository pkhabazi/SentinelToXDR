function New-ApiConstraintDiagnostic {
    <#
    .SYNOPSIS
        Records that the custom detection API will refuse, or has constrained, this rule.

    .DESCRIPTION
        A class of finding the module did not have before 1.0.0: the rule converts, the
        payload validates against CustomDetection.schema.json, the query runs in advanced
        hunting - and POST /security/rules/detectionRules answers 400.

        Five such constraints are enforced by the service and stated in neither the Graph
        reference nor the product documentation. Each was found by deploying to a live
        tenant and reading the error; they are recorded with their provenance in
        src/Data/GraphDetectionRule.psd1 (TacticConstraints, RequiredAlertTemplateFields,
        EntityIdentifierRequirements) and written up in docs/API-Constraints.md.

        Every diagnostic from here carries the constraint name as its TargetValue, which is
        what src/Data/MigrationReadiness.psd1 matches on to decide the impact. This function
        deliberately does NOT choose an impact: doing so in code would put a verdict
        decision somewhere nobody can find it.

        None of these is Blocking. In every case one added field on the SOURCE rule fixes
        it, which is why the caller is expected to name that field in the reason.

    .PARAMETER Constraint
        The constraint name, used as TargetValue and as the join key into
        MigrationReadiness.psd1: TacticsTruncated, EntityMappingsMissing, AssetEntityMissing
        or EntityIdentifierWeak. (TacticsMissing and TechniqueMissing were retired on
        2026-09-15 when the service stopped enforcing them.)

    .PARAMETER Reason
        The human-readable finding. Should name the field to add on the source rule.

    .PARAMETER SourceValue
        What the source rule carried, for the diagnostic record.

    .PARAMETER Action
        The conversion action recorded on the diagnostic. Defaults to Unsupported.

    .PARAMETER DiagnosticSink
        A List[object] the diagnostic is appended to. Nothing happens when it is $null.

    .OUTPUTS
        The diagnostic record, or $null when there is no sink.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Creates an in-memory diagnostic record; changes no system state.')]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Constraint,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Reason,

        [Parameter()]
        [AllowNull()]
        [object]$SourceValue,

        [Parameter()]
        [ValidateSet('Dropped', 'Unsupported', 'RequiresReview', 'Constrained')]
        [string]$Action = 'Unsupported',

        [Parameter()]
        [AllowNull()]
        [object]$DiagnosticSink
    )

    $record = New-ConversionDiagnostic -Feature 'Rule deployment' -Capability 'Custom detection API requirements' `
        -Severity 'Warning' -Action $Action -SourceValue $SourceValue -TargetValue $Constraint `
        -Reason $Reason -DocReference 'docs/API-Constraints.md - observed from the live API; not in the Graph reference'

    if ($null -ne $DiagnosticSink) {
        $DiagnosticSink.Add($record)
        Write-Warning $record.Reason
    }

    return $record
}
