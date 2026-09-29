function ConvertTo-DetectionText {
    <#
    .SYNOPSIS
        Serializes a detection rule object to YAML or JSON.

    .DESCRIPTION
        One place decides how a detection is rendered, so the converter, the exporter and
        the report writer cannot drift apart.

        JSON is written with enough depth for the nested Graph shape
        (detectionAction.alertTemplate.entityMappings.accounts[].nameColumn is five levels
        down before the array) and without escaping non-ASCII characters, because rule
        descriptions in the community content contain them.

    .PARAMETER Rule
        The detection rule object (ordered hashtable).

    .PARAMETER As
        Yaml or Json.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Rule,

        [Parameter()]
        [ValidateSet('Yaml', 'Json')]
        [string]$As = 'Yaml'
    )

    if ($As -eq 'Json') {
        return ($Rule | ConvertTo-Json -Depth 20)
    }

    return ($Rule | ConvertTo-Yaml)
}
