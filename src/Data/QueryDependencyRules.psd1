@{
    # -------------------------------------------------------------------------
    # KQL constructs that convert cleanly and then cannot RUN in Defender XDR.
    #
    # This is the false-green class of failure, and it is the most expensive one
    # this module can produce: every structural check passes, the report says
    # deploy it, and the detection fails the moment it runs in the tenant.
    #
    # A Sentinel query can reach things that exist only in a Log Analytics
    # workspace — a watchlist, an ASIM parser, a saved function, another
    # workspace. Advanced hunting has no equivalent, so the query is not
    # portable no matter how well the rule around it converts.
    #
    # Measured against the Azure/Azure-Sentinel content repository (3,671 rules,
    # 2026-08-19): 226 rules carry at least one of these, and 150 of them were
    # graded Ready or Review before this check existed.
    #
    # Detection is a HEURISTIC, run over the query with string literals blanked
    # and comments stripped (the same treatment Get-QueryTableClassification and
    # Test-NrtQueryCompatibility use). It is deliberately biased toward saying
    # something: a false warning costs a minute of reading, a false green costs
    # a detection that silently never fires. Test-XDRDetectionQuery is what
    # settles it for certain, by running the query against the tenant.
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc   = 'Advanced hunting schema and Sentinel workspace-only constructs'
        SourceUrl   = 'https://learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables'
        FetchedDate = '2026-08-19'
        Note        = 'Heuristic. Proven per-rule only by Test-XDRDetectionQuery against a live tenant.'
    }

    # Feature/Capability stamped on the diagnostic. These constructs are a
    # property of the QUERY, so they are reported under the same Feature the
    # data-tier classification uses.
    Feature    = 'Rule query'
    Capability = 'Defender XDR data'

    Dependencies = @(
        @{
            Name     = 'Watchlist'
            # _GetWatchlist('name') is the documented accessor; the alias form
            # and the legacy _GetWatchlistAlias are covered by the same prefix.
            Pattern  = '_GetWatchlist\w*\s*\('
            Severity = 'Warning'
            Action   = 'RequiresReview'
            Reason   = "references a Microsoft Sentinel watchlist. Watchlists live in the Log Analytics workspace and have no equivalent in advanced hunting, so this query will fail to run as a custom detection even though the rule around it converted cleanly. Replace the lookup with an inline datatable, an externally maintained list, or a Defender XDR table before deploying."
        }
        @{
            Name     = 'AsimParser'
            # ASIM parsers are workspace-deployed functions: _Im_Dns(), ASimDnsNetwork,
            # imProcessCreate. The leading-underscore form is the parameterised parser.
            Pattern  = '\b_Im_\w+|\bASim\w+|\bimProcessCreate\b|\bim[A-Z]\w+\s*\('
            Severity = 'Warning'
            Action   = 'RequiresReview'
            Reason   = "references an ASIM parser. ASIM parsers are functions deployed into the Log Analytics workspace, not tables in advanced hunting, so this query will fail to run as a custom detection. Rewrite it against the underlying Defender XDR tables, or keep the rule in Microsoft Sentinel."
        }
        @{
            Name     = 'ExternalData'
            Pattern  = '\bexternaldata\s*\('
            Severity = 'Warning'
            Action   = 'RequiresReview'
            Reason   = "uses the externaldata operator to pull from a URI at query time. Advanced hunting custom detections do not support externaldata, so this query will fail to run. Materialise the list into the query as a datatable, or into a Defender XDR table, before deploying."
        }
        @{
            Name     = 'CrossWorkspace'
            Pattern  = '\bworkspace\s*\(|\bcluster\s*\(|\bdatabase\s*\('
            Severity = 'Warning'
            Action   = 'RequiresReview'
            Reason   = "reaches another workspace, cluster or database. A custom detection runs only against the advanced hunting data of its own tenant ('Cross workspaces detection using the workspace operator' is Planned), so this query will fail to run. Scope it to local tables before deploying."
        }
        @{
            Name     = 'SavedFunction'
            # A bare _Name(...) call that is not one of the above: the leading
            # underscore is the Sentinel convention for a workspace-saved function.
            # Warning, not Info: a query the tenant cannot resolve is refused at POST,
            # not at first run (docs/API-Constraints.md, 2026-09-16).
            Pattern  = '(?<![\w.])_(?!Im_|GetWatchlist)\w+\s*\('
            Severity = 'Warning'
            Action   = 'RequiresReview'
            Reason   = "calls a workspace-saved function (a name beginning with an underscore). Saved functions live in the Log Analytics workspace and are not available to a custom detection. Confirm the function resolves in advanced hunting, or inline its body, before deploying."
        }
    )
}
