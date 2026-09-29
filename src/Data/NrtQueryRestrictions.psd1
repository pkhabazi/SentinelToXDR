@{
    # -------------------------------------------------------------------------
    # NRT / continuous custom-detection KQL restrictions (Stage 3 of the
    # Edge-Case plan).
    #
    # A Sentinel NRT (kind=NRT) rule maps to a Defender XDR "Continuous (NRT)"
    # custom detection. Continuous queries run on a single streaming table and
    # support only a RESTRICTED subset of KQL. When the source query uses a
    # construct that continuous mode disallows, the rule CANNOT be emitted as
    # continuous ('0') — it is downgraded to the shortest scheduled frequency
    # and diagnosed. This file is the SINGLE SOURCE OF TRUTH for that restricted
    # set: when Microsoft changes the continuous-query limitations, this is a
    # DATA edit (mirrors the Stage 0/1/2 psd1 + metadata-stamp pattern) — no code
    # change in Test-NrtQueryCompatibility.
    #
    # AUTHORITATIVE SOURCE (fetched 2026-06-04):
    #   https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules
    #   section "Queries you can run continuously" (git_commit_id
    #   78bcfca43507e505a7685982479783c2ee0634da, ms.date 2026-05-19). It states a
    #   query can run continuously ONLY as long as:
    #     - the query references ONE table only;
    #     - it uses operators from the supported KQL features list;
    #     - it does NOT use joins, unions, or the externaldata operator;
    #     - it does NOT include any comment lines.
    #
    # The DisallowedOperators list below starts from that authoritative trio
    # (join / union / externaldata) and adds a CONSERVATIVE set of other tabular
    # operators that are not part of the supported continuous KQL feature set
    # (evaluate plugins, graph operators, fork, partition, cross-cluster/
    # cross-workspace references). Erring toward flagging is safe: a false
    # "incompatible" only downgrades the rule to scheduled (with a diagnostic),
    # whereas a false "compatible" would emit an invalid continuous detection.
    # Remove an entry here if Microsoft later supports it in continuous mode.
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc    = 'custom-detection-rules.md'
        DocUrl       = 'https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules'
        DocAnchor    = '#queries-you-can-run-continuously'
        GitCommitId  = '78bcfca43507e505a7685982479783c2ee0634da'
        MsDate       = '2026-05-19'
        FetchedDate  = '2026-06-04'
        Note         = 'Disallowed KQL operators/constructs for Continuous (NRT) custom detection queries. Authoritative trio = join, union, externaldata + single-table rule + no comments; remaining entries are a conservative superset of operators outside the supported continuous KQL feature set.'
    }

    # Each entry:
    #   Operator   = the KQL operator/construct keyword (lower-case) to scan for
    #                as a standalone token / pipe operator.
    #   Label      = the human-readable violation label surfaced in diagnostics.
    #   Authoritative = $true when the restriction is stated VERBATIM in the MS doc
    #                   ("doesn't use joins, unions, or the externaldata operator");
    #                   $false for the conservative additions.
    #                   NOTE: Authoritative is INFORMATIONAL-ONLY METADATA. It is not
    #                   consumed by Test-NrtQueryCompatibility and does NOT affect the
    #                   downgrade decision (an authoritative and a conservative violation
    #                   both downgrade the rule identically). It exists to document the
    #                   provenance of each entry for maintainers reviewing this data file.
    DisallowedOperators = @(
        @{ Operator = 'join';              Label = 'join';                  Authoritative = $true  }
        @{ Operator = 'union';             Label = 'union';                 Authoritative = $true  }
        @{ Operator = 'externaldata';      Label = 'externaldata';          Authoritative = $true  }
        @{ Operator = 'evaluate';          Label = 'evaluate (plugin)';     Authoritative = $false }
        @{ Operator = 'partition';         Label = 'partition';             Authoritative = $false }
        @{ Operator = 'fork';              Label = 'fork';                  Authoritative = $false }
        @{ Operator = 'make-graph';        Label = 'make-graph (graph)';    Authoritative = $false }
        @{ Operator = 'graph-match';       Label = 'graph-match (graph)';   Authoritative = $false }
        @{ Operator = 'graph-mark-components'; Label = 'graph-mark-components (graph)'; Authoritative = $false }
        @{ Operator = 'lookup';            Label = 'lookup (join-like)';    Authoritative = $false }
    )

    # Cross-cluster / cross-workspace references are not addressable by a single
    # continuous table stream. These are matched as substrings (function-call /
    # operator forms) rather than standalone pipe operators.
    DisallowedConstructs = @(
        @{ Pattern = 'cluster(';   Label = 'cross-cluster reference (cluster())';     Authoritative = $false }
        @{ Pattern = 'workspace(';  Label = 'cross-workspace reference (workspace())'; Authoritative = $false }
        @{ Pattern = 'database(';   Label = 'cross-database reference (database())';   Authoritative = $false }
    )

    # The authoritative doc also requires a continuous query to reference ONE
    # table only, and to contain NO comment lines. These are validated in code
    # (multi-table via the Stage 1 table extractor; comments via the raw query),
    # but their flags live here so the policy is data-visible.
    SingleTableOnly      = $true   # >1 referenced base table => not continuous.
    CommentsDisallowed   = $true   # any // or /* */ comment => not continuous.
}
