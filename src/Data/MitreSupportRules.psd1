@{
    # -------------------------------------------------------------------------
    # MITRE completeness rules (Stage 4 of the Edge-Case plan).
    #
    # This file is the DATA SOURCE for how the converter handles MITRE tactics
    # and techniques/subtechniques. It mirrors the Stage 0/1/2/3 psd1 +
    # metadata-stamp pattern: when Microsoft closes a parity gap (compare-doc
    # State flips Planned -> Supported), the BEHAVIOR changes via a data edit
    # here and in CustomDetectionCapabilities.psd1 — not via a code change.
    #
    # Source of truth (compare doc, "Alert enrichment" rows):
    #   "Feature comparison- Microsoft Sentinel analytics rules and Microsoft
    #    Defender custom detections.md"
    # The relevant rows are:
    #   - 'Link multiple MITRE tactics'                              => Planned
    #   - 'Support full list of MITRE techniques and subtechniques'  => Planned
    #   - 'Reflect custom detections in MITRE ATT&CK page'           => Planned
    # The converter reads the live STATE for each of these from
    # CustomDetectionCapabilities.psd1 (single source of truth for States) and
    # uses the structural rules below to decide what to do.
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc    = 'Feature comparison- Microsoft Sentinel analytics rules and Microsoft Defender custom detections.md'
        GitCommitId  = '5c6b247409b0a426e2a24485684a6bcd0a14cf05'
        MsDate       = '2026-05-19'
        DocReference = 'Stage 4 — MITRE completeness'
        Note         = 'Structural rules for MITRE tactic + technique/subtechnique mapping. Capability STATES are read from CustomDetectionCapabilities.psd1; this file holds the structural constraints (format pattern, subset policy, selection strategy).'
    }

    # -------------------------------------------------------------------------
    # The compare-doc Feature/Capability rows this stage consults. The converter
    # looks up each State at runtime via Get-CustomDetectionCapabilities so that
    # a Planned -> Supported flip is a pure data edit. These string pairs MUST
    # match the rows in CustomDetectionCapabilities.psd1 exactly.
    # -------------------------------------------------------------------------
    Capabilities = @{
        MultipleTactics = @{
            Feature    = 'Alert enrichment'
            Capability = 'Link multiple MITRE tactics'
        }
        FullTechniques = @{
            Feature    = 'Alert enrichment'
            Capability = 'Support full list of MITRE techniques and subtechniques'
        }
        AttackPageReflection = @{
            Feature    = 'Alert enrichment'
            Capability = 'Reflect custom detections in MITRE ATT&CK page'
        }
    }

    # -------------------------------------------------------------------------
    # Tactics → single alertCategory.
    #
    # SelectionStrategy controls WHICH single source tactic is kept when a rule
    # lists multiple tactics and the 'Link multiple MITRE tactics' State is NOT
    # Supported. Today only 'FirstMappable' is implemented (keep existing chosen-
    # value behavior). When the State flips to Supported the converter carries
    # ALL mapped tactics instead of one (gated on the State — see the converter).
    # -------------------------------------------------------------------------
    SelectionStrategy = 'FirstMappable'

    # -------------------------------------------------------------------------
    # Techniques / subtechniques.
    #
    # TechniquePattern : the validation regex. Matches a parent technique
    #   ('T1234') or a subtechnique ('T1234.001'). Same pattern as the JSON
    #   schemas (Sentinel.schema.json / CustomDetection.schema.json). Entries
    #   that do NOT match are INVALID and are DROPPED + counted.
    #
    # SubtechniquePattern : distinguishes a subtechnique ('T1234.001') from a
    #   parent ('T1234') AFTER it has passed TechniquePattern.
    #
    # SubsetPolicy : how to treat VALID techniques given the (Planned) State of
    #   'Support full list of MITRE techniques and subtechniques'. Options:
    #     'PassThroughFlag' — pass all valid techniques through unchanged but
    #         emit a RequiresReview diagnostic (the SAFE, HONEST default while
    #         the exact supported subset is undocumented; do NOT silently drop
    #         valid IDs). Subtechniques are listed + counted so the user can
    #         verify against the live product.
    #     'ParentOnly'      — collapse/keep only parent techniques; subtechniques
    #         are DROPPED + counted (use ONLY if the product is CONFIRMED to
    #         reject subtechniques).
    #     'Capped'          — keep at most MaxTechniqueCount entries (order
    #         preserved); the remainder are DROPPED + counted (use ONLY if a real
    #         cap is CONFIRMED).
    #
    # >>> DECISION (2026-06-04): SubsetPolicy = 'PassThroughFlag'. <<<
    #   We could NOT find a documented, concrete constraint on which technique /
    #   subtechnique IDs a custom detection accepts. The compare-doc only marks
    #   "full list ... and subtechniques" as Planned, which means a SUBSET is
    #   supported today but the subset is not enumerated anywhere we can rely on.
    #   Silently dropping valid IDs would lose real ATT&CK coverage, so the safe
    #   behavior is to pass valid techniques through and FLAG (RequiresReview),
    #   separating + counting subtechniques for manual verification.
    #
    #   >>> USER ACTION: confirm against the LIVE product whether custom
    #   detections accept subtechniques (T1234.001) and/or impose a count cap.
    #   If they do, switch SubsetPolicy to 'ParentOnly' or 'Capped' (+ set
    #   MaxTechniqueCount) HERE — no code change required.
    # -------------------------------------------------------------------------
    TechniquePattern    = '^T\d{4}(\.\d{3})?$'
    SubtechniquePattern = '^T\d{4}\.\d{3}$'
    SubsetPolicy        = 'PassThroughFlag'
    MaxTechniqueCount   = 0   # 0 = no cap. Only consulted when SubsetPolicy = 'Capped'.
}
