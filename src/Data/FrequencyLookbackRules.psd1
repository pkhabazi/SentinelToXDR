@{
    # -------------------------------------------------------------------------
    # Frequency & lookback behaviour of Defender XDR custom detections.
    #
    # Every value here is QUOTED from the product documentation. That matters:
    # the previous version of this file inferred the lookback ("it probably
    # equals the frequency") and was wrong in all four cases, which meant the
    # converter reported confident, specific, incorrect numbers.
    #
    # Source of truth: "Create custom detection rules in Microsoft Defender XDR",
    # sections "Rule frequency" and "Lookback".
    #   https://learn.microsoft.com/defender-xdr/custom-detection-rules#lookback
    #
    # When Microsoft changes these, it is a DATA edit — no code change.
    # -------------------------------------------------------------------------
    Metadata = @{
        SourceDoc    = 'Create custom detection rules in Microsoft Defender XDR'
        SourceUrl    = 'https://learn.microsoft.com/defender-xdr/custom-detection-rules'
        DocAnchor    = '#lookback'
        FetchedDate  = '2026-08-11'
        DocReference = 'Rule frequency + Lookback sections'
        Note         = 'Lookback values are QUOTED FROM the product documentation, not inferred. Earlier versions of this file guessed that the lookback equals the frequency; every value was wrong.'
    }
    # -------------------------------------------------------------------------
    # SENTINEL-ONLY data: the lookback is customizable, and how far it can reach
    # depends on how often the rule runs. Quoted from the product docs:
    #
    #   "For detections set to run in frequencies higher (more frequent) than one
    #    hour, the lookback period is limited to less than 48 hours."
    #   "For detections set to run in frequencies higher than one day, the
    #    lookback can be set up to 14 days."
    #   "For detections set to run in frequencies of one day or less, the
    #    lookback can be set up to 30 days."
    #
    # Read as a ladder (the more often it runs, the shorter the reach):
    #   frequency < 1 hour            -> lookback < 48 hours
    #   1 hour <= frequency < 1 day   -> lookback <= 14 days
    #   frequency >= 1 day            -> lookback <= 30 days
    #
    # The overall supported range is five minutes to 30 days.
    #
    # The earlier version of this file had this INVERTED: it allowed 14 days for
    # sub-hourly rules and clamped everything else to 48 hours, so it shortened
    # lookbacks that were legal and passed ones that were not.
    # -------------------------------------------------------------------------
    Parity = @{
        MinLookbackMinutes = 5
        MaxLookbackDays    = 30
        Tiers = @(
            @{ MaxFrequencyHoursExclusive = 1.0;  MaxLookbackHours = 48.0;  Label = 'less than 48 hours' }
            @{ MaxFrequencyHoursExclusive = 24.0; MaxLookbackHours = 336.0; Label = '14 days' }
            @{ MaxFrequencyHoursExclusive = 0.0;  MaxLookbackHours = 720.0; Label = '30 days' }
        )
    }

    # -------------------------------------------------------------------------
    # DEFENDER XDR data (and Mixed): the lookback is NOT settable. A fixed period
    # is applied based on the frequency. Quoted from the product docs:
    #
    #   "If your custom detections include Defender XDR data, a fixed lookback
    #    period is applied depending on the rule frequency that you choose:
    #      every 24 hours -> 30 days
    #      every 12 hours -> 48 hours
    #      every 3 hours  -> 12 hours
    #      hourly         -> 4 hours"
    #
    # These describe OBSERVED PRODUCT BEHAVIOUR, not a field the converter sets:
    # the Graph schedule carries a frequency and nothing else. They are here so
    # the assessment can tell the user what window the rule will actually see,
    # and flag when the source rule asked for more data than that window holds.
    #
    # The non-'0' keys also define the scheduled rounding buckets (label -> hours
    # via the leading number), so adding a future frequency stays a data edit.
    # -------------------------------------------------------------------------
    FixedLookbackPerFrequency = @{
        '0'   = '0'      # Continuous (NRT): events are tested as they stream.
        '1H'  = 'PT4H'
        '3H'  = 'PT12H'
        '12H' = 'PT48H'
        '24H' = 'P30D'
    }
}
