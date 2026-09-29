**What this changes**

**Why**
<!-- Link the issue, a Microsoft doc, or a service error message. -->

**Checklist**
- [ ] `./tests/Invoke-Tests.ps1` is green (paste the pass/fail line)
- [ ] Behaviour changes have a Pester test
- [ ] A new gap has a sample in `Samples/` and an entry in `Samples/expected.psd1`
- [ ] Lookup changes are data edits in `src/Data/*.psd1`, with the `Metadata` block updated
- [ ] `CHANGELOG.md` has an `[Unreleased]` entry for anything a user would notice
