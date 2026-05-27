<!--
Thanks for the contribution! Quick checklist before you push the
"Create pull request" button.

If your PR addresses a SECURITY ISSUE, please use a private advisory
instead of a public PR. See SECURITY.md.
-->

## What this PR does

(one-line summary that would make sense in the CHANGELOG)

## Why

(the motivating problem; link the issue if there is one)

## Implementation notes

(anything reviewers need to know that isn't obvious from the diff)

## Checklist

- [ ] Tests added / updated (race, fuzz, property, or chaos as appropriate — see CONTRIBUTING.md)
- [ ] `make test` passes locally
- [ ] `make bench-compare-strict` passes (no >2x performance regression)
- [ ] If a new wire format / flag / metric / endpoint: PLAYBOOK.md updated
- [ ] If a new defence: THREATMODEL.md row added or updated
- [ ] If a breaking change: CHANGELOG.md "Unreleased" section flagged with `BREAKING` and a deprecation path
- [ ] If touching crypto / fwdsec / threshold / hybrid: extra reviewer ping (CODEOWNERS handles this automatically)
