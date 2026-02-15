# Issue: Update CHANGELOG.md for Changes Since v0.2.0

## Table of Contents

- [Description](#description)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 2026-02-09-01

## Status: completed

## Priority: medium

## Difficulty: medium

## Description

The `[Unreleased]` section in CHANGELOG.md needs to be reviewed and updated to
accurately reflect all changes since the v0.2.0 release. There are currently 126
non-merge commits since v0.2.0, covering several major feature areas that are either
missing or incomplete in the changelog.

### Current State of [Unreleased]

The existing [Unreleased] section covers some items but is likely incomplete.
A thorough review is needed comparing git log against the changelog.

### Feature Areas Since v0.2.0

Based on commit history, the following areas need to be verified in the changelog:

1. **Admin Force Logout** - Force logout feature with session status indicators
2. **Login History / Audit** - Login history tracking, audit page, date filtering
3. **Passkey Promotion** - OAuth2 post-login passkey registration promotion
   (`ask`/`force` modes), UA + AAGUID heuristic for modal control
4. **Demo Improvements** - Cross-origin demo, HTTPS removal, demo cleanup
5. **Documentation** - README updates, API reference updates, issue tracking system
6. **Dependency Updates** - reqwest, memchr, and other dependency updates
7. **Refactoring** - Visibility minimization, module reorganization
8. **Bug Fixes** - credential_id recording on passkey login, etc.

## Approach

1. Run `git log --oneline v0.2.0..HEAD --no-merges` to get the full commit list
2. Categorize each commit into Added/Changed/Fixed/Security/Removed sections
3. Compare against the existing [Unreleased] content to identify gaps
4. Draft missing entries, following the existing changelog style
5. Update the [Unreleased] section with all missing entries
6. Ensure formatting matches Keep a Changelog conventions

## Related Files

- `CHANGELOG.md`

## Implementation Tasks

- [x] Review full git log since v0.2.0 (195 commits)
- [x] Identify entries already present in [Unreleased]
- [x] Draft missing entries for each feature area
- [x] Update [Unreleased] section in CHANGELOG.md
- [x] Verify no significant changes are omitted

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-09: Issue created

- Context: CHANGELOG.md [Unreleased] section may be incomplete after extensive
  development since v0.2.0 release
- Decision: Create a dedicated issue to systematically review and update the changelog
- Reason: With 126 commits across multiple feature areas, a focused review ensures
  nothing is missed before the next release

## Resolution

Reviewed 195 non-merge commits since v0.2.0 and updated the [Unreleased] section.
Added 12 new entries to Added, 7 to Fixed, reorganized Changed, and added Removed section.
Commit: 6fc04f9.

