# Issue: Documentation and Demo Cleanup

## ID: 2026-01-26-02

## Status: completed

## Priority: low

## Description

Documentation structure improvements and demo application consistency fixes.

## Related Files

- `docs/src/integration/customizing-css.md` - New CSS customization docs
- `docs/src/integration/customizing-templates.md` - Renamed from custom-pages.md
- `demo-profile/src/db.rs` - APP_DATABASE_URL
- `demo-todo/src/db.rs` - APP_DATABASE_URL

## Notes

Key decisions:
1. Documentation parallel structure: CSS and template customization with matching titles
2. Unified environment variable: `APP_DATABASE_URL` for all demos
3. Keep demo-profile and demo-todo separate (distinct data patterns, better education)

## Resolution

Completed 2026-01-26. Documentation restructured and demo configs unified.
