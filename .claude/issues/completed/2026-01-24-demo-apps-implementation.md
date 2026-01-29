# Issue: Demo Apps Implementation (demo-profile, demo-todo)

## ID: 2026-01-24-02

## Status: completed

## Priority: medium

## Description

Implement demo applications demonstrating how to extend user data with application-specific tables:
- demo-profile: User profile extension with avatar support
- demo-todo: User-specific data management (ToDo list)

## Related Files

- `demo-profile/` - Profile extension demo
- `demo-todo/` - ToDo list demo
- `docs/src/getting-started/architecture.md` - Added to documentation

## Notes

Key pattern: Use separate tables linked by `user_id` rather than modifying the library's user table.

Avatar support uses Google `picture` URL from `oauth2_accounts` table via `list_accounts_core()`.

Database schema for demo-profile:
```sql
CREATE TABLE user_profiles (
    user_id TEXT PRIMARY KEY,
    display_name TEXT,
    bio TEXT,
    avatar_url TEXT,
    theme TEXT DEFAULT 'light',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Resolution

Completed 2026-01-26. Both demo applications implemented with PostgreSQL support.
Commits: f2dad8e, multiple follow-up fixes.
