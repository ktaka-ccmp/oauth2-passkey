# Update CHANGELOG

Review all changes since the last release and update `CHANGELOG.md` with new entries.

## Instructions

1. **Identify the last release version and tag**: Read the top of `CHANGELOG.md` to find the current dev section (e.g., `[0.4.1-dev]`) and the last released version (e.g., `[0.4.0] - 2026-03-15`). Find the corresponding git tag (e.g., `v0.4.0`).

2. **Gather all changes since the last release** by running these commands:
   ```
   git log <tag>..HEAD --oneline
   git log <tag>..HEAD --stat
   ```

3. **Read the Development Journal** (`.claude/issues/JOURNAL.md`) for entries since the last release date. The journal contains detailed motivation, user impact, and design decisions that should inform the CHANGELOG entries.

4. **Read the current CHANGELOG.md** to understand the existing format and avoid duplicating entries already present in the dev section.

5. **Categorize changes** using [Keep a Changelog](https://keepachangelog.com/) categories:
   - **Added**: New features
   - **Changed**: Changes in existing functionality
   - **Deprecated**: Soon-to-be removed features
   - **Removed**: Removed features
   - **Fixed**: Bug fixes
   - **Security**: Vulnerability fixes

6. **Draft the updated dev section** and present it to the user for review. Follow these guidelines:
   - Write from the **library consumer's perspective** (what changes for users of the crate)
   - Each entry should be a single bullet point, concise but informative
   - Use sub-bullets for details when a change has multiple aspects
   - Include env var names, API changes, and behavior changes explicitly
   - Reference PRs or issue IDs where helpful (e.g., `(#274)`)
   - Security fixes should always be in the **Security** section, even if they're also bug fixes
   - Internal refactoring or CI changes generally don't belong in CHANGELOG unless they affect users
   - **Do NOT include**: issue tracking changes, journal entries, session snapshots, or other `.claude/` file changes

7. **Ask the user for approval** before writing the changes. Present a clear diff of what will be added/changed in the dev section.

8. **Update CHANGELOG.md** only after user approval.

9. **Clean up whitespace**: Run `sed -i -e 's/^[[:space:]]*$//g' -e 's/[[:space:]]*$//' CHANGELOG.md`

## Example output format

```markdown
## [0.4.1-dev]

### Added

- MySQL/MariaDB database support via `GENERIC_DATA_STORE_TYPE=mysql`
  - Full CRUD for all storage modules (userdb, oauth2, passkey, audit)
  - Docker Compose setup in `db/mysql/` for MySQL 8.0 and MariaDB 11

### Fixed

- SQLite `last_insert_rowid()` race condition in login history insertion
  - INSERT and SELECT now wrapped in a transaction to guarantee same-connection execution

### Security

- Update rustls-webpki 0.103.9 -> 0.103.10 (RUSTSEC-2026-0049: CRL Distribution Point matching)
```