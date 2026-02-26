# Development Journal

Append an entry to `.claude/issues/JOURNAL.md` summarizing the current session's work.

## Instructions

1. **Review the current session's work**: Look at what was accomplished (files changed, issues resolved, features added, bugs fixed, decisions made).

2. **Create a new entry** in English, prepended to the top of the journal (after the header). Use this format:

```markdown
## YYYY-MM-DD: <Short title>

**Issue**: `<ID>` | **Priority**: <priority> | **Difficulty**: <difficulty>

<Context label: "New feature", "Enhancement of <feature name>", "Bug fix", "Breaking change", "Refactoring", "Not merged (deferred)", etc.>

### Motivation

<Why this work was needed. What problem or gap existed before.>

### User-facing impact

- **Before**: <What users experienced before this change>
- **After**: <What users experience after this change>

<Include API changes, behavior changes, new endpoints, new env vars, error message improvements, UI changes -- anything visible to library consumers or end users.>

<Code examples showing the Before/After where they clarify the change:>
```rust
// Before: ...
// After: ...
```

### Design decisions

<Alternatives considered and why this approach was chosen. Trade-offs made. Discoveries during implementation (e.g., security issues found, edge cases uncovered).>

### Key files

`path/to/file1.rs`, `path/to/file2.rs`
```

3. **Entry guidelines**:
   - Write in English
   - Be detailed -- match the depth of the Japanese daily journal entries
   - **User impact is mandatory**: every entry must describe how the change affects library consumers or end users (Before/After)
   - Include code examples for API or behavior changes
   - Document design decisions with rationale (not just what, but why)
   - Note alternatives that were considered and rejected
   - Mark new features, enhancements, breaking changes, and bug fixes explicitly
   - Reference related issue IDs when applicable
   - For multi-topic sessions, create separate entries per topic
   - Newest entries go at the top (reverse chronological)

4. **Read the existing JOURNAL.md first** to avoid duplicating entries already recorded.

5. **Write the updated file** with the new entry prepended after the `# Development Journal` header line.

6. **Clean up whitespace**: Run `sed -i -e 's/^[[:space:]]*$//g' -e 's/[[:space:]]*$//' .claude/issues/JOURNAL.md`
