# Visibility Check

Check Rust code visibility and ensure minimal visibility is used.

## Usage

```
/visibility-check [path]
```

- `path`: Optional. File or directory to check. Defaults to the entire project.

## Instructions

### 1. Find All Public Items

Search for visibility declarations in the specified scope:

```bash
# Find all pub items
grep -rn "^pub \|pub(" --include="*.rs" <path>
```

### 2. Analyze Each Item

For each `pub` or `pub(crate)` item found:

1. **Find all usages** of the item across the codebase
2. **Determine the minimum required visibility**:
   - `private` (no modifier): Only used within the same module
   - `pub(super)`: Only used by parent module or sibling modules via `super::`
   - `pub(crate)`: Used by other modules within the same crate
   - `pub`: Re-exported in `lib.rs` for external use

### 3. Check Re-exports

For items in submodules:
- Check if re-exported in parent `mod.rs`
- Verify the re-export visibility matches the minimum required
- Remember: Source definition must have at least the same visibility as re-export

### 4. Common Issues to Check

| Issue | How to Detect |
|-------|---------------|
| `pub(crate)` should be `pub(super)` | Item only used by sibling modules via `super::` |
| `pub` should be `pub(crate)` | Item not re-exported in `lib.rs` |
| Unused public items | No usage found outside the defining module |
| Struct fields too public | Fields are `pub` but only accessed internally |

### 5. Report Format

Report findings as:

```markdown
## Visibility Check Results

### Issues Found

| File:Line | Item | Current | Recommended | Reason |
|-----------|------|---------|-------------|--------|
| `path/file.rs:42` | `fn foo()` | `pub(crate)` | `pub(super)` | Only used by sibling modules |

### Summary

- Files checked: N
- Items checked: N
- Issues found: N
```

### 6. Fixing Issues

After reporting, offer to fix the issues:
1. Show proposed changes
2. Get user approval
3. Apply changes
4. Verify build passes with `cargo build`
5. Run `cargo clippy` to check for any new warnings

## Visibility Priority Reference

Most restrictive first:
1. `private` (no modifier) - Same module only
2. `pub(super)` - Parent module and siblings via `super::`
3. `pub(crate)` - Any module in the same crate
4. `pub` - External crates (via re-export in lib.rs)

## Examples

```
/visibility-check oauth2_passkey/src/audit
/visibility-check oauth2_passkey/src/coordination/login_history.rs
/visibility-check
```
