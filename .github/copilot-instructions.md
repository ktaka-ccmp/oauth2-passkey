# Development Guidelines

**Primary Reference**: All development guidelines are consolidated in `CLAUDE.md`.

Please review and follow the complete guidelines in `CLAUDE.md`, which include:

## Library Design Principles
- Publication readiness for crates.io
- Simplicity and minimal dependencies
- Error handling with `thiserror` (not `anyhow` for libraries)
- Minimal visibility and proper API design

## Development Workflow
- Minimal, targeted changes only
- Explicit approval required for changes beyond immediate request
- Meaningful commit messages reflecting actual changes
- Error safety (avoid `unwrap()`/`expect()` except where reasonable)

## Testing Standards
- Incremental testing (write one test at a time, ensure it passes)
- Approval required before proceeding to next file or writing multiple tests
- Non-invasive testing (don't modify original functions without permission)
- Test placement at bottom of files
- Use `test_utils` module for data store and cache initialization
- Test actual functionality by calling functions, not mimicking behavior

## Documentation Standards
- **Fact-based only** - never make assumptions about codebase structure
- **Verify first** - always examine actual code before making statements
- **Explicit uncertainty** - use phrases like "Based on examination of..."
- **Error prevention**: STOP → Verify → Use Tools → Examine Code → Document Facts

## Code Quality
- Clippy enforcement (automated via pre-commit hook)
- Consistent formatting with `cargo fmt`
- All warnings must be addressed before commits

## Quick Reminders for Copilot
- Use `thiserror` instead of `anyhow` for library code
- Avoid `unwrap()`/`expect()` except in unit tests where reasonable
- Ask before making changes beyond the immediate request
- Always verify code structure exists before documenting it
- Follow the incremental testing approach

**Please consult CLAUDE.md for complete details on all development standards.**
