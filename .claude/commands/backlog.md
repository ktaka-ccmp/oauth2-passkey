# View Backlog

List all open issues in the project.

## Instructions

1. Read all markdown files in `.claude/issues/open/` directory
2. Parse each file to extract:
   - ID (from `## ID: <id>`)
   - Title (from `# Issue: <Title>`)
   - Priority (from `## Priority: <priority>`)
   - Description (first paragraph after `## Description`)

3. Display as a sorted list (by priority: high > medium > low, then by date)

## Output Format

```
# Open Issues

## High Priority
- `ID` [Title](path)
  Related: path/to/files

## Medium Priority
- `ID` [Title](path)
  Related: path/to/files

## Low Priority
- `ID` [Title](path)
  Related: path/to/files

---
Total: N open issues
```

If no open issues exist, report:
```
# Open Issues

No open issues found.
```

## Optional: Show Other Categories

If user requests, also show counts from other directories:
- `.claude/issues/completed/` - Completed issues
- `.claude/issues/deferred/` - Deferred issues
