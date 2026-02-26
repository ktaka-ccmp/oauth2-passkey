#!/bin/bash
# Update oauth2-passkey-axum version numbers in documentation files.
# Searches docs/src/, Readme.md, and crate READMEs for version strings
# like `version = "X.Y"` and updates them to the specified version.
#
# Usage:
#   ./utils/update_doc_versions.sh 0.4        # Update to 0.4
#   ./utils/update_doc_versions.sh 0.4 --dry   # Preview changes only
#
# This script is called automatically by release.sh but can also be
# run manually when version numbers need updating outside of a release.

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <major.minor> [--dry]"
    echo "Example: $0 0.4"
    echo "         $0 0.4 --dry"
    exit 1
fi

TARGET_VERSION="$1"
DRY_RUN=false

if [ "$2" = "--dry" ]; then
    DRY_RUN=true
fi

# Validate format: X.Y
if [[ ! "$TARGET_VERSION" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "Error: version must be in X.Y format (e.g., 0.4), got: $TARGET_VERSION"
    exit 1
fi

# Files to scan (excluding archived docs which are historical records)
DOC_FILES=(
    "docs/src/"
    "Readme.md"
    "oauth2_passkey/README.md"
    "oauth2_passkey_axum/README.md"
)

# Pattern: oauth2-passkey-axum with a version string like "X.Y"
# Matches: version = "0.2", version "0.3", = "0.4" etc.
SEARCH_PATTERN='oauth2-passkey-axum.*"[0-9]\+\.[0-9]\+"'

echo "Updating oauth2-passkey-axum version references to \"$TARGET_VERSION\""
echo ""

# Find all matching files (excluding archived/)
matches=$(grep -rn "$SEARCH_PATTERN" "${DOC_FILES[@]}" \
    --include='*.md' 2>/dev/null | grep -v archived/ || true)

if [ -z "$matches" ]; then
    echo "No version references found."
    exit 0
fi

# Show current state
echo "Found references:"
echo "$matches"
echo ""

# Count files that need updating (have a different version)
stale=$(echo "$matches" | grep -v "\"$TARGET_VERSION\"" || true)

if [ -z "$stale" ]; then
    echo "All references already use \"$TARGET_VERSION\". Nothing to do."
    exit 0
fi

echo "References to update:"
echo "$stale"
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "[dry run] No files modified."
    exit 0
fi

# Perform the replacement
# Replace version = "X.Y" patterns in oauth2-passkey-axum references
# Uses a precise sed pattern to avoid replacing unrelated version strings
find_and_replace() {
    local file="$1"
    # Replace: oauth2-passkey-axum = "X.Y" -> oauth2-passkey-axum = "TARGET"
    sed -i "s/\(oauth2-passkey-axum.*\)\"[0-9]\+\.[0-9]\+\"/\1\"$TARGET_VERSION\"/g" "$file"
}

# Get unique file paths from stale matches
files_to_update=$(echo "$stale" | cut -d: -f1 | sort -u)

for file in $files_to_update; do
    echo "Updating: $file"
    find_and_replace "$file"
done

echo ""
echo "Done. Updated $(echo "$files_to_update" | wc -l) file(s)."

# Verify
echo ""
echo "Verification:"
remaining=$(grep -rn "$SEARCH_PATTERN" "${DOC_FILES[@]}" \
    --include='*.md' 2>/dev/null | grep -v archived/ | grep -v "\"$TARGET_VERSION\"" || true)

if [ -n "$remaining" ]; then
    echo "WARNING: Some references were not updated:"
    echo "$remaining"
    exit 1
fi
echo "All references now use \"$TARGET_VERSION\"."
