#!/bin/bash
# Update oauth2-passkey-axum version numbers in documentation files.
# Searches docs/src/, Readme.md, and crate READMEs for version strings
# like `version = "X.Y"` and updates them to the specified version.
#
# Usage:
#   ./utils/update_doc_versions.sh            # Auto-detect from Cargo.toml
#   ./utils/update_doc_versions.sh --dry      # Auto-detect, preview only
#   ./utils/update_doc_versions.sh 0.4        # Override to 0.4
#   ./utils/update_doc_versions.sh 0.4 --dry  # Override to 0.4, preview only
#
# This script is called automatically by release.sh but can also be
# run manually when version numbers need updating outside of a release.

set -e

# Auto-detect version from workspace Cargo.toml (extract major.minor from e.g. "0.3.1-dev")
auto_detect_version() {
    local cargo_toml="Cargo.toml"
    if [ ! -f "$cargo_toml" ]; then
        echo "Error: $cargo_toml not found. Run from project root." >&2
        return 1
    fi
    grep '^version = ' "$cargo_toml" | head -1 | sed 's/.*"\([0-9]*\.[0-9]*\).*/\1/'
}

# Parse arguments
DRY_RUN=false
TARGET_VERSION=""

for arg in "$@"; do
    if [ "$arg" = "--dry" ]; then
        DRY_RUN=true
    elif [ -z "$TARGET_VERSION" ]; then
        TARGET_VERSION="$arg"
    fi
done

# Auto-detect if no version specified
if [ -z "$TARGET_VERSION" ]; then
    TARGET_VERSION=$(auto_detect_version) || exit 1
    echo "Auto-detected version: $TARGET_VERSION (from Cargo.toml)"
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
