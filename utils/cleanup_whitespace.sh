#!/bin/bash
# Whitespace cleanup utility for oauth2-passkey project
#
# ⚠️  IMPORTANT: This script is for NON-RUST files only!
# For Rust files (.rs), use `cargo fmt --all` which handles all formatting.
#
# This script cleans whitespace in non-Rust files (.md, .toml, .sh, etc.):
# - Removes trailing spaces from all lines
# - Clears whitespace from empty lines
# - Ensures files end with a single newline
#
# Usage: ./utils/cleanup_whitespace.sh [file_pattern]
#        ./utils/cleanup_whitespace.sh                    # Clean non-Rust files
#        ./utils/cleanup_whitespace.sh "docs/*.md"        # Clean specific pattern

set -e

# Default pattern covers NON-RUST files only (Rust files handled by cargo fmt)
PATTERN="${1:-*.md *.toml utils/*.sh docs/*.md}"

echo "🧹 Cleaning whitespace in oauth2-passkey NON-RUST files..."
echo "ℹ️  Rust files (.rs) should use 'cargo fmt --all' instead!"

# Function to clean a single file
cleanup_file() {
    local file="$1"
    if [[ -f "$file" && ! "$file" == *.rs ]]; then
        echo "  Cleaning: $file"
        # Remove trailing spaces and empty line whitespace
        sed -i -e 's/^[[:space:]]*$//g' -e 's/[[:space:]]*$//' "$file"

        # Ensure file ends with exactly one newline
        # Remove all trailing newlines, then add exactly one
        # Use printf to avoid the extra newline that echo adds
        # Preserve file permissions by copying them to temp file
        cp "$file" "$file.tmp"
        printf '%s\n' "$(sed -e :a -e '/^\s*$/{$d;N;ba' -e '}' "$file")" > "$file.tmp"
        mv "$file.tmp" "$file"
    elif [[ "$file" == *.rs ]]; then
        echo "  Skipping Rust file: $file (use 'cargo fmt --all' instead)"
    fi
}

# Process files based on pattern
if [[ "$PATTERN" == *"*"* ]]; then
    # Pattern contains wildcards, use find but exclude .rs files
    find . -name "*.md" -o -name "*.toml" -o -name "*.sh" -o -name "*.yml" -o -name "*.yaml" | while read -r file; do
        cleanup_file "$file"
    done
else
    # Single file
    cleanup_file "$PATTERN"
fi

echo "✅ Whitespace cleanup completed!"
echo ""
echo "🔍 To verify clean output, check that files don't show:"
echo "   - 'trailing whitespace' warnings"
echo "   - 'No newline at end of file' messages"
