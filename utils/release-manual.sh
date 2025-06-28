#!/bin/bash
# Simple manual release helper for oauth2-passkey workspace

set -e

VERSION=${1:-$(grep '^version =' oauth2_passkey/Cargo.toml | cut -d'"' -f2)}

echo "📋 Manual Release Process for version: $VERSION"
echo "================================================"

echo ""
echo "🔄 STEP 1: Prepare for release"
echo "Current workspace dependency setup:"
grep -A 10 "\[workspace.dependencies\]" Cargo.toml

echo ""
echo "🎯 STEP 2: Release oauth2-passkey first"
echo "Run: cd oauth2_passkey && cargo publish --dry-run"
echo "Then: cd oauth2_passkey && cargo publish"
echo ""
echo "⏳ STEP 3: Wait for oauth2-passkey to be available"
echo "Check: cargo search oauth2-passkey"
echo "Wait until you see version $VERSION listed"

echo ""
echo "🔄 STEP 4: Update oauth2-passkey-axum dependency"
echo "Edit oauth2_passkey_axum/Cargo.toml:"
echo "Change: oauth2-passkey = { workspace = true }"
echo "To:     oauth2-passkey = \"$VERSION\""

echo ""
echo "🎯 STEP 5: Release oauth2-passkey-axum"
echo "Run: cd oauth2_passkey_axum && cargo publish --dry-run"
echo "Then: cd oauth2_passkey_axum && cargo publish"

echo ""
echo "🔄 STEP 6: Revert for development"
echo "Edit oauth2_passkey_axum/Cargo.toml:"
echo "Change: oauth2-passkey = \"$VERSION\""
echo "Back to: oauth2-passkey = { workspace = true }"

echo ""
echo "🏷️  STEP 7: Tag and commit"
echo "Run: git add . && git commit -m 'chore: release v$VERSION'"
echo "Run: git tag v$VERSION"
echo "Run: git push origin main --tags"

echo ""
echo "✅ That's it! Both crates should be published in the correct order."
