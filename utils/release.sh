#!/bin/bash
# Release script for oauth2-passkey workspace
# This script handles the sequential release of oauth2-passkey and oauth2-passkey-axum

set -e

echo "🚀 Starting release process for oauth2-passkey workspace"

# Function to check if we're in a clean git state
check_git_clean() {
    if [[ -n $(git status --porcelain) ]]; then
        echo "❌ Git working directory is not clean. Please commit or stash changes."
        exit 1
    fi
}

# Function to wait for crates.io to update
wait_for_crates_io() {
    local crate_name=$1
    local version=$2
    echo "⏳ Waiting for $crate_name $version to be available on crates.io..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if cargo search "$crate_name" | grep -q "^$crate_name.*$version"; then
            echo "✅ $crate_name $version is now available on crates.io"
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts: $crate_name $version not yet available, waiting 10 seconds..."
        sleep 10
        ((attempt++))
    done
    
    echo "❌ Timeout waiting for $crate_name $version to be available on crates.io"
    return 1
}

# Check if version is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 0.1.2"
    exit 1
fi

VERSION=$1

echo "📋 Releasing version: $VERSION"

# Check git status
check_git_clean

# Step 1: Release oauth2-passkey first
echo "🎯 Step 1: Releasing oauth2-passkey $VERSION"
cd oauth2_passkey
cargo release --execute --no-confirm $VERSION
cd ..

# Step 2: Wait for oauth2-passkey to be available on crates.io
wait_for_crates_io "oauth2-passkey" "$VERSION"

# Step 3: Update oauth2-passkey-axum to use the published version
echo "🔄 Step 2: Updating oauth2-passkey-axum dependencies"
cd oauth2_passkey_axum

# Replace workspace dependency with published version
sed -i "s/oauth2-passkey = { workspace = true }/oauth2-passkey = \"$VERSION\"/" Cargo.toml

# Verify the change
if grep -q "oauth2-passkey = \"$VERSION\"" Cargo.toml; then
    echo "✅ Updated oauth2-passkey dependency to version $VERSION"
else
    echo "❌ Failed to update oauth2-passkey dependency"
    exit 1
fi

# Step 4: Release oauth2-passkey-axum
echo "🎯 Step 3: Releasing oauth2-passkey-axum $VERSION"
cargo release --execute --no-confirm $VERSION
cd ..

# Step 5: Revert back to workspace dependencies for development
echo "🔄 Step 4: Reverting to workspace dependencies for development"
cd oauth2_passkey_axum
sed -i "s/oauth2-passkey = \"$VERSION\"/oauth2-passkey = { workspace = true }/" Cargo.toml

# Verify the revert
if grep -q "oauth2-passkey = { workspace = true }" Cargo.toml; then
    echo "✅ Reverted oauth2-passkey dependency to workspace version"
else
    echo "❌ Failed to revert oauth2-passkey dependency"
    exit 1
fi

cd ..

# Commit the version updates
git add .
git commit -m "chore: release oauth2-passkey and oauth2-passkey-axum $VERSION"

echo "🎉 Release process completed successfully!"
echo "📌 Next steps:"
echo "   1. Review the changes: git log --oneline -5"
echo "   2. Push to remote: git push origin main --tags"
echo "   3. Check crates.io for both packages"
