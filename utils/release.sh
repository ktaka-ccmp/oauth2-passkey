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

check_branch() {
    # Ensure we are on the master branch and it's up-to-date with origin/master
    current_branch=$(git rev-parse --abbrev-ref HEAD)
    if [[ "$current_branch" != "master" ]]; then
        echo "❌ You are not on the master branch."
        exit 1
    fi

    git fetch origin

    behind_count=$(git rev-list --count master..origin/master)
    if [[ "$behind_count" -ne 0 ]]; then
        echo "❌ Your local master is behind origin/master by $behind_count commit(s)."
        exit 1
    fi
    echo "✅ You are on the master branch and it's up-to-date with origin/master."
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

prep_version() {
    local version=$1
    echo "📦 Preparing version $version"

    sed -i "s/^version = \".*\"/version = \"$version\"/" Cargo.toml || {
        echo "❌ Failed to update workspace version in Cargo.toml"
        exit 1
    }

    sed -i "s/oauth2-passkey = { workspace = true }/oauth2-passkey = \"$version\"/" oauth2_passkey_axum/Cargo.toml || {
        echo "❌ Failed to update oauth2-passkey dependency in oauth2_passkey_axum/Cargo.toml"
        exit 1
    }
}

update_tag() {
    local version=$1
    echo "🔖 Updating tag to v$version"

    if git rev-parse "v$version" >/dev/null 2>&1; then
        echo "❌ Tag v$version already exists. Please delete it first."
        exit 1
    fi

    git tag "v$version" -m "Release version $version" || {
        echo "❌ Failed to create tag v$version"
        exit 1
    }

    git push origin "v$version" || {
        echo "❌ Failed to push tag v$version to origin"
        exit 1
    }
    echo "📤 Pushed tag v$version to origin"
}

# Check if version is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <version> [--dry-run]"
    echo "Example: $0 0.1.2"
    exit 1
fi

VERSION=$1
DRY_RUN=false
if [[ "$2" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "🧪 Dry run mode enabled. No changes will be pushed or published."
fi

echo "📋 Releasing version: $VERSION"

check_git_clean
check_branch

git checkout -b "release-$VERSION" || {
    echo "❌ Failed to create and switch to release branch release-$VERSION"
    exit 1
}

prep_version "$VERSION"

git add Cargo.toml oauth2_passkey_axum/Cargo.toml || {
    echo "❌ Failed to stage changes"
    exit 1
}

git commit -m "Prepare for release $VERSION" || {
    echo "❌ Failed to commit changes"
    exit 1
}

if [ "$DRY_RUN" = false ]; then
    git push origin "release-$VERSION" || {
        echo "❌ Failed to push release branch release-$VERSION"
        exit 1
    }

    echo "🎯 Step 1: Releasing oauth2-passkey $VERSION"
    cargo publish -p oauth2-passkey || {
        echo "❌ Failed to publish oauth2-passkey"
        exit 1
    }

    wait_for_crates_io "oauth2-passkey" "$VERSION"

    echo "🎯 Step 3: Releasing oauth2-passkey-axum $VERSION"
    cargo publish -p oauth2-passkey-axum || {
        echo "❌ Failed to publish oauth2-passkey-axum"
        exit 1
    }

    update_tag "$VERSION"
else
    echo "🧪 Dry run: Skipping push and publish steps."
fi

git checkout master || {
    echo "❌ Failed to switch back to master branch"
    exit 1
}
