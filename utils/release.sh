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

get_latest_version() {
    local crate_name=$1
#   echo "🔍 Fetching latest version of $crate_name from crates.io"

    latest_version=$(cargo search "$crate_name" | grep "^$crate_name " | awk '{print $3}' | tr -d '"')

    if [ -z "$latest_version" ]; then
        echo "❌ Failed to fetch latest version for $crate_name"
        exit 1
    fi

#    echo "✅ Latest version of $crate_name is $latest_version"
    echo "$latest_version"
}

increment_version() {
    local latest_version=$1

    if [[ "$latest_version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        major=${BASH_REMATCH[1]}
        minor=${BASH_REMATCH[2]}
        patch=${BASH_REMATCH[3]}

        new_patch=$((patch + 1))
        new_version="$major.$minor.$new_patch"

        echo "$new_version"
    else
        echo "❌ Invalid version format: $latest_version"
        exit 1
    fi
}

set_workspace_version() {
    local version=$1
    echo "📦 Setting workspace version $version"

    sed -i "s/^version = \".*\"/version = \"$version\"/" Cargo.toml || {
        echo "❌ Failed to update workspace version in Cargo.toml"
        exit 1
    }

    if ! grep -q "^version = \"$version\"" Cargo.toml; then
        echo "❌ Failed to update workspace version in Cargo.toml"
        exit 1
    fi
}

set_crate_version() {
    local version=$1
    echo "📦 Setting crate version to $version"

    # Set oauth2-passkey dependency to specific version for publishing
    sed -i "s/^oauth2-passkey = .*/oauth2-passkey = \"$version\"/" oauth2_passkey_axum/Cargo.toml || {
        echo "❌ Failed to update oauth2-passkey dependency in oauth2_passkey_axum/Cargo.toml"
        exit 1
    }

    # Verify the version was set correctly
    if ! grep -q "oauth2-passkey = \"$version\"" oauth2_passkey_axum/Cargo.toml; then
        echo "❌ Failed to update oauth2-passkey dependency in oauth2_passkey_axum/Cargo.toml"
        exit 1
    fi
}

revert_crate_version() {
    echo "📦 Reverting crate to path dependency for development"

    # Revert oauth2-passkey dependency back to path for development
    sed -i 's/^oauth2-passkey = .*/oauth2-passkey = { path = "..\/oauth2_passkey" }/' oauth2_passkey_axum/Cargo.toml || {
        echo "❌ Failed to revert oauth2-passkey dependency in oauth2_passkey_axum/Cargo.toml"
        exit 1
    }

    # Verify the path dependency was set correctly
    if ! grep -q 'oauth2-passkey = { path = "../oauth2_passkey" }' oauth2_passkey_axum/Cargo.toml; then
        echo "❌ Failed to revert oauth2-passkey dependency in oauth2_passkey_axum/Cargo.toml"
        exit 1
    fi
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
    echo "Usage: $0 [--exec|-e|--dry-run|-d|-n]"
    echo "Example: $0 -e"
    exit 1
fi

latest=$(get_latest_version oauth2-passkey-axum)
release=$(increment_version $latest)
next=$(increment_version $release)-dev

VERSION=$release
DRY_RUN=false
if [[ "$1" == "--dry-run" || "$1" == "-d" || "$1" == "-n" ]]; then
    DRY_RUN=true
    echo "🧪 Dry run mode enabled. No changes will be pushed or published."
elif [[ "$1" == "--exec" || "$1" == "-e" ]]; then
    DRY_RUN=false
    echo "🚀 Execution mode enabled. Changes will be pushed and published."
else
    echo "❌ Invalid option. Use --dry-run or --exec."
    exit 1
fi

echo "📋 Releasing version: $VERSION"

check_git_clean
check_branch

git checkout "release-$VERSION" || {
    echo "Creating new branch release-$VERSION"
    git checkout -b "release-$VERSION" || {
        echo "❌ Failed to create and switch to release branch release-$VERSION"
        exit 1
    }
}
git rebase master || {
    echo "❌ Failed to rebase release branch on master"
    exit 1
}

set_workspace_version "$VERSION"

if [ "$DRY_RUN" = true ]; then
    echo "🧪 Dry run:"

    echo "cargo publish -p oauth2-passkey -n"
    cargo publish -p oauth2-passkey -n

    if cargo search "oauth2-passkey" | grep -q "^oauth2-passkey.*$VERSION"; then
        echo "cargo publish -p oauth2-passkey-axum -n"
        cargo publish -p oauth2-passkey-axum -n
    fi
else
    git add Cargo.toml && git commit -m "Set workspace version for release $VERSION" || {
        echo "❌ Failed to stage or commit workspace version changes"
        exit 1
    }

    git push origin "release-$VERSION" || {
        echo "❌ Failed to push release branch release-$VERSION"
        exit 1
    }

    echo "🎯 Step 1: Releasing oauth2-passkey $VERSION"
    if cargo search "oauth2-passkey" | grep -q "^oauth2-passkey.*$VERSION"; then
        echo "✅ oauth2-passkey $VERSION is already published. Skipping."
    else
        cargo publish -p oauth2-passkey || {
            echo "❌ Failed to publish oauth2-passkey"
            exit 1
        }
    fi

    wait_for_crates_io "oauth2-passkey" "$VERSION"

    echo "🎯 Step 2: Preparing oauth2-passkey-axum release"

    set_crate_version "$VERSION"

    git add oauth2_passkey_axum/Cargo.toml && git commit -m "Set workspace version for release $VERSION" || {
        echo "❌ Failed to stage or commit workspace version changes"
        exit 1
    }

    git push origin "release-$VERSION" || {
        echo "❌ Failed to push release branch release-$VERSION"
        exit 1
    }

    echo "🎯 Step 3: Releasing oauth2-passkey-axum $VERSION"
    if cargo search "oauth2-passkey-axum" | grep -q "^oauth2-passkey-axum.*$VERSION"; then
        echo "✅ oauth2-passkey-axum $VERSION is already published. Skipping."
    else
        cargo publish -p oauth2-passkey-axum || {
            echo "❌ Failed to publish oauth2-passkey-axum"
            exit 1
        }
    fi

    update_tag "$VERSION"

    set_workspace_version "$next"
    revert_crate_version

    git add Cargo.toml oauth2_passkey_axum/Cargo.toml && git commit -m "Prepare for next development version $next" || {
        echo "❌ Failed to stage or commit next development version changes"
        exit 1
    }
    git push origin "release-$VERSION" || {
        echo "❌ Failed to push release branch release-$VERSION"
        exit 1
    }

    gh pr create --base master --head "release-$VERSION" --title "Release $VERSION" --body "Release $VERSION of oauth2-passkey workspace" || {
        echo "❌ Failed to create pull request for release branch"
        exit 1
    }
    echo "🎉 Pull request created for release branch release-$VERSION"
fi

git checkout master || {
    echo "❌ Failed to switch back to master branch"
    exit 1
}
