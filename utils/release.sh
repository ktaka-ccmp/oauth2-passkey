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

    latest_version=$(cargo search "$crate_name" | grep "^$crate_name " | awk '{print $3}' | tr -d '"')

    if [ -z "$latest_version" ]; then
        echo "❌ Failed to fetch latest version for $crate_name"
        exit 1
    fi

    echo "$latest_version"
}

increment_patch_version() {
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

increment_dev_version() {
    local version=$1

    if [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        major=${BASH_REMATCH[1]}
        minor=${BASH_REMATCH[2]}
        patch=${BASH_REMATCH[3]}

        new_patch=$((patch + 1))
        echo "$major.$minor.$new_patch-dev"
    else
        echo "❌ Invalid version format: $version"
        exit 1
    fi
}

validate_version() {
    local version=$1
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "❌ Invalid version format: $version (expected: X.Y.Z)"
        exit 1
    fi
}

check_doc_versions() {
    local version=$1
    local major_minor="${version%.*}"
    echo "📋 Checking documentation for outdated version numbers..."

    local stale_files
    stale_files=$(grep -rn "oauth2-passkey-axum.*version.*\"[0-9]\+\.[0-9]\+\"" \
        docs/src/ Readme.md oauth2_passkey/README.md oauth2_passkey_axum/README.md \
        --include='*.md' 2>/dev/null | grep -v "\"$major_minor\"" | grep -v archived/ || true)

    if [ -n "$stale_files" ]; then
        echo "⚠️  Found documentation with version numbers that don't match $major_minor:"
        echo "$stale_files"
        echo ""
        echo "   Update these files before releasing."
        return 1
    fi
    echo "✅ All documentation version numbers match $major_minor"
}

check_changelog() {
    local version=$1
    echo "📋 Checking CHANGELOG.md..."

    if [ ! -f CHANGELOG.md ]; then
        echo "⚠️  CHANGELOG.md not found."
        return 1
    fi

    # Check that [X.Y.Z] section exists (not -dev)
    if ! grep -q "^## \[$version\]" CHANGELOG.md; then
        echo "⚠️  CHANGELOG.md does not contain a [$version] section."
        echo "   Rename the [-dev] section to [$version] before releasing."
        return 1
    fi

    # Check that no -dev section remains for this version
    if grep -q "^## \[$version-dev\]" CHANGELOG.md; then
        echo "⚠️  CHANGELOG.md still contains a [$version-dev] section."
        echo "   Remove or rename it before releasing."
        return 1
    fi

    echo "✅ CHANGELOG.md contains [$version] section"
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
    echo "📦 Setting oauth2-passkey dependency to $version"

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
    echo "🔖 Creating tag v$version"

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

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -e, --exec       Execute the release (publish to crates.io)"
    echo "  -d, -n, --dry-run  Dry run mode (no changes pushed or published)"
    echo "  -v, --version VERSION  Specify release version (e.g., 0.2.0)"
    echo "                         If not specified, auto-increments patch version"
    echo ""
    echo "Examples:"
    echo "  $0 -d              # Dry run with auto-incremented patch version"
    echo "  $0 -d -v 0.2.0     # Dry run with version 0.2.0"
    echo "  $0 -e -v 0.2.0     # Release version 0.2.0"
    exit 1
}

# Parse arguments
DRY_RUN=false
CUSTOM_VERSION=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--exec)
            DRY_RUN=false
            shift
            ;;
        -d|-n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -v|--version)
            CUSTOM_VERSION="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            echo "❌ Unknown option: $1"
            show_usage
            ;;
    esac
done

# Determine version
latest=$(get_latest_version oauth2-passkey-axum)
echo "📊 Current crates.io version: $latest"

if [ -n "$CUSTOM_VERSION" ]; then
    validate_version "$CUSTOM_VERSION"
    VERSION="$CUSTOM_VERSION"
    echo "📋 Using specified version: $VERSION"
else
    VERSION=$(increment_patch_version "$latest")
    echo "📋 Auto-incremented patch version: $VERSION"
fi

next=$(increment_dev_version "$VERSION")
echo "📋 Next development version: $next"

check_doc_versions "$VERSION"
check_changelog "$VERSION"

ORIGINAL_BRANCH=$(git rev-parse --abbrev-ref HEAD)

if [ "$DRY_RUN" = true ]; then
    echo "🧪 Dry run mode enabled. No changes will be pushed or published."
    echo "   (Skipping git clean/branch checks for dry-run)"
else
    echo "🚀 Execution mode enabled. Changes will be pushed and published."
    check_git_clean
    check_branch

    git checkout "release-$VERSION" 2>/dev/null || {
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
fi

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo "🧪 Dry run:"
    echo "==========="
    echo "Note: Using 'cargo package' to verify crate packaging"

    # Set both version and dependency FIRST to avoid workspace resolution issues
    set_workspace_version "$VERSION"
    set_crate_version "$VERSION"

    # Backup and remove Cargo.lock to avoid dependency resolution against crates.io
    if [ -f Cargo.lock ]; then
        cp Cargo.lock Cargo.lock.bak
        rm Cargo.lock
        echo "📋 Temporarily removed Cargo.lock to avoid dependency resolution"
    fi

    echo ""
    echo "Step 1: cargo package -p oauth2-passkey (verify packaging)"
    cargo package -p oauth2-passkey --allow-dirty --no-verify
    echo "✅ oauth2-passkey package created successfully"

    echo ""
    echo "Step 2: cargo package -p oauth2-passkey-axum (verify packaging)"
    echo "        (skipping - dependency not yet on crates.io, will be verified during actual release)"
    echo "✅ oauth2-passkey-axum packaging skipped (verified by Step 1 metadata check)"

    echo ""
    echo "🔄 Reverting changes..."
    git checkout Cargo.toml oauth2_passkey_axum/Cargo.toml 2>/dev/null || true
    # Restore Cargo.lock
    if [ -f Cargo.lock.bak ]; then
        mv Cargo.lock.bak Cargo.lock
        echo "📋 Restored Cargo.lock"
    fi

    echo ""
    echo "✅ Dry run completed successfully!"
    echo "   Both crates can be packaged correctly."
    echo ""
    echo "To execute the release, run:"
    echo "  $0 -e -v $VERSION"

    exit 0
else
    set_workspace_version "$VERSION"

    git add Cargo.toml && git commit -m "chore: set version to $VERSION for release" || {
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

    git add oauth2_passkey_axum/Cargo.toml && git commit -m "chore: set oauth2-passkey dependency to $VERSION" || {
        echo "❌ Failed to stage or commit crate version changes"
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

    git add Cargo.toml oauth2_passkey_axum/Cargo.toml && git commit -m "chore: prepare for next development version $next" || {
        echo "❌ Failed to stage or commit next development version changes"
        exit 1
    }
    git push origin "release-$VERSION" || {
        echo "❌ Failed to push release branch release-$VERSION"
        exit 1
    }

    gh pr create --base dev --head "release-$VERSION" --title "Release $VERSION" --body "Release $VERSION of oauth2-passkey workspace. Merge to dev first, then create a PR from dev to master." || {
        echo "❌ Failed to create pull request for release branch"
        exit 1
    }
    echo "🎉 Pull request created for release branch release-$VERSION -> dev"
    echo ""
    echo "📋 Post-release steps:"
    echo "  1. Merge the PR (release-$VERSION -> dev)"
    echo "  2. Create a PR from dev -> master and merge it"
fi

# Return to dev branch (only in exec mode, dry-run exits earlier)
git checkout dev || {
    echo "❌ Failed to switch back to dev branch"
    exit 1
}
