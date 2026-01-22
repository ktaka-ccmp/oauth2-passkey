# Release Process for OAuth2-Passkey Workspace

This document explains how to release the `oauth2-passkey` and `oauth2-passkey-axum` crates in the correct sequential order.

## Overview

The workspace contains two publishable crates with a dependency relationship:

- `oauth2-passkey` (core library)
- `oauth2-passkey-axum` (Axum integration, depends on `oauth2-passkey`)

During development, we use local path dependencies for immediate feedback. During release, we need to publish `oauth2-passkey` first, then update `oauth2-passkey-axum` to use the published version before publishing it.

## Development vs. Publishing Dependencies

### Development Setup (Current)

```toml
# In workspace Cargo.toml
[workspace.dependencies]
oauth2-passkey = { path = "./oauth2_passkey" }
oauth2-passkey-axum = { path = "./oauth2_passkey_axum" }
```

### Publishing Setup

```toml
# oauth2-passkey-axum temporarily uses published version
oauth2-passkey = "0.1.2"  # published version
```

## Release Methods

We provide two methods for releasing: automated and manual.

### Method 1: Automated Release (Recommended)

Use the automated release script for a streamlined process:

```bash
./utils/release.sh <version>
```

**Example:**

```bash
./utils/release.sh 0.1.2
```

**What it does:**

1. ✅ Checks that git working directory is clean
2. 🎯 Publishes `oauth2-passkey` with the specified version
3. ⏳ Waits for the package to be available on crates.io
4. 🔄 Updates `oauth2-passkey-axum/Cargo.toml` to use the published version
5. 🎯 Publishes `oauth2-passkey-axum` with the same version
6. 🔄 Reverts `oauth2-passkey-axum` back to workspace dependencies
7. 📝 Commits the version bump changes
8. 🏷️ Creates git tags for both releases

**Prerequisites:**

- Clean git working directory
- Valid `cargo` login credentials for crates.io
- Internet connection for crates.io verification

### Method 2: Manual Release Process

For more control or troubleshooting, use the manual process:

```bash
./utils/release-manual.sh [version]
```

This script provides step-by-step instructions you can follow manually.

**Manual Steps:**

1. **Prepare Release**

   ```bash
   # Ensure clean git state
   git status
   ```

2. **Release oauth2-passkey First**

   ```bash
   cd oauth2_passkey
   cargo publish --dry-run  # Test first
   cargo publish            # Actually publish
   cd ..
   ```

3. **Wait for Availability**

   ```bash
   # Check until your version appears
   cargo search oauth2-passkey
   ```

4. **Update oauth2-passkey-axum Dependency**

   ```bash
   # Edit oauth2_passkey_axum/Cargo.toml
   # Change: oauth2-passkey = { workspace = true }
   # To:     oauth2-passkey = "0.1.2"
   ```

5. **Release oauth2-passkey-axum**

   ```bash
   cd oauth2_passkey_axum
   cargo publish --dry-run  # Test first
   cargo publish            # Actually publish
   cd ..
   ```

6. **Revert for Development**

   ```bash
   # Edit oauth2_passkey_axum/Cargo.toml
   # Change: oauth2-passkey = "0.1.2"
   # Back to: oauth2-passkey = { workspace = true }
   ```

7. **Tag and Commit**

   ```bash
   git add .
   git commit -m "chore: release v0.1.2"
   git tag v0.1.2
   git push origin main --tags
   ```

## Configuration Details

The release process is configured using `cargo-release` metadata in the `Cargo.toml` files:

### Workspace Configuration

```toml
# In main Cargo.toml
[workspace.metadata.release]
sign-commit = false
sign-tag = false
push = false
publish = false
tag = false
```

### Per-Crate Configuration

```toml
# In oauth2_passkey/Cargo.toml and oauth2_passkey_axum/Cargo.toml
[package.metadata.release]
publish = true
tag = true
sign-tag = false
sign-commit = false
push = false
```

## Troubleshooting

### Common Issues

#### 1. "Package not found on crates.io"

- Wait longer for crates.io to update (can take up to 5 minutes)
- Check your internet connection
- Verify the package was actually published

#### 2. "Working directory not clean"

- Commit or stash any pending changes before releasing
- Check `git status` and resolve any conflicts

#### 3. "Permission denied" on crates.io

- Ensure you're logged in: `cargo login`
- Verify you have publish permissions for both crates

#### 4. "Version already exists"

- Bump the version number in `workspace.package.version`
- Ensure you're not trying to republish an existing version

### Recovery from Failed Release

If the automated release fails partway through:

1. **Check what was published:**

   ```bash
   cargo search oauth2-passkey
   cargo search oauth2-passkey-axum
   ```

2. **If only oauth2-passkey was published:**
   - Continue from step 4 of the manual process
   - Or fix the issue and re-run the automated script

3. **If both were published but git wasn't updated:**
   - Manually create tags and commit the version bump

## Version Management

The workspace uses a shared version number in `Cargo.toml`:

```toml
[workspace.package]
version = "0.1.1"  # Update this for releases
```

All crates inherit this version with:

```toml
[package]
version = { workspace = true }
```

## Security Considerations

### Obtaining and Setting Crates.io Token

Before you can publish crates, you need to authenticate with crates.io:

1. **Create a crates.io account:**
   - Visit [crates.io](https://crates.io/) and sign up/log in
   - You can use GitHub authentication for convenience

2. **Generate an API token:**
   - Go to [crates.io/me](https://crates.io/me) (Account Settings)
   - Click on "API Tokens" in the left sidebar
   - Click "New Token"
   - Give it a descriptive name (e.g., "oauth2-passkey-release")
   - Select appropriate scopes:
     - `publish-new` - allows publishing new crates
     - `publish-update` - allows updating existing crates
   - Copy the generated token immediately (you won't see it again)

3. **Set the token locally:**

   ```bash
   cargo login <your-token-here>
   ```

   Or alternatively, set it as an environment variable:

   ```bash
   export CARGO_REGISTRY_TOKEN=<your-token-here>
   ```

4. **Verify authentication:**

   ```bash
   cargo owner --list oauth2-passkey
   ```

   This should show you as an owner if the crate exists, or give appropriate error if it doesn't.

### Security Best Practices

- Never commit crates.io tokens to git
- Use `cargo login` to authenticate securely
- Store tokens in secure password managers
- Regularly rotate API tokens (every 6-12 months)
- Use minimal required scopes for tokens
- Review all changes with `--dry-run` before publishing
- Both scripts avoid automatic git pushing for safety review

### Managing Crate Ownership

For collaborative projects, you may need to add co-owners:

```bash
# Add a co-owner to both crates
cargo owner --add username oauth2-passkey
cargo owner --add username oauth2-passkey-axum

# List current owners
cargo owner --list oauth2-passkey
cargo owner --list oauth2-passkey-axum
```

## Related Files

- `utils/release.sh` - Automated release script
- `utils/release-manual.sh` - Manual release guide
- `oauth2_passkey/Cargo.toml` - Core library configuration
- `oauth2_passkey_axum/Cargo.toml` - Axum integration configuration
- `Cargo.toml` - Workspace configuration

## Next Steps After Release

1. **Verify Publications:**
   - Check [crates.io/crates/oauth2-passkey](https://crates.io/crates/oauth2-passkey)
   - Check [crates.io/crates/oauth2-passkey-axum](https://crates.io/crates/oauth2-passkey-axum)

2. **Update Documentation:**
   - Update README.md files with new version numbers
   - Update any version references in documentation

3. **Test Integration:**
   - Create a new project and test importing the published crates
   - Verify all examples still work with the new versions

4. **Announcement:**
   - Update CHANGELOG.md
   - Consider announcing on relevant platforms
