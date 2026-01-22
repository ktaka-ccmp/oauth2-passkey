# oauth2-passkey Documentation

This directory contains the documentation for oauth2-passkey, built with [mdBook](https://rust-lang.github.io/mdBook/).

## View Online

**[Read the documentation online](https://ktaka-ccmp.github.io/oauth2-passkey/)**

## Build Locally

```bash
# Install mdbook
cargo install mdbook

# Build the documentation
mdbook build docs

# Serve locally (with hot reload)
mdbook serve docs
```

The built documentation will be available at `docs/book/` or http://localhost:3000 when using `mdbook serve`.

## Structure

```
docs/
├── book.toml          # mdbook configuration
├── src/
│   ├── SUMMARY.md     # Table of contents
│   ├── README.md      # Landing page
│   ├── getting-started/
│   ├── integration/
│   ├── security/
│   ├── webauthn/
│   ├── compatibility/
│   ├── api/
│   ├── maintainer/
│   ├── appendix/
│   └── archived/
└── book/              # Build output (gitignored)
```

## Quick Links

- [Main README](../Readme.md) - Project overview
- [CHANGELOG](../CHANGELOG.md) - Release history
- [CONTRIBUTING](../CONTRIBUTING.md) - How to contribute
