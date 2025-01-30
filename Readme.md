# Readme

Table of Contents

- [Blog](#blog)
- [Recorded screen](#recorded-screen)
- [Howto](#howto)
  - [Clone repository](#clone-repository)
  - [Environment Variables](#environment-variables)
  - [Run](#run)

## Blog

Wrote [a blog post](https://ktaka.blog.ccmp.jp/2025/01/implementing-passkeys-authentication-in-rust-axum.html) about this repository

## Recorded screen

https://github.com/user-attachments/assets/b06460a9-1389-4b67-b96a-99d7c32bfb5a


## Howto

### Clone repository

```bash
git clone https://github.com/ktaka-ccmp/axum-passkey.git
cd axum-passkey
```

### Environment Variables

Create .env file

```text
PASSKEY_AUTHENTICATOR_ATTACHMENT='platform'
ORIGIN='http://localhost:3001'
```

### Run

```bash
cargo run
```
