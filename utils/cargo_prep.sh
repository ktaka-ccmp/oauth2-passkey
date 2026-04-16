#!/bin/bash

 rustup update

 cargo update
 cargo upgrade --incompatible
 cargo update
 cargo upgrade --incompatible
 cargo machete --with-metadata
 cargo clippy --all-targets --all-features
 cargo fmt --all -- --check
 cargo audit

 git status
