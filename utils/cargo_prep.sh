#!/bin/bash

 cargo update
 cargo upgrade --incompatible
 cargo update
 cargo upgrade --incompatible
 cargo machete --with-metadata
 cargo clippy --all-targets --all-features
 cargo fmt --all -- --check

 git status

