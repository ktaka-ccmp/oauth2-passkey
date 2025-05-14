mod core;
mod none;
mod packed;
mod tpm;
mod u2f;
mod utils;

pub(crate) use core::{extract_aaguid, verify_attestation};
