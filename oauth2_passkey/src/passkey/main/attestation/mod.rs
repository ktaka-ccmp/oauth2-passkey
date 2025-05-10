mod core;
mod none;
mod packed;
mod tpm;
mod utils;
mod u2f;

pub(crate) use core::{extract_aaguid, verify_attestation};
