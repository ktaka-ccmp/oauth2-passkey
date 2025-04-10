mod core;
mod none;
mod packed;
mod tpm;
mod utils;

pub(crate) use core::{extract_aaguid, verify_attestation};
