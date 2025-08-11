#!/usr/bin/env rust-script
//! Key pair generator for oauth2-passkey test suite
//!
//! This utility generates a fixed ECDSA P-256 key pair for use in integration tests.
//! The generated key pair ensures that mock WebAuthn authentication produces valid
//! signatures that can be verified by stored credentials.
//!
//! Usage:
//!   cargo run --bin generate_fixed_keys
//!
//! Output:
//!   - Private key in PKCS#8 DER format (for fixtures.rs)
//!   - Public key in WebAuthn base64url format (for test_utils.rs)

use ring::{rand, signature};
use ring::signature::KeyPair;
use base64::Engine;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 Generating ECDSA P-256 key pair for oauth2-passkey test suite...\n");

    // Generate a new ECDSA P-256 key pair with proper entropy
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::EcdsaKeyPair::generate_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    ).map_err(|e| format!("Failed to generate key pair: {:?}", e))?;

    // Create key pair object to extract public key
    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8_bytes.as_ref(),
        &rng,
    ).map_err(|e| format!("Failed to create key pair: {:?}", e))?;

    let public_key_bytes = key_pair.public_key().as_ref();

    // Convert public key to WebAuthn format (base64url, no padding, skip 0x04 prefix)
    let public_key_coords = &public_key_bytes[1..]; // Remove uncompressed point indicator (0x04)
    let public_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(public_key_coords);

    println!("📋 Copy the following into your test code:\n");

    // Output for fixtures.rs
    println!("// For fixtures.rs::FIRST_USER_PRIVATE_KEY:");
    println!("const FIRST_USER_PRIVATE_KEY: &[u8] = &[");
    print!("    ");
    for (i, byte) in pkcs8_bytes.as_ref().iter().enumerate() {
        if i > 0 && i % 16 == 0 {
            println!(",");
            print!("    ");
        } else if i > 0 {
            print!(", ");
        }
        print!("{}", byte);
    }
    println!("\n];");

    println!("\n// For test_utils.rs::generate_first_user_public_key():");
    println!("\"{}\"", public_key_b64);

    // Verification information
    println!("\n🔍 Key pair information:");
    println!("  Private key size: {} bytes (PKCS#8 DER)", pkcs8_bytes.as_ref().len());
    println!("  Public key size: {} bytes (uncompressed P-256 point)", public_key_bytes.len());
    println!("  WebAuthn format: {} characters (base64url, no padding)", public_key_b64.len());

    println!("\n✅ Key pair generated successfully!");
    println!("\n⚠️  Remember: This is for TEST PURPOSES ONLY - never use in production!");

    Ok(())
}
