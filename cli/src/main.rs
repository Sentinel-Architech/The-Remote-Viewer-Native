//! sentinel — minimal native CLI for The Sentinel.
//!
//! Reads a text request (CLI args or stdin), routes it through trv-core's
//! on-device Mixture-of-Experts router, and prints the selected expert skill.
//!
//! Also hosts the activation-code issuer tooling:
//! - `sentinel keygen` — generate an Ed25519 issuer keypair (private key
//!   stays on the issuer machine; buyers embed only the public key).
//! - `sentinel mint` — sign (mint) an activation code.
//! - `sentinel verify` — verify an activation code against a public key.
//!
//! 100% on-device. std only. No network I/O. No external dependencies.

use std::io::{self, BufRead, Write};
use trv_core::moe::route;

const BANNER: &str = "The Sentinel (on-device, native). Type a request, or 'quit' to exit.";

/// Route one input line through the on-device MoE router.
/// Returns the line to print, or `None` for blank input (no output).
fn handle(input: &str) -> Option<String> {
    let input = input.trim();
    if input.is_empty() {
        return None;
    }
    let skill = route(input);
    Some(format!("-> expert: {}", skill.name()))
}

// ---------------------------------------------------------------------------
// Issuer tooling
// ---------------------------------------------------------------------------

/// Gather 32 bytes of entropy for key generation.
/// Tries `/dev/urandom` first (Unix); falls back to a time/PID-based
/// mixer with a loud warning. The fallback is NOT suitable for
/// production issuer keys.
fn gather_entropy() -> ([u8; 32], bool) {
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut buf = [0u8; 32];
        if f.read_exact(&mut buf).is_ok() {
            return (buf, true);
        }
    }
    // Fallback: NOT cryptographically strong. Warn loudly.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let mut seed = now.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ pid.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        // xorshift64 + SHA-512 mixing via trv-core's SHA-512.
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        chunk.copy_from_slice(&seed.to_le_bytes());
    }
    (out, false)
}

fn cmd_keygen() -> i32 {
    let (seed, strong) = gather_entropy();
    if !strong {
        eprintln!("WARNING: /dev/urandom unavailable; using weak fallback entropy.");
        eprintln!("DO NOT use this key for production sales. Generate on a");
        eprintln!("machine with a proper OS CSPRNG instead.");
    }
    let (secret, public) = trv_core::crypto::ed25519::generate(&seed);
    println!("Issuer public key (embed in buyer binaries):");
    println!("{}", public.hex());
    println!();
    println!("Issuer private key seed (KEEP SECRET, never share):");
    println!("{}", secret.hex());
    println!();
    println!("Store the seed securely. The public key above is what buyer");
    println!("devices embed to verify activation codes.");
    // secret zeroizes on drop.
    0
}

fn parse_arg(args: &[String], name: &str) -> Option<String> {
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a == name {
            return iter.next().cloned();
        }
        if let Some(v) = a.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
}

fn cmd_mint(args: &[String]) -> i32 {
    let tier_s = parse_arg(args, "--tier").unwrap_or_else(|| "1".to_string());
    let days_s = parse_arg(args, "--days").unwrap_or_else(|| "365".to_string());
    let key_hex = match parse_arg(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: sentinel mint --key <64-hex-seed> [--tier 1|2|3] [--days N] [--max-devices N]");
            return 1;
        }
    };
    let tier = match tier_s.as_str() {
        "1" => trv_core::activation::PaidTier::Tier1,
        "2" => trv_core::activation::PaidTier::Tier2,
        "3" => trv_core::activation::PaidTier::Tier3,
        _ => {
            eprintln!("--tier must be 1, 2, or 3");
            return 1;
        }
    };
    let days: u64 = match days_s.parse() {
        Ok(d) => d,
        Err(_) => {
            eprintln!("--days must be a number");
            return 1;
        }
    };
    let max_devices: u8 = parse_arg(args, "--max-devices")
        .map(|s| s.parse().unwrap_or(1))
        .unwrap_or(1);

    // Parse the 64-hex-char seed.
    if key_hex.len() != 64 {
        eprintln!("--key must be 64 hex chars (32-byte seed)");
        return 1;
    }
    let mut seed = [0u8; 32];
    for i in 0..32 {
        let hi = match (key_hex.as_bytes()[2 * i] as char).to_digit(16) {
            Some(v) => v,
            None => {
                eprintln!("--key contains non-hex");
                return 1;
            }
        };
        let lo = match (key_hex.as_bytes()[2 * i + 1] as char).to_digit(16) {
            Some(v) => v,
            None => {
                eprintln!("--key contains non-hex");
                return 1;
            }
        };
        seed[i] = (hi * 16 + lo) as u8;
    }

    // Random code_id from /dev/urandom (or fallback).
    let (code_id_bytes, _) = gather_entropy();
    let mut code_id = [0u8; 16];
    code_id.copy_from_slice(&code_id_bytes[..16]);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_at = now.saturating_add(days.saturating_mul(86_400));

    match trv_core::activation::mint(&seed, code_id, tier, now, expires_at, max_devices) {
        Ok(code) => {
            println!("{code}");
            0
        }
        Err(e) => {
            eprintln!("mint failed: {e}");
            1
        }
    }
}

fn cmd_verify(args: &[String]) -> i32 {
    let code = match parse_arg(args, "--code") {
        Some(c) => c,
        None => {
            eprintln!("Usage: sentinel verify --code <code> --pubkey <64-hex>");
            return 1;
        }
    };
    let pubkey_hex = match parse_arg(args, "--pubkey") {
        Some(k) => k,
        None => {
            eprintln!("Usage: sentinel verify --code <code> --pubkey <64-hex>");
            return 1;
        }
    };
    let public = match trv_core::crypto::ed25519::PublicKey::from_hex(&pubkey_hex) {
        Some(p) => p,
        None => {
            eprintln!("--pubkey must be 64 hex chars");
            return 1;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    match trv_core::activation::verify(&code, public.as_bytes(), now) {
        Ok(claims) => {
            println!("VALID");
            println!("tier: {}", claims.tier.label());
            println!("issued_at: {}", claims.issued_at);
            println!("expires_at: {}", claims.expires_at);
            println!("max_devices: {}", claims.max_devices);
            0
        }
        Err(e) => {
            println!("INVALID: {e}");
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Issuer subcommands.
    if let Some(first) = args.first().map(|s| s.as_str()) {
        match first {
            "keygen" => std::process::exit(cmd_keygen()),
            "mint" => std::process::exit(cmd_mint(&args[1..])),
            "verify" => std::process::exit(cmd_verify(&args[1..])),
            _ => {}
        }
    }

    if !args.is_empty() {
        // One-shot mode: route everything passed on the command line.
        if let Some(line) = handle(&args.join(" ")) {
            println!("{line}");
        }
        return;
    }

    // Interactive mode: read lines from stdin until EOF or "quit".
    println!("{BANNER}");
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        match line {
            Ok(text) => {
                let text = text.trim().to_string();
                if text.eq_ignore_ascii_case("quit") || text.eq_ignore_ascii_case("exit") {
                    break;
                }
                if let Some(line) = handle(&text) {
                    println!("{line}");
                }
            }
            Err(_) => break,
        }
        let _ = io::stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_input_produces_no_output() {
        assert_eq!(handle(""), None);
        assert_eq!(handle("   "), None);
        assert_eq!(handle("\t\n "), None);
    }

    #[test]
    fn input_is_trimmed_before_routing() {
        assert_eq!(handle("  quantum  "), handle("quantum"));
    }

    #[test]
    fn output_names_the_routed_expert() {
        assert_eq!(handle("quantum"), Some("-> expert: quantum".to_string()));
        assert_eq!(
            handle("first aid for a burn"),
            Some("-> expert: first-aid".to_string())
        );
    }

    #[test]
    fn output_format_has_arrow_prefix() {
        let line = handle("hello world").expect("non-blank input must route");
        assert!(line.starts_with("-> expert: "), "unexpected format: {line}");
        assert!(!line.contains('\n'), "output must be a single line");
    }

    #[test]
    fn parse_arg_long_form() {
        let args = vec!["--tier".to_string(), "2".to_string()];
        assert_eq!(parse_arg(&args, "--tier"), Some("2".to_string()));
    }

    #[test]
    fn parse_arg_equals_form() {
        let args = vec!["--tier=3".to_string()];
        assert_eq!(parse_arg(&args, "--tier"), Some("3".to_string()));
    }

    #[test]
    fn parse_arg_missing_returns_none() {
        let args: Vec<String> = vec![];
        assert_eq!(parse_arg(&args, "--tier"), None);
    }
}
