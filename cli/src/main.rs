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
//! And the vault tooling:
//! - `sentinel vault-migrate --from <plain> --to <enc>` — one-time
//!   upgrade of a legacy plaintext vault file to the encrypted format.
//!   The passphrase is read from stdin (never from argv, so it does not
//!   land in shell history).
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
///
/// Tries `/dev/urandom` (Unix). If the OS CSPRNG is unavailable,
/// returns an error: production key generation MUST fail rather than
/// fall back to weak time/PID-based entropy. A weak issuer key would
/// let anyone forge activation codes.
fn gather_entropy() -> Result<[u8; 32], &'static str> {
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let mut buf = [0u8; 32];
        if f.read_exact(&mut buf).is_ok() {
            return Ok(buf);
        }
    }
    Err("OS entropy (/dev/urandom) unavailable; refusing to generate weak key material")
}

fn cmd_keygen() -> i32 {
    let seed = match gather_entropy() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("keygen failed: {e}");
            eprintln!("Generate on a machine with a proper OS CSPRNG instead.");
            return 1;
        }
    };
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

    // Random code_id from the OS CSPRNG. Fails closed if unavailable:
    // a predictable code_id would make activation codes guessable.
    let code_id_bytes = match gather_entropy() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("mint failed: {e}");
            return 1;
        }
    };
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

/// One-time upgrade of a legacy plaintext vault file to the encrypted
/// format: `sentinel vault-migrate --from <plain> --to <enc>`.
///
/// The passphrase is read from stdin (prompted on stderr) so it never
/// appears in argv or shell history. The plaintext source is left in
/// place; verify the encrypted copy opens, then delete it yourself.
fn cmd_vault_migrate(args: &[String]) -> i32 {
    let from = match parse_arg(args, "--from") {
        Some(p) => p,
        None => {
            eprintln!("Usage: sentinel vault-migrate --from <plaintext> --to <encrypted>");
            return 1;
        }
    };
    let to = match parse_arg(args, "--to") {
        Some(p) => p,
        None => {
            eprintln!("Usage: sentinel vault-migrate --from <plaintext> --to <encrypted>");
            return 1;
        }
    };
    eprint!("Vault passphrase: ");
    let _ = io::stderr().flush();
    let mut pass = String::new();
    if io::stdin().read_line(&mut pass).is_err() {
        eprintln!("could not read passphrase from stdin");
        return 1;
    }
    // Strip the trailing newline without keeping a second copy.
    let trimmed_len = pass.trim_end_matches(['\n', '\r']).len();
    pass.truncate(trimmed_len);
    let rc = match trv_backend::profile::ProfileVault::migrate_from_plaintext(
        std::path::Path::new(&from),
        std::path::Path::new(&to),
        &pass,
    ) {
        Ok(()) => {
            println!("Migrated to {to}.");
            println!("Verify it opens (wrong passphrase fails closed), then delete {from}.");
            0
        }
        Err(e) => {
            eprintln!("MIGRATE FAILED: {e}");
            1
        }
    };
    // Best-effort: wipe the passphrase bytes before they are dropped
    // (same write_volatile pattern as the vault's DerivedKey).
    // SAFETY: zero bytes are valid UTF-8; the String is not used after this.
    unsafe {
        for b in pass.as_bytes_mut().iter_mut() {
            core::ptr::write_volatile(b, 0u8);
        }
    }
    rc
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Issuer subcommands.
    if let Some(first) = args.first().map(|s| s.as_str()) {
        match first {
            "keygen" => std::process::exit(cmd_keygen()),
            "mint" => std::process::exit(cmd_mint(&args[1..])),
            "verify" => std::process::exit(cmd_verify(&args[1..])),
            "vault-migrate" => std::process::exit(cmd_vault_migrate(&args[1..])),
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
