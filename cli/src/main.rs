//! sentinel — minimal native CLI for The Sentinel.
//!
//! Reads a text request (CLI args or stdin), routes it through trv-core's
//! on-device Mixture-of-Experts router, and prints the selected expert skill.
//!
//! Also hosts the activation-code issuer tooling:
//! - `sentinel keygen` — generate an Ed25519 issuer keypair (private key
//!   stays on the issuer machine; buyers embed only the public key).
//! - `sentinel mint` — sign (mint) an activation code. The issuer seed
//!   is read from `--key-file <path>` or from stdin with terminal echo
//!   disabled — never from argv, so it cannot leak via `ps` or shell
//!   history. Seed memory is wiped after use.
//! - `sentinel verify` — verify an activation code against a public key.
//!
//! And the vault tooling:
//! - `sentinel vault-migrate --from <plain> --to <enc>` — one-time
//!   upgrade of a legacy plaintext vault file to the encrypted format.
//!   The passphrase is read from stdin with terminal echo disabled
//!   (never from argv, so it does not land in shell history).
//!
//! 100% on-device. std only. No network I/O. No external dependencies.

use std::io::{self, BufRead, Write};
use trv_core::moe::route;

mod secret;

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
    let seed_bytes = match gather_entropy() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("keygen failed: {e}");
            eprintln!("Generate on a machine with a proper OS CSPRNG instead.");
            return 1;
        }
    };
    // SecretSeed wipes itself on drop: the raw seed never lingers in RAM
    // after this function returns, on any path.
    let seed = secret::SecretSeed(seed_bytes);
    let (secret, public) = trv_core::crypto::ed25519::generate(&seed.0);
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

/// Load the 32-byte issuer seed for `mint`.
///
/// The seed NEVER comes from argv: `--key` was removed because command-line
/// arguments are visible to other users via `ps` and persist in shell
/// history — anyone glimpsing the seed could forge activation codes
/// forever. Instead the seed is read from `--key-file <path>` or, when
/// that is absent, from stdin with terminal echo disabled.
///
/// Returns the parsed seed (self-wiping on drop) or a human-readable error.
/// The intermediate hex buffer is wiped before returning on every path.
fn load_seed(args: &[String]) -> Result<secret::SecretSeed, String> {
    if parse_arg(args, "--key").is_some() {
        return Err(
            "refusing: --key was removed because argv secrets leak via `ps` and shell history.\n\
             Use --key-file <path>, or enter the 64-hex seed when prompted (input hidden)."
                .to_string(),
        );
    }
    let mut key_hex = if let Some(path) = parse_arg(args, "--key-file") {
        std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read key file '{path}': {e}"))?
    } else {
        secret::read_secret_line("Issuer seed (64 hex chars, input hidden): ")
            .map_err(|e| format!("cannot read seed from stdin: {e}"))?
    };

    let result = (|| {
        let hex = key_hex.trim();
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("seed must be exactly 64 hex chars (32 bytes)".to_string());
        }
        fn val(b: u8) -> u8 {
            match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => b - b'A' + 10, // validated hexdigit above
            }
        }
        let mut seed = secret::SecretSeed([0u8; 32]);
        let hb = hex.as_bytes();
        for i in 0..32 {
            seed.0[i] = (val(hb[2 * i]) << 4) | val(hb[2 * i + 1]);
        }
        Ok(seed)
    })();

    // Wipe the hex text on every path — parsed, rejected, or errored.
    secret::wipe_string(&mut key_hex);
    result
}

fn cmd_mint(args: &[String]) -> i32 {
    let tier_s = parse_arg(args, "--tier").unwrap_or_else(|| "1".to_string());
    let days_s = parse_arg(args, "--days").unwrap_or_else(|| "365".to_string());
    let seed = match load_seed(args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            eprintln!(
                "Usage: sentinel mint [--key-file <path>] [--tier 1|2|3] [--days N] [--max-devices N]"
            );
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

    // `seed` is a SecretSeed: wiped automatically when this function
    // returns, on every path (success or failure).
    match trv_core::activation::mint(&seed.0, code_id, tier, now, expires_at, max_devices) {
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
/// The passphrase is read from stdin with terminal echo disabled (never
/// from argv, so it does not land in shell history and is not
/// shoulder-surfable). The plaintext source is left in
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
    let mut pass = match secret::read_secret_line("Vault passphrase: ") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("could not read passphrase from stdin");
            return 1;
        }
    };
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

    #[test]
    fn mint_rejects_legacy_key_in_argv() {
        // --key must never be accepted: argv secrets leak via ps/history.
        let args = vec!["--key".to_string(), "ab".repeat(32)];
        assert!(load_seed(&args).is_err());
        let args = vec!["--key=deadbeef".to_string()];
        assert!(load_seed(&args).is_err());
    }

    #[test]
    fn mint_loads_seed_from_key_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("trv-test-seed.hex");
        let hex = "0123456789abcdef".repeat(4); // 64 hex chars
        std::fs::write(&path, format!("  {hex}\n")).expect("write temp key file");
        let args = vec![
            "--key-file".to_string(),
            path.to_string_lossy().into_owned(),
        ];
        let seed = load_seed(&args).expect("valid key file must load");
        let mut expected = [0u8; 32];
        for i in 0..32 {
            expected[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        assert_eq!(seed.0, expected);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn mint_rejects_bad_key_file_contents() {
        let dir = std::env::temp_dir();
        // Wrong length.
        let p1 = dir.join("trv-test-seed-bad1.hex");
        std::fs::write(&p1, "abcd").unwrap();
        let args = vec!["--key-file".to_string(), p1.to_string_lossy().into_owned()];
        assert!(load_seed(&args).is_err());
        // Non-hex.
        let p2 = dir.join("trv-test-seed-bad2.hex");
        std::fs::write(&p2, "zz".repeat(32)).unwrap();
        let args = vec!["--key-file".to_string(), p2.to_string_lossy().into_owned()];
        assert!(load_seed(&args).is_err());
        // Missing file.
        let args = vec![
            "--key-file".to_string(),
            "/nonexistent-dir-xyz/trv-seed.hex".to_string(),
        ];
        assert!(load_seed(&args).is_err());
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }
}
