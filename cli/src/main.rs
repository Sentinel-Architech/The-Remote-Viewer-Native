//! sentinel — minimal native CLI for The Sentinel.
//!
//! Reads a text request (CLI args or stdin), routes it through trv-core's
//! on-device Mixture-of-Experts router, and prints the selected expert skill.
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

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

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
}
