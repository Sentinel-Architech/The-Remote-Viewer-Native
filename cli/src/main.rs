//! sentinel — minimal native CLI for The Sentinel.
//!
//! Reads a text request (CLI args or stdin), routes it through trv-core's
//! on-device Mixture-of-Experts router, and prints the selected expert skill.
//!
//! 100% on-device. std only. No network I/O. No external dependencies.

use std::io::{self, BufRead, Write};
use trv_core::moe::route;

const BANNER: &str = "The Sentinel (on-device, native). Type a request, or 'quit' to exit.";

fn handle(input: &str) {
    let input = input.trim();
    if input.is_empty() {
        return;
    }
    let skill = route(input);
    println!("-> expert: {}", skill.name());
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if !args.is_empty() {
        // One-shot mode: route everything passed on the command line.
        handle(&args.join(" "));
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
                handle(&text);
            }
            Err(_) => break,
        }
        let _ = io::stdout().flush();
    }
}
