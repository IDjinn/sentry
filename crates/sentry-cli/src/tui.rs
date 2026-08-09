//! TUI (ratatui) live view — skeleton.
//!
//! Full implementation lands in F1.9. For now we stub the entrypoint so the
//! `tail --tui` subcommand compiles.

use std::io;

/// Run the TUI. Stub: prints a placeholder line and returns.
pub async fn run() -> io::Result<()> {
    println!("TUI not yet implemented (F1.9). Use `sentry tail --stream` for now.");
    Ok(())
}
