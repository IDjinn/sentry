//! Universal atom registry for the `on_message.run` pipeline.
//!
//! The crate ships only framing-level pipeline atoms. Protocol-specific
//! read macros (variable-length integers, custom strings…) are *not*
//! registered here —
//! they are defined per schema in `types:` and inlined by the compiler
//! (see [`crate::compile`]).

/// Pipeline atoms available in `on_message.run`.
pub const RUN_ATOMS: &[&str] = &["check_len", "parse_header"];

/// Whether `name` (without the trailing `!`) is a run atom.
pub fn is_run_atom(name: &str) -> bool {
    RUN_ATOMS.contains(&name)
}

/// Comma-separated atom list for error messages.
pub fn run_atoms_list() -> String {
    RUN_ATOMS
        .iter()
        .map(|a| format!("{a}!"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_run_atoms() {
        assert!(is_run_atom("check_len"));
        assert!(is_run_atom("parse_header"));
        assert!(!is_run_atom("read_vlint"));
    }
}
