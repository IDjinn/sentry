//! Parsing of the `on_message.run` pipeline and macro-atom call syntax.
//!
//! `run: check_len! | parse_header! {as: hdr}` is pipe sugar for a list of
//! atom calls. Each call is `name!` plus an optional braced YAML flow map
//! of arguments. The trailing `!` is part of the surface syntax and
//! stripped before registry lookup.

use std::collections::BTreeMap;

use serde_yaml::Value;

use crate::error::ProtocolError;

/// One call in the `run:` pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct RunStep {
    /// Atom name without the trailing `!`.
    pub name: String,
    /// Braced arguments, if any.
    pub args: BTreeMap<String, Value>,
}

/// Parses `a! | b! {k: v} | c!` into ordered calls.
pub fn parse_run(schema: &str, text: &str) -> Result<Vec<RunStep>, ProtocolError> {
    let mut steps = Vec::new();
    for part in text.split('|') {
        let part = part.trim();
        if part.is_empty() {
            return Err(ProtocolError::schema(
                schema,
                "empty step in on_message.run",
            ));
        }
        let (call, args_text) = match part.find('{') {
            Some(idx) if part.ends_with('}') => (&part[..idx], &part[idx..]),
            Some(_) => {
                return Err(ProtocolError::schema(
                    schema,
                    format!("unbalanced braces in run step {part:?}"),
                ))
            }
            None => (part, ""),
        };
        let call = call.trim();
        let name = call.strip_suffix('!').ok_or_else(|| {
            ProtocolError::schema(
                schema,
                format!("run step {call:?} must end with '!' (macro-call syntax)"),
            )
        })?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(ProtocolError::schema(
                schema,
                format!("invalid atom name {name:?}"),
            ));
        }
        let args = if args_text.is_empty() {
            BTreeMap::new()
        } else {
            serde_yaml::from_str::<BTreeMap<String, Value>>(args_text).map_err(|e| {
                ProtocolError::schema(schema, format!("bad args in run step {call:?}: {e}"))
            })?
        };
        steps.push(RunStep {
            name: name.to_string(),
            args,
        });
    }
    Ok(steps)
}

/// A parsed macro-body statement.
///
/// Note: the statement namespace is separate from the `on_message.run`
/// atom namespace — `check_len!` here is a register length check, while
/// the `check_len!` of `run:` is the framing atom.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedStatement {
    /// `name!(arg, …)` positional call (`check_mask!`, `check_range!`,
    /// `check_len!`).
    Call {
        /// Macro name without the trailing `!`.
        name: String,
        /// Raw arguments (register names, integers, quoted strings).
        args: Vec<String>,
    },
    /// `return <reg>` — yield a register as the macro's value.
    Return(String),
}

/// Parses a macro-body statement: `check_mask!(bi, 0xC0, 0x40)` or
/// `return acc`.
pub fn parse_statement(schema: &str, text: &str) -> Result<ParsedStatement, ProtocolError> {
    let bad = |what: String| ProtocolError::parse(schema, format!("statement: {what}"));
    let text = text.trim();
    if let Some(rest) = text.strip_prefix("return") {
        let reg = rest.trim();
        let valid_ident = reg.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && reg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid_ident {
            return Err(bad(
                "`return` requires a register name (return acc)".to_string()
            ));
        }
        return Ok(ParsedStatement::Return(reg.to_string()));
    }
    let Some(bang) = text.find('!') else {
        return Err(bad(format!(
            "unknown statement {text:?}; use name!(args) or `return <reg>`"
        )));
    };
    let name = &text[..bang];
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(bad(format!("invalid macro name {name:?}")));
    }
    let rest = text[bang + 1..].trim();
    if !rest.starts_with('(') || !rest.ends_with(')') {
        return Err(bad(format!(
            "macro {name}! expects parenthesized args: {name}!(a, b)"
        )));
    }
    let inner = &rest[1..rest.len() - 1];
    let args = if inner.trim().is_empty() {
        Vec::new()
    } else {
        inner
            .split(',')
            .map(|a| a.trim().to_string())
            .collect::<Vec<_>>()
    };
    if args.iter().any(|a| a.is_empty()) {
        return Err(bad(format!("empty argument in {name}! call")));
    }
    Ok(ParsedStatement::Call {
        name: name.to_string(),
        args,
    })
}

/// Parses an atom argument that must be a string.
pub(crate) fn arg_str(args: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    args.get(key).and_then(|v| v.as_str().map(String::from))
}

/// Parses an atom argument that must be an integer (accepts `0x` hex).
pub(crate) fn arg_int(args: &BTreeMap<String, Value>, key: &str) -> Option<i64> {
    match args.get(key)? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => parse_int_literal(s),
        _ => None,
    }
}

/// Parses a bare integer literal: decimal or `0x`-prefixed hex.
pub(crate) fn parse_int_literal(s: &str) -> Option<i64> {
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let n = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        rest.parse::<i64>().ok()?
    };
    Some(if neg { -n } else { n })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pipe_and_args() {
        let steps = parse_run("t", "check_len! | parse_header! {as: hdr} | filter_end!").unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0].name, "check_len");
        assert!(steps[0].args.is_empty());
        assert_eq!(steps[1].name, "parse_header");
        assert_eq!(arg_str(&steps[1].args, "as").as_deref(), Some("hdr"));
        assert_eq!(steps[2].name, "filter_end");
    }

    #[test]
    fn rejects_missing_bang_and_empty_parts() {
        assert!(parse_run("t", "check_len | parse_header!").is_err());
        assert!(parse_run("t", "a! || b!").is_err());
        assert!(parse_run("t", "a! {unbalanced").is_err());
    }

    #[test]
    fn parses_int_literals() {
        assert_eq!(parse_int_literal("42"), Some(42));
        assert_eq!(parse_int_literal("0x38"), Some(56));
        assert_eq!(parse_int_literal("-7"), Some(-7));
        assert_eq!(parse_int_literal("nope"), None);
    }

    #[test]
    fn parses_statements() {
        use ParsedStatement::*;
        assert_eq!(
            parse_statement("t", "check_mask!(bi, 0xC0, 0x40)").unwrap(),
            Call {
                name: "check_mask".into(),
                args: vec!["bi".into(), "0xC0".into(), "0x40".into()]
            }
        );
        assert_eq!(
            parse_statement("t", "return acc").unwrap(),
            Return("acc".into())
        );
        assert_eq!(
            parse_statement("t", "  return   acc  ").unwrap(),
            Return("acc".into())
        );
        assert_eq!(
            parse_statement("t", "check_range!(n, -1, 148)").unwrap(),
            Call {
                name: "check_range".into(),
                args: vec!["n".into(), "-1".into(), "148".into()]
            }
        );
        assert_eq!(
            parse_statement("t", "check_len!(s, 0, 64)").unwrap(),
            Call {
                name: "check_len".into(),
                args: vec!["s".into(), "0".into(), "64".into()]
            }
        );
    }

    #[test]
    fn rejects_bad_statements() {
        assert!(parse_statement("t", "").is_err());
        assert!(parse_statement("t", "check_mask!(bi,)").is_err());
        assert!(parse_statement("t", "check_mask! bi, 0xC0").is_err());
        assert!(parse_statement("t", "42!").is_err());
        assert!(parse_statement("t", "return").is_err());
        assert!(parse_statement("t", "return 0xC0").is_err());
        assert!(
            parse_statement("t", "shout!()").is_ok(),
            "arity is checked at compile"
        );
    }
}
