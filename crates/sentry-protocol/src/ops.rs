//! Field one-liner parser: `name: TYPE op op ...`.
//!
//! ## Grammar
//!
//! ```text
//! field_line := NAME ":" TYPE OP*
//! OP         := ">N" | "<N" | "len>N" | "len<N"
//!             | "regex" QUOTED
//!             | CHARSET
//!             | "in" QUOTED ("," QUOTED)*
//!             | "not_in" IDENT
//!             | "req"
//! CHARSET    := "b64" | "b64url" | "hex" | "alnum" | "digits" | "printable"
//! TYPE       := rust primitive (i8..i64, u8..u64, f32, f64, bool)
//!             | custom type declared in `types:`
//! ```
//!
//! Ops apply to the value read by TYPE: on numeric values `>N`/`<N` are
//! value bounds, on string/bytes values they are length bounds. `len>N`
//! and `len<N` always address length. Quoted strings use `'` or `"` and
//! may contain spaces.

use std::sync::Arc;

use crate::error::{ProtocolError, Result};

/// Character-set classes usable as field ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharClass {
    /// RFC 4648 standard alphabet (`A-Za-z0-9+/=`).
    B64,
    /// URL-safe base64 (`A-Za-z0-9-_=`).
    B64Url,
    /// Hex digits, case-insensitive.
    Hex,
    /// `A-Za-z0-9`.
    Alnum,
    /// ASCII digits only.
    Digits,
    /// Any printable ASCII (0x20..=0x7E).
    Printable,
}

impl CharClass {
    /// Parses a charset keyword.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "b64" => Self::B64,
            "b64url" => Self::B64Url,
            "hex" => Self::Hex,
            "alnum" => Self::Alnum,
            "digits" => Self::Digits,
            "printable" => Self::Printable,
            _ => return None,
        })
    }

    /// Keyword spelling (used in error messages and tests).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::B64 => "b64",
            Self::B64Url => "b64url",
            Self::Hex => "hex",
            Self::Alnum => "alnum",
            Self::Digits => "digits",
            Self::Printable => "printable",
        }
    }

    /// Checks whether every byte of `s` belongs to the class.
    pub fn matches(self, s: &[u8]) -> bool {
        s.iter().all(|&b| match self {
            Self::B64 => b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=',
            Self::B64Url => b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=',
            Self::Hex => b.is_ascii_hexdigit(),
            Self::Alnum => b.is_ascii_alphanumeric(),
            Self::Digits => b.is_ascii_digit(),
            Self::Printable => (0x20..=0x7E).contains(&b),
        })
    }
}

/// A single field constraint parsed from the one-liner.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldOp {
    /// Numeric value bound (or length bound for string/bytes values).
    Gt(i64),
    /// Numeric value bound (or length bound for string/bytes values).
    Lt(i64),
    /// Length bound, always interpreted as length.
    LenGt(u64),
    /// Length bound, always interpreted as length.
    LenLt(u64),
    /// Regex pattern (compiled at compile time, not here).
    Regex(Arc<str>),
    /// Every byte must belong to the class.
    Charset(CharClass),
    /// Value must be one of the listed strings.
    In(Vec<String>),
    /// Value must not appear in the named dataset.
    NotIn(String),
    /// Field must be present (reserved for optional/discretionary reads).
    Required,
}

/// A parsed validate line: declared type plus ordered constraints.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldLine {
    /// Wire type: a Rust primitive or a custom `types:` name.
    pub type_name: String,
    /// Constraints in declaration order.
    pub ops: Vec<FieldOp>,
}

/// Splits `text` into tokens; quoted spans (`'`/`"`) become single tokens
/// with the quotes stripped. Returns the token plus whether it was quoted.
pub(crate) fn tokenize(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut in_quote: Option<char> = None;
    for c in text.chars() {
        match in_quote {
            Some(q) if c == q => {
                out.push((std::mem::take(&mut cur), true));
                in_quote = None;
                quoted = false;
            }
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => in_quote = Some(c),
            None if c.is_whitespace() || c == ',' => {
                if quoted {
                    out.push((std::mem::take(&mut cur), false));
                    quoted = false;
                }
                if c == ',' {
                    out.push((",".to_string(), false));
                }
            }
            None => {
                cur.push(c);
                quoted = true;
            }
        }
    }
    if !cur.is_empty() {
        out.push((cur, in_quote.is_some()));
    }
    out
}

fn parse_int(tok: &str) -> Option<i64> {
    let neg = tok.starts_with('-');
    let digits = tok.strip_prefix(['>', '<', '-']).unwrap_or(tok);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: i64 = digits.parse().ok()?;
    Some(if neg { -n } else { n })
}

/// Parses the ops tail of a validate line (everything after `TYPE`).
pub fn parse_ops(context: &str, ops_text: &str) -> Result<Vec<FieldOp>> {
    parse_ops_tokens(context, &tokenize(ops_text))
}

/// Token-vector entry point, shared with the full-line parser.
fn parse_ops_tokens(context: &str, toks: &[(String, bool)]) -> Result<Vec<FieldOp>> {
    let mut ops = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let (tok, was_quoted) = &toks[i];
        if *was_quoted {
            return Err(ProtocolError::parse(
                context,
                format!("unexpected quoted token {tok:?}"),
            ));
        }
        let op =
            if let Some(rest) = tok.strip_prefix('>') {
                parse_int(rest)
                    .map(FieldOp::Gt)
                    .ok_or_else(|| ProtocolError::parse(context, format!("bad bound {tok:?}")))?
            } else if let Some(rest) = tok.strip_prefix('<') {
                parse_int(rest)
                    .map(FieldOp::Lt)
                    .ok_or_else(|| ProtocolError::parse(context, format!("bad bound {tok:?}")))?
            } else if let Some(rest) = tok.strip_prefix("len>") {
                FieldOp::LenGt(parse_int(rest).ok_or_else(|| {
                    ProtocolError::parse(context, format!("bad length bound {tok:?}"))
                })? as u64)
            } else if let Some(rest) = tok.strip_prefix("len<") {
                FieldOp::LenLt(parse_int(rest).ok_or_else(|| {
                    ProtocolError::parse(context, format!("bad length bound {tok:?}"))
                })? as u64)
            } else if tok == "regex" {
                let pat = toks
                    .get(i + 1)
                    .filter(|(_, q)| *q)
                    .map(|(t, _)| t.clone())
                    .ok_or_else(|| {
                        ProtocolError::parse(context, "regex requires a quoted pattern".to_string())
                    })?;
                i += 1;
                FieldOp::Regex(pat.into())
            } else if tok == "in" {
                let mut vals = Vec::new();
                i += 1;
                while i < toks.len() && toks[i].1 {
                    vals.push(toks[i].0.clone());
                    i += 1;
                    if i < toks.len() && toks[i].0 == "," {
                        i += 1;
                    }
                }
                if vals.is_empty() {
                    return Err(ProtocolError::parse(
                        context,
                        "in requires at least one quoted value".to_string(),
                    ));
                }
                i -= 1;
                FieldOp::In(vals)
            } else if tok == "not_in" {
                let name = toks
                    .get(i + 1)
                    .filter(|(_, q)| !*q)
                    .map(|(t, _)| t.clone())
                    .ok_or_else(|| {
                        ProtocolError::parse(context, "not_in requires a dataset name".to_string())
                    })?;
                i += 1;
                FieldOp::NotIn(name)
            } else if tok == "req" {
                FieldOp::Required
            } else if let Some(class) = CharClass::parse(tok) {
                FieldOp::Charset(class)
            } else {
                return Err(ProtocolError::parse(context, format!("unknown op {tok:?}")));
            };
        ops.push(op);
        i += 1;
    }
    Ok(ops)
}

/// Parses a full validate line into type + ops (the field name is carried
/// by the YAML key and already extracted by the caller).
pub fn parse_field_line(context: &str, line: &str) -> Result<FieldLine> {
    let toks = tokenize(line);
    let (type_name, _) = toks
        .first()
        .ok_or_else(|| ProtocolError::parse(context, "expected a wire type".to_string()))?;
    if toks.iter().any(|(_, q)| *q) && toks.iter().position(|(_, q)| *q) == Some(0) {
        return Err(ProtocolError::parse(
            context,
            "wire type must be a bare identifier".to_string(),
        ));
    }
    let ops = parse_ops_tokens(context, &toks[1..])?;
    Ok(FieldLine {
        type_name: type_name.clone(),
        ops,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizes_quoted_patterns() {
        let toks = tokenize("regex 'GAME-[a-z]+ 1' b64");
        assert_eq!(
            toks,
            vec![
                ("regex".to_string(), false),
                ("GAME-[a-z]+ 1".to_string(), true),
                ("b64".to_string(), false),
            ]
        );
    }

    #[test]
    fn parses_bounds_and_charsets() {
        let ops = parse_ops("t", ">16 <56 b64url printable").unwrap();
        assert_eq!(
            ops,
            vec![
                FieldOp::Gt(16),
                FieldOp::Lt(56),
                FieldOp::Charset(CharClass::B64Url),
                FieldOp::Charset(CharClass::Printable),
            ]
        );
    }

    #[test]
    fn parses_regex_len_in_not_in() {
        let ops = parse_ops("t", "len<8 len>1 regex 'x y' in 'a','b' not_in revoked").unwrap();
        assert_eq!(
            ops,
            vec![
                FieldOp::LenLt(8),
                FieldOp::LenGt(1),
                FieldOp::Regex("x y".into()),
                FieldOp::In(vec!["a".into(), "b".into()]),
                FieldOp::NotIn("revoked".into()),
            ]
        );
    }

    #[test]
    fn rejects_regex_without_quotes() {
        assert!(parse_ops("t", "regex abc").is_err());
    }

    #[test]
    fn parses_field_line() {
        let line = parse_field_line("f", "LPStr >16 <56").unwrap();
        assert_eq!(line.type_name, "LPStr");
        assert_eq!(line.ops, vec![FieldOp::Gt(16), FieldOp::Lt(56)]);
    }

    #[test]
    fn charset_classes_match() {
        assert!(CharClass::B64.matches(b"ab+/="));
        assert!(!CharClass::B64.matches(b"ab-_"));
        assert!(CharClass::B64Url.matches(b"ab-_"));
        assert!(CharClass::Hex.matches(b"DeAdB33f"));
        assert!(!CharClass::Digits.matches(b"12a"));
        assert!(CharClass::Printable.matches(b" hello "));
        assert!(!CharClass::Printable.matches(b"\x00"));
    }
}
