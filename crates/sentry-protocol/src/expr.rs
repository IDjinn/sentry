//! Infix expression parser for macro-body assignments, `if` conditions and
//! `while` bounds.
//!
//! ## Grammar
//!
//! ```text
//! expr    := or_expr
//! or_expr := xor_expr (OR xor_expr)*          // or, |
//! xor_expr:= and_expr (XOR and_expr)*         // xor, ^
//! and_expr:= shift_expr (AND shift_expr)*     // and, &
//! shift   := add_expr (SHIFT add_expr)*       // shl/shr, <</>>
//! add     := mul_expr (ADD mul_expr)*         // add/sub, +/-
//! mul     := unary (MUL unary)*               // mul, *
//! unary   := "-" unary | "not" unary | primary
//! primary := INT | IDENT | "(" expr ")"
//!          | "min" "(" expr "," expr ")"      // while bounds only
//! ```
//!
//! Word operators are canonical; the symbolic forms compile to the same
//! operations. Word operators and the I/O atom names (`read`, `decode`,
//! `peek`) are reserved and can never name a register.

use crate::error::ProtocolError;
use crate::instr::BinOp;

/// Words that can never name a register: expression operators, the `min!`
/// helper and the prefix I/O atoms of an assignment.
pub const RESERVED: &[&str] = &[
    "and", "or", "xor", "shl", "shr", "add", "sub", "mul", "not", "min", "read", "decode", "peek",
    "return", "if", "while",
];

/// Whether `name` is a reserved word (operators / atoms).
pub fn is_reserved(name: &str) -> bool {
    RESERVED.contains(&name)
}

/// Parsed expression tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Register reference.
    Reg(String),
    /// Integer literal (decimal or `0x` hex).
    Int(i64),
    /// Binary operation.
    Bin(BinOp, Box<Expr>, Box<Expr>),
    /// Arithmetic negation.
    Neg(Box<Expr>),
    /// Logical negation (`0` ↔ `1`).
    Not(Box<Expr>),
    /// `min!(a, b)` — valid only as a `while` bound.
    Min(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Int(i64),
    Ident(String),
    Bin(BinOp),
    Not,
    MinFn,
    Minus,
    LParen,
    RParen,
    Comma,
}

fn word_op(w: &str) -> Option<Tok> {
    Some(match w {
        "and" => Tok::Bin(BinOp::And),
        "or" => Tok::Bin(BinOp::Or),
        "xor" => Tok::Bin(BinOp::Xor),
        "shl" => Tok::Bin(BinOp::Shl),
        "shr" => Tok::Bin(BinOp::Shr),
        "add" => Tok::Bin(BinOp::Add),
        "sub" => Tok::Bin(BinOp::Sub),
        "mul" => Tok::Bin(BinOp::Mul),
        "not" => Tok::Not,
        _ => return None,
    })
}

fn tokenize(text: &str, schema: &str) -> Result<Vec<Tok>, ProtocolError> {
    let bad = |what: &str| ProtocolError::parse(schema, format!("expression: {what}"));
    let mut toks = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            _ if c.is_whitespace() => {
                chars.next();
            }
            _ if c.is_ascii_digit() => {
                let mut num = String::new();
                while let Some(&d) = chars.peek() {
                    if d.is_ascii_alphanumeric() {
                        num.push(d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let value =
                    parse_int(&num, false).ok_or_else(|| bad(&format!("bad number {num:?}")))?;
                toks.push(Tok::Int(value));
            }
            _ if c.is_ascii_alphabetic() || c == '_' => {
                let mut word = String::new();
                while let Some(&d) = chars.peek() {
                    if d.is_ascii_alphanumeric() || d == '_' {
                        word.push(d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if word == "min" {
                    if chars.peek() == Some(&'!') {
                        chars.next();
                        toks.push(Tok::MinFn);
                    } else {
                        return Err(bad("`min` must be written as min!(a, b)"));
                    }
                } else if let Some(t) = word_op(&word) {
                    toks.push(t);
                } else {
                    toks.push(Tok::Ident(word));
                }
            }
            '-' => {
                chars.next();
                toks.push(Tok::Minus);
            }
            '(' => {
                chars.next();
                toks.push(Tok::LParen);
            }
            ')' => {
                chars.next();
                toks.push(Tok::RParen);
            }
            ',' => {
                chars.next();
                toks.push(Tok::Comma);
            }
            '<' => {
                chars.next();
                if chars.peek() == Some(&'<') {
                    chars.next();
                    toks.push(Tok::Bin(BinOp::Shl));
                } else {
                    return Err(bad("unexpected '<' (shift is `<<` or `shl`)"));
                }
            }
            '>' => {
                chars.next();
                if chars.peek() == Some(&'>') {
                    chars.next();
                    toks.push(Tok::Bin(BinOp::Shr));
                } else {
                    return Err(bad("unexpected '>' (shift is `>>` or `shr`)"));
                }
            }
            '|' => {
                chars.next();
                toks.push(Tok::Bin(BinOp::Or));
            }
            '&' => {
                chars.next();
                toks.push(Tok::Bin(BinOp::And));
            }
            '^' => {
                chars.next();
                toks.push(Tok::Bin(BinOp::Xor));
            }
            '+' => {
                chars.next();
                toks.push(Tok::Bin(BinOp::Add));
            }
            '*' => {
                chars.next();
                toks.push(Tok::Bin(BinOp::Mul));
            }
            other => {
                return Err(bad(&format!("unexpected character {other:?}")));
            }
        }
    }
    Ok(toks)
}

fn parse_int(num: &str, neg: bool) -> Option<i64> {
    let n = if let Some(hex) = num.strip_prefix("0x").or_else(|| num.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        num.parse::<i64>().ok()?
    };
    Some(if neg { -n } else { n })
}

/// Operator precedence (higher binds tighter).
fn prec(op: BinOp) -> u8 {
    match op {
        BinOp::Or => 1,
        BinOp::Xor => 2,
        BinOp::And => 3,
        BinOp::Shl | BinOp::Shr => 4,
        BinOp::Add | BinOp::Sub => 5,
        BinOp::Mul => 6,
    }
}

struct Parser<'a> {
    schema: &'a str,
    toks: Vec<Tok>,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn err(&self, what: impl Into<String>) -> ProtocolError {
        ProtocolError::parse(self.schema, format!("expression: {}", what.into()))
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_full(mut self) -> Result<Expr, ProtocolError> {
        let e = self.parse_bin(1)?;
        if self.pos != self.toks.len() {
            return Err(self.err("trailing tokens after expression"));
        }
        Ok(e)
    }

    fn parse_bin(&mut self, min_prec: u8) -> Result<Expr, ProtocolError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Bin(op)) => *op,
                Some(Tok::Minus) => BinOp::Sub,
                _ => break,
            };
            if prec(op) < min_prec {
                break;
            }
            self.next();
            let rhs = self.parse_bin(prec(op) + 1)?;
            lhs = Expr::Bin(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ProtocolError> {
        match self.peek() {
            Some(Tok::Minus) => {
                self.next();
                let inner = self.parse_unary()?;
                Ok(match inner {
                    Expr::Int(n) => Expr::Int(
                        n.checked_neg()
                            .ok_or_else(|| self.err("cannot negate this literal"))?,
                    ),
                    other => Expr::Neg(Box::new(other)),
                })
            }
            Some(Tok::Not) => {
                self.next();
                Ok(Expr::Not(Box::new(self.parse_unary()?)))
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, ProtocolError> {
        match self.next() {
            Some(Tok::Int(n)) => Ok(Expr::Int(n)),
            Some(Tok::Ident(name)) => {
                if is_reserved(&name) {
                    return Err(self.err(format!(
                        "{name:?} is a reserved word and cannot be used as a register"
                    )));
                }
                Ok(Expr::Reg(name))
            }
            Some(Tok::LParen) => {
                let e = self.parse_bin(1)?;
                match self.next() {
                    Some(Tok::RParen) => Ok(e),
                    _ => Err(self.err("expected ')'")),
                }
            }
            Some(Tok::MinFn) => {
                match self.next() {
                    Some(Tok::LParen) => {}
                    _ => return Err(self.err("min! expects (expr, expr)")),
                }
                let a = self.parse_bin(1)?;
                match self.next() {
                    Some(Tok::Comma) => {}
                    _ => return Err(self.err("min! expects two arguments separated by ','")),
                }
                let b = self.parse_bin(1)?;
                match self.next() {
                    Some(Tok::RParen) => {}
                    _ => return Err(self.err("min! expects a closing ')'")),
                }
                Ok(Expr::Min(Box::new(a), Box::new(b)))
            }
            Some(Tok::Bin(op)) => {
                Err(self.err(format!("unexpected operator {:?}", bin_op_name(op))))
            }
            Some(tok) => Err(self.err(format!("unexpected token {tok:?}"))),
            None => Err(self.err("unexpected end of expression")),
        }
    }
}

/// Operator keyword (error messages).
pub(crate) fn bin_op_name(op: BinOp) -> &'static str {
    match op {
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::Xor => "xor",
        BinOp::Shl => "shl",
        BinOp::Shr => "shr",
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
    }
}

/// Parses a complete infix expression.
pub fn parse_expression(schema: &str, text: &str) -> Result<Expr, ProtocolError> {
    if text.trim().is_empty() {
        return Err(ProtocolError::parse(schema, "expression is empty"));
    }
    let toks = tokenize(text, schema)?;
    Parser {
        schema,
        toks,
        pos: 0,
    }
    .parse_full()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Expr {
        parse_expression("t", text).unwrap()
    }

    #[test]
    fn parses_precedence_and_parens() {
        // or binds loosest: a or (b and c)
        assert_eq!(
            ok("a or b and c"),
            Expr::Bin(
                BinOp::Or,
                Box::new(Expr::Reg("a".into())),
                Box::new(Expr::Bin(
                    BinOp::And,
                    Box::new(Expr::Reg("b".into())),
                    Box::new(Expr::Reg("c".into()))
                ))
            )
        );
        // parens override
        assert_eq!(
            ok("(a or b) and c"),
            Expr::Bin(
                BinOp::And,
                Box::new(Expr::Bin(
                    BinOp::Or,
                    Box::new(Expr::Reg("a".into())),
                    Box::new(Expr::Reg("b".into()))
                )),
                Box::new(Expr::Reg("c".into()))
            )
        );
        // shift over add: (a << 6) or 3 == or(shl(a,6), 3)
        assert_eq!(
            ok("a shl 6 or 3"),
            Expr::Bin(
                BinOp::Or,
                Box::new(Expr::Bin(
                    BinOp::Shl,
                    Box::new(Expr::Reg("a".into())),
                    Box::new(Expr::Int(6))
                )),
                Box::new(Expr::Int(3))
            )
        );
    }

    #[test]
    fn symbolic_sugar_matches_words() {
        for (words, sugar) in [
            ("a and b", "a & b"),
            ("a or b", "a | b"),
            ("a xor b", "a ^ b"),
            ("a shl 4", "a << 4"),
            ("a shr 4", "a >> 4"),
            ("a add 4", "a + 4"),
            ("a sub 4", "a - 4"),
            ("a mul 4", "a * 4"),
        ] {
            assert_eq!(ok(words), ok(sugar), "{words} vs {sugar}");
        }
    }

    #[test]
    fn unary_ops() {
        assert_eq!(ok("-5"), Expr::Int(-5));
        assert_eq!(ok("-acc"), Expr::Neg(Box::new(Expr::Reg("acc".into()))));
        assert_eq!(
            ok("not flag"),
            Expr::Not(Box::new(Expr::Reg("flag".into())))
        );
        assert_eq!(ok("0x38"), Expr::Int(0x38));
        assert_eq!(ok("- 0x10"), Expr::Int(-0x10));
    }

    #[test]
    fn parses_min_call() {
        assert_eq!(
            ok("min!(n, 4)"),
            Expr::Min(Box::new(Expr::Reg("n".into())), Box::new(Expr::Int(4)))
        );
        assert_eq!(
            ok("min!(acc + 1, 0x10)"),
            Expr::Min(
                Box::new(Expr::Bin(
                    BinOp::Add,
                    Box::new(Expr::Reg("acc".into())),
                    Box::new(Expr::Int(1))
                )),
                Box::new(Expr::Int(0x10))
            )
        );
    }

    #[test]
    fn rejects_bad_expressions() {
        assert!(parse_expression("t", "").is_err());
        assert!(parse_expression("t", "a <").is_err());
        assert!(parse_expression("t", "a < b").is_err());
        assert!(parse_expression("t", "and").is_err());
        assert!(parse_expression("t", "a and").is_err());
        assert!(parse_expression("t", "read").is_err());
        assert!(parse_expression("t", "min(n, 4)").is_err());
        assert!(parse_expression("t", "(a").is_err());
        assert!(parse_expression("t", "a b").is_err());
        assert!(parse_expression("t", "1.5").is_err());
    }
}
