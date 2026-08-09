//! DSL parser for rule match expressions.
//!
//! Translates the textual `match = 'ip=10.0.0.0/8 AND path regex "\\.env"'`
//! form into a [`RuleMatch`] tree. Used by config loading (`[[rules.custom]]`)
//! and the CLI (`sentry rules add --match '...'`).
//!
//! ## Grammar
//!
//! ```text
//! expr     := or_expr
//! or_expr  := and_expr ('OR' and_expr)*
//! and_expr := not_expr ('AND' not_expr)*
//! not_expr := 'NOT' not_expr | primary
//! primary  := '(' expr ')' | atom
//! atom     := key op value
//! ```
//!
//! ## Examples
//!
//! - `ip=10.0.0.0/8`
//! - `path regex "\\.env"`
//! - `country=RU AND path=/admin/*`
//! - `ip=10.0.0.0/8 AND (path=/.env OR path=/.git)`
//! - `asn=14061 AND NOT country=US`
//! - `ua regex "(?i)sqlmap"`
//! - `method=TRACE`
//! - `status=404`
//! - `reputation=tor`
//! - `time inside(09:00-18:00 America/Sao_Paulo)`
//! - `rate 50/60s per_ip`

use crate::event::{HttpMethod, ProtocolKind};
use crate::rules::{PathOp, RateScope, ReputationTier, RuleMatch, StrOp, TimeWindow};

/// Parse a DSL expression into a [`RuleMatch`].
pub fn parse(input: &str) -> Result<RuleMatch, DslError> {
    let tokens = tokenize(input)?;
    let mut parser = Parser::new(tokens);
    let expr = parser.parse_expr()?;
    if parser.peek().is_some() {
        return Err(DslError::UnexpectedToken(format!("{:?}", parser.peek())));
    }
    Ok(expr)
}

/// DSL parse error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DslError {
    /// Unexpected token.
    #[error("unexpected token: {0:?}")]
    UnexpectedToken(String),
    /// Missing value after operator.
    #[error("expected value after operator")]
    MissingValue,
    /// Missing closing parenthesis.
    #[error("missing closing parenthesis")]
    MissingParen,
    /// Invalid number.
    #[error("invalid number: {0}")]
    InvalidNumber(String),
    /// Invalid IP.
    #[error("invalid IP: {0}")]
    InvalidIp(String),
    /// Unknown key.
    #[error("unknown key: {0}")]
    UnknownKey(String),
    /// Empty input.
    #[error("empty expression")]
    Empty,
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    Quoted(String),
    LParen,
    RParen,
    And,
    Or,
    Not,
}

fn tokenize(input: &str) -> Result<Vec<Token>, DslError> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                i += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '"' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '"' {
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(DslError::MissingParen);
                }
                let val: String = chars[start..i].iter().collect();
                tokens.push(Token::Quoted(val));
                i += 1;
            }
            _ => {
                let start = i;
                while i < chars.len()
                    && !chars[i].is_whitespace()
                    && chars[i] != '('
                    && chars[i] != ')'
                    && chars[i] != '"'
                {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let upper = word.to_ascii_uppercase();
                match upper.as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR" => tokens.push(Token::Or),
                    "NOT" => tokens.push(Token::Not),
                    _ => tokens.push(Token::Word(word)),
                }
            }
        }
    }
    if tokens.is_empty() {
        return Err(DslError::Empty);
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn parse_expr(&mut self) -> Result<RuleMatch, DslError> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<RuleMatch, DslError> {
        let mut left = self.parse_and()?;
        while let Some(Token::Or) = self.peek() {
            self.next();
            let right = self.parse_and()?;
            left = match left {
                RuleMatch::Any(mut items) => {
                    items.push(right);
                    RuleMatch::Any(items)
                }
                other => RuleMatch::Any(vec![other, right]),
            };
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<RuleMatch, DslError> {
        let mut left = self.parse_not()?;
        while let Some(Token::And) = self.peek() {
            self.next();
            let right = self.parse_not()?;
            left = match left {
                RuleMatch::All(mut items) => {
                    items.push(right);
                    RuleMatch::All(items)
                }
                other => RuleMatch::All(vec![other, right]),
            };
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<RuleMatch, DslError> {
        if let Some(Token::Not) = self.peek() {
            self.next();
            let inner = self.parse_not()?;
            return Ok(RuleMatch::Not(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<RuleMatch, DslError> {
        match self.peek() {
            Some(Token::LParen) => {
                self.next();
                let expr = self.parse_expr()?;
                match self.next() {
                    Some(Token::RParen) => {}
                    _ => return Err(DslError::MissingParen),
                }
                Ok(expr)
            }
            Some(Token::Word(_)) | Some(Token::Quoted(_)) => self.parse_atom(),
            _ => Err(DslError::UnexpectedToken(format!("{:?}", self.peek()))),
        }
    }

    /// Splits `key=value` into `(key, Some(value))` or `key` into `(key, None)`.
    fn split_eq(token: &str) -> (String, Option<String>) {
        if let Some(idx) = token.find('=') {
            let (k, v) = token.split_at(idx);
            let v = &v[1..];
            if v.is_empty() {
                (k.to_string(), None)
            } else {
                (k.to_string(), Some(v.to_string()))
            }
        } else {
            (token.to_string(), None)
        }
    }

    fn parse_atom(&mut self) -> Result<RuleMatch, DslError> {
        let raw = match self.next() {
            Some(Token::Word(w)) => w,
            Some(Token::Quoted(q)) => q,
            other => return Err(DslError::UnexpectedToken(format!("{other:?}"))),
        };

        let (key, inline_val) = Self::split_eq(&raw);
        let key_lower = key.to_ascii_lowercase();

        match key_lower.as_str() {
            "ip" => {
                let val = self.resolve_value(inline_val)?;
                Ok(RuleMatch::Ip { cidr: val })
            }
            "asn" => {
                let val = self.resolve_value(inline_val)?;
                let n = val
                    .parse::<u32>()
                    .map_err(|_| DslError::InvalidNumber(val))?;
                Ok(RuleMatch::Asn(n))
            }
            "country" => {
                let val = self.resolve_value(inline_val)?;
                Ok(RuleMatch::Country(val))
            }
            "path" => self.parse_path_atom(inline_val),
            "ua" | "user_agent" | "useragent" => {
                self.parse_str_op_atom(inline_val, RuleMatch::UserAgent)
            }
            "query" => self.parse_str_op_atom(inline_val, RuleMatch::Query),
            "body" => self.parse_str_op_atom(inline_val, RuleMatch::Body),
            "method" => {
                let val = self.resolve_value(inline_val)?;
                Ok(RuleMatch::Method(HttpMethod::from_str_lossy(&val)))
            }
            "protocol" => {
                let val = self.resolve_value(inline_val)?;
                let p = match val.to_ascii_lowercase().as_str() {
                    "http" => ProtocolKind::Http,
                    "http3" | "http/3" => ProtocolKind::Http3,
                    "tcp" => ProtocolKind::Tcp,
                    "udp" => ProtocolKind::Udp,
                    "tls" => ProtocolKind::Tls,
                    _ => ProtocolKind::Other,
                };
                Ok(RuleMatch::Protocol(p))
            }
            "status" => {
                let val = self.resolve_value(inline_val)?;
                let n = val
                    .parse::<u16>()
                    .map_err(|_| DslError::InvalidNumber(val))?;
                Ok(RuleMatch::Status(n))
            }
            k if k.starts_with("header.") => {
                let header_name = k["header.".len()..].to_string();
                let op = if let Some(v) = inline_val {
                    StrOp::Equals { value: v }
                } else {
                    self.parse_str_op()?
                };
                Ok(RuleMatch::Header {
                    name: header_name,
                    op,
                })
            }
            "reputation" => {
                let val = self.resolve_value(inline_val)?;
                let tier = match val.to_ascii_lowercase().as_str() {
                    "unknown" => ReputationTier::Unknown,
                    "clean" => ReputationTier::Clean,
                    "suspicious" => ReputationTier::Suspicious,
                    "malicious" => ReputationTier::Malicious,
                    "datacenter" => ReputationTier::Datacenter,
                    "vpn" | "proxy" | "vpn_proxy" => ReputationTier::VpnProxy,
                    "tor" => ReputationTier::Tor,
                    _ => return Err(DslError::UnknownKey(val)),
                };
                Ok(RuleMatch::Reputation(tier))
            }
            "time" => {
                let mode = self.resolve_value(inline_val)?;
                let mode_lower = mode.to_ascii_lowercase();
                let (range, tz) = if let Some(Token::LParen) = self.peek() {
                    self.next();
                    let mut parts = Vec::new();
                    while let Some(t) = self.peek() {
                        if t == &Token::RParen {
                            break;
                        }
                        let s = match self.next() {
                            Some(Token::Word(w)) => w,
                            Some(Token::Quoted(q)) => q,
                            _ => continue,
                        };
                        parts.push(s);
                    }
                    match self.next() {
                        Some(Token::RParen) => {}
                        _ => return Err(DslError::MissingParen),
                    }
                    if parts.len() < 2 {
                        return Err(DslError::MissingValue);
                    }
                    (parts[0].clone(), parts[1..].join(" "))
                } else {
                    let range = self.expect_value()?;
                    let tz = self.expect_value()?;
                    (range, tz)
                };
                let window = match mode_lower.as_str() {
                    "inside" => TimeWindow::Inside { range, tz },
                    "outside" => TimeWindow::Outside { range, tz },
                    _ => return Err(DslError::UnknownKey(mode)),
                };
                Ok(RuleMatch::Time { window })
            }
            "rate" => {
                let count_val = self.resolve_value(inline_val)?;
                let (count_str, window_str) = if let Some(idx) = count_val.find('/') {
                    (
                        count_val[..idx].to_string(),
                        count_val[idx + 1..].to_string(),
                    )
                } else {
                    (count_val, String::from("60s"))
                };
                let count: u32 = count_str
                    .parse()
                    .map_err(|_| DslError::InvalidNumber(count_str))?;
                let per_secs = parse_duration_secs(&window_str);
                let scope = if let Some(Token::Word(w)) = self.peek() {
                    let scope = match w.to_ascii_lowercase().as_str() {
                        "per_ip" | "per-ip" => RateScope::PerIp,
                        "per_asn" | "per-asn" => RateScope::PerAsn,
                        "per_path" | "per-path" => RateScope::PerPath,
                        "global" => RateScope::Global,
                        _ => RateScope::PerIp,
                    };
                    self.next();
                    scope
                } else {
                    RateScope::PerIp
                };
                Ok(RuleMatch::Rate {
                    count,
                    per_secs,
                    scope,
                })
            }
            _ => Err(DslError::UnknownKey(key)),
        }
    }

    /// If `inline_val` is `Some`, return it; otherwise consume the next token as a value.
    fn resolve_value(&mut self, inline_val: Option<String>) -> Result<String, DslError> {
        if let Some(v) = inline_val {
            Ok(v)
        } else {
            self.expect_value()
        }
    }

    fn parse_path_atom(&mut self, inline_val: Option<String>) -> Result<RuleMatch, DslError> {
        if let Some(val) = inline_val {
            let op = if val.contains('*') {
                PathOp::Glob
            } else {
                PathOp::Equals
            };
            return Ok(RuleMatch::Path { op, pattern: val });
        }

        let op_word = match self.peek() {
            Some(Token::Word(w)) => w.to_ascii_lowercase(),
            Some(Token::Quoted(_)) => {
                let val = self.expect_value()?;
                let op = if val.contains('*') {
                    PathOp::Glob
                } else {
                    PathOp::Equals
                };
                return Ok(RuleMatch::Path { op, pattern: val });
            }
            _ => return Err(DslError::MissingValue),
        };

        match op_word.as_str() {
            "=" | "eq" | "equals" => {
                self.next();
                let val = self.expect_value()?;
                let op = if val.contains('*') {
                    PathOp::Glob
                } else {
                    PathOp::Equals
                };
                Ok(RuleMatch::Path { op, pattern: val })
            }
            "regex" => {
                self.next();
                let val = self.expect_value()?;
                Ok(RuleMatch::Path {
                    op: PathOp::Regex,
                    pattern: val,
                })
            }
            "starts_with" | "startswith" | "prefix" => {
                self.next();
                let val = self.expect_value()?;
                Ok(RuleMatch::Path {
                    op: PathOp::StartsWith,
                    pattern: val,
                })
            }
            "contains" => {
                self.next();
                let val = self.expect_value()?;
                Ok(RuleMatch::Path {
                    op: PathOp::Regex,
                    pattern: regex::escape(&val),
                })
            }
            _ => {
                let val = op_word.clone();
                self.next();
                let op = if val.contains('*') {
                    PathOp::Glob
                } else {
                    PathOp::Equals
                };
                Ok(RuleMatch::Path { op, pattern: val })
            }
        }
    }

    fn parse_str_op_atom(
        &mut self,
        inline_val: Option<String>,
        ctor: fn(StrOp) -> RuleMatch,
    ) -> Result<RuleMatch, DslError> {
        if let Some(val) = inline_val {
            return Ok(ctor(StrOp::Equals { value: val }));
        }
        let op = self.parse_str_op()?;
        Ok(ctor(op))
    }

    fn parse_str_op(&mut self) -> Result<StrOp, DslError> {
        let op_word = match self.peek() {
            Some(Token::Word(w)) => w.to_ascii_lowercase(),
            Some(Token::Quoted(_)) => {
                let val = self.expect_value()?;
                return Ok(StrOp::Equals { value: val });
            }
            _ => return Err(DslError::MissingValue),
        };

        match op_word.as_str() {
            "=" | "eq" | "equals" => {
                self.next();
                let val = self.expect_value()?;
                Ok(StrOp::Equals { value: val })
            }
            "regex" => {
                self.next();
                let val = self.expect_value()?;
                Ok(StrOp::Regex { pattern: val })
            }
            "contains" => {
                self.next();
                let val = self.expect_value()?;
                Ok(StrOp::Contains { value: val })
            }
            "starts_with" | "startswith" => {
                self.next();
                let val = self.expect_value()?;
                Ok(StrOp::StartsWith { value: val })
            }
            "in" => {
                self.next();
                let mut values = Vec::new();
                while let Some(Token::Quoted(_)) | Some(Token::Word(_)) = self.peek() {
                    values.push(self.expect_value()?);
                }
                Ok(StrOp::In { values })
            }
            _ => {
                let val = op_word.clone();
                self.next();
                Ok(StrOp::Equals { value: val })
            }
        }
    }

    fn expect_value(&mut self) -> Result<String, DslError> {
        match self.next() {
            Some(Token::Quoted(s)) => Ok(s),
            Some(Token::Word(s)) => Ok(s),
            _ => Err(DslError::MissingValue),
        }
    }
}

fn parse_duration_secs(s: &str) -> u64 {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("s") {
        return num.parse().unwrap_or(60);
    }
    if let Some(num) = s.strip_suffix("m") {
        return num.parse::<u64>().unwrap_or(1) * 60;
    }
    if let Some(num) = s.strip_suffix("h") {
        return num.parse::<u64>().unwrap_or(1) * 3600;
    }
    s.parse().unwrap_or(60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::ProtocolKind;

    #[test]
    fn parse_ip() {
        let m = parse("ip=10.0.0.0/8").unwrap();
        assert!(matches!(m, RuleMatch::Ip { cidr } if cidr == "10.0.0.0/8"));
    }

    #[test]
    fn parse_path_regex() {
        let m = parse(r#"path regex "\.env""#).unwrap();
        match m {
            RuleMatch::Path { op, pattern } => {
                assert_eq!(op, PathOp::Regex);
                assert_eq!(pattern, r"\.env");
            }
            _ => panic!("expected Path"),
        }
    }

    #[test]
    fn parse_path_glob() {
        let m = parse("path=/admin/*").unwrap();
        match m {
            RuleMatch::Path { op, pattern } => {
                assert_eq!(op, PathOp::Glob);
                assert_eq!(pattern, "/admin/*");
            }
            _ => panic!("expected Path"),
        }
    }

    #[test]
    fn parse_and() {
        let m = parse("country=RU AND path=/admin/*").unwrap();
        match m {
            RuleMatch::All(items) => assert_eq!(items.len(), 2),
            _ => panic!("expected All"),
        }
    }

    #[test]
    fn parse_or_with_parens() {
        let m = parse("ip=10.0.0.0/8 AND (path=/.env OR path=/.git)").unwrap();
        match m {
            RuleMatch::All(items) => {
                assert_eq!(items.len(), 2);
                match &items[1] {
                    RuleMatch::Any(or_items) => assert_eq!(or_items.len(), 2),
                    _ => panic!("expected Any inside"),
                }
            }
            _ => panic!("expected All"),
        }
    }

    #[test]
    fn parse_not() {
        let m = parse("asn=14061 AND NOT country=US").unwrap();
        match m {
            RuleMatch::All(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(&items[1], RuleMatch::Not(_)));
            }
            _ => panic!("expected All"),
        }
    }

    #[test]
    fn parse_ua_regex() {
        let m = parse(r#"ua regex "(?i)sqlmap""#).unwrap();
        match m {
            RuleMatch::UserAgent(StrOp::Regex { pattern }) => {
                assert_eq!(pattern, "(?i)sqlmap");
            }
            _ => panic!("expected UserAgent Regex"),
        }
    }

    #[test]
    fn parse_method() {
        let m = parse("method=TRACE").unwrap();
        assert!(matches!(m, RuleMatch::Method(HttpMethod::Trace)));
    }

    #[test]
    fn parse_status() {
        let m = parse("status=404").unwrap();
        assert!(matches!(m, RuleMatch::Status(404)));
    }

    #[test]
    fn parse_protocol() {
        let m = parse("protocol=http").unwrap();
        assert!(matches!(m, RuleMatch::Protocol(ProtocolKind::Http)));
    }

    #[test]
    fn parse_reputation() {
        let m = parse("reputation=tor").unwrap();
        assert!(matches!(m, RuleMatch::Reputation(ReputationTier::Tor)));
    }

    #[test]
    fn parse_rate() {
        let m = parse("rate 50/60s per_ip").unwrap();
        match m {
            RuleMatch::Rate {
                count,
                per_secs,
                scope,
            } => {
                assert_eq!(count, 50);
                assert_eq!(per_secs, 60);
                assert_eq!(scope, RateScope::PerIp);
            }
            _ => panic!("expected Rate"),
        }
    }

    #[test]
    fn parse_time_inside() {
        let m = parse("time inside(09:00-18:00 America/Sao_Paulo)").unwrap();
        match m {
            RuleMatch::Time { window } => match window {
                TimeWindow::Inside { range, tz } => {
                    assert_eq!(range, "09:00-18:00");
                    assert_eq!(tz, "America/Sao_Paulo");
                }
                _ => panic!("expected Inside"),
            },
            _ => panic!("expected Time"),
        }
    }

    #[test]
    fn parse_header() {
        let m = parse(r#"header.X-Forwarded-For = "1.2.3.4""#).unwrap();
        match m {
            RuleMatch::Header { name, op } => {
                assert_eq!(name, "x-forwarded-for");
                assert!(matches!(op, StrOp::Equals { value } if value == "1.2.3.4"));
            }
            _ => panic!("expected Header"),
        }
    }

    #[test]
    fn parse_complex_expression() {
        let m = parse(
            r#"ip=10.0.0.0/8 AND (path regex "\.env" OR ua regex "sqlmap") AND NOT country=US"#,
        )
        .unwrap();
        match m {
            RuleMatch::All(items) => assert_eq!(items.len(), 3),
            _ => panic!("expected All with 3 items"),
        }
    }

    #[test]
    fn parse_empty_errors() {
        assert!(parse("").is_err());
    }

    #[test]
    fn parse_unknown_key_errors() {
        assert!(parse("bogus=123").is_err());
    }
}
