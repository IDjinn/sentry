//! Lexer + recursive-descent parser for the configuration language.
//!
//! ```text
//! file      = body
//! body      = { stmt | sep }
//! stmt      = key ":" value { value }            (directive, ends at sep/`}`/next key)
//!           | name { label } "{" body "}"        (block)
//! value     = string | word | number | "[" { value | sep } "]" | "{" body "}"
//! sep       = newline | ";" | ","
//! ```
//!
//! A word followed by `:` and whitespace is a key; a `:` inside a word
//! (`0.0.0.0:80`, `http://x:3000`) stays part of it. Double-quoted strings
//! expand `${VAR}` / `${VAR:-default}` from the environment; single-quoted
//! strings are raw (regexes, rule DSL).

use std::sync::Arc;

use crate::ast::{Block, Body, Directive, Node, Span, Stmt, Value};
use crate::error::{Error, Result};

/// Environment lookup used for `${VAR}` expansion.
pub type EnvLookup<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Parse one source text. `file` is the display name used in spans.
pub fn parse(src: &str, file: &str, env: EnvLookup<'_>) -> Result<Body> {
    let file: Arc<str> = Arc::from(file);
    let tokens = Lexer::new(src, file.clone(), env).run()?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        eof: Span {
            file,
            line: src.lines().count().max(1) as u32,
            col: 1,
        },
    };
    parser.body(None)
}

/// Parse with the process environment.
pub fn parse_str(src: &str, file: &str) -> Result<Body> {
    parse(src, file, &|k| std::env::var(k).ok())
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Int(i64),
    Float(f64),
    Colon,
    LBrace,
    RBrace,
    LBrack,
    RBrack,
    Sep,
}

struct Lexer<'a> {
    chars: Vec<char>,
    i: usize,
    line: u32,
    col: u32,
    file: Arc<str>,
    env: EnvLookup<'a>,
    out: Vec<(Tok, Span)>,
}

/// Characters that always end a bare word.
fn is_delim(c: char) -> bool {
    c.is_whitespace() || matches!(c, '{' | '}' | '[' | ']' | ';' | ',' | '"' | '\'')
}

impl<'a> Lexer<'a> {
    fn new(src: &str, file: Arc<str>, env: EnvLookup<'a>) -> Self {
        Self {
            chars: src.chars().collect(),
            i: 0,
            line: 1,
            col: 1,
            file,
            env,
            out: Vec::new(),
        }
    }

    fn span(&self) -> Span {
        Span {
            file: self.file.clone(),
            line: self.line,
            col: self.col,
        }
    }

    fn peek(&self, off: usize) -> Option<char> {
        self.chars.get(self.i + off).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.chars.get(self.i).copied()?;
        self.i += 1;
        if c == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    /// `:` right after a key: followed by whitespace, EOF or a value opener.
    fn colon_ends_key(&self) -> bool {
        self.peek(0) == Some(':')
            && match self.peek(1) {
                None => true,
                Some(c) => {
                    c.is_whitespace() || matches!(c, '[' | '{' | '"' | '\'' | '#' | ';' | ',' | '}')
                }
            }
    }

    fn run(mut self) -> Result<Vec<(Tok, Span)>> {
        while let Some(c) = self.peek(0) {
            let span = self.span();
            match c {
                '\n' | ';' | ',' => {
                    self.bump();
                    self.out.push((Tok::Sep, span));
                }
                c if c.is_whitespace() => {
                    self.bump();
                }
                '#' => self.skip_line(),
                '/' if self.peek(1) == Some('/') => self.skip_line(),
                '/' if self.peek(1) == Some('*') => self.skip_block_comment(&span)?,
                '{' => {
                    self.bump();
                    self.out.push((Tok::LBrace, span));
                }
                '}' => {
                    self.bump();
                    self.out.push((Tok::RBrace, span));
                }
                '[' => {
                    self.bump();
                    self.out.push((Tok::LBrack, span));
                }
                ']' => {
                    self.bump();
                    self.out.push((Tok::RBrack, span));
                }
                ':' => {
                    return Err(Error::at(
                        &span,
                        "unexpected `:` — a directive needs a name before the colon",
                    ));
                }
                '"' => {
                    let s = self.double_quoted(&span)?;
                    self.out.push((Tok::Str(s), span));
                    self.maybe_colon();
                }
                '\'' => {
                    let s = self.single_quoted(&span)?;
                    self.out.push((Tok::Str(s), span));
                    self.maybe_colon();
                }
                _ => {
                    let word = self.word();
                    self.out.push((classify(word), span));
                    self.maybe_colon();
                }
            }
        }
        Ok(self.out)
    }

    fn maybe_colon(&mut self) {
        if self.colon_ends_key() {
            let span = self.span();
            self.bump();
            self.out.push((Tok::Colon, span));
        }
    }

    fn skip_line(&mut self) {
        while let Some(c) = self.peek(0) {
            if c == '\n' {
                break;
            }
            self.bump();
        }
    }

    fn skip_block_comment(&mut self, start: &Span) -> Result<()> {
        self.bump();
        self.bump();
        loop {
            match self.bump() {
                None => return Err(Error::at(start, "unterminated `/*` comment")),
                Some('*') if self.peek(0) == Some('/') => {
                    self.bump();
                    return Ok(());
                }
                Some(_) => {}
            }
        }
    }

    fn word(&mut self) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek(0) {
            if is_delim(c) {
                break;
            }
            if c == ':' && self.colon_ends_key() {
                break;
            }
            s.push(c);
            self.bump();
        }
        s
    }

    fn single_quoted(&mut self, start: &Span) -> Result<String> {
        self.bump();
        let mut s = String::new();
        loop {
            match self.bump() {
                None => return Err(Error::at(start, "unterminated string (missing `'`)")),
                Some('\\') if self.peek(0) == Some('\'') => {
                    self.bump();
                    s.push('\'');
                }
                Some('\'') => return Ok(s),
                Some(c) => s.push(c),
            }
        }
    }

    fn double_quoted(&mut self, start: &Span) -> Result<String> {
        self.bump();
        let mut s = String::new();
        loop {
            let here = self.span();
            match self.bump() {
                None => return Err(Error::at(start, "unterminated string (missing `\"`)")),
                Some('"') => return Ok(s),
                Some('\\') => match self.bump() {
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('r') => s.push('\r'),
                    Some('0') => s.push('\0'),
                    Some(c @ ('\\' | '"' | '\'' | '$')) => s.push(c),
                    Some(c) => {
                        s.push('\\');
                        s.push(c);
                    }
                    None => return Err(Error::at(start, "unterminated string (missing `\"`)")),
                },
                Some('$') if self.peek(0) == Some('{') => {
                    self.bump();
                    let mut inner = String::new();
                    loop {
                        match self.bump() {
                            None => return Err(Error::at(&here, "unterminated `${…}`")),
                            Some('}') => break,
                            Some(c) => inner.push(c),
                        }
                    }
                    let (name, default) = match inner.split_once(":-") {
                        Some((n, d)) => (n.trim(), Some(d)),
                        None => (inner.trim(), None),
                    };
                    if name.is_empty()
                        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    {
                        return Err(Error::at(
                            &here,
                            format!("invalid environment variable name in `${{{inner}}}`"),
                        ));
                    }
                    match ((self.env)(name), default) {
                        (Some(v), _) if !v.is_empty() => s.push_str(&v),
                        (_, Some(d)) => s.push_str(d),
                        (Some(v), None) => s.push_str(&v),
                        (None, None) => {
                            return Err(Error::at(
                                &here,
                                format!(
                                    "environment variable `{name}` is not set \
                                     (use `${{{name}:-default}}` for a fallback)"
                                ),
                            ))
                        }
                    }
                }
                Some(c) => s.push(c),
            }
        }
    }
}

fn classify(word: String) -> Tok {
    let digits = word.strip_prefix('-').unwrap_or(&word);
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(i) = word.parse::<i64>() {
            return Tok::Int(i);
        }
    }
    if let Some((a, b)) = digits.split_once('.') {
        if !a.is_empty()
            && !b.is_empty()
            && a.bytes().all(|c| c.is_ascii_digit())
            && b.bytes().all(|c| c.is_ascii_digit())
        {
            if let Ok(f) = word.parse::<f64>() {
                return Tok::Float(f);
            }
        }
    }
    Tok::Word(word)
}

struct Parser {
    tokens: Vec<(Tok, Span)>,
    pos: usize,
    eof: Span,
}

impl Parser {
    fn peek(&self) -> Option<&(Tok, Span)> {
        self.tokens.get(self.pos)
    }

    fn peek_tok(&self, off: usize) -> Option<&Tok> {
        self.tokens.get(self.pos + off).map(|(t, _)| t)
    }

    fn next(&mut self) -> Option<(Tok, Span)> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn skip_seps(&mut self) {
        while matches!(self.peek_tok(0), Some(Tok::Sep)) {
            self.pos += 1;
        }
    }

    /// Statements until EOF (top level, `opener = None`) or the closing `}`.
    fn body(&mut self, opener: Option<&Span>) -> Result<Body> {
        let mut body = Vec::new();
        loop {
            self.skip_seps();
            let Some((tok, span)) = self.peek().cloned() else {
                return match opener {
                    None => Ok(body),
                    Some(open) => Err(Error::at(open, "block is never closed (missing `}`)")),
                };
            };
            let name = match tok {
                Tok::RBrace => {
                    self.pos += 1;
                    return match opener {
                        Some(_) => Ok(body),
                        None => Err(Error::at(&span, "unexpected `}` (no block to close)")),
                    };
                }
                Tok::Word(w) | Tok::Str(w) => w,
                Tok::Int(i) => i.to_string(),
                Tok::Float(f) => f.to_string(),
                Tok::LBrace => return Err(Error::at(&span, "unexpected `{` — blocks need a name")),
                Tok::LBrack => {
                    return Err(Error::at(
                        &span,
                        "unexpected `[` — lists need a `key:` before them",
                    ))
                }
                Tok::RBrack => return Err(Error::at(&span, "unexpected `]`")),
                Tok::Colon | Tok::Sep => unreachable!("handled by the lexer / skip_seps"),
            };
            self.pos += 1;
            if matches!(self.peek_tok(0), Some(Tok::Colon)) {
                self.pos += 1;
                let values = self.values()?;
                if values.is_empty() {
                    return Err(Error::at(&span, format!("`{name}:` needs a value")));
                }
                body.push(Stmt::Directive(Directive {
                    key: name,
                    values,
                    span,
                }));
                continue;
            }
            let mut labels = Vec::new();
            loop {
                match self.next() {
                    Some((Tok::LBrace, open)) => {
                        let inner = self.body(Some(&open))?;
                        body.push(Stmt::Block(Block {
                            name,
                            labels,
                            body: inner,
                            span,
                        }));
                        break;
                    }
                    Some((Tok::Word(w), s)) => labels.push(Node {
                        value: Value::Word(w),
                        span: s,
                    }),
                    Some((Tok::Str(w), s)) => labels.push(Node {
                        value: Value::Str(w),
                        span: s,
                    }),
                    Some((Tok::Int(i), s)) => labels.push(Node {
                        value: Value::Int(i),
                        span: s,
                    }),
                    Some((Tok::Float(f), s)) => labels.push(Node {
                        value: Value::Float(f),
                        span: s,
                    }),
                    Some((Tok::Sep, _))
                        if {
                            let mut k = 0;
                            while matches!(self.peek_tok(k), Some(Tok::Sep)) {
                                k += 1;
                            }
                            matches!(self.peek_tok(k), Some(Tok::LBrace))
                        } =>
                    {
                        self.skip_seps();
                    }
                    Some((Tok::Colon, s)) => {
                        return Err(Error::at(
                            &s,
                            format!("unexpected `:` after `{name}` — put the colon right after the directive name"),
                        ))
                    }
                    other => {
                        let at = other.map(|(_, s)| s).unwrap_or_else(|| self.eof.clone());
                        return Err(Error::at(
                            &span,
                            format!("expected `:` or `{{` after `{name}`"),
                        )
                        .or_span(&at));
                    }
                }
            }
        }
    }

    /// Values of a directive: until a separator, `}`, EOF or the next `key:`.
    fn values(&mut self) -> Result<Vec<Node>> {
        let mut values = Vec::new();
        loop {
            match self.peek_tok(0) {
                None | Some(Tok::Sep) | Some(Tok::RBrace) => return Ok(values),
                Some(Tok::Word(_) | Tok::Str(_) | Tok::Int(_) | Tok::Float(_))
                    if matches!(self.peek_tok(1), Some(Tok::Colon)) =>
                {
                    return Ok(values)
                }
                _ => values.push(self.value()?),
            }
        }
    }

    fn value(&mut self) -> Result<Node> {
        let (tok, span) = self
            .next()
            .ok_or_else(|| Error::at(&self.eof, "expected a value"))?;
        let value = match tok {
            Tok::Word(w) => Value::Word(w),
            Tok::Str(s) => Value::Str(s),
            Tok::Int(i) => Value::Int(i),
            Tok::Float(f) => Value::Float(f),
            Tok::LBrack => {
                let mut items = Vec::new();
                loop {
                    self.skip_seps();
                    match self.peek_tok(0) {
                        None => return Err(Error::at(&span, "list is never closed (missing `]`)")),
                        Some(Tok::RBrack) => {
                            self.pos += 1;
                            break;
                        }
                        _ => items.push(self.value()?),
                    }
                }
                Value::List(items)
            }
            Tok::LBrace => Value::Map(self.body(Some(&span))?),
            Tok::Colon => return Err(Error::at(&span, "unexpected `:`")),
            Tok::RBrace | Tok::RBrack | Tok::Sep => {
                return Err(Error::at(&span, "expected a value"))
            }
        };
        Ok(Node { value, span })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(src: &str) -> Body {
        parse(src, "t.conf", &|k| {
            (k == "HOME_DB").then(|| "pg://x".to_string())
        })
        .unwrap()
    }

    fn err(src: &str) -> String {
        parse(src, "t.conf", &|_| None).unwrap_err().to_string()
    }

    #[test]
    fn directives_blocks_and_labels() {
        let body = p("server {\n  data_directory: /var/lib/sentry\n  geo { city_db: \"a.mmdb\" }\n}\nlocation ~* '\\.php$' { return: 403 }\n");
        assert_eq!(body.len(), 2);
        let Stmt::Block(server) = &body[0] else {
            panic!()
        };
        assert_eq!(server.name, "server");
        let Stmt::Directive(d) = &server.body[0] else {
            panic!()
        };
        assert_eq!(d.key, "data_directory");
        assert_eq!(d.values[0].value, Value::Word("/var/lib/sentry".into()));
        let Stmt::Block(loc) = &body[1] else { panic!() };
        assert_eq!(loc.labels[0].value, Value::Word("~*".into()));
        assert_eq!(loc.labels[1].value, Value::Str("\\.php$".into()));
    }

    #[test]
    fn colon_inside_words_is_not_a_key() {
        let body = p("listen: 0.0.0.0:80\nproxy_pass: http://127.0.0.1:3000/x\n");
        let Stmt::Directive(d) = &body[0] else {
            panic!()
        };
        assert_eq!(d.values[0].value, Value::Word("0.0.0.0:80".into()));
        let Stmt::Directive(d) = &body[1] else {
            panic!()
        };
        assert_eq!(
            d.values[0].value,
            Value::Word("http://127.0.0.1:3000/x".into())
        );
    }

    #[test]
    fn several_directives_on_one_line_and_multi_values() {
        let body = p("a: 1 b: [x, y\n z] c: 301 \"https://e\"; d: 2.5, e: -3");
        let keys: Vec<&str> = body.iter().map(Stmt::name).collect();
        assert_eq!(keys, ["a", "b", "c", "d", "e"]);
        let Stmt::Directive(c) = &body[2] else {
            panic!()
        };
        assert_eq!(c.values.len(), 2);
        let Stmt::Directive(b) = &body[1] else {
            panic!()
        };
        let Value::List(items) = &b.values[0].value else {
            panic!()
        };
        assert_eq!(items.len(), 3);
        let Stmt::Directive(e) = &body[4] else {
            panic!()
        };
        assert_eq!(e.values[0].value, Value::Int(-3));
    }

    #[test]
    fn quoted_keys_and_inline_maps() {
        let body = p("routes { \"/api/{id}\": [GET] }\nheaders_env: { Key: SENTRY_X }");
        let Stmt::Block(r) = &body[0] else { panic!() };
        assert_eq!(r.body[0].name(), "/api/{id}");
        let Stmt::Directive(h) = &body[1] else {
            panic!()
        };
        assert!(matches!(h.values[0].value, Value::Map(_)));
    }

    #[test]
    fn env_expansion_in_double_quotes_only() {
        let body = p(
            "a: \"${HOME_DB}\"\nb: \"${MISSING:-fallback}\"\nc: '${HOME_DB}'\nd: \"\\${HOME_DB}\"",
        );
        let texts: Vec<String> = body
            .iter()
            .map(|s| match s {
                Stmt::Directive(d) => d.values[0].as_text().unwrap(),
                Stmt::Block(_) => unreachable!(),
            })
            .collect();
        assert_eq!(texts, ["pg://x", "fallback", "${HOME_DB}", "${HOME_DB}"]);
        assert!(err("a: \"${NOPE}\"").contains("`NOPE` is not set"));
    }

    #[test]
    fn comments_are_skipped() {
        let body = p("# c\na: 1 // trailing\n/* multi\nline */ b: http://x/y#z\n");
        assert_eq!(body.len(), 2);
    }

    #[test]
    fn errors_carry_positions() {
        assert_eq!(
            err("a {\n b: 1\n"),
            "t.conf:1:3: block is never closed (missing `}`)"
        );
        assert!(err("x\n").starts_with("t.conf:1:1: expected `:` or `{` after `x`"));
        assert!(err("}").contains("unexpected `}`"));
        assert!(err("a:\n").contains("`a:` needs a value"));
        assert!(err("a: [1, 2").contains("list is never closed"));
    }
}
