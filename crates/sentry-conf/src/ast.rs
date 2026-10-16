//! Syntax tree of a parsed configuration: statements, values and the source
//! positions every error message points back to.

use std::fmt;
use std::sync::Arc;

/// Source position (file, 1-based line and column).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    /// File the token came from (display name).
    pub file: Arc<str>,
    /// 1-based line.
    pub line: u32,
    /// 1-based column.
    pub col: u32,
}

impl Span {
    /// Span for values that do not come from a file (env overlay, tests).
    pub fn synthetic(label: &str) -> Self {
        Self {
            file: Arc::from(label),
            line: 0,
            col: 0,
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.file)
        } else {
            write!(f, "{}:{}:{}", self.file, self.line, self.col)
        }
    }
}

/// One value token (or composite) on the right side of a directive, or a
/// block label.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Quoted string (`"…"` with escapes/env expansion, or `'…'` raw).
    Str(String),
    /// Unquoted word: identifiers, paths, URLs, durations (`10s`), sizes.
    Word(String),
    /// Integer literal.
    Int(i64),
    /// Floating-point literal.
    Float(f64),
    /// `[a, b, c]`.
    List(Vec<Node>),
    /// Inline map `{ key: value … }` used as a value.
    Map(Body),
}

/// A value with its position.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// The value.
    pub value: Value,
    /// Where it starts.
    pub span: Span,
}

impl Node {
    /// Text of a scalar (string, word or number); `None` for lists/maps.
    pub fn as_text(&self) -> Option<String> {
        match &self.value {
            Value::Str(s) | Value::Word(s) => Some(s.clone()),
            Value::Int(i) => Some(i.to_string()),
            Value::Float(f) => Some(f.to_string()),
            Value::List(_) | Value::Map(_) => None,
        }
    }

    /// Short human description used in error messages.
    pub fn describe(&self) -> &'static str {
        match self.value {
            Value::Str(_) => "a string",
            Value::Word(_) => "a word",
            Value::Int(_) => "an integer",
            Value::Float(_) => "a number",
            Value::List(_) => "a list",
            Value::Map(_) => "a block",
        }
    }
}

/// `key: value…` — one or more values on one line.
#[derive(Debug, Clone, PartialEq)]
pub struct Directive {
    /// Directive name.
    pub key: String,
    /// Values (at least one).
    pub values: Vec<Node>,
    /// Position of the key.
    pub span: Span,
}

/// `name label… { body }`.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    /// Block name.
    pub name: String,
    /// Labels between the name and `{` (e.g. `location ~ "^/api"`).
    pub labels: Vec<Node>,
    /// Statements inside the braces.
    pub body: Body,
    /// Position of the name.
    pub span: Span,
}

/// One statement inside a body.
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// `key: value…`
    Directive(Directive),
    /// `name label… { … }`
    Block(Block),
}

impl Stmt {
    /// Statement name (directive key or block name).
    pub fn name(&self) -> &str {
        match self {
            Stmt::Directive(d) => &d.key,
            Stmt::Block(b) => &b.name,
        }
    }

    /// Statement position.
    pub fn span(&self) -> &Span {
        match self {
            Stmt::Directive(d) => &d.span,
            Stmt::Block(b) => &b.span,
        }
    }
}

/// A sequence of statements (a file, or the inside of a block).
pub type Body = Vec<Stmt>;
