//! Error type: a message with the source position and the block path it was
//! raised in (`sentry.conf:42:9: http › site › location: unknown field …`).

use std::fmt;

use crate::ast::Span;

/// Parse, load or deserialization error.
#[derive(Debug, Clone, PartialEq)]
pub struct Error {
    /// What went wrong.
    pub message: String,
    /// Where (when known).
    pub span: Option<Span>,
    /// Enclosing block names, outermost first.
    pub path: Vec<String>,
}

/// Result alias.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Error without a position yet (attached later by the deserializer).
    pub fn msg(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: None,
            path: Vec::new(),
        }
    }

    /// Error at a position.
    pub fn at(span: &Span, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            span: Some(span.clone()),
            path: Vec::new(),
        }
    }

    /// Attach a span when none is set yet.
    pub fn or_span(mut self, span: &Span) -> Self {
        if self.span.is_none() {
            self.span = Some(span.clone());
        }
        self
    }

    /// Prefix the block path with an enclosing block name.
    pub fn within(mut self, name: &str) -> Self {
        self.path.insert(0, name.to_string());
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(span) = &self.span {
            write!(f, "{span}: ")?;
        }
        if !self.path.is_empty() {
            write!(f, "{}: ", self.path.join(" › "))?;
        }
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for Error {}

impl serde::de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::msg(msg.to_string())
    }

    fn unknown_field(field: &str, expected: &'static [&'static str]) -> Self {
        if field == crate::de::LABELS_KEY {
            return Error::msg("this block does not take a name/label");
        }
        let mut message = format!("unknown directive `{field}`");
        if let Some(best) = suggest(field, expected) {
            message.push_str(&format!(" — did you mean `{best}`?"));
        } else if !expected.is_empty() {
            let shown: Vec<&str> = expected
                .iter()
                .copied()
                .filter(|e| *e != crate::de::LABELS_KEY)
                .collect();
            message.push_str(&format!(" (expected one of: {})", shown.join(", ")));
        }
        Error::msg(message)
    }

    fn missing_field(field: &'static str) -> Self {
        if field == crate::de::LABELS_KEY {
            return Error::msg("this block needs a name/label (e.g. `upstream app { … }`)");
        }
        Error::msg(format!("missing required directive `{field}`"))
    }

    fn unknown_variant(variant: &str, expected: &'static [&'static str]) -> Self {
        let mut message = format!("unknown value `{variant}`");
        if let Some(best) = suggest(variant, expected) {
            message.push_str(&format!(" — did you mean `{best}`?"));
        } else {
            message.push_str(&format!(" (expected one of: {})", expected.join(", ")));
        }
        Error::msg(message)
    }
}

impl serde::ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Error::msg(msg.to_string())
    }
}

/// Closest candidate by edit distance (≤ 2, or ≤ 1/3 of the length).
pub fn suggest<'a>(input: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let input = input.to_ascii_lowercase();
    candidates
        .iter()
        .filter(|c| !c.starts_with('$'))
        .map(|c| (levenshtein(&input, &c.to_ascii_lowercase()), *c))
        .filter(|(d, c)| *d <= 2.max(c.len() / 3))
        .min_by_key(|(d, _)| *d)
        .map(|(_, c)| c)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != *cb);
            cur[j + 1] = (prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggests_close_names_only() {
        assert_eq!(suggest("blance", &["balance", "server"]), Some("balance"));
        assert_eq!(suggest("zzz", &["balance", "server"]), None);
    }
}
