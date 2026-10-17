//! Comment-preserving edits of configuration source text.
//!
//! `sentry config set|unset` must change one directive without
//! reformatting the whole file (the AST carries no comments, so
//! re-emitting it would erase them). Edits therefore work on the source
//! text: the parser locates the directive, and a small scanner finds where
//! its value (or its enclosing block) ends.
//!
//! Paths are dotted block names ending in a directive key
//! (`http.compress.enabled`). Only unlabeled blocks are addressable;
//! labeled ones (`site example.com { … }`) must be edited by hand.

use crate::ast::{Block, Body, Directive, Node, Stmt, Value};
use crate::error::{Error, Result};
use crate::parser::parse_str;

/// What a path resolves to in a parsed tree.
#[derive(Debug)]
pub enum Lookup<'a> {
    /// A directive (`key: value`).
    Directive(&'a Directive),
    /// A block; the names of its direct statements.
    Block(Vec<String>),
}

/// One path segment: a block or directive name, plus the label of a
/// labeled block (`pack[sensitive_paths]`, `site[example.com]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seg {
    /// Block or directive name.
    pub name: String,
    /// Block label(s), space-joined; `None` addresses an unlabeled block.
    pub label: Option<String>,
}

impl std::fmt::Display for Seg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.label {
            Some(l) => write!(f, "{}[{l}]", self.name),
            None => write!(f, "{}", self.name),
        }
    }
}

/// Split `a.b[label].c` into segments. Dots inside `[...]` belong to the
/// label (`site[example.com].proxy_pass`); empty segments are rejected.
pub fn split_path(path: &str) -> Result<Vec<Seg>> {
    let bad = || {
        Error::msg(format!(
            "invalid config path `{path}` (expected names like `http.compress.enabled` or              `rules.pack[sensitive_paths].mode`)"
        ))
    };
    let mut raw: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth = 0usize;
    for c in path.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth = depth.checked_sub(1).ok_or_else(bad)?;
                cur.push(c);
            }
            '.' if depth == 0 => raw.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if depth != 0 {
        return Err(bad());
    }
    raw.push(cur);
    let mut segs = Vec::new();
    for r in raw {
        let r = r.trim();
        let seg = match r.find('[') {
            Some(i) if r.ends_with(']') => Seg {
                name: r[..i].trim().to_string(),
                label: Some(r[i + 1..r.len() - 1].trim().to_string()),
            },
            Some(_) => return Err(bad()),
            None => Seg {
                name: r.to_string(),
                label: None,
            },
        };
        if seg.name.is_empty() || seg.label.as_deref() == Some("") {
            return Err(bad());
        }
        segs.push(seg);
    }
    Ok(segs)
}

fn block_matches(b: &Block, seg: &Seg) -> bool {
    if b.name != seg.name {
        return false;
    }
    match &seg.label {
        None => b.labels.is_empty(),
        Some(l) => {
            let joined: Vec<String> = b.labels.iter().filter_map(Node::as_text).collect();
            joined.len() == b.labels.len() && joined.join(" ") == *l
        }
    }
}

/// Resolve `path` in a tree. Same-name unlabeled blocks (across files or
/// repeated) are all searched; the first match wins.
pub fn lookup<'a>(body: &'a Body, path: &[Seg]) -> Option<Lookup<'a>> {
    let (last, parents) = path.split_last()?;
    for scope in scopes(body, parents) {
        for stmt in scope {
            match stmt {
                Stmt::Directive(d) if d.key == last.name && last.label.is_none() => {
                    return Some(Lookup::Directive(d))
                }
                Stmt::Block(b) if block_matches(b, last) => {
                    return Some(Lookup::Block(
                        b.body.iter().map(|s| s.name().to_string()).collect(),
                    ));
                }
                _ => {}
            }
        }
    }
    None
}

/// Every statement list reachable through the unlabeled blocks `names`.
fn scopes<'a>(body: &'a Body, names: &[Seg]) -> Vec<&'a Body> {
    let mut cur: Vec<&'a Body> = vec![body];
    for name in names {
        cur = cur
            .iter()
            .flat_map(|b| b.iter())
            .filter_map(|s| match s {
                Stmt::Block(b) if block_matches(b, name) => Some(&b.body),
                _ => None,
            })
            .collect();
    }
    cur
}

/// Source text of a value, as it would be written in a config file.
pub fn render_node(node: &Node) -> String {
    match &node.value {
        Value::Str(s) => quote(s),
        Value::Word(w) => w.clone(),
        Value::Int(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::List(items) => format!(
            "[{}]",
            items.iter().map(render_node).collect::<Vec<_>>().join(", ")
        ),
        Value::Map(stmts) => format!(
            "{{ {} }}",
            stmts
                .iter()
                .map(|s| match s {
                    Stmt::Directive(d) => format!(
                        "{}: {}",
                        d.key,
                        d.values
                            .iter()
                            .map(render_node)
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                    Stmt::Block(b) => format!("{} {{ … }}", b.name),
                })
                .collect::<Vec<_>>()
                .join("; ")
        ),
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Turn user input into config source: lists, quoted strings, blocks and
/// plain words pass through; anything else (spaces, `#`, …) gets quoted.
pub fn render_value(input: &str) -> String {
    let t = input.trim();
    let plain = !t.is_empty()
        && t.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '_' | '.' | '/' | ':' | '@' | '%' | '+' | '~' | '*' | '-' | '='
                )
        })
        && !t.starts_with("//");
    let wrapped = (t.starts_with('[') && t.ends_with(']'))
        || (t.starts_with('{') && t.ends_with('}'))
        || (t.len() >= 2 && t.starts_with('"') && t.ends_with('"'))
        || (t.len() >= 2 && t.starts_with('\'') && t.ends_with('\''));
    if plain || wrapped {
        t.to_string()
    } else {
        quote(t)
    }
}

/// Set `path` to `value` (raw text, passed through [`render_value`]).
/// Replaces an existing directive in place or inserts it into the nearest
/// existing block, creating missing blocks.
pub fn set(src: &str, path: &[Seg], value: &str) -> Result<String> {
    let (key_seg, parents) = path
        .split_last()
        .ok_or_else(|| Error::msg("empty config path"))?;
    if key_seg.label.is_some() {
        return Err(Error::msg(format!(
            "`{key_seg}`: the last path segment must be a directive, not a labeled block"
        )));
    }
    let key = &key_seg.name;
    let body = parse_str(src, "edit")?;
    let value = render_value(value);
    if value.is_empty() {
        return Err(Error::msg(
            "empty value (use `config unset` to remove a key)",
        ));
    }
    let index = LineIndex::new(src);

    for scope in scopes(&body, parents) {
        for stmt in scope {
            if let Stmt::Directive(d) = stmt {
                if &d.key == key {
                    return replace_value(src, &index, d, &value);
                }
            }
        }
    }

    for depth in (0..=parents.len()).rev() {
        let existing = &parents[..depth];
        let missing = &parents[depth..];
        if depth == 0 {
            return Ok(append_top_level(src, missing, key, &value));
        }
        if let Some(block) = find_block(&body, existing) {
            return insert_into_block(src, &index, block, missing, key, &value);
        }
    }
    unreachable!("depth 0 always returns")
}

/// Remove `path`. `Ok(None)` when it is not present in `src`.
pub fn unset(src: &str, path: &[Seg]) -> Result<Option<String>> {
    let (key_seg, parents) = path
        .split_last()
        .ok_or_else(|| Error::msg("empty config path"))?;
    if key_seg.label.is_some() {
        return Err(Error::msg(format!(
            "`{key_seg}`: the last path segment must be a directive, not a labeled block"
        )));
    }
    let key = &key_seg.name;
    let body = parse_str(src, "edit")?;
    let index = LineIndex::new(src);
    for scope in scopes(&body, parents) {
        for stmt in scope {
            if let Stmt::Directive(d) = stmt {
                if &d.key == key {
                    return Ok(Some(remove_directive(src, &index, d)));
                }
            }
        }
    }
    Ok(None)
}

fn find_block<'a>(body: &'a Body, names: &[Seg]) -> Option<&'a Block> {
    let (last, parents) = names.split_last()?;
    for scope in scopes(body, parents) {
        for stmt in scope {
            if let Stmt::Block(b) = stmt {
                if block_matches(b, last) {
                    return Some(b);
                }
            }
        }
    }
    None
}

struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    fn new(src: &str) -> Self {
        let mut starts = vec![0];
        for (i, b) in src.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        Self { starts }
    }

    fn line_start(&self, line: u32) -> usize {
        self.starts[(line as usize - 1).min(self.starts.len() - 1)]
    }

    /// Byte offset of a 1-based (line, char column).
    fn offset(&self, src: &str, line: u32, col: u32) -> usize {
        let start = self.line_start(line);
        src[start..]
            .char_indices()
            .nth(col as usize - 1)
            .map_or(src.len(), |(i, _)| start + i)
    }

    fn line_of(&self, offset: usize) -> usize {
        self.starts.partition_point(|&s| s <= offset) - 1
    }
}

fn is_ws(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\r' || b == b'\n'
}

/// Offset one past the closing quote of the string opening at `i`.
fn skip_string(b: &[u8], i: usize) -> usize {
    let quote = b[i];
    let mut j = i + 1;
    while j < b.len() {
        if quote == b'"' && b[j] == b'\\' {
            j += 2;
            continue;
        }
        if b[j] == quote {
            return j + 1;
        }
        j += 1;
    }
    b.len()
}

/// A comment starts at `#` or `//` only at the start of a token, so bare
/// words like `http://x` keep their slashes.
fn comment_at(b: &[u8], i: usize) -> bool {
    let token_start = i == 0 || is_ws(b[i - 1]) || matches!(b[i - 1], b'{' | b'}' | b';' | b',');
    token_start && (b[i] == b'#' || (b[i] == b'/' && matches!(b.get(i + 1), Some(b'/' | b'*'))))
}

/// Offset one past the comment starting at `i`.
fn skip_comment(b: &[u8], i: usize) -> usize {
    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
        let mut j = i + 2;
        while j + 1 < b.len() {
            if b[j] == b'*' && b[j + 1] == b'/' {
                return j + 2;
            }
            j += 1;
        }
        return b.len();
    }
    let mut j = i;
    while j < b.len() && b[j] != b'\n' {
        j += 1;
    }
    j
}

/// End (exclusive, trailing blanks trimmed) of the value starting at `from`.
fn value_end(src: &str, from: usize) -> usize {
    let b = src.as_bytes();
    let mut i = from;
    let mut depth = 0usize;
    while i < b.len() {
        match b[i] {
            b'"' | b'\'' => {
                i = skip_string(b, i);
                continue;
            }
            b'[' | b'{' => depth += 1,
            b']' | b'}' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            b'\n' | b';' | b',' if depth == 0 => break,
            b'#' | b'/' if comment_at(b, i) => {
                if depth == 0 {
                    break;
                }
                i = skip_comment(b, i);
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    while i > from && matches!(b[i - 1], b' ' | b'\t' | b'\r') {
        i -= 1;
    }
    i
}

/// Offset just after the `:` that follows the directive key at `key_off`.
fn after_colon(src: &str, key_off: usize, key: &str) -> Result<usize> {
    let b = src.as_bytes();
    let mut i = key_off + key.len();
    while i < b.len() && matches!(b[i], b' ' | b'\t') {
        i += 1;
    }
    if b.get(i) != Some(&b':') {
        return Err(Error::msg(format!(
            "cannot locate `{key}:` in the source — edit the file by hand"
        )));
    }
    Ok(i + 1)
}

fn replace_value(src: &str, index: &LineIndex, d: &Directive, value: &str) -> Result<String> {
    let key_off = index.offset(src, d.span.line, d.span.col);
    let from = after_colon(src, key_off, &d.key)?;
    let end = value_end(src, from);
    let mut out = String::with_capacity(src.len() + value.len());
    out.push_str(&src[..from]);
    out.push(' ');
    out.push_str(value);
    out.push_str(&src[end..]);
    Ok(out)
}

fn remove_directive(src: &str, index: &LineIndex, d: &Directive) -> String {
    let key_off = index.offset(src, d.span.line, d.span.col);
    let from = after_colon(src, key_off, &d.key).unwrap_or(key_off + d.key.len());
    let end = value_end(src, from);
    let b = src.as_bytes();
    let line_start = index.line_start(d.span.line);
    let only_ws_before = src[line_start..key_off]
        .bytes()
        .all(|c| c == b' ' || c == b'\t');
    let mut after = end;
    while after < b.len() && matches!(b[after], b' ' | b'\t' | b'\r') {
        after += 1;
    }
    let rest_blank = after >= b.len() || b[after] == b'\n' || comment_at(b, after);
    if only_ws_before && rest_blank {
        let line_end = src[end..].find('\n').map_or(src.len(), |i| end + i + 1);
        return format!("{}{}", &src[..line_start], &src[line_end..]);
    }
    let mut cut = end;
    if matches!(b.get(after), Some(b';' | b',')) {
        cut = after + 1;
        while cut < b.len() && matches!(b[cut], b' ' | b'\t') {
            cut += 1;
        }
    }
    format!("{}{}", &src[..key_off], &src[cut..])
}

/// Byte offsets of the `{` and matching `}` of `block`.
fn block_braces(src: &str, index: &LineIndex, block: &Block) -> Option<(usize, usize)> {
    let b = src.as_bytes();
    let mut i = index.offset(src, block.span.line, block.span.col);
    while i < b.len() {
        match b[i] {
            b'"' | b'\'' => {
                i = skip_string(b, i);
                continue;
            }
            b'{' => break,
            _ => {}
        }
        i += 1;
    }
    let open = i;
    let mut depth = 0usize;
    while i < b.len() {
        match b[i] {
            b'"' | b'\'' => {
                i = skip_string(b, i);
                continue;
            }
            b'#' | b'/' if comment_at(b, i) => {
                i = skip_comment(b, i);
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, i));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn leading_ws(src: &str, index: &LineIndex, line: u32) -> String {
    src[index.line_start(line)..]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

/// Nested blocks `missing` wrapping `key: value`, indented from `indent`.
fn render_chain(missing: &[Seg], key: &str, value: &str, indent: &str, unit: &str) -> String {
    let mut out = String::new();
    let mut cur = indent.to_string();
    for name in missing {
        let head = match &name.label {
            Some(l) => format!("{} {}", name.name, render_value(l)),
            None => name.name.clone(),
        };
        out.push_str(&format!("{cur}{head} {{\n"));
        cur.push_str(unit);
    }
    out.push_str(&format!("{cur}{key}: {value}\n"));
    for _ in missing {
        cur.truncate(cur.len() - unit.len());
        out.push_str(&format!("{cur}}}\n"));
    }
    out
}

fn append_top_level(src: &str, missing: &[Seg], key: &str, value: &str) -> String {
    let mut out = src.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() && !out.ends_with("\n\n") {
        out.push('\n');
    }
    if missing.is_empty() {
        out.push_str(&format!("{key}: {value}\n"));
    } else {
        out.push_str(&render_chain(missing, key, value, "", "  "));
    }
    out
}

fn insert_into_block(
    src: &str,
    index: &LineIndex,
    block: &Block,
    missing: &[Seg],
    key: &str,
    value: &str,
) -> Result<String> {
    let (open, close) = block_braces(src, index, block)
        .ok_or_else(|| Error::msg(format!("cannot find the end of block `{}`", block.name)))?;
    let block_indent = leading_ws(src, index, block.span.line);
    let unit = if block_indent.contains('\t') {
        "\t"
    } else {
        "  "
    };
    let child_indent = block
        .body
        .first()
        .map(|s| s.span().line)
        .filter(|l| *l != block.span.line)
        .map(|l| leading_ws(src, index, l))
        .unwrap_or_else(|| format!("{block_indent}{unit}"));
    let text = if missing.is_empty() {
        format!("{child_indent}{key}: {value}\n")
    } else {
        render_chain(missing, key, value, &child_indent, unit)
    };

    let close_line = index.line_of(close);
    let close_line_start = index.starts[close_line];
    let own_line = src[close_line_start..close]
        .bytes()
        .all(|c| c == b' ' || c == b'\t');
    if own_line && index.line_of(open) != close_line {
        return Ok(format!(
            "{}{}{}",
            &src[..close_line_start],
            text,
            &src[close_line_start..]
        ));
    }
    let inner = src[open + 1..close].trim();
    let mut rebuilt = String::from("\n");
    if !inner.is_empty() {
        rebuilt.push_str(&format!("{child_indent}{inner}\n"));
    }
    rebuilt.push_str(&text);
    rebuilt.push_str(&block_indent);
    Ok(format!("{}{}{}", &src[..open + 1], rebuilt, &src[close..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Vec<Seg> {
        split_path(s).unwrap()
    }

    #[test]
    fn replaces_value_in_place_keeping_comments() {
        let src = "# top\nhttp {\n  compress {\n    enabled: on  # keep me\n    level: 3\n  }\n}\n";
        let out = set(src, &p("http.compress.enabled"), "off").unwrap();
        assert_eq!(
            out,
            "# top\nhttp {\n  compress {\n    enabled: off  # keep me\n    level: 3\n  }\n}\n"
        );
    }

    #[test]
    fn replaces_one_liner_block_value() {
        let src = "detect { scan { enabled: on; min: 8 } }\n";
        let out = set(src, &p("detect.scan.min"), "12").unwrap();
        assert_eq!(out, "detect { scan { enabled: on; min: 12 } }\n");
    }

    #[test]
    fn replaces_multiline_list() {
        let src = "trust {\n  proxies: [\n    10.0.0.0/8,\n    \"x\"\n  ]\n  other: 1\n}\n";
        let out = set(src, &p("trust.proxies"), "[192.168.0.0/16]").unwrap();
        assert_eq!(out, "trust {\n  proxies: [192.168.0.0/16]\n  other: 1\n}\n");
    }

    #[test]
    fn inserts_into_existing_block_with_matching_indent() {
        let src = "http {\n  # tuning\n  http2: on\n}\n";
        let out = set(src, &p("http.max_fails"), "5").unwrap();
        assert_eq!(out, "http {\n  # tuning\n  http2: on\n  max_fails: 5\n}\n");
    }

    #[test]
    fn expands_one_liner_block_on_insert() {
        let src = "metrics { enabled: on }\nsentry { mode: passive }\n";
        let out = set(src, &p("metrics.port"), "9100").unwrap();
        assert_eq!(
            out,
            "metrics {\n  enabled: on\n  port: 9100\n}\nsentry { mode: passive }\n"
        );
        crate::parser::parse_str(&out, "t").unwrap();
    }

    #[test]
    fn creates_missing_blocks() {
        let src = "sentry { mode: passive }\n";
        let out = set(src, &p("http.compress.enabled"), "off").unwrap();
        assert_eq!(
            out,
            "sentry { mode: passive }\n\nhttp {\n  compress {\n    enabled: off\n  }\n}\n"
        );
        let nested = set("http {\n  x: 1\n}\n", &p("http.compress.level"), "3").unwrap();
        assert_eq!(
            nested,
            "http {\n  x: 1\n  compress {\n    level: 3\n  }\n}\n"
        );
        crate::parser::parse_str(&nested, "t").unwrap();
    }

    #[test]
    fn top_level_directive_appended() {
        let out = set("a: 1\n", &p("b"), "two words").unwrap();
        assert_eq!(out, "a: 1\n\nb: \"two words\"\n");
    }

    #[test]
    fn braces_in_comments_and_strings_do_not_confuse_block_end() {
        let src = "http {\n  # a } stray\n  path: \"/x{y}\"\n}\nafter: 1\n";
        let out = set(src, &p("http.n"), "1").unwrap();
        assert_eq!(
            out,
            "http {\n  # a } stray\n  path: \"/x{y}\"\n  n: 1\n}\nafter: 1\n"
        );
    }

    #[test]
    fn url_values_keep_double_slash() {
        let src = "http { proxy_pass: http://127.0.0.1:8080 }\n";
        let out = set(src, &p("http.proxy_pass"), "http://app:3000").unwrap();
        assert_eq!(out, "http { proxy_pass: http://app:3000 }\n");
    }

    #[test]
    fn unset_removes_whole_line_or_inline_directive() {
        let src = "http {\n  a: 1\n  b: 2  # c\n}\n";
        assert_eq!(
            unset(src, &p("http.b")).unwrap().unwrap(),
            "http {\n  a: 1\n}\n"
        );
        let inline = "d { a: 1; b: 2 }\n";
        let out = unset(inline, &p("d.a")).unwrap().unwrap();
        crate::parser::parse_str(&out, "t").unwrap();
        assert!(!out.contains("a:"));
        assert!(unset(src, &p("http.zzz")).unwrap().is_none());
    }

    #[test]
    fn render_value_quotes_only_when_needed() {
        assert_eq!(render_value("24h"), "24h");
        assert_eq!(render_value("0.0.0.0:80"), "0.0.0.0:80");
        assert_eq!(render_value("a b"), "\"a b\"");
        assert_eq!(render_value("[a, b]"), "[a, b]");
        assert_eq!(render_value("\"q\""), "\"q\"");
        assert_eq!(render_value("x#y"), "\"x#y\"");
    }

    #[test]
    fn lookup_finds_directives_and_blocks() {
        let body = parse_str("http {\n  a: [1, 2]\n  c { d: x }\n}\n", "t").unwrap();
        let Some(Lookup::Directive(d)) = lookup(&body, &p("http.a")) else {
            panic!()
        };
        assert_eq!(render_node(&d.values[0]), "[1, 2]");
        let Some(Lookup::Block(names)) = lookup(&body, &p("http.c")) else {
            panic!()
        };
        assert_eq!(names, ["d"]);
        assert!(lookup(&body, &p("http.zz")).is_none());
    }

    #[test]
    fn labeled_blocks_are_addressable() {
        let src = "rules {
  pack sensitive_paths { mode: shadow }
  pack tor { mode: off }
}
";
        let path = p("rules.pack[tor].mode");
        assert_eq!(path[1].label.as_deref(), Some("tor"));
        let out = set(src, &path, "enforce").unwrap();
        assert!(out.contains("pack tor { mode: enforce }"), "{out}");
        assert!(
            out.contains("pack sensitive_paths { mode: shadow }"),
            "{out}"
        );

        let created = set(
            "rules {
}
",
            &p("rules.pack[tor].mode"),
            "off",
        )
        .unwrap();
        assert_eq!(
            created,
            "rules {
  pack tor {
    mode: off
  }
}
"
        );
        crate::parser::parse_str(&created, "t").unwrap();

        let dotted = p("site[example.com].proxy_pass");
        assert_eq!(dotted.len(), 2);
        assert_eq!(dotted[0].label.as_deref(), Some("example.com"));
    }

    #[test]
    fn rejects_bad_paths() {
        assert!(split_path("a[b").is_err());
        assert!(split_path("a[]").is_err());
        assert!(split_path("a[x]y").is_err());
        assert!(split_path("a..b").is_err());
        assert!(split_path("").is_err());
    }
}
