//! Emitter: any `Serialize` value → configuration text.
//!
//! Structs/maps become blocks, a field named [`LABELS_KEY`] becomes the
//! block labels, lists of structs become repeated blocks, lists of tuples
//! become repeated multi-value directives. [`to_string_diff`] drops every
//! entry equal to a reference value (defaults), so generated files only
//! carry what differs.

use serde::ser::{self, Serialize};

use crate::de::LABELS_KEY;
use crate::error::{Error, Result};

/// Intermediate ordered tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Tree {
    /// `None` / unit — never printed.
    Null,
    /// Boolean (`on`/`off`).
    Bool(bool),
    /// Signed integer.
    Int(i64),
    /// Unsigned integer.
    UInt(u64),
    /// Float.
    Float(f64),
    /// String.
    Str(String),
    /// Sequence.
    Seq(Vec<Tree>),
    /// Map in field order.
    Map(Vec<(String, Tree)>),
}

/// Serialize into the intermediate tree.
pub fn to_tree<T: Serialize + ?Sized>(value: &T) -> Result<Tree> {
    value.serialize(TreeSer)
}

/// Render a value (must serialize to a map) as configuration text.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    render(&to_tree(value)?)
}

/// Render only the entries that differ from `reference` (e.g. defaults).
pub fn to_string_diff<T: Serialize>(value: &T, reference: &T) -> Result<String> {
    let mut tree = to_tree(value)?;
    let base = to_tree(reference)?;
    prune(&mut tree, &base);
    render(&tree)
}

/// Remove map entries equal to the same entry in `base` (recursively).
pub fn prune(tree: &mut Tree, base: &Tree) {
    if let (Tree::Map(entries), Tree::Map(base_entries)) = (tree, base) {
        entries.retain_mut(|(k, v)| {
            if k == LABELS_KEY {
                return true;
            }
            match base_entries.iter().find(|(bk, _)| bk == k) {
                Some((_, bv)) if bv == v => false,
                Some((_, bv)) => {
                    if matches!(v, Tree::Map(_)) {
                        prune(v, bv);
                        !matches!(v, Tree::Map(m) if m.is_empty())
                    } else {
                        true
                    }
                }
                None => true,
            }
        });
    }
}

/// Render a tree as configuration text.
pub fn render(tree: &Tree) -> Result<String> {
    let Tree::Map(entries) = tree else {
        return Err(Error::msg("top-level value must be a map/struct"));
    };
    let mut out = String::new();
    write_body(&mut out, entries, 0, true);
    Ok(out)
}

fn is_empty(t: &Tree) -> bool {
    match t {
        Tree::Null => true,
        Tree::Seq(items) => items.is_empty(),
        Tree::Map(m) => m.iter().all(|(k, v)| k != LABELS_KEY && is_empty(v)),
        _ => false,
    }
}

fn labels_of(entries: &[(String, Tree)]) -> Vec<String> {
    entries
        .iter()
        .find(|(k, _)| k == LABELS_KEY)
        .map(|(_, v)| match v {
            Tree::Seq(items) => items.iter().filter_map(scalar_text).collect(),
            other => scalar_text(other).into_iter().collect(),
        })
        .unwrap_or_default()
}

fn write_body(out: &mut String, entries: &[(String, Tree)], depth: usize, top: bool) {
    let pad = "    ".repeat(depth);
    let mut last_was_block = false;
    for (key, value) in entries {
        if key == LABELS_KEY
            || is_empty(value) && !matches!(value, Tree::Map(m) if !labels_of(m).is_empty())
        {
            continue;
        }
        match value {
            Tree::Map(m) => {
                if top && !out.is_empty() {
                    out.push('\n');
                }
                write_block(out, key, m, depth);
                last_was_block = true;
            }
            Tree::Seq(items) if items.iter().all(|i| matches!(i, Tree::Map(_))) => {
                for item in items {
                    if let Tree::Map(m) = item {
                        if top && !out.is_empty() {
                            out.push('\n');
                        }
                        write_block(out, key, m, depth);
                    }
                }
                last_was_block = true;
            }
            Tree::Seq(items) if items.iter().all(|i| matches!(i, Tree::Seq(_))) => {
                for item in items {
                    if let Tree::Seq(parts) = item {
                        let rendered: Vec<String> = parts.iter().map(value_text).collect();
                        out.push_str(&format!("{pad}{}: {}\n", key_text(key), rendered.join(" ")));
                    }
                }
            }
            _ => {
                if top && last_was_block {
                    out.push('\n');
                }
                out.push_str(&format!("{pad}{}: {}\n", key_text(key), value_text(value)));
                last_was_block = false;
            }
        }
    }
}

fn write_block(out: &mut String, key: &str, entries: &[(String, Tree)], depth: usize) {
    let pad = "    ".repeat(depth);
    let labels: Vec<String> = labels_of(entries).iter().map(|l| label_text(l)).collect();
    let head = if labels.is_empty() {
        key_text(key)
    } else {
        format!("{} {}", key_text(key), labels.join(" "))
    };
    let has_body = entries.iter().any(|(k, v)| k != LABELS_KEY && !is_empty(v));
    if !has_body {
        out.push_str(&format!("{pad}{head} {{}}\n"));
        return;
    }
    if let Some(inline) = inline_body(entries) {
        let line = format!("{pad}{head} {{ {inline} }}");
        if line.chars().count() <= 88 {
            out.push_str(&line);
            out.push('\n');
            return;
        }
    }
    out.push_str(&format!("{pad}{head} {{\n"));
    write_body(out, entries, depth + 1, false);
    out.push_str(&format!("{pad}}}\n"));
}

/// `k: v, k: v` for small blocks of plain values (≤ 3 entries, no nested
/// blocks, no repeated directives) — rendered on the block's own line.
fn inline_body(entries: &[(String, Tree)]) -> Option<String> {
    let live: Vec<&(String, Tree)> = entries
        .iter()
        .filter(|(k, v)| k != LABELS_KEY && !is_empty(v))
        .collect();
    if live.is_empty() || live.len() > 3 {
        return None;
    }
    let mut parts = Vec::with_capacity(live.len());
    for (k, v) in live {
        let plain = match v {
            Tree::Map(_) => false,
            Tree::Seq(items) => items.iter().all(|i| scalar_text(i).is_some()),
            _ => true,
        };
        if !plain {
            return None;
        }
        parts.push(format!("{}: {}", key_text(k), value_text(v)));
    }
    Some(parts.join(", "))
}

fn scalar_text(t: &Tree) -> Option<String> {
    match t {
        Tree::Str(s) => Some(s.clone()),
        Tree::Int(i) => Some(i.to_string()),
        Tree::UInt(u) => Some(u.to_string()),
        Tree::Float(f) => Some(f.to_string()),
        Tree::Bool(b) => Some(if *b { "on" } else { "off" }.to_string()),
        _ => None,
    }
}

/// True when `s` survives as an unquoted word.
fn is_bare(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('#')
        && !s.starts_with("//")
        && !s.starts_with("/*")
        && !s.ends_with(':')
        && !s.contains(": ")
        && s.chars().all(|c| {
            !c.is_whitespace() && !matches!(c, '{' | '}' | '[' | ']' | ';' | ',' | '"' | '\'')
        })
}

fn quote(s: &str) -> String {
    if !s.contains('\'')
        && !s.contains('\n')
        && (s.contains('\\') || s.contains('$') || s.contains('"'))
    {
        return format!("'{s}'");
    }
    let mut q = String::with_capacity(s.len() + 2);
    q.push('"');
    for c in s.chars() {
        match c {
            '"' => q.push_str("\\\""),
            '\\' => q.push_str("\\\\"),
            '$' => q.push_str("\\$"),
            '\n' => q.push_str("\\n"),
            '\t' => q.push_str("\\t"),
            c => q.push(c),
        }
    }
    q.push('"');
    q
}

fn key_text(k: &str) -> String {
    if is_bare(k) && !k.contains(':') && !k.contains('/') {
        k.to_string()
    } else {
        quote(k)
    }
}

fn label_text(l: &str) -> String {
    if is_bare(l) {
        l.to_string()
    } else {
        quote(l)
    }
}

fn str_text(s: &str) -> String {
    let numeric_looking = s.parse::<f64>().is_ok();
    if is_bare(s) && !numeric_looking && s != "true" && s != "false" {
        s.to_string()
    } else {
        quote(s)
    }
}

fn value_text(t: &Tree) -> String {
    match t {
        Tree::Str(s) => str_text(s),
        Tree::Seq(items) => {
            let parts: Vec<String> = items.iter().map(value_text).collect();
            format!("[{}]", parts.join(", "))
        }
        Tree::Map(entries) => {
            let parts: Vec<String> = entries
                .iter()
                .filter(|(_, v)| !is_empty(v))
                .map(|(k, v)| format!("{}: {}", key_text(k), value_text(v)))
                .collect();
            format!("{{ {} }}", parts.join(", "))
        }
        Tree::Null => String::new(),
        other => scalar_text(other).unwrap_or_default(),
    }
}

struct TreeSer;

impl ser::Serializer for TreeSer {
    type Ok = Tree;
    type Error = Error;
    type SerializeSeq = SeqSer;
    type SerializeTuple = SeqSer;
    type SerializeTupleStruct = SeqSer;
    type SerializeTupleVariant = SeqSer;
    type SerializeMap = MapSer;
    type SerializeStruct = MapSer;
    type SerializeStructVariant = MapSer;

    fn serialize_bool(self, v: bool) -> Result<Tree> {
        Ok(Tree::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<Tree> {
        Ok(Tree::Int(v.into()))
    }
    fn serialize_i16(self, v: i16) -> Result<Tree> {
        Ok(Tree::Int(v.into()))
    }
    fn serialize_i32(self, v: i32) -> Result<Tree> {
        Ok(Tree::Int(v.into()))
    }
    fn serialize_i64(self, v: i64) -> Result<Tree> {
        Ok(Tree::Int(v))
    }
    fn serialize_u8(self, v: u8) -> Result<Tree> {
        Ok(Tree::UInt(v.into()))
    }
    fn serialize_u16(self, v: u16) -> Result<Tree> {
        Ok(Tree::UInt(v.into()))
    }
    fn serialize_u32(self, v: u32) -> Result<Tree> {
        Ok(Tree::UInt(v.into()))
    }
    fn serialize_u64(self, v: u64) -> Result<Tree> {
        Ok(Tree::UInt(v))
    }
    fn serialize_f32(self, v: f32) -> Result<Tree> {
        Ok(Tree::Float(v.into()))
    }
    fn serialize_f64(self, v: f64) -> Result<Tree> {
        Ok(Tree::Float(v))
    }
    fn serialize_char(self, v: char) -> Result<Tree> {
        Ok(Tree::Str(v.to_string()))
    }
    fn serialize_str(self, v: &str) -> Result<Tree> {
        Ok(Tree::Str(v.to_string()))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<Tree> {
        Ok(Tree::Str(String::from_utf8_lossy(v).to_string()))
    }
    fn serialize_none(self) -> Result<Tree> {
        Ok(Tree::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Tree> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<Tree> {
        Ok(Tree::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<Tree> {
        Ok(Tree::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<Tree> {
        Ok(Tree::Str(variant.to_string()))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Tree> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Tree> {
        Ok(Tree::Map(vec![(
            variant.to_string(),
            value.serialize(TreeSer)?,
        )]))
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<SeqSer> {
        Ok(SeqSer(Vec::new()))
    }
    fn serialize_tuple(self, _len: usize) -> Result<SeqSer> {
        Ok(SeqSer(Vec::new()))
    }
    fn serialize_tuple_struct(self, _name: &'static str, _len: usize) -> Result<SeqSer> {
        Ok(SeqSer(Vec::new()))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<SeqSer> {
        Ok(SeqSer(Vec::new()))
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<MapSer> {
        Ok(MapSer {
            entries: Vec::new(),
            key: None,
        })
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<MapSer> {
        self.serialize_map(None)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<MapSer> {
        self.serialize_map(None)
    }
}

struct SeqSer(Vec<Tree>);

impl ser::SerializeSeq for SeqSer {
    type Ok = Tree;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        self.0.push(value.serialize(TreeSer)?);
        Ok(())
    }
    fn end(self) -> Result<Tree> {
        Ok(Tree::Seq(self.0))
    }
}

impl ser::SerializeTuple for SeqSer {
    type Ok = Tree;
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Tree> {
        ser::SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleStruct for SeqSer {
    type Ok = Tree;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Tree> {
        ser::SerializeSeq::end(self)
    }
}

impl ser::SerializeTupleVariant for SeqSer {
    type Ok = Tree;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        ser::SerializeSeq::serialize_element(self, value)
    }
    fn end(self) -> Result<Tree> {
        ser::SerializeSeq::end(self)
    }
}

struct MapSer {
    entries: Vec<(String, Tree)>,
    key: Option<String>,
}

impl ser::SerializeMap for MapSer {
    type Ok = Tree;
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<()> {
        let k = match key.serialize(TreeSer)? {
            Tree::Str(s) => s,
            other => scalar_text(&other).ok_or_else(|| Error::msg("map keys must be scalars"))?,
        };
        self.key = Some(k);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<()> {
        let k = self
            .key
            .take()
            .ok_or_else(|| Error::msg("value without key"))?;
        self.entries.push((k, value.serialize(TreeSer)?));
        Ok(())
    }
    fn end(self) -> Result<Tree> {
        Ok(Tree::Map(self.entries))
    }
}

impl ser::SerializeStruct for MapSer {
    type Ok = Tree;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        self.entries
            .push((key.to_string(), value.serialize(TreeSer)?));
        Ok(())
    }
    fn end(self) -> Result<Tree> {
        Ok(Tree::Map(self.entries))
    }
}

impl ser::SerializeStructVariant for MapSer {
    type Ok = Tree;
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<()> {
        ser::SerializeStruct::serialize_field(self, key, value)
    }
    fn end(self) -> Result<Tree> {
        Ok(Tree::Map(self.entries))
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Default, Clone)]
    #[serde(default, deny_unknown_fields)]
    struct Up {
        #[serde(rename = "$labels")]
        labels: Vec<String>,
        server: Vec<String>,
        balance: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Default, Clone)]
    #[serde(default, deny_unknown_fields)]
    struct Http {
        listen: String,
        enabled: bool,
        upstream: Vec<Up>,
        rewrite: Vec<(String, String)>,
        format: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Default, Clone)]
    #[serde(default, deny_unknown_fields)]
    struct Root {
        http: Http,
        tags: Vec<String>,
    }

    #[test]
    fn round_trips_through_text() {
        let root = Root {
            http: Http {
                listen: "0.0.0.0:80".into(),
                enabled: true,
                upstream: vec![Up {
                    labels: vec!["app".into()],
                    server: vec!["http://a:1".into(), "http://b:1".into()],
                    balance: "least_conn".into(),
                }],
                rewrite: vec![("^/a(.*)$".into(), "/b$1".into())],
                format: "$remote_addr - [$time_local] \"$request\"".into(),
            },
            tags: vec!["x y".into()],
        };
        let text = to_string(&root).unwrap();
        assert!(text.contains("upstream app {"), "{text}");
        assert!(text.contains("listen: 0.0.0.0:80"), "{text}");
        let back: Root =
            crate::de::from_body(&crate::parser::parse_str(&text, "x").unwrap()).unwrap();
        assert_eq!(back, root, "{text}");
    }

    #[test]
    fn diff_only_prints_changes() {
        let base = Root::default();
        let mut changed = base.clone();
        changed.http.listen = "0.0.0.0:8080".into();
        let text = to_string_diff(&changed, &base).unwrap();
        assert_eq!(text, "http { listen: 0.0.0.0:8080 }\n");
    }
}
