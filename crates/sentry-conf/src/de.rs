//! serde `Deserializer` over the syntax tree.
//!
//! Mapping rules:
//! - a body (file, block, inline `{ … }`) is a map keyed by statement name;
//! - a directive with one value is that value, with several values a list;
//! - a statement repeated in the same body (or across merged files) is a
//!   list of its occurrences — `Vec` fields accept a single value, a `[…]`
//!   list and repeated directives alike;
//! - repeated *unlabeled* blocks requested as a struct/map are merged
//!   (`detect {}` split across `sentry.conf` and `detect.conf`); a scalar
//!   given twice is an error naming both positions;
//! - block labels are exposed under the synthetic key [`LABELS_KEY`].
//!
//! Every error is stamped with the position and the block path it came
//! from.

use serde::de::{
    self, DeserializeOwned, DeserializeSeed, IntoDeserializer, MapAccess, SeqAccess, Visitor,
};

use crate::ast::{Block, Body, Node, Span, Stmt, Value};
use crate::error::{Error, Result};

/// Synthetic key carrying a block's labels (`location ~ "^/x" {}` →
/// `["~", "^/x"]`). Schema structs read it with
/// `#[serde(rename = "$labels", default)]`.
pub const LABELS_KEY: &str = "$labels";

/// Deserialize a whole body (a parsed file set).
pub fn from_body<T: DeserializeOwned>(body: &Body) -> Result<T> {
    T::deserialize(BodyDe::new(vec![body], None))
}

/// Deserialize a single value node.
pub fn from_node<T: DeserializeOwned>(node: &Node) -> Result<T> {
    T::deserialize(NodeDe(node))
}

#[derive(Clone, Copy)]
enum Item<'a> {
    Directive(&'a [Node], &'a Span),
    Block(&'a Block),
    Labels(&'a [Node], &'a Span),
}

impl<'a> Item<'a> {
    fn span(&self) -> &'a Span {
        match self {
            Item::Directive(_, s) | Item::Labels(_, s) => s,
            Item::Block(b) => &b.span,
        }
    }
}

/// Path segment for errors: block name plus its first label.
fn segment(key: &str, item: &Item<'_>) -> String {
    match item {
        Item::Block(b) => match b.labels.iter().filter_map(Node::as_text).next_back() {
            Some(label) => format!("{key} {label}"),
            None => key.to_string(),
        },
        _ => key.to_string(),
    }
}

struct BodyDe<'a> {
    entries: Vec<(&'a str, Vec<Item<'a>>)>,
    idx: usize,
}

impl<'a> BodyDe<'a> {
    fn new(bodies: Vec<&'a Body>, labels: Option<(&'a [Node], &'a Span)>) -> Self {
        let mut entries: Vec<(&'a str, Vec<Item<'a>>)> = Vec::new();
        if let Some((labels, span)) = labels {
            if !labels.is_empty() {
                entries.push((LABELS_KEY, vec![Item::Labels(labels, span)]));
            }
        }
        for body in bodies {
            for stmt in body {
                let (name, item) = match stmt {
                    Stmt::Directive(d) => (d.key.as_str(), Item::Directive(&d.values, &d.span)),
                    Stmt::Block(b) => (b.name.as_str(), Item::Block(b)),
                };
                match entries.iter_mut().find(|(k, _)| *k == name) {
                    Some((_, items)) => items.push(item),
                    None => entries.push((name, vec![item])),
                }
            }
        }
        Self { entries, idx: 0 }
    }
}

impl<'de, 'a> de::Deserializer<'de> for BodyDe<'a> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_map(self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

impl<'de, 'a> MapAccess<'de> for BodyDe<'a> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(&mut self, seed: K) -> Result<Option<K::Value>> {
        let Some((key, items)) = self.entries.get(self.idx) else {
            return Ok(None);
        };
        let span = items[0].span();
        seed.deserialize(key.into_deserializer())
            .map(Some)
            .map_err(|e: Error| e.or_span(span))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value> {
        let (key, items) = self.entries[self.idx].clone();
        self.idx += 1;
        let first = items[0];
        let seg = segment(key, &first);
        seed.deserialize(ItemsDe { key, items })
            .map_err(|e| e.or_span(first.span()).within(&seg))
    }
}

/// All occurrences of one key inside a body.
struct ItemsDe<'a> {
    key: &'a str,
    items: Vec<Item<'a>>,
}

impl<'a> ItemsDe<'a> {
    fn single(self) -> Result<ItemDe<'a>> {
        if self.items.len() > 1 {
            let positions: Vec<String> = self.items.iter().map(|i| i.span().to_string()).collect();
            return Err(Error::at(
                self.items[1].span(),
                format!(
                    "`{}` is given {} times ({}) but takes a single value",
                    self.key,
                    self.items.len(),
                    positions.join(", ")
                ),
            ));
        }
        Ok(ItemDe {
            key: self.key,
            item: self.items[0],
            inner: false,
        })
    }
}

macro_rules! single_forward {
    ($($method:ident),*) => {
        $(
            fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
                self.single()?.$method(visitor)
            }
        )*
    };
}

impl<'de, 'a> de::Deserializer<'de> for ItemsDe<'a> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.items.len() == 1 {
            return self.single()?.deserialize_any(visitor);
        }
        let key = self.key;
        visitor.visit_seq(ItemSeq {
            key,
            iter: self.items.into_iter(),
        })
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.items.len() == 1 {
            return self.single()?.deserialize_seq(visitor);
        }
        let key = self.key;
        visitor.visit_seq(ItemSeq {
            key,
            iter: self.items.into_iter(),
        })
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, len: usize, visitor: V) -> Result<V::Value> {
        self.single()?.deserialize_tuple(len, visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.single()?.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        if self.items.len() == 1 {
            return self.single()?.deserialize_map(visitor);
        }
        let mergeable = self
            .items
            .iter()
            .all(|i| matches!(i, Item::Block(b) if b.labels.is_empty()));
        if !mergeable {
            return self.single()?.deserialize_map(visitor);
        }
        let bodies: Vec<&'a Body> = self
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Block(b) => Some(&b.body),
                _ => None,
            })
            .collect();
        visitor.visit_map(BodyDe::new(bodies, None))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_map(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_some(self)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.single()?.deserialize_enum(name, variants, visitor)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_unit()
    }

    single_forward!(
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_unit,
        deserialize_identifier
    );
}

struct ItemSeq<'a> {
    key: &'a str,
    iter: std::vec::IntoIter<Item<'a>>,
}

impl<'de, 'a> SeqAccess<'de> for ItemSeq<'a> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        match self.iter.next() {
            None => Ok(None),
            Some(item) => seed
                .deserialize(ItemDe {
                    key: self.key,
                    item,
                    inner: false,
                })
                .map(Some)
                .map_err(|e| e.or_span(item.span())),
        }
    }
}

/// One occurrence of a key.
struct ItemDe<'a> {
    key: &'a str,
    item: Item<'a>,
    /// Element of the one-occurrence wrapper seq: a multi-value directive is
    /// read as its own values (no further wrapping).
    inner: bool,
}

impl<'a> ItemDe<'a> {
    fn scalar(self) -> Result<NodeDe<'a>> {
        match self.item {
            Item::Directive(values, span) => {
                if values.len() == 1 {
                    Ok(NodeDe(&values[0]))
                } else {
                    Err(Error::at(
                        span,
                        format!(
                            "`{}` takes a single value, found {}",
                            self.key,
                            values.len()
                        ),
                    ))
                }
            }
            Item::Block(b) => Err(Error::at(
                &b.span,
                format!(
                    "`{}` is a value, not a block — write `{}: …`",
                    self.key, self.key
                ),
            )),
            Item::Labels(_, span) => Err(Error::at(span, "unexpected block label")),
        }
    }
}

macro_rules! scalar_forward {
    ($($method:ident),*) => {
        $(
            fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
                self.scalar()?.$method(visitor)
            }
        )*
    };
}

impl<'de, 'a> de::Deserializer<'de> for ItemDe<'a> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.item {
            Item::Directive(values, _) if values.len() == 1 => {
                NodeDe(&values[0]).deserialize_any(visitor)
            }
            Item::Directive(values, _) | Item::Labels(values, _) => {
                visitor.visit_seq(NodeSeq(values.iter()))
            }
            Item::Block(b) => {
                visitor.visit_map(BodyDe::new(vec![&b.body], Some((&b.labels, &b.span))))
            }
        }
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.item {
            Item::Directive(values, _) if values.len() == 1 => {
                NodeDe(&values[0]).deserialize_seq(visitor)
            }
            // One multi-value directive read as a list of occurrences: the
            // element is the whole directive (`rewrite: a b` → [(a, b)]).
            Item::Directive(_, _) if !self.inner => visitor.visit_seq(WrapSeq(Some(ItemDe {
                key: self.key,
                item: self.item,
                inner: true,
            }))),
            Item::Directive(values, _) | Item::Labels(values, _) => {
                visitor.visit_seq(NodeSeq(values.iter()))
            }
            Item::Block(_) => {
                let key = self.key;
                visitor.visit_seq(ItemSeq {
                    key,
                    iter: vec![self.item].into_iter(),
                })
            }
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        match self.item {
            Item::Directive(values, _) | Item::Labels(values, _) => {
                visitor.visit_seq(NodeSeq(values.iter()))
            }
            _ => self.deserialize_seq(visitor),
        }
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match self.item {
            Item::Block(b) => {
                visitor.visit_map(BodyDe::new(vec![&b.body], Some((&b.labels, &b.span))))
            }
            Item::Directive(values, span) => match values {
                [node] => NodeDe(node).deserialize_map(visitor),
                _ => Err(Error::at(
                    span,
                    format!("`{}` expects a block `{{ … }}`", self.key),
                )),
            },
            Item::Labels(_, span) => Err(Error::at(span, "unexpected block label")),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_map(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_some(self)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.scalar()?.deserialize_enum(name, variants, visitor)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_unit()
    }

    scalar_forward!(
        deserialize_bool,
        deserialize_i8,
        deserialize_i16,
        deserialize_i32,
        deserialize_i64,
        deserialize_u8,
        deserialize_u16,
        deserialize_u32,
        deserialize_u64,
        deserialize_f32,
        deserialize_f64,
        deserialize_char,
        deserialize_str,
        deserialize_string,
        deserialize_bytes,
        deserialize_byte_buf,
        deserialize_unit,
        deserialize_identifier
    );
}

struct WrapSeq<'a>(Option<ItemDe<'a>>);

impl<'de, 'a> SeqAccess<'de> for WrapSeq<'a> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        match self.0.take() {
            None => Ok(None),
            Some(item) => seed.deserialize(item).map(Some),
        }
    }
}

struct NodeSeq<'a>(std::slice::Iter<'a, Node>);

impl<'de, 'a> SeqAccess<'de> for NodeSeq<'a> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<Option<T::Value>> {
        match self.0.next() {
            None => Ok(None),
            Some(n) => seed
                .deserialize(NodeDe(n))
                .map(Some)
                .map_err(|e| e.or_span(&n.span)),
        }
    }
}

/// Words accepted as booleans.
pub fn parse_bool_word(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "on" | "yes" | "enabled" => Some(true),
        "false" | "off" | "no" | "disabled" => Some(false),
        _ => None,
    }
}

/// One value node.
struct NodeDe<'a>(&'a Node);

impl<'a> NodeDe<'a> {
    fn text(&self) -> Option<String> {
        self.0.as_text()
    }

    fn invalid(&self, expected: &str) -> Error {
        let shown = match &self.0.value {
            Value::Str(s) => format!("\"{s}\""),
            Value::Word(s) => format!("`{s}`"),
            Value::Int(i) => i.to_string(),
            Value::Float(f) => f.to_string(),
            Value::List(_) => "a list".to_string(),
            Value::Map(_) => "a block".to_string(),
        };
        Error::at(&self.0.span, format!("expected {expected}, found {shown}"))
    }

    fn integer(&self) -> Result<i64> {
        match &self.0.value {
            Value::Int(i) => Ok(*i),
            Value::Str(s) | Value::Word(s) => s
                .trim()
                .replace('_', "")
                .parse::<i64>()
                .map_err(|_| self.invalid("an integer")),
            _ => Err(self.invalid("an integer")),
        }
    }
}

impl<'de, 'a> de::Deserializer<'de> for NodeDe<'a> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let span = &self.0.span;
        match &self.0.value {
            Value::Str(s) => visitor.visit_str(s),
            Value::Word(w) => match w.as_str() {
                "true" => visitor.visit_bool(true),
                "false" => visitor.visit_bool(false),
                _ => visitor.visit_str(w),
            },
            Value::Int(i) => visitor.visit_i64(*i),
            Value::Float(f) => visitor.visit_f64(*f),
            Value::List(items) => visitor.visit_seq(NodeSeq(items.iter())),
            Value::Map(body) => visitor.visit_map(BodyDe::new(vec![body], None)),
        }
        .map_err(|e| e.or_span(span))
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let b = match &self.0.value {
            Value::Str(s) | Value::Word(s) => parse_bool_word(s),
            Value::Int(0) => Some(false),
            Value::Int(1) => Some(true),
            _ => None,
        }
        .ok_or_else(|| self.invalid("on/off (true/false, yes/no)"))?;
        visitor.visit_bool(b)
    }

    fn deserialize_i8<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_i64(v)
    }
    fn deserialize_i16<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_i64(v)
    }
    fn deserialize_i32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_i64(v)
    }
    fn deserialize_i64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let span = self.0.span.clone();
        visitor
            .visit_i64(self.integer()?)
            .map_err(|e: Error| e.or_span(&span))
    }
    fn deserialize_u8<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_u64(v)
    }
    fn deserialize_u16<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_u64(v)
    }
    fn deserialize_u32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_u64(v)
    }
    fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let i = self.integer()?;
        if i < 0 {
            return Err(self.invalid("a non-negative integer"));
        }
        let span = self.0.span.clone();
        visitor
            .visit_u64(i as u64)
            .map_err(|e: Error| e.or_span(&span))
    }

    fn deserialize_f32<V: Visitor<'de>>(self, v: V) -> Result<V::Value> {
        self.deserialize_f64(v)
    }
    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let f = match &self.0.value {
            Value::Float(f) => *f,
            Value::Int(i) => *i as f64,
            Value::Str(s) | Value::Word(s) => s
                .trim()
                .parse::<f64>()
                .map_err(|_| self.invalid("a number"))?,
            _ => return Err(self.invalid("a number")),
        };
        visitor.visit_f64(f)
    }

    fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        let text = self.text().ok_or_else(|| self.invalid("a single value"))?;
        let span = self.0.span.clone();
        visitor
            .visit_string(text)
            .map_err(|e: Error| e.or_span(&span))
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_some(self)
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match &self.0.value {
            Value::List(items) => visitor.visit_seq(NodeSeq(items.iter())),
            _ => visitor.visit_seq(NodeSeq(std::slice::from_ref(self.0).iter())),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        match &self.0.value {
            Value::Map(body) => visitor.visit_map(BodyDe::new(vec![body], None)),
            _ => Err(self.invalid("a block `{ … }`")),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value> {
        let text = self.text().ok_or_else(|| self.invalid("a single value"))?;
        let span = self.0.span.clone();
        visitor
            .visit_enum(text.into_deserializer())
            .map_err(|e: Error| e.or_span(&span))
    }

    fn deserialize_identifier<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
        visitor.visit_unit()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::Deserialize;

    use super::*;
    use crate::parser::parse;

    fn body(src: &str) -> Body {
        parse(src, "t.conf", &|_| None).unwrap()
    }

    #[derive(Debug, Deserialize, PartialEq, Default)]
    #[serde(deny_unknown_fields, default)]
    struct Geo {
        city_db: String,
        asn_db: String,
    }

    #[derive(Debug, Deserialize, PartialEq, Default)]
    #[serde(deny_unknown_fields, default)]
    struct Server {
        data_directory: String,
        channel_buffer: usize,
        enabled: bool,
        geo: Geo,
        ratio: f64,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Upstream {
        #[serde(rename = "$labels")]
        labels: Vec<String>,
        #[serde(default)]
        server: Vec<String>,
    }

    #[derive(Debug, Deserialize, PartialEq, Default)]
    #[serde(deny_unknown_fields, default)]
    struct Root {
        server: Server,
        upstream: Vec<Upstream>,
        tags: Vec<String>,
        weights: HashMap<String, u8>,
        rewrite: Vec<(String, String)>,
        mode: Option<Mode>,
    }

    #[derive(Debug, Deserialize, PartialEq, Clone, Copy)]
    #[serde(rename_all = "snake_case")]
    enum Mode {
        Passive,
        Inline,
    }

    #[test]
    fn maps_blocks_lists_labels_and_enums() {
        let r: Root = from_body(&body(
            "server {\n data_directory: /var/lib/sentry\n channel_buffer: 4096\n enabled: on\n ratio: 0.5\n geo { city_db: a.mmdb }\n}\n\
             upstream app { server: http://a:1 }\n\
             upstream api { server: [http://b:1, http://c:1] }\n\
             upstream web { server: http://d:1\n server: http://e:1 }\n\
             tags: x\nweights { sqli: 35, xss: 30 }\n\
             rewrite: '^/a(.*)' '/b$1'\nrewrite: '^/c' '/d'\nmode: inline\n",
        ))
        .unwrap();
        assert_eq!(r.server.data_directory, "/var/lib/sentry");
        assert!(r.server.enabled);
        assert_eq!(r.server.geo.city_db, "a.mmdb");
        assert_eq!(r.upstream.len(), 3);
        assert_eq!(r.upstream[0].labels, ["app"]);
        assert_eq!(r.upstream[1].server.len(), 2);
        assert_eq!(r.upstream[2].server, ["http://d:1", "http://e:1"]);
        assert_eq!(r.tags, ["x"]);
        assert_eq!(r.weights["xss"], 30);
        assert_eq!(r.rewrite[1], ("^/c".to_string(), "/d".to_string()));
        assert_eq!(r.mode, Some(Mode::Inline));
    }

    #[test]
    fn unlabeled_blocks_merge_across_occurrences() {
        let r: Root = from_body(&body(
            "server { data_directory: /x }\nserver { geo { asn_db: b } }\nserver { geo { city_db: c } }",
        ))
        .unwrap();
        assert_eq!(r.server.data_directory, "/x");
        assert_eq!(r.server.geo.asn_db, "b");
        assert_eq!(r.server.geo.city_db, "c");
    }

    fn err(src: &str) -> String {
        from_body::<Root>(&body(src)).unwrap_err().to_string()
    }

    #[test]
    fn errors_name_position_path_and_suggestion() {
        assert_eq!(
            err("server {\n  chanel_buffer: 1\n}"),
            "t.conf:2:3: server: unknown directive `chanel_buffer` — did you mean `channel_buffer`?"
        );
        assert_eq!(
            err("server {\n channel_buffer: lots\n}"),
            "t.conf:2:18: server › channel_buffer: expected an integer, found `lots`"
        );
        assert!(err("server { enabled: maybe }").contains("expected on/off"));
        let dup = err("server { data_directory: /a }\nserver { data_directory: /b }");
        assert!(
            dup.contains("`data_directory` is given 2 times (t.conf:1:10, t.conf:2:10)"),
            "{dup}"
        );
        assert!(err("upstream { server: x }").contains("needs a name/label"));
        assert!(err("server mine { }").contains("does not take a name/label"));
        assert!(err("mode: hybrid").contains("unknown value `hybrid`"));
        assert!(
            err("server: 1").contains("expects a block")
                || err("server: 1").contains("expected a block")
        );
    }
}
