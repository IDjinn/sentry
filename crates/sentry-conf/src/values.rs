//! Typed values with friendly syntax: durations (`10s`, `5m`, `24h`), sizes
//! (`4k`, `10mb`), "one or many" lists and an untyped [`ConfValue`] for
//! free-form option maps.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, IntoDeserializer, Visitor};
use serde::{Serialize, Serializer};

/// Parse a duration in milliseconds: `250ms`, `10s`, `5m`, `24h`, `7d`, `2w`,
/// or a bare number (seconds). Fractions are allowed (`1.5h`).
pub fn parse_duration_ms(text: &str) -> Option<u64> {
    let t = text.trim().to_ascii_lowercase();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num.parse().ok()?;
    if n < 0.0 {
        return None;
    }
    let factor = match unit.trim() {
        "ms" => 1.0,
        "" | "s" | "sec" | "secs" => 1_000.0,
        "m" | "min" | "mins" => 60_000.0,
        "h" | "hr" | "hrs" => 3_600_000.0,
        "d" | "day" | "days" => 86_400_000.0,
        "w" | "wk" | "weeks" => 604_800_000.0,
        _ => return None,
    };
    Some((n * factor).round() as u64)
}

/// Parse a size in bytes: `512`, `4k`/`4kb`, `10m`/`10mb`, `1g`/`1gb`
/// (binary multiples, case-insensitive).
pub fn parse_size(text: &str) -> Option<u64> {
    let t = text.trim().to_ascii_lowercase();
    let split = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(t.len());
    let (num, unit) = t.split_at(split);
    let n: f64 = num.parse().ok()?;
    let factor: f64 = match unit.trim() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((n * factor).round() as u64)
}

/// Format milliseconds with the largest exact unit (`86400000` → `24h`).
pub fn format_duration_ms(ms: u64) -> String {
    const UNITS: [(u64, &str); 5] = [
        (604_800_000, "w"),
        (86_400_000, "d"),
        (3_600_000, "h"),
        (60_000, "m"),
        (1_000, "s"),
    ];
    if ms == 0 {
        return "0s".to_string();
    }
    for (factor, unit) in UNITS {
        if ms % factor == 0 {
            return format!("{}{unit}", ms / factor);
        }
    }
    format!("{ms}ms")
}

/// Format bytes with the largest exact binary unit (`4194304` → `4mb`).
pub fn format_size(bytes: u64) -> String {
    const UNITS: [(u64, &str); 3] = [(1 << 30, "gb"), (1 << 20, "mb"), (1 << 10, "kb")];
    if bytes == 0 {
        return "0".to_string();
    }
    for (factor, unit) in UNITS {
        if bytes % factor == 0 {
            return format!("{}{unit}", bytes / factor);
        }
    }
    bytes.to_string()
}

struct DurationVisitor;

impl<'de> Visitor<'de> for DurationVisitor {
    type Value = u64;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a duration like 30s, 5m, 24h (a bare number is seconds)")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
        Ok(v.saturating_mul(1000))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
        if v < 0 {
            return Err(E::custom("a duration cannot be negative"));
        }
        Ok((v as u64).saturating_mul(1000))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<u64, E> {
        if v < 0.0 {
            return Err(E::custom("a duration cannot be negative"));
        }
        Ok((v * 1000.0).round() as u64)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
        parse_duration_ms(v).ok_or_else(|| {
            E::custom(format!(
                "invalid duration `{v}` (use e.g. 500ms, 30s, 5m, 24h, 7d)"
            ))
        })
    }
}

/// A duration in whole seconds (`10s`, `5m`, `24h`; bare numbers = seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Secs(pub u64);

impl<'de> Deserialize<'de> for Secs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let ms = d.deserialize_any(DurationVisitor)?;
        Ok(Secs(ms.div_ceil(1000)))
    }
}

impl Serialize for Secs {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_duration_ms(self.0.saturating_mul(1000)))
    }
}

/// A duration in milliseconds (`250ms`, `2s`; bare numbers = seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Millis(pub u64);

impl<'de> Deserialize<'de> for Millis {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Millis(d.deserialize_any(DurationVisitor)?))
    }
}

impl Serialize for Millis {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_duration_ms(self.0))
    }
}

/// A size in bytes (`4k`, `10mb`; bare numbers = bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Bytes(pub u64);

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = u64;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a size like 512, 4k, 10mb, 1gb")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<u64, E> {
                Ok(v)
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<u64, E> {
                u64::try_from(v).map_err(|_| E::custom("a size cannot be negative"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<u64, E> {
                parse_size(v).ok_or_else(|| {
                    E::custom(format!("invalid size `{v}` (use e.g. 512, 4k, 10mb)"))
                })
            }
        }
        Ok(Bytes(d.deserialize_any(V)?))
    }
}

impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_size(self.0))
    }
}

/// A list that accepts one value, a `[…]` list, repeated directives — or any
/// mix, flattened in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneOrMany<T>(pub Vec<T>);

impl<T> Default for OneOrMany<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> OneOrMany<T> {
    /// The flattened values.
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T: Serialize> Serialize for OneOrMany<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0.len() == 1 {
            self.0[0].serialize(s)
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrMany<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut out = Vec::new();
        d.deserialize_any(FlatVisitor {
            out: &mut out,
            _t: std::marker::PhantomData,
        })?;
        Ok(OneOrMany(out))
    }
}

struct FlatVisitor<'o, T> {
    out: &'o mut Vec<T>,
    _t: std::marker::PhantomData<T>,
}

struct FlatSeed<'o, T> {
    out: &'o mut Vec<T>,
}

impl<'de, 'o, T: Deserialize<'de>> de::DeserializeSeed<'de> for FlatSeed<'o, T> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(FlatVisitor {
            out: self.out,
            _t: std::marker::PhantomData,
        })
    }
}

impl<'de, 'o, T: Deserialize<'de>> Visitor<'de> for FlatVisitor<'o, T> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a value or a list of values")
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(FlatSeed { out: self.out })?.is_some() {}
        Ok(())
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<(), E> {
        self.out
            .push(T::deserialize(IntoDeserializer::<E>::into_deserializer(v))?);
        Ok(())
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<(), E> {
        self.out
            .push(T::deserialize(IntoDeserializer::<E>::into_deserializer(v))?);
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<(), E> {
        self.out
            .push(T::deserialize(IntoDeserializer::<E>::into_deserializer(v))?);
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<(), E> {
        self.out
            .push(T::deserialize(IntoDeserializer::<E>::into_deserializer(v))?);
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<(), E> {
        self.out
            .push(T::deserialize(IntoDeserializer::<E>::into_deserializer(v))?);
        Ok(())
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<(), E> {
        self.out
            .push(T::deserialize(IntoDeserializer::<E>::into_deserializer(v))?);
        Ok(())
    }

    fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<(), A::Error> {
        self.out
            .push(T::deserialize(de::value::MapAccessDeserializer::new(map))?);
        Ok(())
    }
}

/// Untyped value for free-form option maps (source/action options).
#[derive(Debug, Clone, PartialEq)]
pub enum ConfValue {
    /// `true`/`false`.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Float.
    Float(f64),
    /// String or bare word.
    Str(String),
    /// List (also produced by repeated directives).
    List(Vec<ConfValue>),
    /// Block / inline map, in source order.
    Map(Vec<(String, ConfValue)>),
}

impl ConfValue {
    /// Text of a scalar.
    pub fn as_text(&self) -> Option<String> {
        match self {
            ConfValue::Str(s) => Some(s.clone()),
            ConfValue::Int(i) => Some(i.to_string()),
            ConfValue::Float(f) => Some(f.to_string()),
            ConfValue::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for ConfValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = ConfValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("any value")
            }
            fn visit_bool<E>(self, v: bool) -> Result<ConfValue, E> {
                Ok(ConfValue::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<ConfValue, E> {
                Ok(ConfValue::Int(v))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<ConfValue, E> {
                i64::try_from(v)
                    .map(ConfValue::Int)
                    .map_err(|_| E::custom("integer too large"))
            }
            fn visit_f64<E>(self, v: f64) -> Result<ConfValue, E> {
                Ok(ConfValue::Float(v))
            }
            fn visit_str<E>(self, v: &str) -> Result<ConfValue, E> {
                Ok(ConfValue::Str(v.to_string()))
            }
            fn visit_string<E>(self, v: String) -> Result<ConfValue, E> {
                Ok(ConfValue::Str(v))
            }
            fn visit_unit<E>(self) -> Result<ConfValue, E> {
                Ok(ConfValue::List(Vec::new()))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<ConfValue, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element()? {
                    out.push(v);
                }
                Ok(ConfValue::List(out))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<ConfValue, A::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, ConfValue>()? {
                    out.push((k, v));
                }
                Ok(ConfValue::Map(out))
            }
        }
        d.deserialize_any(V)
    }
}

impl Serialize for ConfValue {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self {
            ConfValue::Bool(b) => s.serialize_bool(*b),
            ConfValue::Int(i) => s.serialize_i64(*i),
            ConfValue::Float(f) => s.serialize_f64(*f),
            ConfValue::Str(v) => s.serialize_str(v),
            ConfValue::List(items) => items.serialize(s),
            ConfValue::Map(entries) => {
                let mut m = s.serialize_map(Some(entries.len()))?;
                for (k, v) in entries {
                    m.serialize_entry(k, v)?;
                }
                m.end()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_sizes() {
        assert_eq!(parse_duration_ms("250ms"), Some(250));
        assert_eq!(parse_duration_ms("10"), Some(10_000));
        assert_eq!(parse_duration_ms("1.5h"), Some(5_400_000));
        assert_eq!(parse_duration_ms("7d"), Some(604_800_000));
        assert_eq!(parse_duration_ms("10x"), None);
        assert_eq!(parse_size("4k"), Some(4096));
        assert_eq!(parse_size("10MB"), Some(10 * 1024 * 1024));
        assert_eq!(parse_size("ten"), None);
        assert_eq!(format_duration_ms(86_400_000), "1d");
        assert_eq!(format_duration_ms(90_000), "90s");
        assert_eq!(format_duration_ms(250), "250ms");
        assert_eq!(format_size(4 * 1024 * 1024), "4mb");
    }
}

/// Map that keeps source order (routes, packs, weights, …).
#[derive(Debug, Clone, PartialEq)]
pub struct OrderedMap<V>(pub Vec<(String, V)>);

impl<V> Default for OrderedMap<V> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<V> OrderedMap<V> {
    /// Entries in order.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<V> FromIterator<(String, V)> for OrderedMap<V> {
    fn from_iter<I: IntoIterator<Item = (String, V)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl<'de, V: Deserialize<'de>> Deserialize<'de> for OrderedMap<V> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis<V>(std::marker::PhantomData<V>);
        impl<'de, V: Deserialize<'de>> Visitor<'de> for Vis<V> {
            type Value = OrderedMap<V>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a block of `key: value` entries")
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(k) = map.next_key::<String>()? {
                    if k == crate::de::LABELS_KEY {
                        return Err(de::Error::custom("this block does not take a name/label"));
                    }
                    out.push((k, map.next_value()?));
                }
                Ok(OrderedMap(out))
            }
        }
        d.deserialize_map(Vis(std::marker::PhantomData))
    }
}

impl<V: Serialize> Serialize for OrderedMap<V> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(Some(self.0.len()))?;
        for (k, v) in &self.0 {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

/// A labeled block with free-form entries (`source nginx { … }`,
/// `action challenge cloudflare { … }`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RawBlock {
    /// Block labels.
    pub labels: Vec<String>,
    /// Entries in source order.
    pub entries: Vec<(String, ConfValue)>,
}

impl<'de> Deserialize<'de> for RawBlock {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Vis;
        impl<'de> Visitor<'de> for Vis {
            type Value = RawBlock;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a block")
            }
            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<RawBlock, A::Error> {
                let mut block = RawBlock::default();
                while let Some(k) = map.next_key::<String>()? {
                    if k == crate::de::LABELS_KEY {
                        let labels: Vec<ConfValue> = map.next_value()?;
                        block.labels = labels.iter().filter_map(ConfValue::as_text).collect();
                    } else {
                        block.entries.push((k, map.next_value()?));
                    }
                }
                Ok(block)
            }
        }
        d.deserialize_map(Vis)
    }
}

impl Serialize for RawBlock {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(None)?;
        if !self.labels.is_empty() {
            m.serialize_entry(crate::de::LABELS_KEY, &self.labels)?;
        }
        for (k, v) in &self.entries {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}
