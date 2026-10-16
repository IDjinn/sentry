//! Syntax-level shorthands, rewritten on the tree before deserialization
//! (errors keep pointing at the user's own lines):
//!
//! - inside `http {}` and `site {}`, a directive whose key is a path becomes
//!   a location: `"/api/": api` → `location /api/ { proxy_pass: api }`,
//!   `"/health": 200 "ok"` → `return`, `"/old/": redirect 301 "url"` →
//!   `redirect`. A list of URLs balances across them.
//!
//! [`shorten`] is the inverse for rendered output (`config show`/`migrate`).

use sentry_conf::ser::Tree;
use sentry_conf::{Block, Body, Directive, Node, Stmt, Value, LABELS_KEY};

/// Apply every shorthand to a parsed (include-expanded) body.
pub fn desugar(body: &Body) -> Body {
    body.iter()
        .map(|stmt| match stmt {
            Stmt::Block(b) if b.name == "http" => Stmt::Block(Block {
                body: scope(&b.body),
                ..b.clone()
            }),
            other => other.clone(),
        })
        .collect()
}

fn scope(body: &Body) -> Body {
    body.iter()
        .map(|stmt| match stmt {
            Stmt::Directive(d) if d.key.starts_with('/') => path_location(d),
            Stmt::Block(b) if b.name == "site" => Stmt::Block(Block {
                body: scope(&b.body),
                ..b.clone()
            }),
            other => other.clone(),
        })
        .collect()
}

fn path_location(d: &Directive) -> Stmt {
    let (key, values) = match d.values.first().map(|n| &n.value) {
        Some(Value::Int(_)) => ("return", d.values.clone()),
        Some(Value::Word(w)) if w == "redirect" => ("redirect", d.values[1..].to_vec()),
        Some(Value::Word(w)) if w == "return" => ("return", d.values[1..].to_vec()),
        _ => ("proxy_pass", d.values.clone()),
    };
    let values = if values.is_empty() {
        d.values.clone()
    } else {
        values
    };
    Stmt::Block(Block {
        name: "location".into(),
        labels: vec![Node {
            value: Value::Word(d.key.clone()),
            span: d.span.clone(),
        }],
        body: vec![Stmt::Directive(Directive {
            key: key.into(),
            values,
            span: d.span.clone(),
        })],
        span: d.span.clone(),
    })
}

/// Rewrite simple locations of a rendered tree back into `"/path": target`
/// shorthands, inlining anonymous balanced groups (`upstream site/path`).
pub fn shorten(tree: &mut Tree) {
    let Tree::Map(top) = tree else { return };
    let Some((_, Tree::Map(http))) = top.iter_mut().find(|(k, _)| k == "http") else {
        return;
    };
    let mut anon: Vec<(String, Tree)> = Vec::new();
    if let Some((_, Tree::Seq(ups))) = http.iter_mut().find(|(k, _)| k == "upstream") {
        ups.retain(|u| {
            let Tree::Map(entries) = u else { return true };
            let name = labels(entries).into_iter().next().unwrap_or_default();
            let others: Vec<&(String, Tree)> = entries
                .iter()
                .filter(|(k, v)| k != LABELS_KEY && !blank(v))
                .collect();
            match others.as_slice() {
                [(k, servers)] if k == "server" && name.contains('/') => {
                    anon.push((name, servers.clone()));
                    false
                }
                _ => true,
            }
        });
    }
    http.retain(|(k, v)| !(k == "upstream" && matches!(v, Tree::Seq(s) if s.is_empty())));
    for (key, value) in http.iter_mut() {
        if key != "site" {
            continue;
        }
        let Tree::Seq(sites) = value else { continue };
        for site in sites {
            inline_anon(site, &anon);
            if let Tree::Map(entries) = site {
                shorten_locations(entries, &anon);
            }
        }
    }
}

/// Replace every `proxy_pass: <anonymous group>` with the group's servers
/// (`proxy_pass` accepts a list), so the anonymous `upstream` can go.
fn inline_anon(tree: &mut Tree, anon: &[(String, Tree)]) {
    match tree {
        Tree::Map(entries) => {
            for (k, v) in entries.iter_mut() {
                if k == "proxy_pass" {
                    let name = match v {
                        Tree::Str(n) => Some(n.clone()),
                        Tree::Seq(items) => match items.as_slice() {
                            [Tree::Str(n)] => Some(n.clone()),
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Some((_, servers)) =
                        name.and_then(|n| anon.iter().find(|(a, _)| *a == n))
                    {
                        *v = servers.clone();
                    }
                } else {
                    inline_anon(v, anon);
                }
            }
        }
        Tree::Seq(items) => items.iter_mut().for_each(|i| inline_anon(i, anon)),
        _ => {}
    }
}

/// Values the renderer skips (unset options, empty lists/blocks).
fn blank(v: &Tree) -> bool {
    match v {
        Tree::Null => true,
        Tree::Seq(items) => items.is_empty(),
        Tree::Map(entries) => entries.iter().all(|(_, v)| blank(v)),
        _ => false,
    }
}

fn labels(entries: &[(String, Tree)]) -> Vec<String> {
    entries
        .iter()
        .find(|(k, _)| k == LABELS_KEY)
        .map(|(_, v)| match v {
            Tree::Seq(items) => items
                .iter()
                .filter_map(|i| match i {
                    Tree::Str(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        })
        .unwrap_or_default()
}

/// `(path, value)` when a location block is just a prefix path + one target.
fn as_shorthand(loc: &Tree, anon: &[(String, Tree)]) -> Option<(String, Tree)> {
    let Tree::Map(entries) = loc else { return None };
    let path = match labels(entries).as_slice() {
        [p] if p.starts_with('/') => p.clone(),
        _ => return None,
    };
    let others: Vec<&(String, Tree)> = entries
        .iter()
        .filter(|(k, v)| k != LABELS_KEY && !blank(v))
        .collect();
    let [(key, value)] = others.as_slice() else {
        return None;
    };
    let one = |parts: Vec<Tree>| Tree::Seq(vec![Tree::Seq(parts)]);
    let seq = |v: &Tree| match v {
        Tree::Seq(items) => items.clone(),
        other => vec![other.clone()],
    };
    let value = match key.as_str() {
        "proxy_pass" => {
            let target = seq(value);
            match target.as_slice() {
                [Tree::Str(name)] => anon
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, servers)| servers.clone())
                    .unwrap_or_else(|| Tree::Str(name.clone())),
                _ => return None,
            }
        }
        "return" => one(seq(value)),
        "redirect" => {
            let mut parts = vec![Tree::Str("redirect".into())];
            parts.extend(seq(value));
            one(parts)
        }
        _ => return None,
    };
    Some((path, value))
}

fn shorten_locations(entries: &mut Vec<(String, Tree)>, anon: &[(String, Tree)]) {
    let Some(pos) = entries.iter().position(|(k, _)| k == "location") else {
        return;
    };
    let (_, Tree::Seq(locs)) = entries.remove(pos) else {
        return;
    };
    let mut out: Vec<(String, Tree)> = Vec::new();
    for loc in locs {
        match as_shorthand(&loc, anon) {
            Some(short) => out.push(short),
            None => match out.last_mut() {
                Some((k, Tree::Seq(run))) if k == "location" => run.push(loc),
                _ => out.push(("location".into(), Tree::Seq(vec![loc]))),
            },
        }
    }
    for (i, item) in out.into_iter().enumerate() {
        entries.insert(pos + i, item);
    }
}
