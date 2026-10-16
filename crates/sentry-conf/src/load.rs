//! Multi-file loading: `include:` expansion (globs, relative to the including
//! file), directory loading and file concatenation.
//!
//! Statements from every file are spliced into one tree; same-name
//! unlabeled blocks found in different files (`detect {}` in `sentry.conf`
//! and in `detect.conf`) are merged by the deserializer, labeled blocks
//! (`site`, `location`, `source`, …) accumulate.

use std::path::{Path, PathBuf};

use crate::ast::{Body, Stmt, Value};
use crate::error::{Error, Result};
use crate::parser::{parse, EnvLookup};

/// Name of the include directive.
pub const INCLUDE: &str = "include";

/// Maximum include nesting (guards runaway recursion).
const MAX_DEPTH: usize = 16;

/// Reads files and expands includes.
pub struct Loader<'a> {
    env: EnvLookup<'a>,
}

fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

impl Default for Loader<'static> {
    fn default() -> Self {
        Self { env: &process_env }
    }
}

impl<'a> Loader<'a> {
    /// Loader with a custom environment lookup (tests).
    pub fn with_env(env: EnvLookup<'a>) -> Self {
        Self { env }
    }

    /// Load one file with its includes expanded.
    pub fn load_file(&self, path: &Path) -> Result<Body> {
        let mut stack = Vec::new();
        self.load_inner(path, &mut stack, None)
    }

    /// Load several files in order and concatenate their statements.
    pub fn load_files(&self, paths: &[PathBuf]) -> Result<Body> {
        let mut out = Vec::new();
        for p in paths {
            out.extend(self.load_file(p)?);
        }
        Ok(out)
    }

    /// Parse an in-memory source; relative includes resolve against `base`.
    pub fn load_str(&self, src: &str, name: &str, base: &Path) -> Result<Body> {
        let body = parse(src, name, self.env)?;
        let mut stack = Vec::new();
        self.expand(body, base, &mut stack)
    }

    fn load_inner(
        &self,
        path: &Path,
        stack: &mut Vec<PathBuf>,
        from: Option<&crate::ast::Span>,
    ) -> Result<Body> {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if stack.contains(&canonical) {
            let msg = format!("include cycle: {} includes itself", path.display());
            return Err(match from {
                Some(s) => Error::at(s, msg),
                None => Error::msg(msg),
            });
        }
        if stack.len() >= MAX_DEPTH {
            let msg = format!("includes nested deeper than {MAX_DEPTH} levels");
            return Err(match from {
                Some(s) => Error::at(s, msg),
                None => Error::msg(msg),
            });
        }
        let src = std::fs::read_to_string(path).map_err(|e| {
            let msg = format!("cannot read {}: {e}", path.display());
            match from {
                Some(s) => Error::at(s, msg),
                None => Error::msg(msg),
            }
        })?;
        let body = parse(&src, &path.display().to_string(), self.env)?;
        let base = path.parent().map(Path::to_path_buf).unwrap_or_default();
        stack.push(canonical);
        let out = self.expand(body, &base, stack);
        stack.pop();
        out
    }

    fn expand(&self, body: Body, base: &Path, stack: &mut Vec<PathBuf>) -> Result<Body> {
        let mut out = Vec::with_capacity(body.len());
        for stmt in body {
            match stmt {
                Stmt::Directive(d) if d.key == INCLUDE => {
                    for node in &d.values {
                        let patterns: Vec<&crate::ast::Node> = match &node.value {
                            Value::List(items) => items.iter().collect(),
                            _ => vec![node],
                        };
                        for pat in patterns {
                            let Some(text) = pat.as_text() else {
                                return Err(Error::at(&pat.span, "include expects file paths"));
                            };
                            let files =
                                expand_glob(base, &text).map_err(|e| e.or_span(&pat.span))?;
                            for f in files {
                                out.extend(self.load_inner(&f, stack, Some(&pat.span))?);
                            }
                        }
                    }
                }
                Stmt::Block(mut b) => {
                    b.body = self.expand(b.body, base, stack)?;
                    out.push(Stmt::Block(b));
                }
                other => out.push(other),
            }
        }
        Ok(out)
    }
}

/// `*.conf` files directly inside `dir`, sorted by name. A missing directory
/// yields nothing.
pub fn conf_files_in(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "conf"))
        .collect();
    files.sort();
    files
}

/// Resolve an include pattern relative to `base`. Wildcards (`*`, `?`) are
/// allowed in the file-name component only; a pattern with wildcards may
/// match nothing, a literal path must exist.
pub fn expand_glob(base: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
    let full = if Path::new(pattern).is_absolute() {
        PathBuf::from(pattern)
    } else {
        base.join(pattern)
    };
    let name = full
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = full.parent().map(Path::to_path_buf).unwrap_or_default();
    let has_wild = |s: &str| s.contains('*') || s.contains('?');
    if has_wild(&parent.to_string_lossy()) {
        return Err(Error::msg(format!(
            "include `{pattern}`: wildcards are only supported in the file name"
        )));
    }
    if !has_wild(&name) {
        if !full.is_file() {
            return Err(Error::msg(format!(
                "include `{pattern}`: file not found ({})",
                full.display()
            )));
        }
        return Ok(vec![full]);
    }
    let Ok(entries) = std::fs::read_dir(&parent) else {
        return Ok(Vec::new());
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .is_some_and(|n| wildcard_match(&name, &n.to_string_lossy()))
        })
        .collect();
    files.sort();
    Ok(files)
}

/// `*` (any run) and `?` (one char) matching.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sentry_conf_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*.conf", "detect.conf"));
        assert!(wildcard_match("s?te-*.conf", "site-a.conf"));
        assert!(!wildcard_match("*.conf", "detect.conf.bak"));
    }

    #[test]
    fn includes_expand_in_place_and_nested() {
        let d = tmpdir("inc");
        std::fs::create_dir_all(d.join("sites")).unwrap();
        std::fs::write(
            d.join("sentry.conf"),
            "include: detect.conf\nhttp {\n include: \"sites/*.conf\"\n}\n",
        )
        .unwrap();
        std::fs::write(d.join("detect.conf"), "detect { scan { enabled: on } }\n").unwrap();
        std::fs::write(d.join("sites/b.conf"), "site { host: b.com }\n").unwrap();
        std::fs::write(d.join("sites/a.conf"), "site { host: a.com }\n").unwrap();
        let body = Loader::default().load_file(&d.join("sentry.conf")).unwrap();
        assert_eq!(body[0].name(), "detect");
        let Stmt::Block(http) = &body[1] else {
            panic!()
        };
        assert_eq!(http.body.len(), 2);
        let Stmt::Block(first) = &http.body[0] else {
            panic!()
        };
        let Stmt::Directive(h) = &first.body[0] else {
            panic!()
        };
        assert_eq!(h.values[0].as_text().unwrap(), "a.com", "sorted by name");
    }

    #[test]
    fn missing_literal_include_and_cycles_are_errors() {
        let d = tmpdir("cyc");
        std::fs::write(d.join("a.conf"), "include: b.conf\n").unwrap();
        std::fs::write(d.join("b.conf"), "include: a.conf\n").unwrap();
        let e = Loader::default().load_file(&d.join("a.conf")).unwrap_err();
        assert!(e.to_string().contains("include cycle"), "{e}");
        std::fs::write(d.join("c.conf"), "include: nope.conf\n").unwrap();
        let e = Loader::default().load_file(&d.join("c.conf")).unwrap_err();
        assert!(e.to_string().contains("c.conf:1:10"), "{e}");
        assert!(e.to_string().contains("file not found"), "{e}");
        std::fs::write(d.join("e.conf"), "include: \"none/*.conf\"\n").unwrap();
        assert!(Loader::default()
            .load_file(&d.join("e.conf"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn conf_files_are_sorted_and_filtered() {
        let d = tmpdir("dir");
        std::fs::write(d.join("b.conf"), "").unwrap();
        std::fs::write(d.join("a.conf"), "").unwrap();
        std::fs::write(d.join("notes.txt"), "").unwrap();
        let names: Vec<String> = conf_files_in(&d)
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, ["a.conf", "b.conf"]);
    }
}
