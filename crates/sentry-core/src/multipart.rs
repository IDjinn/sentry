//! Request-body parsing (F10): multipart/form-data and urlencoded forms.
//!
//! Pure byte-level parsers — no I/O, no async, no `serde_json`. Multipart is
//! parsed per RFC 7578 with CRLF-tolerant delimiters; nested multipart is
//! rejected (parts stay flat). Text parts (form fields) and urlencoded
//! values feed the upload heuristics; JSON bodies are scanned as raw text by
//! the heuristics themselves, never parsed structurally.

/// One parsed multipart part. Borrows from the request body buffer.
#[derive(Debug, Clone, PartialEq)]
pub struct UploadPart<'a> {
    /// `name` attribute from `Content-Disposition`.
    pub name: Option<String>,
    /// `filename` attribute (RFC 7578 / RFC 5987 `filename*` decoded).
    pub filename: Option<String>,
    /// The part's own `Content-Type`, when declared.
    pub content_type: Option<String>,
    /// Raw part content (borrowed slice of the body buffer).
    pub content: &'a [u8],
}

/// Parse a `multipart/form-data` body into its flat parts.
///
/// Returns an empty vec when the content type carries no usable boundary or
/// the body is malformed — callers treat that as "nothing to inspect", never
/// as an error (upload parsing must not break proxying).
pub fn parse_multipart<'a>(
    content_type: &str,
    body: &'a [u8],
    max_parts: usize,
) -> Vec<UploadPart<'a>> {
    let Some(boundary) = multipart_boundary(content_type) else {
        return Vec::new();
    };
    let delim = format!("--{boundary}");
    let delim_bytes = delim.as_bytes();

    // Everything before the first delimiter is the preamble.
    let Some(start) = find(body, delim_bytes, 0) else {
        return Vec::new();
    };
    let mut pos = start + delim_bytes.len();

    let mut parts = Vec::new();
    loop {
        // Right after a delimiter: `--` marks the closing one, else a line
        // break starts the next part.
        if body[pos..].starts_with(b"--") {
            break;
        }
        pos = skip_line_break(body, pos);
        if pos >= body.len() {
            break;
        }

        // Part content runs until the next `\r\n--boundary` (lenient: also
        // accept a bare `\n--boundary`).
        let (content, delim_start) = match find_part_end(body, delim_bytes, pos) {
            Some((end, dstart)) => (&body[pos..end], dstart),
            None => (&body[pos..], body.len()),
        };
        let (name, filename, part_ct) = parse_part_headers(content);
        parts.push(UploadPart {
            name,
            filename,
            content_type: part_ct,
            content: content_slice(content),
        });
        if parts.len() >= max_parts.max(1) || delim_start >= body.len() {
            break;
        }
        pos = delim_start + delim_bytes.len();
    }
    parts
}

/// Trim the part headers, keeping only the content bytes. `content` spans
/// `headers CRLF CRLF data`; when no header/body separator exists the whole
/// slice is treated as content.
fn content_slice(content: &[u8]) -> &[u8] {
    match find(content, b"\r\n\r\n", 0) {
        Some(i) => &content[i + 4..],
        None => match find(content, b"\n\n", 0) {
            Some(i) => &content[i + 2..],
            None => content,
        },
    }
}

/// Extract `(name, filename, content-type)` from a part's header block.
fn parse_part_headers(raw: &[u8]) -> (Option<String>, Option<String>, Option<String>) {
    let end = find(raw, b"\r\n\r\n", 0)
        .or_else(|| find(raw, b"\n\n", 0))
        .unwrap_or(raw.len());
    let headers = String::from_utf8_lossy(&raw[..end.min(raw.len())]);
    let mut name = None;
    let mut filename = None;
    let mut ct = None;
    for line in headers.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "content-disposition" => {
                name = disposition_param(value, "name").or(name);
                filename = disposition_param(value, "filename")
                    .or_else(|| disposition_param(value, "filename*").and_then(decode_ext_value))
                    .or(filename);
            }
            "content-type" => ct = Some(value.to_string()).or(ct),
            _ => {}
        }
    }
    (name, filename, ct)
}

/// Pull a `key="value"` (or bare `key=value`) parameter out of a
/// `Content-Disposition` header value.
fn disposition_param(value: &str, key: &str) -> Option<String> {
    for segment in value.split(';').skip(1) {
        let segment = segment.trim();
        let Some((k, v)) = segment.split_once('=') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case(key) {
            continue;
        }
        let v = v.trim().trim_matches('"');
        return if v.is_empty() {
            None
        } else {
            Some(v.to_string())
        };
    }
    None
}

/// Decode an RFC 5987 extended parameter value (`filename*=UTF-8''na%C3%AFve`).
fn decode_ext_value(v: String) -> Option<String> {
    let v = v.trim_matches('"');
    let (_charset, rest) = v.split_once('\'')?;
    let (_lang, encoded) = rest.split_once('\'')?;
    let decoded = percent_decode(encoded);
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

/// Extract the boundary from a `Content-Type: multipart/...` header value.
pub fn multipart_boundary(content_type: &str) -> Option<String> {
    let ct = content_type.trim();
    if !ct.to_ascii_lowercase().starts_with("multipart/") {
        return None;
    }
    for segment in ct.split(';').skip(1) {
        let segment = segment.trim();
        let Some((k, v)) = segment.split_once('=') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        let boundary = v.trim().trim_matches('"');
        if boundary.is_empty() {
            return None;
        }
        return Some(boundary.to_string());
    }
    None
}

/// Parse an `application/x-www-form-urlencoded` body into `(key, value)`
/// pairs, percent-decoding both sides (`+` → space).
pub fn parse_urlencoded(body: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(body);
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (decode_component(k), decode_component(v)),
            None => (decode_component(pair), String::new()),
        })
        .collect()
}

/// Whether a request body should be text-scanned as JSON (F10): declared via
/// a `*/json` content type or starting with a JSON value marker.
pub fn looks_like_json(content_type: Option<&str>, body: &[u8]) -> bool {
    if let Some(ct) = content_type {
        if ct.to_ascii_lowercase().contains("json") {
            return true;
        }
    }
    let start = body
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    matches!(body.get(start), Some(b'{') | Some(b'['))
}

/// Whether the content type (or absence of one) marks a part as textually
/// scannable — form fields, JSON, SVG/HTML, and everything that decodes to
/// mostly-printable UTF-8.
pub fn is_scannable_text(content_type: Option<&str>, content: &[u8]) -> bool {
    if let Some(ct) = content_type {
        let ct = ct.to_ascii_lowercase();
        if ct.starts_with("text/")
            || ct.contains("json")
            || ct.contains("xml")
            || ct.contains("html")
            || ct.contains("javascript")
            || ct.contains("x-www-form-urlencoded")
        {
            return true;
        }
        if ct.starts_with("image/")
            || ct.starts_with("audio/")
            || ct.starts_with("video/")
            || ct.starts_with("application/octet-stream")
            || ct.starts_with("application/zip")
            || ct.starts_with("application/gzip")
            || ct.starts_with("application/pdf")
        {
            return false;
        }
    }
    // No (or unrecognized) content type: sniff — a part that decodes to
    // printable text is scanned; binary blobs are skipped.
    printable_ratio(content) > 0.85
}

/// Fraction of bytes that are printable ASCII or valid UTF-8 lead bytes.
fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 1.0;
    }
    let sample_len = bytes.len().min(4096);
    let sample = &bytes[..sample_len];
    let printable = sample
        .iter()
        .filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'))
        .count();
    printable as f64 / sample_len as f64
}

/// Percent-decode a URL component (`+` → space, `%XX` → byte), lossy UTF-8.
pub fn decode_component(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-decode only (`%XX` → byte), used by RFC 5987 values.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

/// Find the end of a part's content: the next `\r\n--boundary` (lenient
/// `\n--boundary`). Returns `(content_end, index_after_crlf)`.
fn find_part_end(body: &[u8], delim: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut search = from;
    while let Some(pos) = find(body, delim, search) {
        if pos >= 2 && &body[pos - 2..pos] == b"\r\n" {
            return Some((pos - 2, pos));
        }
        if pos >= 1 && body[pos - 1] == b'\n' {
            return Some((pos - 1, pos));
        }
        // A delimiter embedded mid-content without a preceding line break is
        // part of the data; keep searching.
        search = pos + 1;
    }
    None
}

/// Skip a single line break after a delimiter (`\r\n` or lone `\n`).
fn skip_line_break(body: &[u8], pos: usize) -> usize {
    if body[pos..].starts_with(b"\r\n") {
        pos + 2
    } else if body[pos..].starts_with(b"\n") {
        pos + 1
    } else {
        pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOUNDARY: &str = "----sentryform";
    const CT: &str = "multipart/form-data; boundary=----sentryform";

    fn body(parts: &[(&str, Option<&str>, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, filename, ct, content) in parts {
            let disp = match filename {
                Some(f) => {
                    format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n")
                }
                None => format!("Content-Disposition: form-data; name=\"{name}\"\r\n"),
            };
            let ct_line = match ct {
                Some(c) => format!("Content-Type: {c}\r\n"),
                None => String::new(),
            };
            out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
            out.extend_from_slice(disp.as_bytes());
            out.extend_from_slice(ct_line.as_bytes());
            out.extend_from_slice(b"\r\n");
            out.extend_from_slice(content);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        out
    }

    #[test]
    fn extracts_boundary() {
        assert_eq!(multipart_boundary(CT).as_deref(), Some("----sentryform"));
        assert_eq!(
            multipart_boundary("multipart/form-data; boundary=\"quoted\"").as_deref(),
            Some("quoted")
        );
        assert_eq!(multipart_boundary("application/json"), None);
        assert_eq!(multipart_boundary("multipart/form-data"), None);
    }

    #[test]
    fn parses_two_parts() {
        let b = body(&[
            ("field", None, None, b"hello world".as_slice()),
            (
                "file",
                Some("a.png"),
                Some("image/png"),
                b"\x89PNG\r\n\x1a\n",
            ),
        ]);
        let parts = parse_multipart(CT, &b, 16);
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name.as_deref(), Some("field"));
        assert_eq!(parts[0].filename, None);
        assert_eq!(parts[0].content, b"hello world");
        assert_eq!(parts[1].filename.as_deref(), Some("a.png"));
        assert_eq!(parts[1].content_type.as_deref(), Some("image/png"));
        assert_eq!(parts[1].content, b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn content_boundary_inside_part_does_not_split() {
        let mut out = Vec::new();
        out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        out.extend_from_slice(b"Content-Disposition: form-data; name=\"f\"\r\n\r\n");
        out.extend_from_slice(b"looks like --");
        out.extend_from_slice(BOUNDARY.as_bytes());
        out.extend_from_slice(b" but is not\r\n");
        out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        let parts = parse_multipart(CT, &out, 16);
        assert_eq!(parts.len(), 1);
        assert_eq!(
            parts[0].content,
            format!("looks like --{BOUNDARY} but is not").as_bytes()
        );
    }

    #[test]
    fn filename_star_rfc5987_decoded() {
        let mut out = Vec::new();
        out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        out.extend_from_slice(
            b"Content-Disposition: form-data; name=\"f\"; filename*=UTF-8''na%C3%AFve.txt\r\n\r\n",
        );
        out.extend_from_slice(b"data\r\n");
        out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        let parts = parse_multipart(CT, &out, 16);
        assert_eq!(parts[0].filename.as_deref(), Some("naïve.txt"));
    }

    #[test]
    fn missing_boundary_yields_no_parts() {
        assert!(parse_multipart("multipart/form-data", b"--x\r\n", 16).is_empty());
        assert!(parse_multipart(CT, b"not multipart at all", 16).is_empty());
    }

    #[test]
    fn max_parts_caps_output() {
        let b = body(&[
            ("a", None, None, b"1".as_slice()),
            ("b", None, None, b"2".as_slice()),
            ("c", None, None, b"3".as_slice()),
        ]);
        let parts = parse_multipart(CT, &b, 2);
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn urlencoded_pairs_decode() {
        let pairs = parse_urlencoded(b"user=admin%27+OR+1%3D1--&x=a+b");
        assert_eq!(pairs[0], ("user".into(), "admin' OR 1=1--".into()));
        assert_eq!(pairs[1], ("x".into(), "a b".into()));
        assert!(parse_urlencoded(b"").is_empty());
    }

    #[test]
    fn json_detection() {
        assert!(looks_like_json(Some("application/json"), b"{}"));
        assert!(looks_like_json(Some("application/ld+json"), b"[]"));
        assert!(looks_like_json(None, b"\r\n {\"a\":1}"));
        assert!(!looks_like_json(Some("text/plain"), b"hello"));
        assert!(!looks_like_json(None, b"binary \xff\xfe"));
    }

    #[test]
    fn scannable_text_classification() {
        assert!(is_scannable_text(Some("image/svg+xml"), b"<svg/>"));
        assert!(is_scannable_text(Some("text/plain"), b"ok"));
        assert!(is_scannable_text(None, b"plain body"));
        assert!(!is_scannable_text(Some("image/png"), b"\x89PNG"));
        assert!(!is_scannable_text(None, b"\x00\x01\x02\xff\xfe\xfd"));
    }
}
