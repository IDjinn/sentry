//! Upload inspection (F10): byte-level classification and abuse signals for
//! files submitted through the inline edge.
//!
//! Three layers live here:
//!
//! - [`sniff_kind`] — magic-byte classification (the declared content type
//!   is a hint, the bytes are the truth).
//! - [`hidden_payload_markers`] — polyglot detection: executable/script
//!   markers hidden inside binary images and archives (PHP after the JPEG
//!   EOI marker, webshell strings in EXIF comment ranges, …).
//! - [`UploadTracker`] — per-IP flood window over upload count and total
//!   bytes, feeding the `UploadFlood` signal.
//!
//! All checks are pure byte scans: no ML, no external AV, no I/O.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::analysis::{Signal, SignalKind, UPLOAD_FLOOD_WEIGHT};
use crate::config::UploadsConfig;
use crate::event::UploadInfo;

/// How far into a part's head the polyglot marker scan looks (PHP embedded
/// as EXIF comment lives in the first bytes; appended payloads ride the
/// tail). Scanning everything would regex multi-MiB blobs on the hot path.
const HEAD_SCAN: usize = 8 * 1024;
const TAIL_SCAN: usize = 4 * 1024;

/// Per-part cap for textual regex scanning (F10 heuristics).
pub const TEXT_SCAN_CAP: usize = 512 * 1024;

/// Effective scan configuration for the upload heuristics, projected from
/// `[uploads]` at daemon startup.
#[derive(Debug, Clone)]
pub struct UploadsScan {
    /// Detection runs at all (off keeps the heuristics zero-cost).
    pub enabled: bool,
    /// `false` (shadow) emits every upload-origin signal with weight 0 —
    /// detections are logged and metricized but never block.
    pub enforce: bool,
    /// Scan JSON bodies as text.
    pub scan_json: bool,
    /// Filename extensions that always raise `UploadExecutable`.
    pub blocked_extensions: Vec<String>,
}

impl UploadsScan {
    /// Project the daemon config onto the scan knobs.
    pub fn from_config(cfg: &UploadsConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            enforce: cfg.mode.is_enforce(),
            scan_json: cfg.scan_json,
            blocked_extensions: cfg
                .blocked_extensions
                .iter()
                .map(|e| e.trim().to_ascii_lowercase())
                .filter(|e| !e.is_empty())
                .collect(),
        }
    }
}

impl Default for UploadsScan {
    fn default() -> Self {
        Self::from_config(&UploadsConfig::default())
    }
}

/// Classify file content by magic bytes; declaration is only a fallback.
pub fn sniff_kind(
    content: &[u8],
    filename: Option<&str>,
    content_type: Option<&str>,
) -> crate::event::UploadKind {
    use crate::event::UploadKind;
    if content.len() >= 8 && content.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
    {
        return UploadKind::Image;
    }
    if content.len() >= 3 && content.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return UploadKind::Image;
    }
    if content.starts_with(b"GIF87a") || content.starts_with(b"GIF89a") {
        return UploadKind::Image;
    }
    if content.len() >= 12 && content.starts_with(b"RIFF") && &content[8..12] == b"WEBP" {
        return UploadKind::Image;
    }
    if content.starts_with(b"BM") && content.len() >= 14 {
        return UploadKind::Image;
    }
    if content.starts_with(b"PK\x03\x04")
        || content.starts_with(b"PK\x05\x06")
        || content.starts_with(b"PK\x07\x08")
    {
        return UploadKind::Archive;
    }
    if content.starts_with(&[0x1F, 0x8B])
        || content.starts_with(b"BZh")
        || content.starts_with(&[0xFD, b'7', b'z', b'X', b'Z'])
    {
        return UploadKind::Archive;
    }
    if content.starts_with(b"%PDF-") {
        return UploadKind::Pdf;
    }
    if content.starts_with(b"MZ") || content.starts_with(&[0x7F, b'E', b'L', b'F']) {
        return UploadKind::Executable;
    }
    if content.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
        || content.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || content.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
        || content.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
    {
        return UploadKind::Executable;
    }
    if content.starts_with(b"#!") {
        return UploadKind::Executable;
    }
    let text = crate::multipart::is_scannable_text(content_type, content);
    if text {
        return UploadKind::Text;
    }
    let _ = filename;
    UploadKind::Unknown
}

/// Whether the file *declares* itself an image (extension or content type).
pub fn declared_image(filename: Option<&str>, content_type: Option<&str>) -> bool {
    if let Some(ct) = content_type {
        if ct.to_ascii_lowercase().starts_with("image/") {
            return true;
        }
    }
    matches!(
        extension(filename).as_deref(),
        Some("png" | "jpg" | "jpeg" | "gif" | "webp" | "bmp" | "ico" | "tif" | "tiff")
    )
}

/// Lowercased extension of a filename (without the dot).
pub fn extension(filename: Option<&str>) -> Option<String> {
    let name = filename?;
    let idx = name.rfind('.')?;
    let ext = name[idx + 1..].trim();
    if ext.is_empty() || ext.len() > 12 {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// First hidden executable/script marker found in a binary file's head or
/// tail scan regions, if any. Text-classified parts (SVG, HTML) are skipped:
/// their script content is handled by the regular XSS heuristics.
pub fn hidden_payload_markers(
    content: &[u8],
    kind: crate::event::UploadKind,
) -> Option<&'static str> {
    use crate::event::UploadKind;
    if !matches!(
        kind,
        UploadKind::Image | UploadKind::Archive | UploadKind::Pdf
    ) {
        return None;
    }
    const MARKERS: &[&str] = &[
        "<?php",
        "<?=",
        "<script",
        "javascript:",
        "system(",
        "passthru(",
        "shell_exec(",
        "eval(base64_decode",
        "Assert(",
        "preg_replace(",
        "/etc/passwd",
    ];
    let head = &content[..content.len().min(HEAD_SCAN)];
    for m in MARKERS {
        if find_ci(head, m.as_bytes()) {
            return Some(m);
        }
    }
    if content.len() > HEAD_SCAN + TAIL_SCAN {
        let tail = &content[content.len() - TAIL_SCAN..];
        for m in MARKERS {
            if find_ci(tail, m.as_bytes()) {
                return Some(m);
            }
        }
    }
    None
}

/// Case-insensitive literal search (marker scans are small and ad hoc — no
/// automaton needed).
fn find_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Per-IP sliding window over upload volume (files and bytes) — the
/// behavioral half of F10: mass-upload campaigns (spam dumps, backup
/// exfiltration, archive bombing) cross the thresholds even when every
/// single file is benign.
#[derive(Debug)]
pub struct UploadTracker {
    window: Duration,
    max_uploads: u32,
    max_total_bytes: u64,
    enforce: bool,
    max_files_tracked: usize,
    entries: HashMap<IpAddr, Vec<(u64, Instant)>>,
}

impl UploadTracker {
    /// Create from config (thresholds of 0 disable the respective check).
    pub fn from_config(cfg: &UploadsConfig) -> Self {
        Self {
            window: Duration::from_secs(cfg.flood.window_secs),
            max_uploads: cfg.flood.max_uploads,
            max_total_bytes: u64::from(cfg.flood.max_total_mb).saturating_mul(1024 * 1024),
            enforce: cfg.mode.is_enforce(),
            max_files_tracked: 256,
            entries: HashMap::new(),
        }
    }

    /// Record one request's uploads and return the flood signals it crossed.
    pub fn record(&mut self, ip: IpAddr, uploads: &[UploadInfo]) -> Vec<Signal> {
        if uploads.is_empty() || (self.max_uploads == 0 && self.max_total_bytes == 0) {
            return Vec::new();
        }
        let now = Instant::now();
        let hits = self.entries.entry(ip).or_default();
        hits.retain(|(_, ts)| now.duration_since(*ts) < self.window);
        if hits.len() + uploads.len() > self.max_files_tracked {
            let overflow = hits.len() + uploads.len() - self.max_files_tracked;
            hits.drain(..overflow.min(hits.len()));
        }
        for u in uploads {
            hits.push((u.size, now));
        }

        let count = hits.len() as u32;
        let total: u64 = hits.iter().map(|(b, _)| b).sum();
        let mut signals = Vec::new();
        if self.max_uploads > 0 && count >= self.max_uploads {
            signals.push(self.signal(format!(
                "{} files in {}s (limit {})",
                count,
                self.window.as_secs(),
                self.max_uploads
            )));
        }
        if self.max_total_bytes > 0 && total >= self.max_total_bytes {
            signals.push(self.signal(format!(
                "{} MiB in {}s (limit {} MiB)",
                total / (1024 * 1024),
                self.window.as_secs(),
                self.max_total_bytes / (1024 * 1024)
            )));
        }
        signals
    }

    fn signal(&self, detail: String) -> Signal {
        Signal {
            kind: SignalKind::UploadFlood,
            weight: if self.enforce { UPLOAD_FLOOD_WEIGHT } else { 0 },
            detail: Some(detail),
        }
    }

    /// Drop IPs whose window has gone quiet.
    pub fn prune(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, hits| {
            hits.retain(|(_, ts)| now.duration_since(*ts) < self.window);
            !hits.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::UploadKind;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 23))
    }

    fn upload(size: u64) -> UploadInfo {
        UploadInfo {
            size,
            ..Default::default()
        }
    }

    #[test]
    fn sniffs_common_formats() {
        assert_eq!(
            sniff_kind(b"\x89PNG\r\n\x1a\n rest", None, None),
            UploadKind::Image
        );
        assert_eq!(
            sniff_kind(b"\xff\xd8\xff\xe0 rest", None, None),
            UploadKind::Image
        );
        assert_eq!(sniff_kind(b"GIF89a.....", None, None), UploadKind::Image);
        assert_eq!(
            sniff_kind(b"RIFF\x00\x00\x00\x00WEBPVP8 ", None, None),
            UploadKind::Image
        );
        assert_eq!(
            sniff_kind(b"PK\x03\x04 zip", None, None),
            UploadKind::Archive
        );
        assert_eq!(
            sniff_kind(b"\x1f\x8b gzip", None, None),
            UploadKind::Archive
        );
        assert_eq!(sniff_kind(b"%PDF-1.7 rest", None, None), UploadKind::Pdf);
        assert_eq!(
            sniff_kind(b"MZ\x90\x00 exe", None, None),
            UploadKind::Executable
        );
        assert_eq!(
            sniff_kind(b"\x7fELF elf", None, None),
            UploadKind::Executable
        );
        assert_eq!(
            sniff_kind(b"#!/bin/sh\n", None, None),
            UploadKind::Executable
        );
        assert_eq!(sniff_kind(b"hello world", None, None), UploadKind::Text);
        assert_eq!(
            sniff_kind(b"\x00\x01\x02\xff", None, None),
            UploadKind::Unknown
        );
    }

    #[test]
    fn declared_image_helpers() {
        assert!(declared_image(Some("cat.PNG"), None));
        assert!(declared_image(None, Some("image/jpeg")));
        assert!(!declared_image(Some("notes.txt"), Some("text/plain")));
    }

    #[test]
    fn extension_extraction() {
        assert_eq!(extension(Some("a.tar.gz")).as_deref(), Some("gz"));
        assert_eq!(extension(Some("noext")).as_deref(), None);
        assert_eq!(extension(Some(".hidden")).as_deref(), Some("hidden"));
        assert_eq!(extension(None), None);
    }

    #[test]
    fn polyglot_markers_found_in_head_and_tail() {
        let mut gif = b"GIF89a".to_vec();
        gif.extend(std::iter::repeat(0x41).take(HEAD_SCAN + 16));
        assert!(hidden_payload_markers(&gif, UploadKind::Image).is_none());

        let mut php_head = b"GIF89a".to_vec();
        php_head.extend_from_slice(b"\x00\x00<?php system($_GET['c']); ?>");
        assert_eq!(
            hidden_payload_markers(&php_head, UploadKind::Image),
            Some("<?php")
        );

        let mut php_tail = b"\xff\xd8\xff\xe0".to_vec();
        php_tail.extend(std::iter::repeat(0x00).take(HEAD_SCAN + TAIL_SCAN - 32));
        php_tail.extend_from_slice(b"\xff\xd9<?php eval(base64_decode($_POST)); ?>");
        assert!(hidden_payload_markers(&php_tail, UploadKind::Image).is_some());
    }

    #[test]
    fn text_parts_never_flag_polyglot() {
        let svg = b"<svg><script>alert(1)</script></svg>".as_slice();
        assert_eq!(hidden_payload_markers(svg, UploadKind::Text), None);
    }

    #[test]
    fn flood_thresholds_fire_and_reset() {
        let cfg = UploadsConfig {
            mode: crate::config::UploadMode::Enforce,
            flood: crate::config::UploadFloodConfig {
                max_uploads: 3,
                max_total_mb: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut t = UploadTracker::from_config(&cfg);

        assert!(t.record(ip(), &[upload(100)]).is_empty());
        assert!(t.record(ip(), &[upload(100)]).is_empty());
        let sigs = t.record(ip(), &[upload(100)]);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].kind, SignalKind::UploadFlood);
        assert_eq!(sigs[0].weight, 25);

        // Bytes threshold on its own window.
        let other = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
        let big = upload(600 * 1024);
        assert!(t.record(other, std::slice::from_ref(&big)).is_empty());
        let sigs = t.record(other, &[big]);
        assert!(sigs
            .iter()
            .any(|s| s.detail.as_deref().is_some_and(|d| d.contains("MiB"))));
    }

    #[test]
    fn shadow_mode_zeroes_flood_weight() {
        let mut cfg = UploadsConfig::default();
        cfg.flood.max_uploads = 1;
        let mut t = UploadTracker::from_config(&cfg);
        let sigs = t.record(ip(), &[upload(1)]);
        assert_eq!(sigs[0].weight, 0, "shadow mode must not enforce");
    }

    #[test]
    fn prune_drops_quiet_ips() {
        let mut cfg = UploadsConfig::default();
        cfg.flood.window_secs = 0;
        cfg.flood.max_uploads = 1;
        let mut t = UploadTracker::from_config(&cfg);
        t.record(ip(), &[upload(1)]);
        t.prune();
        let sigs = t.record(ip(), &[upload(1)]);
        assert_eq!(sigs[0].detail.as_deref(), Some("1 files in 0s (limit 1)"));
    }
}
