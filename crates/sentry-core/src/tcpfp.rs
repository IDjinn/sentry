//! Passive SYN TCP fingerprinting (MuonFP / p0f style).
//!
//! A SYN's window size, TCP options, MSS and window scale form a stable
//! per-stack signature. High-rate scanners (masscan, zmap) handcraft their
//! probes and are trivially separable from real OS stacks — the port scans
//! HTTP access logs never see (F3.2).
//!
//! Fingerprint code format: `window:options:MSS:wscale` where `options` is
//! empty when the SYN carries no TCP options at all (real stacks always send
//! options) and `o` otherwise. masscan/zmap defaults collapse to `65535:::`.

/// Parsed SYN fingerprint components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynFingerprint {
    /// TCP window size from the SYN header.
    pub window: u16,
    /// Advertised MSS from the options block, when present.
    pub mss: Option<u16>,
    /// Advertised window scale, when present.
    pub wscale: Option<u8>,
    /// Whether the SYN carried any TCP options (real stacks always do).
    pub has_options: bool,
}

impl SynFingerprint {
    /// Build a fingerprint from the raw SYN header parts.
    ///
    /// `options` is the raw TCP options bytes (TLV: kind, len, value).
    pub fn from_parts(window: u16, options: &[u8]) -> Self {
        let mut mss = None;
        let mut wscale = None;
        let mut has_options = false;
        let mut i = 0;
        while i < options.len() {
            let kind = options[i];
            match kind {
                0 | 1 => {
                    // EOL / NOP: single byte, no length field.
                    i += 1;
                    if kind == 0 {
                        break;
                    }
                    continue;
                }
                _ => {
                    if i + 1 >= options.len() {
                        break;
                    }
                    let len = options[i + 1] as usize;
                    if len < 2 || i + len > options.len() {
                        break;
                    }
                    let value = &options[i + 2..i + len];
                    match kind {
                        2 if value.len() == 2 => {
                            mss = Some(u16::from_be_bytes([value[0], value[1]]))
                        }
                        3 if value.len() == 1 => wscale = Some(value[0]),
                        _ => {}
                    }
                    has_options = true;
                    i += len;
                }
            }
        }
        Self {
            window,
            mss,
            wscale,
            has_options,
        }
    }

    /// Fingerprint code (`window:options:MSS:wscale`).
    pub fn code(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.window,
            if self.has_options { "o" } else { "" },
            self.mss.map(|m| m.to_string()).unwrap_or_default(),
            self.wscale.map(|w| w.to_string()).unwrap_or_default(),
        )
    }
}

/// Match a fingerprint code against the known high-rate scanner table.
///
/// Returns a short tool name for the signal `detail`. The table is
/// deliberately conservative — unknown stacks must not alert.
pub fn scanner_name(code: &str) -> Option<&'static str> {
    match code {
        // No TCP options at all: no real OS stack does this.
        "65535:::" => Some("zmap/masscan-style high-rate scanner"),
        // masscan's default SYN probe (window 1024, MSS only).
        "1024::1460:" => Some("masscan"),
        // Best-effort nmap SYN scan template (window 1024, options, MSS 1460).
        "1024:o:1460:" => Some("nmap (probable)"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_options_code_matches_backlog_signature() {
        let fp = SynFingerprint::from_parts(65535, &[]);
        assert!(!fp.has_options);
        assert_eq!(fp.code(), "65535:::");
        assert_eq!(
            scanner_name("65535:::"),
            Some("zmap/masscan-style high-rate scanner")
        );
    }

    #[test]
    fn parses_mss_and_wscale_from_options() {
        // MSS(2, len 4, 1460) + WS(3, len 3, scale 7) + SACK(4, len 2).
        let opts = [2u8, 4, 0x05, 0xb4, 3, 3, 7, 4, 2, 1, 1];
        let fp = SynFingerprint::from_parts(8192, &opts);
        assert!(fp.has_options);
        assert_eq!(fp.mss, Some(1460));
        assert_eq!(fp.wscale, Some(7));
        assert_eq!(fp.code(), "8192:o:1460:7");
        assert_eq!(
            scanner_name(&fp.code()),
            None,
            "normal stack must not alert"
        );
    }

    #[test]
    fn masscan_default_signature_matches() {
        // MSS only, no window scale: this code is shared between masscan's
        // default probe and nmap's SYN template — the conservative label is
        // "nmap (probable)".
        let opts = [2u8, 4, 0x05, 0xb4];
        let fp = SynFingerprint::from_parts(1024, &opts);
        assert_eq!(fp.code(), "1024:o:1460:");
        assert_eq!(scanner_name(&fp.code()), Some("nmap (probable)"));
        // masscan's raw variant carries no options at all.
        let fp = SynFingerprint::from_parts(1024, &[]);
        assert_eq!(fp.code(), "1024:::");
        assert_eq!(
            scanner_name(&fp.code()),
            None,
            "options-less window 1024 alone is not a known signature"
        );
    }

    #[test]
    fn truncated_options_do_not_panic() {
        for opts in [
            &[][..],
            &[2u8][..],
            &[2, 8, 1][..],
            &[3, 3][..],
            &[0][..],
            &[1, 1, 1][..],
        ] {
            let fp = SynFingerprint::from_parts(512, opts);
            let _ = fp.code();
        }
        let fp = SynFingerprint::from_parts(512, &[2, 4, 0x05]);
        assert_eq!(fp.mss, None, "truncated MSS value is dropped");
    }

    #[test]
    fn nops_and_eol_are_skipped() {
        let opts = [1u8, 1, 3, 3, 5, 0];
        let fp = SynFingerprint::from_parts(8192, &opts);
        assert_eq!(fp.wscale, Some(5));
        assert!(fp.has_options);
    }

    #[test]
    fn unknown_codes_return_none() {
        assert_eq!(scanner_name("29200:o:1460:7"), None);
        assert_eq!(scanner_name(""), None);
    }
}
