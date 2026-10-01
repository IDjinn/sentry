//! TLS ClientHello telemetry (F8): SNI, JA3 and JA4 fingerprints.
//!
//! Parses the raw ClientHello bytes buffered from the socket before the
//! rustls handshake, so the inline edge can monitor the SSL layer itself:
//! tool fingerprints (JA3/JA4), the requested SNI (a honeypot signal when
//! it is missing or unknown) and the offered protocol versions. The parsed
//! bytes are replayed to rustls through a prefixed stream — the handshake
//! sees the identical octets.
//!
//! - **JA3** (Salesforce scheme): `md5(version,ciphers,exts,curves,ecpf)`
//!   with values in wire order.
//! - **JA4** (FoxIO scheme, openly specified): `t13d1516h2_<ciphers>_<exts>`
//!   — protocol + highest offered version + SNI kind + 2-digit cipher and
//!   extension counts (SNI/ALPN excluded from the extension count) + ALPN
//!   tag, then 12-hex truncated SHA-256 of the *sorted* cipher and
//!   extension lists.

use md5::Md5;
use sha2::{Digest as _, Sha256};

/// Expected ClientHello wire size cap (hard limit; real hellos stay < 4 KiB).
pub const MAX_HELLO_BYTES: usize = 64 * 1024;

/// Outcome of parsing a possibly-incomplete socket prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// A complete ClientHello was parsed.
    Hello(ClientHello),
    /// The buffer does not yet hold the full handshake message.
    NeedMore,
    /// The bytes are not a TLS ClientHello (wrong record type, wrong
    /// handshake message, malformed structure).
    Invalid,
}

/// Telemetry extracted from one ClientHello.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// Server Name Indication hostname, when presented.
    pub sni: Option<String>,
    /// JA3 fingerprint (32 lowercase hex chars, `md5` of the canonical
    /// string) — `None` only when the structure was unparseable.
    pub ja3: Option<String>,
    /// JA4 fingerprint (FoxIO scheme) — `None` only when unparseable.
    pub ja4: Option<String>,
    /// First ALPN protocol the client offered (lowercased).
    pub alpn: Option<String>,
}

/// Parse a socket prefix into [`ClientHello`] telemetry.
///
/// Handles ClientHello messages spanning multiple handshake records; call
/// again with a larger prefix while the result is [`Probe::NeedMore`].
pub fn parse(buf: &[u8]) -> Probe {
    if buf.len() > MAX_HELLO_BYTES {
        return Probe::Invalid;
    }
    let mut hs: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    let mut msg_len: Option<usize> = None;
    loop {
        if pos + 5 > buf.len() {
            return Probe::NeedMore;
        }
        if buf[pos] != 0x16 {
            return Probe::Invalid;
        }
        let rec_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        let body = pos + 5;
        if rec_len == 0 {
            return Probe::Invalid;
        }
        if body + rec_len > buf.len() {
            return Probe::NeedMore;
        }
        hs.extend_from_slice(&buf[body..body + rec_len]);
        pos = body + rec_len;
        let total = match msg_len {
            Some(t) => t,
            None => {
                if hs.len() < 4 {
                    // First record shorter than the handshake header —
                    // keep consuming records from the same buffer.
                    continue;
                }
                if hs[0] != 0x01 {
                    return Probe::Invalid;
                }
                let l = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
                msg_len = Some(4 + l);
                msg_len.unwrap()
            }
        };
        if hs.len() >= total {
            return match parse_body(&hs[4..total]) {
                Some(raw) => Probe::Hello(from_raw(&raw)),
                None => Probe::Invalid,
            };
        }
    }
}

struct RawHello {
    legacy_version: u16,
    ciphers: Vec<u16>,
    /// Extension type ids in wire order.
    ext_ids: Vec<u16>,
    sni: Option<String>,
    groups: Vec<u16>,
    ec_point_formats: Vec<u8>,
    supported_versions: Vec<u16>,
    alpn: Option<String>,
}

fn parse_body(b: &[u8]) -> Option<RawHello> {
    if b.len() < 2 + 32 + 1 {
        return None;
    }
    let legacy_version = u16::from_be_bytes([b[0], b[1]]);
    let mut p = 34;
    let sid_len = b[p] as usize;
    p += 1 + sid_len;
    if p + 2 > b.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    if cs_len % 2 != 0 || p + cs_len > b.len() {
        return None;
    }
    let mut ciphers = Vec::with_capacity(cs_len / 2);
    for i in 0..cs_len / 2 {
        ciphers.push(u16::from_be_bytes([b[p + 2 * i], b[p + 2 * i + 1]]));
    }
    p += cs_len;
    if p >= b.len() {
        return None;
    }
    let comp_len = b[p] as usize;
    p += 1 + comp_len;
    if p + 2 > b.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
    p += 2;
    if p + ext_total > b.len() {
        return None;
    }
    let end = p + ext_total;
    let mut ext_ids = Vec::new();
    let mut sni = None;
    let mut groups = Vec::new();
    let mut ec_point_formats = Vec::new();
    let mut supported_versions = Vec::new();
    let mut alpn = None;
    let mut e = p;
    while e + 4 <= end {
        let t = u16::from_be_bytes([b[e], b[e + 1]]);
        let l = u16::from_be_bytes([b[e + 2], b[e + 3]]) as usize;
        if e + 4 + l > end {
            return None;
        }
        let data = &b[e + 4..e + 4 + l];
        ext_ids.push(t);
        match t {
            0x0000 => sni = parse_sni(data),
            0x000A => groups = parse_u16_list(data, 2),
            0x000B => {
                if let Some(first) = data.first() {
                    let n = *first as usize;
                    if data.len() > n {
                        ec_point_formats = data[1..1 + n].to_vec();
                    }
                }
            }
            0x0010 => alpn = parse_alpn(data),
            0x002B => supported_versions = parse_u16_list(data, 1),
            _ => {}
        }
        e += 4 + l;
    }
    Some(RawHello {
        legacy_version,
        ciphers,
        ext_ids,
        sni,
        groups,
        ec_point_formats,
        supported_versions,
        alpn,
    })
}

fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = 2usize + list_len.min(data.len().saturating_sub(2));
    let mut e = 2usize;
    while e + 3 <= end {
        let name_type = data[e];
        let host_len = u16::from_be_bytes([data[e + 1], data[e + 2]]) as usize;
        e += 3;
        if e + host_len > end {
            return None;
        }
        if name_type == 0 {
            return std::str::from_utf8(&data[e..e + host_len])
                .ok()
                .map(|s| s.to_ascii_lowercase())
                .filter(|s| !s.is_empty());
        }
        e += host_len;
    }
    None
}

/// Parse a TLS vector of `u16` values. All TLS vector length prefixes
/// count **bytes** (`len_bytes` = 1 or 2 for the prefix width).
fn parse_u16_list(data: &[u8], len_bytes: usize) -> Vec<u16> {
    let (prefix, start) = match len_bytes {
        1 => (data.first().copied().unwrap_or(0) as usize, 1usize),
        _ => {
            if data.len() < 2 {
                return Vec::new();
            }
            (u16::from_be_bytes([data[0], data[1]]) as usize, 2usize)
        }
    };
    let end = (start + prefix).min(data.len());
    data[start..end]
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect()
}

fn parse_alpn(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let end = 2usize + list_len.min(data.len().saturating_sub(2));
    let mut e = 2usize;
    while e < end {
        let proto_len = data[e] as usize;
        e += 1;
        if e + proto_len > end {
            return None;
        }
        if proto_len > 0 {
            return std::str::from_utf8(&data[e..e + proto_len])
                .ok()
                .map(|s| s.to_ascii_lowercase());
        }
        e += proto_len;
    }
    None
}

fn from_raw(raw: &RawHello) -> ClientHello {
    let ja3_string = format!(
        "{},{},{},{},{}",
        raw.legacy_version,
        join_u16(&raw.ciphers),
        join_u16(&raw.ext_ids),
        join_u16(&raw.groups),
        raw.ec_point_formats
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("-"),
    );
    let ja3 = hex::encode(Md5::digest(ja3_string.as_bytes()));

    let sni_is_ip = raw
        .sni
        .as_deref()
        .map(|s| s.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or(false);
    let sni_char = match &raw.sni {
        Some(_) if sni_is_ip => 'i',
        Some(_) => 'd',
        None => 'n',
    };
    let version = if raw.supported_versions.contains(&0x0304) {
        "13"
    } else {
        match raw.legacy_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        }
    };
    let ext_count = raw
        .ext_ids
        .iter()
        .filter(|t| **t != 0x0000 && **t != 0x0010)
        .count();
    let alpn_tag = match &raw.alpn {
        Some(p) if p == "h2" => "h2".to_string(),
        Some(p) if p.starts_with("http/1") => "h1".to_string(),
        Some(p) => p.chars().take(2).collect::<String>(),
        None => "00".to_string(),
    };
    let part_a = format!(
        "t{}{}{:02}{:02}{}",
        version,
        sni_char,
        raw.ciphers.len().min(99),
        ext_count.min(99),
        alpn_tag
    );
    let mut sorted_ciphers = raw.ciphers.clone();
    sorted_ciphers.sort_unstable();
    let part_b = sha256_12(&join_u16(&sorted_ciphers));
    let mut sorted_exts = raw
        .ext_ids
        .iter()
        .copied()
        .filter(|t| *t != 0x0000 && *t != 0x0010)
        .collect::<Vec<_>>();
    sorted_exts.sort_unstable();
    let part_c = sha256_12(&join_u16(&sorted_exts));
    let ja4 = format!("{part_a}_{part_b}_{part_c}");

    ClientHello {
        sni: raw.sni.clone(),
        ja3: Some(ja3),
        ja4: Some(ja4),
        alpn: raw.alpn.clone(),
    }
}

fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

fn sha256_12(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    hex::encode(&digest[..6])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext_sni(host: &str) -> (u16, Vec<u8>) {
        // server_name_list: u16 list length + entry (name_type + u16 host
        // length + hostname)
        let mut body = Vec::new();
        body.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
        body.push(0x00); // name_type: host_name
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        body.extend_from_slice(host.as_bytes());
        (0x0000, body)
    }

    fn ext_u16_list(t: u16, values: &[u16], len_bytes: usize) -> (u16, Vec<u8>) {
        let mut body = match len_bytes {
            1 => vec![values.len() as u8 * 2],
            _ => vec![
                ((values.len() * 2) as u16 >> 8) as u8,
                (values.len() * 2) as u8,
            ],
        };
        for v in values {
            body.extend_from_slice(&v.to_be_bytes());
        }
        (t, body)
    }

    fn ext_alpn(proto: &str) -> (u16, Vec<u8>) {
        let mut body = vec![((proto.len() + 1) >> 8) as u8, (proto.len() + 1) as u8];
        body.push(proto.len() as u8);
        body.extend_from_slice(proto.as_bytes());
        (0x0010, body)
    }

    /// Build a full ClientHello record with the given ciphers/extensions.
    fn build_hello(legacy: u16, ciphers: &[u16], exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&legacy.to_be_bytes());
        body.extend_from_slice(&[0x42u8; 32]); // random
        body.push(0); // session_id
        body.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.push(1); // compression methods
        body.push(0);
        let mut ext_bytes = Vec::new();
        for (t, data) in exts {
            ext_bytes.extend_from_slice(&t.to_be_bytes());
            ext_bytes.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext_bytes.extend_from_slice(data);
        }
        body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_bytes);

        let mut record = vec![0x16, 0x03, 0x01];
        // record payload = handshake header (4) + body
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(0x01);
        // handshake length is a 3-byte (u24) big-endian value
        let msg_len = body.len();
        record.push(((msg_len >> 16) & 0xFF) as u8);
        record.push(((msg_len >> 8) & 0xFF) as u8);
        record.push((msg_len & 0xFF) as u8);
        record.extend_from_slice(&body);
        record
    }

    const CURL_CIPHERS: [u16; 3] = [0x1301, 0x1302, 0x00FF];

    fn curl_like_hello() -> Vec<u8> {
        build_hello(
            0x0303,
            &CURL_CIPHERS,
            &[
                ext_sni("example.com"),
                ext_u16_list(0x000A, &[29, 23, 24], 2),
                (0x000B, vec![1, 0]), // ec_point_formats: 1 format (uncompressed)
                ext_alpn("h2"),
                ext_u16_list(0x002B, &[0x0304, 0x0303], 1),
                (0x0017, vec![]),
            ],
        )
    }

    #[test]
    fn parses_sni_ja3_and_ja4() {
        let Probe::Hello(h) = parse(&curl_like_hello()) else {
            panic!("expected hello");
        };
        assert_eq!(h.sni.as_deref(), Some("example.com"));
        assert_eq!(h.alpn.as_deref(), Some("h2"));
        // Canonical JA3 string: version 771, ciphers 4865-4866-255,
        // extensions 0-10-11-16-43-23 (wire order), curves 29-23-24, ecpf 0.
        let ja3 = md5_hex("771,4865-4866-255,0-10-11-16-43-23,29-23-24,0");
        assert_eq!(h.ja3.as_deref(), Some(ja3.as_str()));
        // TLS 1.3 offered, domain SNI, 3 ciphers, 4 counted extensions
        // (6 minus SNI and ALPN), ALPN h2.
        let ja4 = format!(
            "t13d0304h2_{}_{}",
            sha256_12("255-4865-4866"),
            sha256_12("10-11-23-43")
        );
        assert_eq!(h.ja4.as_deref(), Some(ja4.as_str()));
    }

    #[test]
    fn missing_sni_marks_the_fingerprint() {
        let buf = build_hello(
            0x0303,
            &CURL_CIPHERS,
            &[
                ext_u16_list(0x000A, &[29, 23, 24], 2),
                ext_u16_list(0x002B, &[0x0304], 1),
            ],
        );
        let Probe::Hello(h) = parse(&buf) else {
            panic!("expected hello");
        };
        assert_eq!(h.sni, None);
        assert!(h.ja4.as_deref().unwrap_or_default().starts_with("t13n0302"));
    }

    #[test]
    fn ip_sni_uses_the_i_marker() {
        let buf = build_hello(
            0x0303,
            &CURL_CIPHERS,
            &[ext_sni("198.51.100.7"), ext_u16_list(0x002B, &[0x0304], 1)],
        );
        let Probe::Hello(h) = parse(&buf) else {
            panic!("expected hello");
        };
        assert!(h.ja4.as_deref().unwrap_or_default().starts_with("t13i0301"));
    }

    #[test]
    fn legacy_client_without_supported_versions_is_tls12() {
        let buf = build_hello(0x0303, &CURL_CIPHERS, &[(0x0017, vec![])]);
        let Probe::Hello(h) = parse(&buf) else {
            panic!("expected hello");
        };
        assert!(h.ja4.as_deref().unwrap_or_default().starts_with("t12n0301"));
    }

    #[test]
    fn fragmented_records_still_parse() {
        let buf = curl_like_hello();
        // Re-wrap the handshake message across two records so the message
        // body spans multiple handshake records.
        let msg = &buf[5..];
        let split = msg.len() / 2;
        let mut rewrapped = Vec::new();
        push_record(&mut rewrapped, 0x16, &msg[..split]);
        push_record(&mut rewrapped, 0x16, &msg[split..]);
        let Probe::Hello(h) = parse(&rewrapped) else {
            panic!("expected hello from fragmented records");
        };
        assert_eq!(h.sni.as_deref(), Some("example.com"));
    }

    fn push_record(out: &mut Vec<u8>, content_type: u8, payload: &[u8]) {
        out.push(content_type);
        out.extend_from_slice(&[0x03, 0x01]);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
    }

    #[test]
    fn truncated_buffer_needs_more() {
        let buf = curl_like_hello();
        assert_eq!(parse(&buf[..5]), Probe::NeedMore);
        assert_eq!(parse(&buf[..20]), Probe::NeedMore);
        assert_eq!(parse(&buf[..buf.len() - 1]), Probe::NeedMore);
    }

    #[test]
    fn non_tls_bytes_are_invalid() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n\r\n"), Probe::Invalid);
        let alert = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
        assert_eq!(parse(&alert), Probe::Invalid);
        let mut wrong_handshake = curl_like_hello();
        wrong_handshake[5] = 0x02; // server_hello
        assert_eq!(parse(&wrong_handshake), Probe::Invalid);
    }

    fn md5_hex(s: &str) -> String {
        hex::encode(Md5::digest(s.as_bytes()))
    }
}
