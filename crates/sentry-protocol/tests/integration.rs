//! Integration tests over the committed schema fixtures: both fixtures
//! must load and compile, and the game-relay binary fixtures must validate
//! end-to-end through the engine.

use std::path::PathBuf;

use sentry_protocol::compile::CompileOptions;
use sentry_protocol::{Compiled, ConnectionState, ProtocolEngine, ProtocolSchema};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn load_all() -> Compiled {
    let mut compiled = Compiled::default();
    for name in ["game-relay.protocol.yaml", "chat-relay.protocol.yaml"] {
        let text = std::fs::read_to_string(fixture(name)).unwrap();
        let schema = ProtocolSchema::from_yaml(&text).unwrap();
        compiled.add(schema, &CompileOptions::default()).unwrap();
    }
    compiled
}

fn game_frame(header: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(2 + payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn game_string(s: &[u8]) -> Vec<u8> {
    let mut out = (s.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(s);
    out
}

fn vlint(n: i64) -> Vec<u8> {
    let negative = n < 0;
    let v = n.unsigned_abs();
    // Layout matching the VLInt body: byte0 carries the MOST significant
    // 2 value bits; each continuation byte the next 6-bit group down to
    // the least significant (decode shifts acc left).
    let mut c = 0usize;
    while v >> (2 + 6 * c) > 0 {
        c += 1;
    }
    let sign = if negative { 4u8 } else { 0 };
    let mut out = vec![0x40 | (((c as u8) & 0x07) << 3) | sign | ((v >> (6 * c)) as u8 & 0x03)];
    for i in (0..c).rev() {
        out.push(((v >> (6 * i)) as u8 & 0x3F) | 0x40);
    }
    out
}

#[test]
fn fixtures_load_and_bind_ports() {
    let compiled = load_all();
    assert!(compiled.for_port(14901).is_some());
    assert!(compiled.for_port(8080).is_some());
    assert!(compiled.for_port(1234).is_none());
}

#[test]
fn game_full_session_flow() {
    let compiled = load_all();
    let engine = ProtocolEngine::new(compiled);
    let snapshot = engine.current();
    let proto = snapshot.for_port(14901).unwrap();
    let mut state = ConnectionState::new();

    let ticket = b"GAME-tester-3324";
    let sso = game_frame(400, &game_string(ticket));
    let info = engine.feed(proto, &mut state, &sso).unwrap();
    assert_eq!(&*info.message, "sso_ticket_event");

    let mut chat_payload = game_string(b"Hello, world");
    chat_payload.extend(game_string(b"smile"));
    chat_payload.extend(vlint(7));
    let chat = game_frame(2064, &chat_payload);
    let info = engine.feed(proto, &mut state, &chat).unwrap();
    assert_eq!(&*info.message, "chat_event");

    let ping = game_frame(4096, &game_string(b""));
    let info = engine.feed(proto, &mut state, &ping).unwrap();
    assert_eq!(&*info.message, "ping_event");
    assert!(info.keepalive);
    assert!(state.last_keepalive().is_some());
}

#[test]
fn game_unknown_header_and_flood() {
    let compiled = load_all();
    let engine = ProtocolEngine::new(compiled);
    let snapshot = engine.current();
    let proto = snapshot.for_port(14901).unwrap();
    let mut state = ConnectionState::new();

    let errs = engine
        .feed(proto, &mut state, &game_frame(7777, &[]))
        .unwrap_err();
    assert_eq!(&*errs[0].policy, "unknown_header");

    let empty_string = game_string(b"");
    let ping = game_frame(4096, &empty_string);
    for _ in 0..3 {
        let r = engine.feed(proto, &mut state, &ping);
        match r {
            Ok(_) | Err(_) => {}
        }
    }
    let errs = engine.feed(proto, &mut state, &ping).unwrap_err();
    assert!(
        errs.iter().any(|v| v.reason.contains("keepalive flood")),
        "expected flood violation, got {errs:?}"
    );
}
