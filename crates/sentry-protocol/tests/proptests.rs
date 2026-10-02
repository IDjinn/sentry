//! Property tests for the compiled validator (F9).

use proptest::prelude::*;

use sentry_protocol::compile::CompileOptions;
use sentry_protocol::{Compiled, ConnectionState, ProtocolEngine, ProtocolSchema};

const SIMPLE: &str = r#"
id: prop
transport: {protocol: tcp, ports: [0]}
on_message:
  run: "check_len! | parse_header!"
policies:
  default: {weight: 20}
messages:
  ping_event:
    when: {header: 4096}
    keepalive: true
    validate:
      - payload_len: u16 >0 <512
"#;

/// Frame builder mirroring the schema framing: [len:4][header:2][payload].
fn frame(header: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(2 + payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&header.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// The engine never panics on arbitrary bytes; violations carry the
    /// framing/unknown-header policy.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        let schema = ProtocolSchema::from_yaml(SIMPLE).unwrap();
        let mut compiled = Compiled::default();
        compiled.add(schema, &CompileOptions::default()).unwrap();
        let engine = ProtocolEngine::new(compiled);
        let snapshot = engine.current();
        let proto = snapshot.for_port(0).unwrap();
        let mut state = ConnectionState::new();
        let _ = sentry_protocol::feed_on(proto, &mut state, &bytes);
    }

    /// Compiled verdict matches a hand-written reference check on the
    /// same frame: VM == arithmetic + bounds.
    #[test]
    fn compiled_matches_reference(
        header in any::<u16>(),
        payload_len in 0usize..64,
        byte in any::<u8>(),
    ) {
        let payload = vec![byte; payload_len];
        let frame = frame(header, &payload);
        let schema = ProtocolSchema::from_yaml(SIMPLE).unwrap();
        let mut compiled = Compiled::default();
        compiled.add(schema, &CompileOptions::default()).unwrap();
        let engine = ProtocolEngine::new(compiled);
        let snapshot = engine.current();
        let proto = snapshot.for_port(0).unwrap();
        let mut state = ConnectionState::new();
        let got = sentry_protocol::feed_on(proto, &mut state, &frame).is_ok();

        let declared = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        let want = header == 4096
            && frame.len() == 4 + declared
            && payload_len > 0
            && payload_len < 512;
        prop_assert_eq!(got, want);
    }
}
