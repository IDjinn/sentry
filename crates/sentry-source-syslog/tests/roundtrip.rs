//! End-to-end roundtrip: send a real datagram/TCP frame to a bound source
//! and assert the RawEvent that comes out.

use std::time::Duration;

use sentry_core::event::Transport;
use sentry_core::source::Source;
use sentry_source_syslog::{SyslogSource, SyslogSourceConfig, SyslogTransport};

/// Bind a throwaway socket to discover a free ephemeral port, then drop it.
///
/// Windows reserves ranges of ephemeral ports (Hyper-V etc.) and hands them
/// out from `:0` anyway — binding them afterwards fails with os error 10013.
/// Retry until the discovered port is actually bindable.
fn free_port() -> u16 {
    for _ in 0..20 {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = s.local_addr().unwrap().port();
        drop(s);
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("could not find a bindable ephemeral port (Windows excluded-range flake)");
}

#[tokio::test]
async fn udp_datagram_flows_through_source() {
    let port = free_port();
    let src = SyslogSource::new(SyslogSourceConfig {
        bind_addr: format!("127.0.0.1:{port}"),
        transport: SyslogTransport::Udp,
    })
    .unwrap();
    let mut rx = src.stream().await.unwrap();

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sock.send_to(
        b"<34>1 2003-10-11T22:14:15Z mymachine su - ID47 - failed for lonvick",
        format!("127.0.0.1:{port}"),
    )
    .await
    .unwrap();

    let evt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for event")
        .expect("channel closed");
    assert_eq!(evt.source, sentry_core::event::SourceKind::Syslog);
    assert_eq!(evt.transport, Transport::Udp);
    assert_eq!(evt.client_ip, Some("127.0.0.1".parse().unwrap()));
    assert_eq!(evt.server_port, Some(port));
    let data = match evt.protocol {
        sentry_core::event::ProtocolData::Syslog(d) => d,
        other => panic!("expected syslog payload, got {other:?}"),
    };
    assert_eq!(data.facility, 4);
    assert_eq!(data.severity, 2);
    assert_eq!(data.app_name.as_deref(), Some("su"));
    assert_eq!(data.message, "failed for lonvick");
    assert!(evt.raw.as_deref().unwrap().contains("failed for lonvick"));
}

#[tokio::test]
async fn tcp_newline_frame_flows_through_source() {
    let port = free_port();
    let src = SyslogSource::new(SyslogSourceConfig {
        bind_addr: format!("127.0.0.1:{port}"),
        transport: SyslogTransport::Tcp,
    })
    .unwrap();
    let mut rx = src.stream().await.unwrap();

    let mut sock = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    use tokio::io::AsyncWriteExt;
    sock.write_all(b"<13>1 - - - - - tcp hello\n")
        .await
        .unwrap();

    let evt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for event")
        .expect("channel closed");
    assert_eq!(evt.transport, Transport::Tcp);
    assert_eq!(evt.client_port, Some(sock.local_addr().unwrap().port()));
    let data = match evt.protocol {
        sentry_core::event::ProtocolData::Syslog(d) => d,
        other => panic!("expected syslog payload, got {other:?}"),
    };
    assert_eq!(data.message, "tcp hello");
}

#[tokio::test]
async fn tcp_octet_counting_frame_flows_through_source() {
    let port = free_port();
    let src = SyslogSource::new(SyslogSourceConfig {
        bind_addr: format!("127.0.0.1:{port}"),
        transport: SyslogTransport::Tcp,
    })
    .unwrap();
    let mut rx = src.stream().await.unwrap();

    let payload = "<13>1 - - - - - octet framed";
    let mut sock = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    use tokio::io::AsyncWriteExt;
    sock.write_all(format!("{} {}", payload.len(), payload).as_bytes())
        .await
        .unwrap();

    let evt = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timed out waiting for event")
        .expect("channel closed");
    let data = match evt.protocol {
        sentry_core::event::ProtocolData::Syslog(d) => d,
        other => panic!("expected syslog payload, got {other:?}"),
    };
    assert_eq!(data.message, "octet framed");
}
