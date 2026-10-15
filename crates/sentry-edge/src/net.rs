//! Listener socket tuning (F14).
//!
//! Edge listeners bind through `socket2` instead of `TcpListener::bind` so
//! the kernel-level knobs nginx exposes apply here too:
//!
//! - `SO_REUSEADDR` always (fast restart);
//! - `SO_REUSEPORT` per accept worker (unix) — each worker owns a kernel
//!   accept queue, removing the single-listener accept bottleneck;
//! - configurable listen backlog (0 = system maximum);
//! - configurable `TCP_NODELAY`, keepalive and `SO_SNDBUF`/`SO_RCVBUF` on
//!   client-facing connections.
//!
//! `TCP_DEFER_ACCEPT`/`TCP_QUICKACK` stay out: the crate forbids unsafe and
//! there is no safe wrapper for them yet (`TCP_QUICKACK` also resets after
//! every ACK, so a listener-level knob would be misleading).
//!
//! The event loop itself (epoll on Linux, kqueue on macOS, IOCP on
//! Windows) is tokio/mio — there is nothing to switch on.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

/// Client-facing TCP flags (`[edge] tcp_*`), applied to every accepted
/// connection and projected from the config by the proxy.
#[derive(Debug, Clone, Copy)]
pub struct TcpTuning {
    /// Write request/response payloads immediately (`TCP_NODELAY`).
    pub nodelay: bool,
    /// Keepalive idle time in seconds; `0` disables keepalive.
    pub keepalive_secs: u64,
    /// `SO_SNDBUF` in KiB; `0` = system default.
    pub send_buffer_kb: u32,
    /// `SO_RCVBUF` in KiB; `0` = system default.
    pub recv_buffer_kb: u32,
}

impl Default for TcpTuning {
    fn default() -> Self {
        Self {
            nodelay: true,
            keepalive_secs: 60,
            send_buffer_kb: 0,
            recv_buffer_kb: 0,
        }
    }
}

/// How to bind one edge listener.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListenerOptions {
    /// Listen backlog; `0` = system maximum (`SOMAXCONN`).
    pub backlog: u32,
    /// Set `SO_REUSEPORT` so several sockets can bind the same port
    /// (unix; ignored elsewhere).
    pub reuseport: bool,
    /// Client-facing flags for accepted connections.
    pub tuning: TcpTuning,
}

/// System listen backlog when the config leaves it at 0: the kernel
/// maximum on Linux (`/proc/sys/net/core/somaxconn`, re-read at startup),
/// `SOMAXCONN` elsewhere.
fn system_backlog() -> u32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(v) = std::fs::read_to_string("/proc/sys/net/core/somaxconn") {
            if let Ok(n) = v.trim().parse::<u32>() {
                return n.clamp(16, 65_535);
            }
        }
        4096
    }
    #[cfg(not(target_os = "linux"))]
    {
        1024
    }
}

/// Bind `addr` with the requested socket options. `reuseport` is only
/// applied on unix — on Windows a second bind would fail, so callers pass
/// `reuseport = false` there (the helper ignores the flag off-unix).
pub fn bind_listener(addr: SocketAddr, opts: ListenerOptions) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    if opts.reuseport {
        socket.set_reuse_port(true)?;
    }
    apply_buffers(&socket, &opts.tuning);
    socket.bind(&addr.into())?;
    let backlog = if opts.backlog == 0 {
        system_backlog()
    } else {
        opts.backlog
    };
    socket.listen(backlog.clamp(1, i32::MAX as u32) as i32)?;
    let listener = TcpListener::from_std(socket.into())?;
    Ok(listener)
}

/// `SO_SNDBUF`/`SO_RCVBUF` in KiB (0 = leave the system default). On Linux
/// buffers set on the listening socket are inherited by accepted sockets.
fn apply_buffers(socket: &Socket, tuning: &TcpTuning) {
    if tuning.send_buffer_kb > 0 {
        let _ = socket.set_send_buffer_size((tuning.send_buffer_kb as usize) * 1024);
    }
    if tuning.recv_buffer_kb > 0 {
        let _ = socket.set_recv_buffer_size((tuning.recv_buffer_kb as usize) * 1024);
    }
}

/// Apply the client-facing TCP flags to a freshly accepted connection.
/// Keepalive probe count stays at the system default off-Windows: socket2
/// only exposes it per-socket on Windows.
pub fn tune_accepted(stream: &tokio::net::TcpStream, tuning: &TcpTuning) {
    let sock: socket2::SockRef<'_> = stream.into();
    if tuning.nodelay {
        let _ = sock.set_nodelay(true);
    }
    if tuning.send_buffer_kb > 0 {
        let _ = sock.set_send_buffer_size((tuning.send_buffer_kb as usize) * 1024);
    }
    if tuning.recv_buffer_kb > 0 {
        let _ = sock.set_recv_buffer_size((tuning.recv_buffer_kb as usize) * 1024);
    }
    if tuning.keepalive_secs == 0 {
        return;
    }
    #[cfg_attr(windows, allow(unused_mut))]
    let mut ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(tuning.keepalive_secs));
    #[cfg(not(windows))]
    {
        ka = ka.with_interval(Duration::from_secs(10));
    }
    let _ = sock.set_tcp_keepalive(&ka);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn free_addr() -> SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], 0))
    }

    #[tokio::test]
    async fn binds_with_backlog_and_reuseport() {
        let l1 = bind_listener(
            free_addr(),
            ListenerOptions {
                backlog: 64,
                reuseport: false,
                tuning: TcpTuning::default(),
            },
        )
        .expect("plain bind");
        let addr = l1.local_addr().unwrap();

        // A second bind on the same port requires SO_REUSEPORT (unix). On
        // Windows this fails — the daemon passes reuseport=false there.
        #[cfg(unix)]
        {
            let l2 = bind_listener(
                addr,
                ListenerOptions {
                    backlog: 64,
                    reuseport: true,
                    tuning: TcpTuning::default(),
                },
            )
            .expect("reuseport bind on the same port");
            assert_eq!(l2.local_addr().unwrap().port(), addr.port());
        }
        #[cfg(not(unix))]
        {
            let _ = addr;
        }
    }

    #[tokio::test]
    async fn backlog_zero_falls_back_to_the_system_maximum() {
        let listener = bind_listener(free_addr(), ListenerOptions::default()).expect("bind");
        assert!(listener.local_addr().is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_backlog_reads_somaxconn() {
        let v = system_backlog();
        assert!((16..=65_535).contains(&v));
    }
}
