//! Nginx access log tailing source.
//!
//! Watches the configured `access.log` via `notify` and feeds each new line
//! through the [`LogFormat`] parser, emitting [`RawEvent`]s into a tokio
//! channel. Handles file rotation by reopening when the file is truncated or
//! moved.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use sentry_core::event::RawEvent;
use sentry_core::source::{event_channel, Source};
use sentry_core::Result;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc::Sender;
use tracing::{error, info, warn};

use crate::parser::LogFormat;

/// Configuration for the nginx source.
#[derive(Debug, Clone)]
pub struct NginxSourceConfig {
    /// Path to the access log file.
    pub path: PathBuf,
    /// `log_format` string (nginx `$var` syntax).
    pub format: String,
    /// Whether to start from the end of file (tail) or the beginning.
    pub start_from_end: bool,
}

impl Default for NginxSourceConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/log/nginx/access.log"),
            format: r#"$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent""#.to_string(),
            start_from_end: true,
        }
    }
}

/// Nginx log file source.
pub struct NginxSource {
    cfg: NginxSourceConfig,
    fmt: Arc<LogFormat>,
}

impl NginxSource {
    /// Create a new nginx source, compiling the format string.
    pub fn new(cfg: NginxSourceConfig) -> Result<Self> {
        let fmt = LogFormat::compile(&cfg.format)
            .map_err(|e| sentry_core::CoreError::Config(format!("nginx log_format: {e}")))?;
        Ok(Self {
            cfg,
            fmt: Arc::new(fmt),
        })
    }
}

#[async_trait]
impl Source for NginxSource {
    fn name(&self) -> &'static str {
        "nginx"
    }

    async fn stream(&self) -> Result<tokio::sync::mpsc::Receiver<RawEvent>> {
        let (tx, rx) = event_channel(4096);
        let fmt = self.fmt.clone();
        let path = self.cfg.path.clone();
        let start_from_end = self.cfg.start_from_end;

        tokio::spawn(async move {
            if let Err(e) = tail_file(&path, start_from_end, fmt, tx).await {
                error!(source = "nginx", error = %e, "source stream ended with error");
            }
        });

        Ok(rx)
    }
}

/// Tail a file, emitting parsed events. Polls for new data every 100ms.
/// Detects truncation (rotation) by checking file size.
async fn tail_file(
    path: &Path,
    start_from_end: bool,
    fmt: Arc<LogFormat>,
    tx: Sender<RawEvent>,
) -> std::io::Result<()> {
    info!(path = %path.display(), "tailing nginx log");

    loop {
        // Try to open the file; retry if it doesn't exist yet.
        let mut file = loop {
            match tokio::fs::File::open(path).await {
                Ok(f) => break f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        };

        // Seek to end if configured.
        if start_from_end {
            let meta = file.metadata().await?;
            file.seek(std::io::SeekFrom::Start(meta.len())).await?;
        }

        let mut reader = BufReader::new(file);
        let mut last_size = reader.buffer().len() as u64;

        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).await?;

            if n > 0 {
                let trimmed = line.trim_end_matches(['\n', '\r']);
                if !trimmed.is_empty() {
                    match fmt.parse_line(trimmed) {
                        Ok(evt) => {
                            if tx.try_send(evt).is_err() {
                                warn!("event channel full or closed, stopping nginx source");
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            warn!(source = "nginx", line = trimmed, error = %e, "skipping unparseable line");
                        }
                    }
                }
                continue;
            }

            // No new data — check for rotation.
            match tokio::fs::metadata(path).await {
                Ok(meta) => {
                    let current_size = meta.len();
                    if current_size < last_size {
                        // File was truncated/rotated — reopen.
                        info!(path = %path.display(), "log rotation detected, reopening");
                        break;
                    }
                    last_size = current_size;
                }
                Err(_) => {
                    // File deleted — wait and reopen.
                    info!(path = %path.display(), "log file disappeared, waiting");
                    break;
                }
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
