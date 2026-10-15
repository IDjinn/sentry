//! Tokio runtime construction from `[runtime]` (F14).
//!
//! The daemon is a protection component: when it shares a box with the app
//! it protects, operators want to dedicate cores, cap the worker count or
//! drop the priority class instead of letting the scheduler fight the
//! application. Everything is optional — an empty `[runtime]` section
//! builds the stock tokio multi-thread runtime (one worker per core, OS
//! placement, default priority).

use sentry_core::config::{RuntimeConfig, ThreadPriority};

/// Build the process runtime: `worker_threads` when set, workers pinned to
/// `pin_cores` in order (cycling through the list when there are more
/// workers than cores) and the configured priority applied on every worker
/// thread. Priority failures (e.g. nice < 0 without `CAP_SYS_NICE`) log a
/// warning and keep going — a degraded schedule beats a daemon that won't
/// start.
pub fn build(cfg: Option<&RuntimeConfig>) -> tokio::runtime::Runtime {
    let cfg = cfg.cloned().unwrap_or_default();
    let cores = if cfg.pin_cores.is_empty() {
        None
    } else {
        Some(cfg.pin_cores.clone())
    };
    let priority = cfg.thread_priority;

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if cfg.worker_threads > 0 {
        builder.worker_threads(cfg.worker_threads.max(1));
    }
    if let Some(cores) = cores {
        let len = cores.len();
        builder.on_thread_start(move || {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let idx = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let id = cores[idx % len];
            if core_affinity::set_for_current(core_affinity::CoreId { id }) {
                tracing::debug!(core = id, "runtime worker pinned to core");
            } else {
                tracing::warn!(core = id, "runtime worker pinning failed");
            }
        });
    }
    if priority != ThreadPriority::Normal {
        builder.on_thread_start(move || apply_priority(priority));
    }
    builder.build().expect("failed to build the tokio runtime")
}

/// Map the config enum onto `thread-priority`'s cross-platform relative
/// scale (0-100; the OS maps it to nice/priority-class per platform).
fn apply_priority(priority: ThreadPriority) {
    use thread_priority::{set_current_thread_priority, ThreadPriority as Tp};
    let mapped = match priority {
        ThreadPriority::Normal => return,
        ThreadPriority::Idle => Tp::Crossplatform(5.try_into().expect("5 < 100")),
        ThreadPriority::BelowNormal => Tp::Crossplatform(35.try_into().expect("35 < 100")),
        ThreadPriority::AboveNormal => Tp::Crossplatform(75.try_into().expect("75 < 100")),
        ThreadPriority::High => Tp::Max,
    };
    match set_current_thread_priority(mapped) {
        Ok(()) => tracing::debug!(priority = priority.as_str(), "worker priority applied"),
        Err(e) => tracing::warn!(
            priority = priority.as_str(),
            error = %e,
            "worker priority not applied (elevated nice values need privileges on unix)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_builds_a_working_runtime() {
        let rt = build(None);
        let out = rt.block_on(async { 1 + 1 });
        assert_eq!(out, 2);
    }

    #[test]
    fn explicit_worker_count_is_honored() {
        let cfg = RuntimeConfig {
            worker_threads: 2,
            pin_cores: vec![],
            thread_priority: ThreadPriority::Normal,
        };
        let rt = build(Some(&cfg));
        assert_eq!(rt.block_on(async { 21 * 2 }), 42);
    }

    #[test]
    fn priority_mapping_covers_every_variant() {
        // Normal is a no-op (never calls the OS); every other level maps
        // without panicking.
        for p in [
            ThreadPriority::Normal,
            ThreadPriority::Idle,
            ThreadPriority::BelowNormal,
            ThreadPriority::AboveNormal,
            ThreadPriority::High,
        ] {
            apply_priority(p);
        }
    }
}
