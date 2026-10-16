//! Binary self-update (F13): check GitHub Releases and swap the running
//! binary in place.
//!
//! `sentry update` is the manual path and always works — `[update] enabled`
//! only gates the daemon's periodic *check*, which logs and never installs.
//!
//! Integrity: the crate's `checksums` feature verifies the downloaded
//! artifact against the `sha256:<hex>` digest GitHub publishes for every
//! release asset; a mismatch aborts before anything is installed. Install
//! goes through `self_replace` (atomic rename on unix, rename dance on
//! Windows), so a running process keeps the old image until the service is
//! restarted — which is what `[update] auto_restart` is for.

#![forbid(unsafe_code)]

use std::cmp::Ordering;

use color_eyre::eyre::eyre;
use sentry_core::config::{SentryConfig, UpdateConfig};

use self_update::update::Release;

/// Repository used when neither `--repo` nor `[update] repo` is set.
pub const DEFAULT_REPO: &str = "IDjinn/sentry";

const BIN_NAME: &str = "sentry";

/// Options for [`run`], parsed from `sentry update`.
#[derive(Debug, Clone, Default)]
pub struct UpdateOpts {
    /// Only compare versions; never download.
    pub check: bool,
    /// Pin the target release tag (e.g. `v0.2.0`). Applied only when newer
    /// than the running binary — no downgrades.
    pub version: Option<String>,
    /// `owner/name` override for `[update] repo`.
    pub repo: Option<String>,
    /// `Some(true)`/`Some(false)` override `[update] auto_restart`; `None`
    /// falls back to the config value (default: no restart, log a hint).
    pub restart: Option<bool>,
}

/// Split an `owner/name` repository slug.
pub fn parse_repo(repo: &str) -> color_eyre::Result<(String, String)> {
    let (owner, name) = repo
        .split_once('/')
        .ok_or_else(|| eyre!("repo must be `owner/name`, got {repo:?}"))?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return Err(eyre!("repo must be `owner/name`, got {repo:?}"));
    }
    Ok((owner.to_string(), name.to_string()))
}

/// Archive asset published by the release workflow for `target`:
/// `sentry-<triple>.tar.gz` on unix, `.zip` on Windows. The crate's default
/// asset matcher finds it by the target-triple substring.
pub fn asset_name(target: &str) -> String {
    if cfg!(windows) {
        format!("{BIN_NAME}-{target}.zip")
    } else {
        format!("{BIN_NAME}-{target}.tar.gz")
    }
}

/// Version of the running binary.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Container image deployments update by pulling a new image, not by
/// swapping the binary: the periodic check skips and `sentry update` warns.
pub fn in_container() -> bool {
    std::path::Path::new("/.dockerenv").exists()
        || std::env::var_os("KUBERNETES_SERVICE_HOST").is_some()
}

fn build_updater(
    config: &UpdateConfig,
    repo: Option<&str>,
    pinned: Option<&str>,
) -> color_eyre::Result<self_update::backends::github::AsyncUpdate> {
    let (owner, name) = parse_repo(repo.unwrap_or(&config.repo))?;
    let mut builder = self_update::backends::github::Update::configure();
    let builder = builder
        .repo_owner(owner)
        .repo_name(name)
        .bin_name(BIN_NAME)
        .current_version(current_version())
        .no_confirm(true)
        .check_install_path_writable(true)
        .show_download_progress(true);
    if let Some(tag) = pinned {
        builder.release_tag(tag);
    }
    Ok(builder.build_async()?)
}

/// Map the backend's structured errors onto actionable messages; anything
/// else keeps its own Display.
fn friendly(e: self_update::Error) -> color_eyre::Report {
    use self_update::errors::Error as E;
    let hint = match e {
        E::NoReleaseFound { .. } => "no published release yet — push a `v<version>` tag to run \
             .github/workflows/release.yml"
            .to_string(),
        E::NotFound { .. } => {
            "release repository not found — check `--repo` / sentry › update › repo".to_string()
        }
        E::Unauthorized { .. } => {
            "GitHub rejected the auth token (GH_TOKEN / GITHUB_TOKEN)".to_string()
        }
        E::RateLimited { .. } => {
            "GitHub API rate limit exhausted — export GH_TOKEN to move to the 5000/h budget"
                .to_string()
        }
        E::ChecksumMismatch { .. } => {
            "downloaded artifact failed SHA-256 verification — nothing was installed".to_string()
        }
        E::InstallPathNotWritable { .. } => {
            "cannot write next to the running binary — check permissions \
             (Windows: elevated shell; stop the Sentry service first)"
                .to_string()
        }
        other => return other.into(),
    };
    eyre!("{hint}")
}

/// Newest published release strictly newer than the running binary
/// (`None` = up to date). Never downloads or installs anything.
pub async fn check_available(
    config: &UpdateConfig,
    repo: Option<&str>,
) -> color_eyre::Result<Option<Release>> {
    let updater = build_updater(config, repo, None)?;
    updater.is_update_available_async().await.map_err(friendly)
}

/// Resolve a pinned tag (for `--version`) to its release.
async fn pinned_release(
    config: &UpdateConfig,
    repo: Option<&str>,
    tag: &str,
) -> color_eyre::Result<Release> {
    let updater = build_updater(config, repo, Some(tag))?;
    updater
        .get_release_version_async(tag)
        .await
        .map_err(friendly)
}

/// Download and install `pinned` (exact tag) or the newest release. The
/// file on disk is replaced; running processes keep the old image until
/// restarted.
pub async fn apply(
    config: &UpdateConfig,
    repo: Option<&str>,
    pinned: Option<&str>,
) -> color_eyre::Result<self_update::VersionStatus> {
    let updater = build_updater(config, repo, pinned)?;
    updater.update_async().await.map_err(friendly)
}

/// `sentry update` handler.
pub async fn run(cfg: Option<&SentryConfig>, opts: UpdateOpts) -> color_eyre::Result<()> {
    let uc = cfg.map(|c| c.update.clone()).unwrap_or_default();
    let repo = opts.repo.as_deref();

    if in_container() {
        tracing::warn!(
            "running inside a container image — binary updates are image \
             pulls; this will swap a binary a new image would overwrite"
        );
    }

    let latest = match &opts.version {
        Some(tag) => Some(pinned_release(&uc, repo, tag).await?),
        None => check_available(&uc, repo).await?,
    };
    let latest = match latest {
        Some(release) => release,
        None => {
            println!(
                "sentry v{} is up to date (repo: {})",
                current_version(),
                repo.unwrap_or(&uc.repo)
            );
            return Ok(());
        }
    };
    match self_update::version::cmp_versions(current_version(), latest.version()) {
        Ok(Ordering::Greater) => {
            println!(
                "already running v{} — requested v{} is older (no downgrades)",
                current_version(),
                latest.version()
            );
            return Ok(());
        }
        Ok(_) => {}
        Err(e) => return Err(eyre!("cannot compare versions: {e}")),
    }

    println!(
        "sentry v{} -> v{} (repo: {})",
        current_version(),
        latest.version(),
        repo.unwrap_or(&uc.repo)
    );
    if opts.check {
        return Ok(());
    }

    let want_restart = opts.restart.unwrap_or(uc.auto_restart);
    let mut stopped = false;
    if crate::service::running() {
        if want_restart {
            match crate::service::stop() {
                Ok(()) => stopped = true,
                Err(e) if cfg!(windows) => {
                    return Err(eyre!(
                        "could not stop the Sentry service ({e}) — stop it first with \
                         `sc stop Sentry`, then re-run `sentry update`"
                    ));
                }
                Err(e) => {
                    tracing::warn!(
                        "could not stop the service ({e}) — the binary will be swapped \
                         anyway; restart the service manually afterwards"
                    );
                }
            }
        } else {
            println!(
                "note: the Sentry service is running and will keep the old binary until \
                 restarted — set [update] auto_restart = true, pass --restart, or run \
                 `sentry service restart` after this"
            );
        }
    }

    let status = apply(&uc, repo, opts.version.as_deref()).await?;
    if stopped {
        crate::service::start()?;
        println!("service restarted");
    }
    if status.is_updated() {
        println!(
            "updated to v{} — restart running daemons to pick it up",
            status.version()
        );
    } else {
        println!("already up to date (v{})", status.version());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_splits_owner_and_name() {
        assert_eq!(
            parse_repo(DEFAULT_REPO).unwrap(),
            ("IDjinn".to_string(), "sentry".to_string())
        );
        assert_eq!(
            parse_repo("a/b").unwrap(),
            ("a".to_string(), "b".to_string())
        );
    }

    #[test]
    fn parse_repo_rejects_malformed_slugs() {
        assert!(parse_repo("").is_err());
        assert!(parse_repo("just-a-name").is_err());
        assert!(parse_repo("a/b/c").is_err());
        assert!(parse_repo("owner/").is_err());
        assert!(parse_repo("/name").is_err());
    }

    #[test]
    fn asset_name_matches_release_workflow_archive() {
        let name = asset_name("x86_64-unknown-linux-gnu");
        if cfg!(windows) {
            assert_eq!(name, "sentry-x86_64-unknown-linux-gnu.zip");
        } else {
            assert_eq!(name, "sentry-x86_64-unknown-linux-gnu.tar.gz");
        }
        // The crate's default matcher finds the asset by triple substring.
        assert!(name.contains(&format!("{BIN_NAME}-")));
    }

    #[test]
    fn current_version_is_a_version_string() {
        let v = current_version();
        assert!(!v.is_empty());
        assert!(self_update::version::cmp_versions(v, v).unwrap() == Ordering::Equal);
    }

    #[test]
    fn update_opts_default_disables_restart_and_check() {
        let opts = UpdateOpts::default();
        assert!(!opts.check);
        assert!(opts.version.is_none());
        assert!(opts.repo.is_none());
        assert!(opts.restart.is_none());
    }
}
