use clap::Parser;
use std::path::PathBuf;

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = sentry_cli::Cli::parse();

    let cfg = {
        let path = cli.config.as_ref().map(|s| PathBuf::from(s.as_str()));
        match sentry_cli::config::load(path.as_deref()) {
            Ok(c) => Some(c),
            Err(e) => {
                let needs_config = match &cli.command {
                    sentry_cli::cli::Command::Run => true,
                    sentry_cli::cli::Command::Config { action } => !matches!(
                        action,
                        sentry_cli::cli::ConfigCmd::Migrate { .. }
                            | sentry_cli::cli::ConfigCmd::Files
                    ),
                    _ => false,
                };
                if needs_config {
                    return Err(e);
                }
                None
            }
        }
    };

    sentry_cli::logging::init(cli.verbose);

    // The runtime is built AFTER the config loads so `sentry { runtime }` (worker
    // threads, CPU pinning, priority — F14) applies to every command.
    let runtime = sentry_cli::runtime::build(cfg.as_ref().map(|c| &c.runtime));
    runtime.block_on(sentry_cli::cmd::dispatch_with_config(cli, cfg))
}
