use clap::Parser;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = sentry_cli::Cli::parse();

    let needs_config = matches!(
        cli.command,
        sentry_cli::cli::Command::Run | sentry_cli::cli::Command::Config { .. }
    );

    let cfg = if needs_config {
        let path = cli.config.as_ref().map(|s| PathBuf::from(s.as_str()));
        Some(sentry_cli::config::load(path.as_deref())?)
    } else {
        None
    };

    sentry_cli::logging::init(cli.verbose);

    sentry_cli::cmd::dispatch_with_config(cli, cfg).await
}
