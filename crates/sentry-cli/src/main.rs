use clap::Parser;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cli = sentry_cli::Cli::parse();

    let cfg = {
        let path = cli.config.as_ref().map(|s| PathBuf::from(s.as_str()));
        match sentry_cli::config::load(path.as_deref()) {
            Ok(c) => Some(c),
            Err(e) => {
                let needs_config = matches!(
                    cli.command,
                    sentry_cli::cli::Command::Run | sentry_cli::cli::Command::Config { .. }
                );
                if needs_config {
                    return Err(e);
                }
                None
            }
        }
    };

    sentry_cli::logging::init(cli.verbose);

    sentry_cli::cmd::dispatch_with_config(cli, cfg).await
}
