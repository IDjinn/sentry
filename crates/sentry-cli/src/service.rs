//! Service mode (F4.1): run the daemon under the OS service manager.
//!
//! - Linux: systemd unit (`/etc/systemd/system/sentry.service`).
//! - macOS: launchd agent (`~/Library/LaunchAgents/com.sentry.daemon.plist`).
//! - Windows: real SCM integration (feature `service`, `windows-service`
//!   crate) driven by `sentry service run`; install/uninstall invoke `sc.exe`
//!   with an argument list (never a shell string) and require admin.
//!
//! Template rendering is pure and unit-tested; the install commands are
//! best-effort — when they fail (no root/admin), the generated file/command
//! is printed for manual installation.

#![forbid(unsafe_code)]

use std::fmt::Write as _;
use std::path::{Component, Path, PathBuf};

const SERVICE_NAME: &str = "sentry";
const WINDOWS_SERVICE_NAME: &str = "Sentry";

/// Absolute path of the running sentry executable, normalized.
///
/// Rejects paths that would traverse upwards (`..` components) before they
/// are embedded into unit files or service registrations.
pub fn exe_path() -> color_eyre::Result<PathBuf> {
    let exe = std::env::current_exe()
        .map_err(|e| color_eyre::eyre::eyre!("cannot resolve executable path: {e}"))?;
    validate_service_path(&exe)?;
    Ok(exe)
}

/// Normalize a path and refuse `..` traversal before it reaches a unit file
/// or the service manager.
fn validate_service_path(path: &Path) -> color_eyre::Result<()> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(color_eyre::eyre::eyre!(
            "refusing service path with `..` components: {}",
            path.display()
        ));
    }
    Ok(())
}

/// Refuse shell metacharacters in arguments handed to the process API
/// (defense in depth — `Command` never spawns a shell, but our arguments end
/// up inside unit files and service registrations where they must stay inert).
fn sanitize_arg(arg: &str) -> color_eyre::Result<&str> {
    if arg
        .chars()
        .any(|c| matches!(c, ';' | '&' | '|' | '$' | '`' | '\n' | '\r' | '<' | '>'))
    {
        return Err(color_eyre::eyre::eyre!(
            "refusing service argument with shell metacharacters"
        ));
    }
    Ok(arg)
}

/// Validated plist location under the user's LaunchAgents directory.
fn home_plist_path() -> color_eyre::Result<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = Path::new(&home).join("Library/LaunchAgents/com.sentry.daemon.plist");
    validate_service_path(&path)?;
    Ok(path)
}

/// systemd unit contents.
pub fn systemd_unit(exec: &str, user: &str, workdir: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "[Unit]");
    let _ = writeln!(out, "Description=Sentry access monitor daemon");
    let _ = writeln!(out, "After=network-online.target postgresql.service");
    let _ = writeln!(out, "Wants=network-online.target");
    let _ = writeln!(out);
    let _ = writeln!(out, "[Service]");
    let _ = writeln!(out, "ExecStart={exec} run");
    let _ = writeln!(out, "WorkingDirectory={workdir}");
    let _ = writeln!(out, "User={user}");
    let _ = writeln!(out, "Restart=on-failure");
    let _ = writeln!(out, "RestartSec=5");
    let _ = writeln!(out, "# Secrets come from the environment:");
    let _ = writeln!(
        out,
        "# SENTRY_CF_TOKEN, SENTRY_LLM_KEY, SENTRY_WEBHOOK_SECRET, ..."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "[Install]");
    let _ = writeln!(out, "WantedBy=multi-user.target");
    out
}

/// launchd plist contents.
pub fn launchd_plist(exec: &str, workdir: &str) -> String {
    let mut out = String::new();
    let _ = writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    let _ = writeln!(
        out,
        r#"<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"?>"#
    );
    let _ = writeln!(out, r#"<plist version="1.0">"#);
    let _ = writeln!(out, "<dict>");
    let _ = writeln!(out, "  <key>Label</key>");
    let _ = writeln!(out, "  <string>com.sentry.daemon</string>");
    let _ = writeln!(out, "  <key>ProgramArguments</key>");
    let _ = writeln!(out, "  <array>");
    let _ = writeln!(out, "    <string>{exec}</string>");
    let _ = writeln!(out, "    <string>run</string>");
    let _ = writeln!(out, "  </array>");
    let _ = writeln!(out, "  <key>WorkingDirectory</key>");
    let _ = writeln!(out, "  <string>{workdir}</string>");
    let _ = writeln!(out, "  <key>RunAtLoad</key>");
    let _ = writeln!(out, "  <true/>");
    let _ = writeln!(out, "  <key>KeepAlive</key>");
    let _ = writeln!(out, "  <true/>");
    let _ = writeln!(out, "  <key>StandardOutPath</key>");
    let _ = writeln!(out, "  <string>{workdir}/sentry.log</string>");
    let _ = writeln!(out, "  <key>StandardErrorPath</key>");
    let _ = writeln!(out, "  <string>{workdir}/sentry.err.log</string>");
    let _ = writeln!(out, "</dict>");
    let _ = writeln!(out, "</plist>");
    out
}

/// argv-style `sc.exe` invocations that register the Windows service
/// (admin shell). Argument lists only — no shell string is ever built.
pub fn windows_sc_commands(exec: &str) -> Vec<Vec<String>> {
    vec![
        vec![
            "create".into(),
            WINDOWS_SERVICE_NAME.into(),
            "binPath=".into(),
            format!("\"{exec}\" service run"),
            "start=".into(),
            "auto".into(),
            "DisplayName=".into(),
            "Sentry access monitor".into(),
        ],
        vec![
            "failure".into(),
            WINDOWS_SERVICE_NAME.into(),
            "reset=".into(),
            "86400".into(),
            "actions=".into(),
            "restart/60000/restart/60000/restart/60000".into(),
        ],
        vec!["start".into(), WINDOWS_SERVICE_NAME.into()],
    ]
}

/// Install the service for the current OS.
pub fn install(user: Option<&str>, workdir: Option<&str>) -> color_eyre::Result<()> {
    let exe = exe_path()?;
    let workdir = workdir
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    validate_service_path(&workdir)?;
    let exe_str = exe.display().to_string();
    let exe = sanitize_arg(&exe_str)?;
    let workdir_str = workdir.display().to_string();
    let workdir = sanitize_arg(&workdir_str)?;

    match std::env::consts::OS {
        "linux" => {
            let unit = systemd_unit(exe, user.unwrap_or("root"), workdir);
            let path = Path::new("/etc/systemd/system").join(format!("{SERVICE_NAME}.service"));
            match std::fs::write(&path, &unit) {
                Ok(()) => {
                    println!("unit written to {}", path.display());
                    systemctl(&["daemon-reload"]);
                    systemctl(&["enable", "--now", SERVICE_NAME]);
                    println!("service enabled — check with `systemctl status {SERVICE_NAME}`");
                }
                Err(e) => {
                    println!(
                        "could not write {} ({e}) — install manually as root:\n",
                        path.display()
                    );
                    println!("{unit}");
                }
            }
        }
        "macos" => {
            let plist = launchd_plist(exe, workdir);
            let path = home_plist_path()?;
            match std::fs::write(&path, &plist) {
                Ok(()) => {
                    println!("plist written to {}", path.display());
                    launchctl(&["load", sanitize_arg(&path.display().to_string())?]);
                    println!("agent loaded — check with `launchctl list | grep sentry`");
                }
                Err(e) => {
                    println!(
                        "could not write {} ({e}) — install manually:\n",
                        path.display()
                    );
                    println!("{plist}");
                }
            }
        }
        "windows" => {
            println!("the following commands require an elevated shell:\n");
            for argv in windows_sc_commands(exe) {
                println!("  sc.exe {}", argv.join(" "));
                sc(&argv);
            }
            println!("\nconfig: set the machine-wide SENTRY_CONFIG env var (or rely on ./sentry.toml in the WorkingDirectory).");
        }
        other => {
            return Err(color_eyre::eyre::eyre!(
                "unsupported platform for `sentry service install`: {other}"
            ));
        }
    }
    Ok(())
}

/// Stop and remove the service.
pub fn uninstall() -> color_eyre::Result<()> {
    match std::env::consts::OS {
        "linux" => {
            systemctl(&["disable", "--now", SERVICE_NAME]);
            let path = Path::new("/etc/systemd/system").join(format!("{SERVICE_NAME}.service"));
            match std::fs::remove_file(&path) {
                Ok(()) => println!("removed {}", path.display()),
                Err(e) => println!("could not remove {} ({e})", path.display()),
            }
            systemctl(&["daemon-reload"]);
        }
        "macos" => {
            let path = home_plist_path()?;
            launchctl(&["unload", sanitize_arg(&path.display().to_string())?]);
            match std::fs::remove_file(&path) {
                Ok(()) => println!("removed {}", path.display()),
                Err(e) => println!("could not remove {} ({e})", path.display()),
            }
        }
        "windows" => {
            sc(&["stop".into(), WINDOWS_SERVICE_NAME.into()]);
            sc(&["delete".into(), WINDOWS_SERVICE_NAME.into()]);
        }
        other => {
            return Err(color_eyre::eyre::eyre!(
                "unsupported platform for `sentry service uninstall`: {other}"
            ));
        }
    }
    Ok(())
}

/// Print install paths + best-effort live status.
pub fn status() {
    let exe = exe_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "(unresolved)".to_string());
    println!("executable: {exe}");
    match std::env::consts::OS {
        "linux" => {
            let unit = Path::new("/etc/systemd/system").join(format!("{SERVICE_NAME}.service"));
            println!("unit:       {}", unit.display());
            systemctl(&["is-active", SERVICE_NAME]);
        }
        "macos" => match home_plist_path() {
            Ok(path) => println!("plist:      {}", path.display()),
            Err(e) => println!("plist:      ({e})"),
        },
        "windows" => {
            sc(&["query".into(), WINDOWS_SERVICE_NAME.into()]);
        }
        _ => println!("service management not supported on this platform"),
    }
}

/// Entry point for `sentry service run` — Windows SCM only (feature `service`).
#[cfg(all(windows, feature = "service"))]
pub fn run_windows_service() -> color_eyre::Result<()> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::ServiceControlHandlerResult;
    use windows_service::{define_windows_service, service_control_handler, service_dispatcher};

    fn sentry_service_main(_args: Vec<std::ffi::OsString>) {
        let handler = |control: ServiceControl| match control {
            // The daemon loop has no stop hook yet; SCM stop terminates the
            // process (sources/tailing are restart-safe by design).
            ServiceControl::Stop => {
                std::thread::spawn(|| std::process::exit(0));
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = match service_control_handler::register(WINDOWS_SERVICE_NAME, handler) {
            Ok(h) => h,
            Err(_) => return,
        };
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(10),
            process_id: None,
        });

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let result = rt.block_on(async {
            match crate::config::load(None) {
                Ok(cfg) => crate::daemon::run(cfg).await,
                Err(e) => Err(e),
            }
        });
        if let Err(e) = result {
            tracing::error!(error = %e, "service run failed");
        }

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::from_secs(1),
            process_id: None,
        });
    }

    define_windows_service!(ffi_service_main, sentry_service_main);
    service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
        .map_err(|e| color_eyre::eyre::eyre!("service dispatcher: {e}"))?;
    Ok(())
}

/// Non-Windows or non-`service` builds reject the SCM entrypoint.
#[cfg(not(all(windows, feature = "service")))]
pub fn run_windows_service() -> color_eyre::Result<()> {
    Err(color_eyre::eyre::eyre!(
        "sentry was built without the Windows service runtime (rebuild with --features service on Windows)"
    ))
}

/// Run the fixed binary `systemctl` with sanitized argument-list arguments
/// (no shell is ever spawned; best-effort — failures are silent).
fn systemctl(args: &[&str]) {
    for a in args {
        if sanitize_arg(a).is_err() {
            return;
        }
    }
    let _ = std::process::Command::new("systemctl").args(args).status();
}

/// Run the fixed binary `launchctl` with sanitized argument-list arguments.
fn launchctl(args: &[&str]) {
    for a in args {
        if sanitize_arg(a).is_err() {
            return;
        }
    }
    let _ = std::process::Command::new("launchctl").args(args).status();
}

/// Run the fixed binary `sc.exe` with sanitized argument-list arguments.
fn sc(args: &[String]) {
    for a in args {
        if sanitize_arg(a).is_err() {
            return;
        }
    }
    let _ = std::process::Command::new("sc.exe").args(args).status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_contains_required_directives() {
        let unit = systemd_unit("/usr/local/bin/sentry", "sentry", "/var/lib/sentry");
        assert!(unit.contains("ExecStart=/usr/local/bin/sentry run"));
        assert!(unit.contains("User=sentry"));
        assert!(unit.contains("WorkingDirectory=/var/lib/sentry"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(unit.contains("Restart=on-failure"));
    }

    #[test]
    fn launchd_plist_is_well_formed() {
        let plist = launchd_plist("/opt/sentry/bin/sentry", "/var/lib/sentry");
        assert!(plist.starts_with("<?xml"));
        assert!(plist.contains("<string>/opt/sentry/bin/sentry</string>"));
        assert!(plist.contains("<string>run</string>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.trim_end().ends_with("</plist>"));
    }

    #[test]
    fn windows_sc_commands_are_argv_lists() {
        let cmds = windows_sc_commands(r"C:\sentry\sentry.exe");
        assert_eq!(cmds.len(), 3);
        assert_eq!(cmds[0][0], "create");
        assert!(cmds[0].windows(2).any(|w| w[0] == "binPath="));
        assert!(cmds[0]
            .iter()
            .any(|a| a.contains("service run") && a.contains("sentry.exe")));
        assert!(cmds[1].contains(&"failure".to_string()));
        assert!(cmds[2].contains(&"start".to_string()));
    }

    #[test]
    fn traversal_paths_are_rejected() {
        assert!(validate_service_path(Path::new("/opt/../etc/passwd")).is_err());
        assert!(validate_service_path(Path::new("C:\\opt\\..\\evil.exe")).is_err());
        assert!(validate_service_path(Path::new("/usr/local/bin/sentry")).is_ok());
        assert!(validate_service_path(Path::new("C:\\sentry\\sentry.exe")).is_ok());
    }

    #[test]
    fn shell_metacharacters_are_rejected_in_args() {
        assert!(sanitize_arg("/usr/local/bin/sentry").is_ok());
        assert!(sanitize_arg("systemctl; reboot").is_err());
        assert!(sanitize_arg("a&b").is_err());
        assert!(sanitize_arg("$(id)").is_err());
        assert!(sanitize_arg("a|b").is_err());
        assert!(sanitize_arg("`id`").is_err());
    }
}
