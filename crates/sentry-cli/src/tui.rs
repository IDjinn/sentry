//! TUI live view (ratatui + crossterm).
//!
//! Standalone mode: polls Postgres for recent events and renders a scrollable
//! list with stats and keyboard shortcuts. Requires `storage.postgres.url`.

use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use sentry_core::config::SentryConfig;
use sentry_core::event::ProtocolData;
use sentry_storage::{EventRow, Repo};

type Terminal = ratatui::Terminal<CrosstermBackend<Stdout>>;

/// Run the TUI. Requires a loaded config with `storage.postgres.url`.
pub async fn run(cfg: Option<&SentryConfig>) -> io::Result<()> {
    let Some(cfg) = cfg else {
        println!("TUI needs a config — pass --config or create sentry.toml");
        return Ok(());
    };
    if cfg.storage.postgres.url.is_empty() {
        println!("TUI needs storage.postgres.url configured (or run with `--stream`).");
        return Ok(());
    }

    let pool = sentry_storage::PgPool::connect(&cfg.storage.postgres)
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    let repo = Repo::new(pool);

    let mut terminal = enter_alt()?;
    let mut app = App::default();
    let res = app.run(&mut terminal, &repo).await;
    leave_alt(&mut terminal);
    res
}

fn enter_alt() -> io::Result<Terminal> {
    enable_raw_mode().map_err(io::Error::other)?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen).map_err(io::Error::other)?;
    let backend = CrosstermBackend::new(out);
    Terminal::new(backend).map_err(io::Error::other)
}

fn leave_alt(terminal: &mut Terminal) {
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
}

/// Application state for the live event view.
#[derive(Default)]
struct App {
    events: Vec<EventRow>,
    state: ListState,
    paused: bool,
    quit: bool,
    last_fetch_ok: bool,
}

impl App {
    async fn run(&mut self, terminal: &mut Terminal, repo: &Repo) -> io::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        self.refresh(repo).await;
        loop {
            self.draw(terminal)?;
            self.handle_input().await;

            interval.tick().await;
            if !self.paused {
                self.refresh(repo).await;
            }
            if self.quit {
                break;
            }
        }
        Ok(())
    }

    async fn refresh(&mut self, repo: &Repo) {
        match repo.events().recent(200).await {
            Ok(rows) => {
                self.events = rows;
                self.last_fetch_ok = true;
            }
            Err(e) => {
                self.last_fetch_ok = false;
                tracing::warn!(error = %e, "tui fetch failed");
            }
        }
    }

    async fn handle_input(&mut self) {
        while event::poll(Duration::ZERO).unwrap_or(false) {
            let Ok(Event::Key(k)) = event::read() else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
                KeyCode::Char(' ') => self.paused = !self.paused,
                KeyCode::Char('j') | KeyCode::Down => self.scroll(1),
                KeyCode::Char('k') | KeyCode::Up => self.scroll(-1),
                KeyCode::Char('g') | KeyCode::Home => {
                    self.state.select(Some(0));
                }
                KeyCode::Char('G') | KeyCode::End if !self.events.is_empty() => {
                    self.state.select(Some(self.events.len() - 1));
                }
                _ => {}
            }
        }
    }

    fn scroll(&mut self, delta: i32) {
        let len = self.events.len();
        if len == 0 {
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as i32;
        let mut next = cur + delta;
        if next < 0 {
            next = 0;
        } else if next as usize >= len {
            next = (len - 1) as i32;
        }
        self.state.select(Some(next as usize));
    }

    fn draw(&mut self, terminal: &mut Terminal) -> io::Result<()> {
        terminal.draw(|f| self.render(f))?;
        Ok(())
    }

    fn render(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(3),
            ])
            .split(f.area());

        f.render_widget(self.header(), chunks[0]);

        let items: Vec<ListItem> = self
            .events
            .iter()
            .map(|row| Line::from(row_spans(row)))
            .map(ListItem::new)
            .collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Events"))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            );
        f.render_stateful_widget(list, chunks[1], &mut self.state);

        f.render_widget(self.footer(), chunks[2]);
    }

    fn header(&self) -> Paragraph<'_> {
        let status = if self.paused {
            Span::styled("[PAUSED] ", Style::default().fg(Color::Yellow))
        } else {
            Span::raw("")
        };
        let feed = if self.last_fetch_ok {
            Span::styled("ok", Style::default().fg(Color::Green))
        } else {
            Span::styled("fetch error", Style::default().fg(Color::Red))
        };
        let line = Line::from(vec![
            Span::styled(" Sentry ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw("events="),
            Span::styled(
                self.events.len().to_string(),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("  "),
            status,
            Span::raw("db: "),
            feed,
        ]);
        Paragraph::new(line)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .wrap(Wrap { trim: false })
    }

    fn footer(&self) -> Paragraph<'_> {
        let line = Line::from(vec![
            Span::styled("q", bold()),
            Span::raw(" quit  "),
            Span::styled("Space", bold()),
            Span::raw(" pause  "),
            Span::styled("j/k", bold()),
            Span::raw(" scroll  "),
            Span::styled("g/G", bold()),
            Span::raw(" top/bottom  "),
            Span::styled("Esc", bold()),
            Span::raw(" quit"),
        ]);
        Paragraph::new(line)
            .block(Block::default().borders(Borders::ALL).title("Shortcuts"))
            .wrap(Wrap { trim: false })
    }
}

fn row_spans(row: &EventRow) -> Vec<Span<'_>> {
    let level_color = level_color(&row.risk_level);
    let (method, path, status) = protocol_summary(row);
    let time = row.timestamp.format("%H:%M:%S").to_string();
    vec![
        Span::raw(format!("{time} ")),
        Span::styled(
            format!("{:<5}", row.risk_level),
            Style::default().fg(level_color),
        ),
        Span::raw(format!(" {:>3}", row.risk_score)),
        Span::raw(format!(" {:<15}", row.client_ip)),
        Span::raw(format!(" [{:<8}]", row.source)),
        Span::raw(format!(" {:<6}", method)),
        Span::raw(format!(" {:<40}", truncate(&path, 40))),
        Span::raw(format!(" {:>3}", status)),
    ]
}

fn bold() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

fn level_color(s: &str) -> Color {
    match s {
        "critical" => Color::Red,
        "high" => Color::LightRed,
        "medium" => Color::Yellow,
        "low" => Color::Blue,
        _ => Color::Gray,
    }
}

fn port_service(port: u16) -> &'static str {
    match port {
        22 => "ssh",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        443 => "https",
        445 => "smb",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        _ => "",
    }
}

fn port_label(port: Option<i32>) -> String {
    port.and_then(|p| u16::try_from(p).ok())
        .map(|p| {
            let svc = port_service(p);
            if svc.is_empty() {
                p.to_string()
            } else {
                svc.to_string()
            }
        })
        .unwrap_or_default()
}

fn protocol_summary(row: &EventRow) -> (String, String, String) {
    match serde_json::from_value::<ProtocolData>(row.protocol.clone()) {
        Ok(ProtocolData::Http(h)) => (
            h.method
                .map(|m| format!("{m:?}"))
                .unwrap_or_else(|| "-".into()),
            h.path,
            h.status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
        ),
        Ok(ProtocolData::Tcp(_)) => {
            let port = port_label(row.server_port);
            let label = if port.is_empty() {
                "tcp".to_string()
            } else {
                format!("tcp/{port}")
            };
            ("-".into(), format!("({label})"), "-".into())
        }
        Ok(ProtocolData::Udp(d)) => {
            let label = match &d.dns_query {
                Some(q) => format!("udp/dns {q}"),
                None => match port_label(row.server_port) {
                    p if p.is_empty() => "udp".to_string(),
                    p => format!("udp/{p}"),
                },
            };
            ("-".into(), format!("({label})"), "-".into())
        }
        Ok(ProtocolData::TlsHandshake(d)) => (
            "-".into(),
            match &d.sni {
                Some(sni) => format!("(tls {sni})"),
                None => "(tls)".into(),
            },
            "-".into(),
        ),
        Ok(ProtocolData::Syslog(d)) => (
            "-".into(),
            match &d.app_name {
                Some(app) => format!("(syslog {app})"),
                None => "(syslog)".into(),
            },
            "-".into(),
        ),
        _ => ("-".into(), "(non-http)".into(), "-".into()),
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

#[allow(dead_code)]
fn _unused(_: Rect) {}
