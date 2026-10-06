//! TUI live view (ratatui + crossterm).
//!
//! Standalone mode: polls Postgres for recent events and renders the
//! documented 3-zone layout (header/sparkline, colored stream, aggregated
//! footer) with filters, event detail and per-IP actions. Requires
//! `storage.postgres.url`.

pub mod agg;
pub mod stream;
pub mod theme;

use std::io::{self, Stdout};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Sparkline, Wrap,
};
use ratatui::Frame;
use sentry_core::analysis::Verdict;
use sentry_core::challenge::{ChallengeProvider, EdgeMode, EdgeOptions};
use sentry_core::config::SentryConfig;
use sentry_core::trust::TrustSet;
use sentry_storage::{EventRow, Repo};
use tokio::sync::mpsc;

use theme::{Theme, ThemeName};

/// Event window polled from Postgres.
const WINDOW: i64 = 500;
/// Rows pre-rendered in the aggregated footer.
const FOOTER_ROWS: usize = 5;
/// Transient status message lifetime.
const FLASH_SECS: u64 = 5;

/// Options for the interactive tail.
#[derive(Debug, Clone, Default)]
pub struct TailOptions {
    /// Normalized risk-level filter (`--only`).
    pub only: Vec<String>,
    /// Color theme (`--theme`).
    pub theme: ThemeName,
}

/// Run the TUI. Requires a loaded config with `storage.postgres.url`.
pub async fn run(cfg: Option<&SentryConfig>, opts: TailOptions) -> io::Result<()> {
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
    let trust = TrustSet::from_config(&cfg.real_ip).ok();

    let mut terminal = enter_alt()?;
    let mut app = App::new(opts, trust);
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

type Terminal = ratatui::Terminal<CrosstermBackend<Stdout>>;

/// Per-IP action awaiting confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    /// Persistent block via `ip_state` + NOTIFY.
    Block(IpAddr),
    /// Remove block + strikes via `ip_state`.
    Unblock(IpAddr),
    /// Cloudflare managed challenge via the CF provider.
    Challenge(IpAddr),
}

/// Action keys without a resolved IP yet.
#[derive(Debug, Clone, Copy)]
enum Action {
    /// `b` key.
    Block,
    /// `u` key.
    Unblock,
    /// `c` key.
    Challenge,
}

impl Pending {
    fn prompt(self) -> String {
        match self {
            Pending::Block(ip) => format!("Bloquear {ip} persistentemente?"),
            Pending::Unblock(ip) => format!("Desbloquear {ip} (remove strikes)?"),
            Pending::Challenge(ip) => {
                format!("Disparar managed challenge no Cloudflare para {ip}?")
            }
        }
    }
}

/// UI focus mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Live stream.
    Live,
    /// Event detail popup.
    Detail,
    /// Filter text input popup.
    Input,
    /// Confirmation popup.
    Confirm(Pending),
    /// Per-IP info popup.
    IpInfo,
    /// Routes popup.
    Routes,
}

/// Application state for the live event view.
struct App {
    events: Vec<EventRow>,
    view: Vec<usize>,
    state: ListState,
    paused: bool,
    quit: bool,
    last_fetch_ok: bool,
    backlog: usize,
    filters: agg::Filters,
    input: String,
    mode: Mode,
    detail_scroll: u16,
    status: Option<(String, bool, Instant)>,
    ip_info: Option<Vec<String>>,
    routes: Option<Vec<String>>,
    theme: Theme,
    trust: Option<TrustSet>,
    status_tx: mpsc::UnboundedSender<String>,
    status_rx: mpsc::UnboundedReceiver<String>,
}

impl App {
    fn new(opts: TailOptions, trust: Option<TrustSet>) -> Self {
        let (status_tx, status_rx) = mpsc::unbounded_channel();
        Self {
            events: Vec::new(),
            view: Vec::new(),
            state: ListState::default(),
            paused: false,
            quit: false,
            last_fetch_ok: true,
            backlog: 0,
            filters: agg::Filters {
                only: opts.only,
                text: None,
            },
            input: String::new(),
            mode: Mode::Live,
            detail_scroll: 0,
            status: None,
            ip_info: None,
            routes: None,
            theme: Theme::new(opts.theme),
            trust,
            status_tx,
            status_rx,
        }
    }

    async fn run(&mut self, terminal: &mut Terminal, repo: &Repo) -> io::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        self.refresh(repo).await;
        loop {
            terminal.draw(|f| self.render(f))?;
            self.handle_input(repo).await;
            self.drain_status();

            interval.tick().await;
            self.refresh(repo).await;
            if self.quit {
                break;
            }
        }
        Ok(())
    }

    async fn refresh(&mut self, repo: &Repo) {
        match repo.events().recent(WINDOW).await {
            Ok(rows) => {
                self.last_fetch_ok = true;
                if self.paused {
                    if let (Some(newest), Some(current)) = (rows.first(), self.events.first()) {
                        if newest.timestamp > current.timestamp {
                            let fresh = rows
                                .iter()
                                .take_while(|r| r.timestamp > current.timestamp)
                                .count();
                            self.backlog += fresh;
                        }
                    }
                } else {
                    self.events = rows;
                    self.recompute_view();
                }
            }
            Err(e) => {
                self.last_fetch_ok = false;
                tracing::warn!(error = %e, "tui fetch failed");
            }
        }
    }

    fn recompute_view(&mut self) {
        self.view = self
            .events
            .iter()
            .enumerate()
            .filter(|(_, row)| self.filters.matches(row))
            .map(|(idx, _)| idx)
            .collect();
        let len = self.view.len();
        if len == 0 {
            self.state.select(None);
        } else {
            let cur = self.state.selected().unwrap_or(0).min(len - 1);
            self.state.select(Some(cur));
        }
    }

    fn drain_status(&mut self) {
        while let Ok(msg) = self.status_rx.try_recv() {
            self.flash(msg, false);
        }
        if let Some((_, _, until)) = self.status {
            if Instant::now() > until {
                self.status = None;
            }
        }
    }

    fn flash(&mut self, msg: impl Into<String>, is_error: bool) {
        self.status = Some((
            msg.into(),
            is_error,
            Instant::now() + Duration::from_secs(FLASH_SECS),
        ));
    }

    async fn handle_input(&mut self, repo: &Repo) {
        while event::poll(Duration::ZERO).unwrap_or(false) {
            let Ok(Event::Key(k)) = event::read() else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            let plain = k.modifiers.is_empty() || k.modifiers == KeyModifiers::SHIFT;
            if !plain {
                continue;
            }

            match self.mode {
                Mode::Live => self.handle_live_key(k.code, repo).await,
                Mode::Detail => match k.code {
                    KeyCode::Char('j') | KeyCode::Down => self.detail_scroll += 4,
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.detail_scroll = self.detail_scroll.saturating_sub(4)
                    }
                    KeyCode::PageDown => self.detail_scroll += 20,
                    KeyCode::PageUp => self.detail_scroll = self.detail_scroll.saturating_sub(20),
                    _ => self.mode = Mode::Live,
                },
                Mode::Input => match k.code {
                    KeyCode::Char(c) => self.input.push(c),
                    KeyCode::Backspace => {
                        self.input.pop();
                    }
                    KeyCode::Enter => {
                        let text = self.input.trim().to_string();
                        self.filters.text = if text.is_empty() { None } else { Some(text) };
                        self.recompute_view();
                        self.mode = Mode::Live;
                    }
                    _ => self.mode = Mode::Live,
                },
                Mode::Confirm(pending) => match k.code {
                    KeyCode::Char('y') | KeyCode::Char('Y') => {
                        self.mode = Mode::Live;
                        self.execute(pending, repo).await;
                    }
                    _ => self.mode = Mode::Live,
                },
                Mode::IpInfo | Mode::Routes => self.mode = Mode::Live,
            }
        }
    }

    async fn handle_live_key(&mut self, code: KeyCode, repo: &Repo) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                if !self.paused {
                    self.backlog = 0;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => self.scroll(1),
            KeyCode::Char('k') | KeyCode::Up => self.scroll(-1),
            KeyCode::PageDown => self.scroll(10),
            KeyCode::PageUp => self.scroll(-10),
            KeyCode::Char('g') | KeyCode::Home => {
                if !self.view.is_empty() {
                    self.state.select(Some(0));
                }
            }
            KeyCode::Char('G') | KeyCode::End => {
                if !self.view.is_empty() {
                    self.state.select(Some(self.view.len() - 1));
                }
            }
            KeyCode::Char('f') | KeyCode::Char('/') => {
                self.input = self.filters.text.clone().unwrap_or_default();
                self.mode = Mode::Input;
            }
            KeyCode::Enter => {
                if self.selected_row().is_some() {
                    self.detail_scroll = 0;
                    self.mode = Mode::Detail;
                }
            }
            KeyCode::Char('b') => self.confirm(Action::Block),
            KeyCode::Char('u') => self.confirm(Action::Unblock),
            KeyCode::Char('c') => self.confirm(Action::Challenge),
            KeyCode::Char('i') => self.open_ip_info(repo).await,
            KeyCode::Char('r') => self.open_routes(repo).await,
            _ => {}
        }
    }

    fn selected_row(&self) -> Option<&EventRow> {
        let idx = self.state.selected()?;
        self.view.get(idx).map(|i| &self.events[*i])
    }

    fn selected_ip(&self) -> Option<IpAddr> {
        self.selected_row()
            .and_then(|row| row.client_ip.parse().ok())
    }

    fn confirm(&mut self, action: Action) {
        let Some(ip) = self.selected_ip() else {
            self.flash("selecione um evento com IP para esta ação", true);
            return;
        };
        let pending = match action {
            Action::Block => Pending::Block(ip),
            Action::Unblock => Pending::Unblock(ip),
            Action::Challenge => Pending::Challenge(ip),
        };
        if !matches!(pending, Pending::Unblock(_)) {
            if let Some(trust) = &self.trust {
                if trust.is_never_ban(ip) {
                    self.flash(format!("{ip} é trusted/never-ban — ação ignorada"), true);
                    return;
                }
            }
        }
        self.mode = Mode::Confirm(pending);
    }

    async fn execute(&mut self, pending: Pending, repo: &Repo) {
        let result: Result<String, String> = match pending {
            Pending::Block(ip) => {
                async {
                    repo.ip_state()
                        .block(ip, Some("tui"), None)
                        .await
                        .map_err(|e| e.to_string())?;
                    let _ = repo.pool().notify("sentry_blocks_changed").await;
                    Ok(format!("{ip} bloqueado — edge aplica em segundos"))
                }
                .await
            }
            Pending::Unblock(ip) => {
                async {
                    repo.ip_state()
                        .unblock(ip)
                        .await
                        .map_err(|e| e.to_string())?;
                    let _ = repo.pool().notify("sentry_blocks_changed").await;
                    Ok(format!("{ip} desbloqueado"))
                }
                .await
            }
            Pending::Challenge(ip) => match crate::cmd::build_cf_provider() {
                Err(e) => Err(e.to_string()),
                Ok(provider) => {
                    let tx = self.status_tx.clone();
                    tokio::spawn(async move {
                        let opts = EdgeOptions {
                            ttl: Duration::from_secs(86400),
                            mode: Some(EdgeMode::ManagedChallenge),
                        };
                        let msg = match provider.apply(ip, Verdict::Challenge, &opts).await {
                            Ok(()) => format!("{ip}: managed challenge aplicado no Cloudflare"),
                            Err(e) => format!("{ip}: challenge falhou: {e}"),
                        };
                        let _ = tx.send(msg);
                    });
                    Ok(format!("{ip}: disparando challenge…"))
                }
            },
        };
        match result {
            Ok(msg) => self.flash(msg, false),
            Err(msg) => self.flash(msg, true),
        }
    }

    async fn open_ip_info(&mut self, repo: &Repo) {
        let Some(ip) = self.selected_ip() else {
            self.flash("selecione um evento com IP", true);
            return;
        };
        let mut lines = vec![format!("IP {}", ip)];
        match repo.ip_state().is_blocked(ip).await {
            Ok(true) => lines.push("bloqueado: sim".to_string()),
            Ok(false) => lines.push("bloqueado: não".to_string()),
            Err(e) => lines.push(format!("bloqueado: erro ({e})")),
        }
        match repo.ip_state().offender(ip).await {
            Ok(Some(off)) => lines.push(format!(
                "strikes: {} · violações totais: {} · última: {}",
                off.strikes,
                off.total_violations,
                off.last_violation_at
                    .map(|t| t.format("%d/%m %H:%M:%S").to_string())
                    .unwrap_or_else(|| "-".to_string()),
            )),
            Ok(None) => lines.push("strikes: 0".to_string()),
            Err(e) => lines.push(format!("strikes: erro ({e})")),
        }
        match repo.incidents().open_incident_for_ip(ip).await {
            Ok(Some(id)) => lines.push(format!("incidente aberto: {id}")),
            Ok(None) => lines.push("incidente aberto: não".to_string()),
            Err(e) => lines.push(format!("incidente: erro ({e})")),
        }
        match repo.events().recent_for_ip(ip, 15).await {
            Ok(rows) => {
                lines.push(String::new());
                lines.push(format!("últimos {} eventos:", rows.len()));
                for row in rows {
                    let parts = agg::http_parts(&row);
                    lines.push(format!(
                        "  {} {:<8} {:<6} {} {}",
                        row.timestamp.format("%d/%m %H:%M:%S"),
                        row.risk_level,
                        parts.method.unwrap_or_else(|| "-".to_string()),
                        agg::truncate(&parts.path, 40),
                        agg::signal_summary(&row),
                    ));
                }
            }
            Err(e) => lines.push(format!("eventos: erro ({e})")),
        }
        self.ip_info = Some(lines);
        self.mode = Mode::IpInfo;
    }

    async fn open_routes(&mut self, repo: &Repo) {
        match repo.routes().list().await {
            Ok(rows) => {
                let mut lines = vec![format!("{} rotas conhecidas", rows.len())];
                for r in rows.iter().take(100) {
                    lines.push(format!("  {:<24} {}", r.methods.join(","), r.path));
                }
                self.routes = Some(lines);
                self.mode = Mode::Routes;
            }
            Err(e) => self.flash(format!("rotas: {e}"), true),
        }
    }

    fn scroll(&mut self, delta: i32) {
        let len = self.view.len();
        if len == 0 {
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as i32;
        let next = (cur + delta).clamp(0, len as i32 - 1);
        self.state.select(Some(next as usize));
    }

    fn render(&mut self, f: &mut Frame) {
        let chunks = Layout::vertical([
            Constraint::Length(4),
            Constraint::Min(5),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .split(f.area());

        self.render_header(f, chunks[0]);
        self.render_stream(f, chunks[1]);
        self.render_footer(f, chunks[2]);
        self.render_hints(f, chunks[3]);

        match self.mode {
            Mode::Live => {}
            Mode::Detail => self.render_detail(f),
            Mode::Input => self.render_input(f),
            Mode::Confirm(pending) => self.render_confirm(f, pending),
            Mode::IpInfo => {
                self.render_lines_popup(f, "IP", self.ip_info.as_deref().unwrap_or(&[]))
            }
            Mode::Routes => {
                self.render_lines_popup(f, "Rotas", self.routes.as_deref().unwrap_or(&[]))
            }
        }
    }

    fn view_rows(&self) -> Vec<&EventRow> {
        self.view.iter().map(|i| &self.events[*i]).collect()
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let title_style = if self.theme.mono {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default()
                .fg(self.theme.accent)
                .add_modifier(Modifier::BOLD)
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" Sentry — live ", title_style));
        let inner = block.inner(area);
        f.render_widget(block, area);

        let rows = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).split(inner);
        let top = Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(rows[0]);

        let view_rows = self.view_rows();
        let data = agg::sparkline(&view_rows, agg::now_ms(), 5_000, 40);
        let spark = Sparkline::default().data(&data);
        f.render_widget(spark, top[0]);

        let counts = agg::level_counts(&view_rows);
        let rps = agg::req_per_sec(&view_rows, agg::now_ms());
        let names = ["Info", "Low", "Med", "High", "Crit"];
        let mut spans = vec![Span::raw(format!("req/s {rps}  "))];
        for (i, name) in names.iter().enumerate() {
            spans.push(Span::styled(
                format!("{name} {}  ", counts[i]),
                self.theme.level_style(agg::LEVELS[i]),
            ));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), top[1]);

        let mut spans = Vec::new();
        if self.paused {
            spans.push(Span::styled("[PAUSED]", self.theme.warn_style()));
            if self.backlog > 0 {
                spans.push(Span::raw(format!(" +{} novos ", self.backlog)));
            }
        }
        if let Some(text) = &self.filters.text {
            spans.push(Span::styled(
                format!(" filtro:\"{text}\" "),
                self.theme.accent_style(),
            ));
        }
        if !self.filters.only.is_empty() {
            spans.push(Span::styled(
                format!(" levels:{} ", self.filters.only.join(",")),
                self.theme.accent_style(),
            ));
        }
        spans.push(Span::styled(
            if self.last_fetch_ok {
                " db: ok"
            } else {
                " db: ERRO"
            },
            if self.last_fetch_ok {
                self.theme.dim_style()
            } else {
                self.theme.error_style()
            },
        ));
        if let Some((msg, is_error, _)) = &self.status {
            spans.push(Span::styled(
                format!("  {msg}"),
                if *is_error {
                    self.theme.error_style()
                } else {
                    self.theme.ok_style()
                },
            ));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), rows[1]);
    }

    fn render_stream(&mut self, f: &mut Frame, area: Rect) {
        let view = self.view.clone();
        let items: Vec<ListItem> = view
            .iter()
            .map(|i| Line::from(row_spans(&self.events[*i], &self.theme, area.width)))
            .map(ListItem::new)
            .collect();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Eventos"))
            .highlight_style(self.theme.highlight_style());
        f.render_stateful_widget(list, area, &mut self.state);
    }

    fn render_footer(&self, f: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Agregados — janela");
        let inner = block.inner(area);
        f.render_widget(block, area);

        let view_rows = self.view_rows();
        let width = inner.width;
        let constraints = if width >= 100 {
            vec![Constraint::Ratio(1, 3); 3]
        } else if width >= 60 {
            vec![Constraint::Percentage(50), Constraint::Percentage(50)]
        } else {
            vec![Constraint::Percentage(100)]
        };
        let cols = Layout::horizontal(constraints).split(inner);

        let mut ips = vec![Span::styled("Top IPs", self.theme.accent_style())];
        for ip in agg::top_ips(&view_rows, FOOTER_ROWS) {
            ips.push(Span::raw("\n"));
            ips.push(Span::raw(format!("{:<15}", agg::truncate(&ip.ip, 15))));
            ips.push(Span::raw(format!(" {:>3} ", ip.count)));
            ips.push(Span::styled(
                ip.worst_level.to_uppercase(),
                self.theme.level_style(&ip.worst_level),
            ));
        }
        f.render_widget(
            Paragraph::new(Line::from(ips)).wrap(Wrap { trim: false }),
            cols[0],
        );

        if cols.len() > 1 {
            let mut paths = vec![Span::styled("Top paths", self.theme.accent_style())];
            for (path, count) in agg::top_paths(&view_rows, FOOTER_ROWS) {
                paths.push(Span::raw("\n"));
                paths.push(Span::raw(format!("{:<28}", agg::truncate(&path, 28))));
                paths.push(Span::raw(format!("{:>4}", count)));
            }
            f.render_widget(
                Paragraph::new(Line::from(paths)).wrap(Wrap { trim: false }),
                cols[1],
            );
        }

        if cols.len() > 2 {
            let geo = agg::asn_geo(&view_rows, 3);
            let mut lines = vec![Span::styled("ASN/Geo", self.theme.accent_style())];
            for (asn, _) in &geo.asns {
                lines.push(Span::raw("\n"));
                lines.push(Span::raw(format!("AS{asn:<12} {}%", geo.asn_pct(*asn))));
            }
            if geo.tor > 0 {
                lines.push(Span::raw("\n"));
                lines.push(Span::styled(
                    format!("Tor          {}%", geo.tor_pct()),
                    self.theme.warn_style(),
                ));
            }
            f.render_widget(
                Paragraph::new(Line::from(lines)).wrap(Wrap { trim: false }),
                cols[2],
            );
        }
    }

    fn render_hints(&self, f: &mut Frame, area: Rect) {
        let keys = [
            ("f", "filtrar"),
            ("Enter", "detalhe"),
            ("b", "bloquear"),
            ("u", "unblock"),
            ("c", "challenge"),
            ("i", "info IP"),
            ("r", "rotas"),
            ("Space", "pausa"),
            ("q", "sair"),
        ];
        let mut spans = Vec::new();
        for (i, (key, label)) in keys.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(" · "));
            }
            spans.push(Span::styled(
                format!("[{key}]"),
                if self.theme.mono {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(self.theme.accent)
                },
            ));
            spans.push(Span::styled(label.to_string(), self.theme.dim_style()));
        }
        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn render_detail(&self, f: &mut Frame) {
        let Some(row) = self.selected_row() else {
            return;
        };
        let area = centered_rect(80, 85, f.area());
        f.render_widget(Clear, area);
        let lines = detail_lines(row);
        let title = format!(
            " Evento {} {} (j/k rola, Esc fecha) ",
            row.client_ip, row.risk_level
        );
        let block = Block::default().borders(Borders::ALL).title(title);
        let para = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.detail_scroll, 0));
        f.render_widget(para, area);
    }

    fn render_input(&self, f: &mut Frame) {
        let area = popup_rect(60, 3, f.area());
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Filtrar (Enter aplica · vazio limpa · Esc cancela) ");
        let line = Line::from(vec![Span::raw(format!("> {}_", self.input))]);
        f.render_widget(Paragraph::new(line).block(block), area);
    }

    fn render_confirm(&self, f: &mut Frame, pending: Pending) {
        let area = popup_rect(60, 5, f.area());
        f.render_widget(Clear, area);
        let block = Block::default().borders(Borders::ALL).title(" Confirmar ");
        let lines = vec![
            Line::raw(pending.prompt()),
            Line::raw(String::new()),
            Line::from(vec![
                Span::styled("[y]", self.theme.accent_style()),
                Span::raw(" confirmar   "),
                Span::styled("[n/Esc]", self.theme.accent_style()),
                Span::raw(" cancelar"),
            ]),
        ];
        f.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn render_lines_popup(&self, f: &mut Frame, title: &str, lines: &[String]) {
        let area = popup_rect(70, (lines.len() as u16 + 2).min(f.area().height), f.area());
        f.render_widget(Clear, area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" {title} (Esc fecha) "));
        let body: Vec<Line> = lines.iter().map(|l| Line::raw(l.clone())).collect();
        f.render_widget(Paragraph::new(body).block(block), area);
    }
}

fn popup_rect(width_pct: u16, height: u16, r: Rect) -> Rect {
    let width = (r.width * width_pct / 100).max(10).min(r.width);
    let height = height.min(r.height);
    Rect {
        x: r.x + (r.width - width) / 2,
        y: r.y + (r.height - height) / 2,
        width,
        height,
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(r);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

fn row_spans<'a>(row: &'a EventRow, theme: &'a Theme, width: u16) -> Vec<Span<'a>> {
    let parts = agg::http_parts(row);
    let time = row.timestamp.format("%H:%M:%S").to_string();
    let fixed = 26;
    let path_w = (width.saturating_sub(fixed) as usize).clamp(10, 60);
    let mut spans = vec![
        Span::styled(time, theme.dim_style()),
        Span::raw(" "),
        Span::styled(
            format!("{:<8}", row.risk_level),
            theme.level_style(&row.risk_level),
        ),
        Span::raw(format!(" {:>3}", row.risk_score)),
        Span::raw(format!(" {:<15}", row.client_ip)),
        Span::styled(format!(" [{:<7}]", row.source), theme.dim_style()),
        Span::raw(format!(" {:<7}", parts.method.as_deref().unwrap_or("-"))),
        Span::raw(format!(
            " {:<w$}",
            agg::truncate(&parts.path, path_w),
            w = path_w
        )),
        Span::raw(format!(
            " {:>3}",
            parts
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into())
        )),
    ];
    let summary = agg::signal_summary(row);
    if !summary.is_empty() {
        spans.push(Span::styled(format!(" {summary}"), theme.warn_style()));
    }
    spans
}

fn detail_lines(row: &EventRow) -> Vec<Line<'static>> {
    let parts = agg::http_parts(row);
    let mut lines = vec![
        Line::raw(format!(
            "hora     {}",
            row.timestamp.format("%d/%m/%Y %H:%M:%S")
        )),
        Line::raw(format!(
            "cliente  {}:{} → porta {}",
            row.client_ip,
            row.client_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
            row.server_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".into()),
        )),
        Line::raw(format!(
            "geo      ASN {} · {}",
            row.asn.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
            row.country.as_deref().unwrap_or("-"),
        )),
        Line::raw(format!(
            "request  {} {} → {}",
            parts.method.as_deref().unwrap_or("-"),
            parts.path,
            parts
                .status
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".into()),
        )),
        Line::raw(format!(
            "risco    {} (score {}) · verdict {} · source {}",
            row.risk_level, row.risk_score, row.verdict, row.source,
        )),
        Line::raw(String::new()),
        Line::raw("sinais:"),
    ];

    let signals = agg::signals_of(row);
    if signals.is_empty() {
        lines.push(Line::raw("  (nenhum)"));
    } else {
        for (kind, weight, detail) in signals {
            let label = agg::signal_label(&kind);
            if detail.is_empty() {
                lines.push(Line::raw(format!("  • {label} (+{weight})")));
            } else {
                lines.push(Line::raw(format!("  • {label} (+{weight}) {detail}")));
            }
        }
    }

    lines.push(Line::raw(String::new()));
    lines.push(Line::raw("protocolo:"));
    if let Ok(pretty) = serde_json::to_string_pretty(&row.protocol) {
        for l in pretty.lines().take(60) {
            lines.push(Line::raw(format!("  {l}")));
        }
        if pretty.lines().count() > 60 {
            lines.push(Line::raw("  … (truncado)"));
        }
    }
    if let Some(raw) = &row.raw {
        lines.push(Line::raw(String::new()));
        lines.push(Line::raw(format!("raw: {}", agg::truncate(raw, 400))));
    }
    lines
}
