//! Terminal interface for the forensics lab.
//!
//! The interface renders a fixture catalog, a findings panel, a summary tab,
//! and an aggregated flow tab. It never opens a socket and never requests input from
//! the user. All navigation is keyboard driven.

use crate::analysis::{self, Report, Severity};
use crate::loader::{self, Loaded};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Row, Table, Tabs},
    Terminal,
};
use std::io;

/// Tab identifiers in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Findings,
    Summary,
    Flows,
}

impl Tab {
    fn _label(self) -> &'static str {
        match self {
            Self::Findings => "Findings",
            Self::Summary => "Summary",
            Self::Flows => "Flows",
        }
    }
}

/// Run the interactive terminal against the bundled fixtures.
pub async fn run() -> anyhow::Result<()> {
    let entries = loader::load_bundled().await;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(entries);
    let result = app_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    result
}

struct App {
    entries: Vec<(crate::fixtures::Bundled, anyhow::Result<Loaded>)>,
    selected: usize,
    list_state: ListState,
    tab: Tab,
}

impl App {
    fn new(entries: Vec<(crate::fixtures::Bundled, anyhow::Result<Loaded>)>) -> Self {
        let mut list_state = ListState::default();
        if !entries.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            entries,
            selected: 0,
            list_state,
            tab: Tab::Findings,
        }
    }

    fn current(&self) -> Option<&(crate::fixtures::Bundled, anyhow::Result<Loaded>)> {
        self.entries.get(self.selected)
    }

    fn move_selection(&mut self, delta: i32) {
        if self.entries.is_empty() {
            return;
        }
        let n = self.entries.len() as i32;
        let mut next = self.selected as i32 + delta;
        next = ((next % n) + n) % n;
        self.selected = next as usize;
        self.list_state.select(Some(next as usize));
    }

    fn cycle_tab(&mut self, delta: i32) {
        let order = [Tab::Findings, Tab::Summary, Tab::Flows];
        let idx = order.iter().position(|t| *t == self.tab).unwrap_or(0) as i32;
        let n = order.len() as i32;
        let next = (((idx + delta) % n) + n) % n;
        self.tab = order[next as usize];
    }
}

fn app_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|f| draw(f, app))?;
        if !event::poll(std::time::Duration::from_millis(100))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
                KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
                KeyCode::Tab => app.cycle_tab(1),
                KeyCode::BackTab => app.cycle_tab(-1),
                KeyCode::Char('1') => app.tab = Tab::Findings,
                KeyCode::Char('2') => app.tab = Tab::Summary,
                KeyCode::Char('3') => app.tab = Tab::Flows,
                _ => {}
            }
        }
    }
}

fn draw(f: &mut ratatui::Frame<'_>, app: &mut App) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(2),
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_body(f, app, chunks[1]);
    draw_help(f, chunks[2]);
}

fn draw_header(f: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
    let title = Line::from(vec![Span::styled(
        " PACKET FORENSICS LAB ",
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )]);
    let tabs = Tabs::new(vec!["Findings", "Summary", "Flows"])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .select(app.tab as usize)
        .divider(" | ");
    f.render_widget(tabs, area);
}

fn draw_body(f: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(34), Constraint::Min(0)])
        .split(area);

    draw_catalog(f, app, columns[0]);

    let Some((fixture, loaded)) = app.current() else {
        let p = Paragraph::new("No fixtures available.").block(block("Detail", Color::DarkGray));
        f.render_widget(p, columns[1]);
        return;
    };
    match app.tab {
        Tab::Findings => draw_findings(f, fixture, loaded, columns[1]),
        Tab::Summary => draw_summary(f, fixture, loaded, columns[1]),
        Tab::Flows => draw_flows(f, loaded, columns[1]),
    }
}

fn draw_catalog(f: &mut ratatui::Frame<'_>, app: &mut App, area: Rect) {
    let items: Vec<ListItem<'_>> = app
        .entries
        .iter()
        .map(|(fixture, loaded)| {
            let sev = loaded
                .as_ref()
                .map(|l| l.report.max_severity())
                .unwrap_or(Severity::Info);
            let badge = severity_span(sev);
            ListItem::new(vec![
                Line::from(vec![
                    badge,
                    Span::styled(
                        format!(" {:<10}", fixture.name),
                        Style::default().fg(Color::Cyan),
                    ),
                ]),
                Line::from(Span::styled(
                    format!(" {}", fixture.title),
                    Style::default().fg(Color::DarkGray),
                )),
            ])
        })
        .collect();
    let list = List::new(items)
        .block(block("Fixtures", Color::Cyan))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");
    f.render_stateful_widget(&list, area, &mut app.list_state);
}

fn draw_findings(
    f: &mut ratatui::Frame<'_>,
    fixture: &crate::fixtures::Bundled,
    loaded: &anyhow::Result<Loaded>,
    area: Rect,
) {
    let Ok(loaded) = loaded else {
        let err = match loaded {
            Err(e) => format!("{e}"),
            Ok(_) => String::new(),
        };
        let p = Paragraph::new(format!("Failed to analyze fixture {}: {err}", fixture.name))
            .block(block("Findings", Color::Red));
        f.render_widget(p, area);
        return;
    };
    let report: &Report = &loaded.report;
    if report.findings.is_empty() {
        let p = Paragraph::new("No anomalies were detected in this fixture.")
            .block(block("Findings", Color::Green));
        f.render_widget(p, area);
        return;
    }
    let mut lines = Vec::new();
    for finding in &report.findings {
        lines.push(Line::from(vec![
            severity_span(finding.severity),
            Span::styled(
                format!(" [{}] ", finding.category.label()),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                finding.title.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::from(Span::styled(
            format!("  {}\n", finding.detail),
            Style::default().fg(Color::Gray),
        )));
    }
    let p =
        Paragraph::new(lines).block(block(&format!("Findings - {}", fixture.name), Color::Cyan));
    f.render_widget(p, area);
}

fn draw_summary(
    f: &mut ratatui::Frame<'_>,
    fixture: &crate::fixtures::Bundled,
    loaded: &anyhow::Result<Loaded>,
    area: Rect,
) {
    let mut lines = vec![
        Line::from(Span::styled(
            format!("Fixture:  {}\n", fixture.name),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            format!("Scenario: {}\n", fixture.title),
            Style::default().fg(Color::Gray),
        )),
    ];
    match loaded {
        Ok(loaded) => {
            let r = &loaded.report;
            let s = &r.summary;
            lines.push(make_line(format!("Source file:    {}", r.source)));
            lines.push(make_line(format!("Frames decoded: {}", s.frames)));
            lines.push(make_line(format!("IP flows:       {}", s.flows)));
            lines.push(make_line(format!("DNS queries:    {}", s.dns_queries)));
            lines.push(make_line(format!("DNS responses:  {}", s.dns_responses)));
            lines.push(make_line(format!("TCP SYN packets:{}", s.tcp_syns)));
            lines.push(make_line(format!(
                "Capture window: {:.2} s",
                s.span_micros as f64 / 1_000_000.0
            )));
            lines.push(make_line(format!("Findings count: {}", r.findings.len())));
        }
        Err(e) => lines.push(make_line(format!("Error: {e}"))),
    }
    let p = Paragraph::new(lines).block(block("Summary", Color::Cyan));
    f.render_widget(p, area);
}

fn draw_flows(f: &mut ratatui::Frame<'_>, loaded: &anyhow::Result<Loaded>, area: Rect) {
    let Ok(loaded) = loaded else {
        let p = Paragraph::new("No flow data available.").block(block("Flows", Color::DarkGray));
        f.render_widget(p, area);
        return;
    };
    let stats = analysis::flow_stats(&loaded.frames);
    if stats.is_empty() {
        let p = Paragraph::new("No decodable frames were present in this fixture.")
            .block(block("Flows", Color::DarkGray));
        f.render_widget(p, area);
        return;
    }
    let header = Row::new(vec![
        "#",
        "proto",
        "source",
        "destination",
        "pkts",
        "bytes",
        "span",
        "SYNs",
    ])
    .style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row<'_>> = stats
        .iter()
        .take(200)
        .enumerate()
        .map(|(i, stat)| {
            Row::new(vec![
                i.to_string(),
                proto_label(stat.flow.proto).to_string(),
                format_endpoint(stat.flow.src, stat.flow.src_port),
                format_endpoint(stat.flow.dst, stat.flow.dst_port),
                stat.packets.to_string(),
                format_bytes(stat.bytes),
                format_duration(stat.duration_micros()),
                stat.tcp_syns.to_string(),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Length(22),
        Constraint::Length(22),
        Constraint::Length(6),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(5),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(block("Flows (aggregated five-tuples)", Color::Cyan));
    f.render_widget(table, area);
}

fn draw_help(f: &mut ratatui::Frame<'_>, area: Rect) {
    let help = "Up/Down select  Tab switch view  1-3 jump tab  q quit";
    let p = Paragraph::new(help)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::TOP));
    f.render_widget(p, area);
}

// Helpers ---------------------------------------------------------------

fn block<'a>(title: &str, accent: Color) -> Block<'a> {
    let title = format!(" {} ", title);
    Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(accent))
}

fn severity_span(sev: Severity) -> Span<'static> {
    let (label, color) = match sev {
        Severity::High => ("HIGH", Color::Red),
        Severity::Medium => ("MED ", Color::Yellow),
        Severity::Low => ("LOW ", Color::Green),
        Severity::Info => ("INFO", Color::DarkGray),
    };
    Span::styled(
        format!(" {label} "),
        Style::default()
            .fg(Color::Black)
            .bg(color)
            .add_modifier(Modifier::BOLD),
    )
}

fn make_line(text: String) -> Line<'static> {
    Line::from(text)
}

fn proto_label(p: crate::packet::Proto) -> &'static str {
    match p {
        crate::packet::Proto::Udp => "UDP",
        crate::packet::Proto::Tcp => "TCP",
    }
}

fn format_endpoint(address: std::net::Ipv4Addr, port: u16) -> String {
    format!("{address}:{port}")
}

fn format_bytes(bytes: usize) -> String {
    format!("{bytes} B")
}

fn format_duration(micros: u64) -> String {
    if micros < 1_000 {
        format!("{micros} us")
    } else {
        format!("{:.2} ms", micros as f64 / 1_000.0)
    }
}
