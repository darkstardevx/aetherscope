use crate::app::{self, App, Mode};
use crate::theme::Theme;
use aetherscope_core::packet::TransportHeader;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Row, Table, TableState, Wrap};
use ratatui::Frame;

pub fn draw(frame: &mut Frame, app: &App, theme: &Theme) {
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(theme.bg)), area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(area);

    draw_table(frame, app, theme, chunks[0]);
    draw_status(frame, app, theme, chunks[1]);
    draw_footer(frame, app, theme, chunks[2]);

    match app.mode {
        Mode::Detail => draw_detail_popup(frame, area, app, theme),
        Mode::Stream => draw_stream_popup(frame, area, app, theme),
        Mode::ExportPrompt => draw_export_prompt(frame, area, app, theme),
        Mode::Help => draw_help_popup(frame, area, theme),
        _ => {}
    }
}

fn protocol_label_and_color(
    transport: Option<&TransportHeader>,
    theme: &Theme,
) -> (&'static str, ratatui::style::Color) {
    match transport {
        Some(TransportHeader::Tcp { .. }) => ("TCP", theme.acid_green),
        Some(TransportHeader::Udp { .. }) => ("UDP", theme.cyan),
        Some(TransportHeader::Icmp { .. }) => ("ICMP", theme.orange),
        Some(TransportHeader::Icmpv6 { .. }) => ("ICMPv6", theme.purple),
        Some(TransportHeader::Other { .. }) => ("OTHER", theme.muted),
        None => ("?", theme.muted),
    }
}

fn draw_table(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let header = Row::new(vec!["#", "Src", "Dst", "Proto", "Len", "Info"]).style(
        Style::default()
            .fg(theme.orange)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .filtered
        .iter()
        .map(|&i| {
            let f = &app.frames[i];
            let (proto, proto_color) = protocol_label_and_color(f.parsed.transport.as_ref(), theme);
            let (src, dst) = match (&f.parsed.ip, &f.parsed.transport) {
                (
                    Some(ip),
                    Some(TransportHeader::Tcp {
                        src_port, dst_port, ..
                    }),
                ) => (
                    format!("{}:{}", ip.src, src_port),
                    format!("{}:{}", ip.dst, dst_port),
                ),
                (
                    Some(ip),
                    Some(TransportHeader::Udp {
                        src_port, dst_port, ..
                    }),
                ) => (
                    format!("{}:{}", ip.src, src_port),
                    format!("{}:{}", ip.dst, dst_port),
                ),
                (Some(ip), _) => (ip.src.to_string(), ip.dst.to_string()),
                (None, _) => ("?".to_string(), "?".to_string()),
            };
            let info = match &f.parsed.transport {
                Some(TransportHeader::Tcp { flags, .. }) => format!("[{}]", flags.short()),
                Some(TransportHeader::Icmp { icmp_type, code }) => {
                    format!("type={icmp_type} code={code}")
                }
                _ => String::new(),
            };

            Row::new(vec![
                Line::from(Span::styled(
                    (i + 1).to_string(),
                    Style::default().fg(theme.muted),
                )),
                Line::from(Span::styled(src, Style::default().fg(theme.white))),
                Line::from(Span::styled(dst, Style::default().fg(theme.white))),
                Line::from(Span::styled(proto, Style::default().fg(proto_color))),
                Line::from(Span::styled(
                    f.parsed.len.to_string(),
                    Style::default().fg(theme.muted),
                )),
                Line::from(Span::styled(info, Style::default().fg(theme.muted))),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(6),
        Constraint::Percentage(28),
        Constraint::Percentage(28),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Min(10),
    ];

    let source_label = app
        .loaded_from
        .as_ref()
        .map(|p| format!(" — {}", p.display()))
        .unwrap_or_default();
    let follow_indicator = if app.loaded_from.is_some() {
        String::new()
    } else if app.follow_live {
        " [following]".to_string()
    } else {
        " [browsing]".to_string()
    };
    let title = format!(
        " proteus — {} packets{}{} ",
        app.frames.len(),
        source_label,
        follow_indicator
    );
    let table = Table::new(rows, widths)
        .header(header)
        .row_highlight_style(
            Style::default()
                .bg(theme.hot_pink)
                .fg(theme.white)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ")
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(theme.orange))
                .title(Span::styled(title, Style::default().fg(theme.orange))),
        );

    let mut state = TableState::default();
    state.select(if app.filtered.is_empty() {
        None
    } else {
        Some(app.selected)
    });
    frame.render_stateful_widget(table, area, &mut state);
}

fn draw_status(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let (text, color) = match &app.mode {
        Mode::Filter => (format!("filter: {}_", app.filter_text), theme.cyan),
        Mode::ExportPrompt => (format!("export to: {}_", app.export_path_input), theme.cyan),
        _ if app.frames.is_empty() && app.loaded_from.is_none() => (
            "no packets yet — waiting for live traffic".to_string(),
            theme.red,
        ),
        _ => (app.status.clone().unwrap_or_default(), theme.cyan),
    };
    frame.render_widget(Paragraph::new(text).style(Style::default().fg(color)), area);
}

fn draw_footer(frame: &mut Frame, app: &App, theme: &Theme, area: Rect) {
    let follow_key = if app.loaded_from.is_some() {
        ""
    } else if app.follow_live {
        "f pause  "
    } else {
        "f follow  "
    };
    let text = format!(
        "j/k nav  enter/l detail  s follow stream  w export  /  filter  {follow_key}? help  q quit"
    );
    frame.render_widget(
        Paragraph::new(text).style(Style::default().fg(theme.muted)),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn draw_detail_popup(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let popup = centered_rect(85, 80, area);
    frame.render_widget(Clear, popup);
    let text = app
        .selected_frame()
        .map(app::detail_lines)
        .unwrap_or_default();
    let block = Block::default()
        .style(Style::default().bg(theme.panel).fg(theme.white))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.orange))
        .title(Span::styled(
            " packet detail (Esc to close) ",
            Style::default().fg(theme.orange),
        ));
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(block),
        popup,
    );
}

fn draw_stream_popup(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let popup = centered_rect(85, 80, area);
    frame.render_widget(Clear, popup);

    let lines: Vec<Line> = app
        .stream_lines
        .iter()
        .map(|l| {
            let color = if l.from_a {
                theme.acid_green
            } else {
                theme.cyan
            };
            Line::from(Span::styled(l.text.clone(), Style::default().fg(color)))
        })
        .collect();

    let title = if app.stream_lines.is_empty() {
        " follow tcp stream — no readable payload in this conversation (Esc to close) ".to_string()
    } else {
        " follow tcp stream — green = one side, cyan = the other (Esc to close) ".to_string()
    };
    let block = Block::default()
        .style(Style::default().bg(theme.panel).fg(theme.white))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.orange))
        .title(Span::styled(title, Style::default().fg(theme.orange)));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        popup,
    );
}

fn draw_export_prompt(frame: &mut Frame, area: Rect, app: &App, theme: &Theme) {
    let popup = centered_rect(60, 20, area);
    frame.render_widget(Clear, popup);
    let text = format!(
        "Export {} packet(s) to:\n\n{}_\n\nEnter to confirm, Esc to cancel",
        app.frames.len(),
        app.export_path_input
    );
    let block = Block::default()
        .style(Style::default().bg(theme.panel).fg(theme.white))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.orange))
        .title(Span::styled(
            " export to .pcap ",
            Style::default().fg(theme.orange),
        ));
    frame.render_widget(
        Paragraph::new(text).wrap(Wrap { trim: false }).block(block),
        popup,
    );
}

fn draw_help_popup(frame: &mut Frame, area: Rect, theme: &Theme) {
    let popup = centered_rect(65, 60, area);
    frame.render_widget(Clear, popup);
    let lines = [
        "j/k, ↑/↓   move",
        "/          filter by src/dst/proto/info substring",
        "enter, l   show full packet detail (headers + hexdump)",
        "s          Follow TCP Stream for the selected packet",
        "w          export all captured packets to a .pcap file",
        "f          toggle follow-live / browse-history (live capture only)",
        "?          toggle this help",
        "q, Esc     quit (Esc closes a popup first)",
    ]
    .join("\n");
    let block = Block::default()
        .style(Style::default().bg(theme.panel).fg(theme.white))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.line))
        .title(Span::styled(
            " proteus — keys ",
            Style::default().fg(theme.line),
        ));
    frame.render_widget(Paragraph::new(lines).block(block), popup);
}
