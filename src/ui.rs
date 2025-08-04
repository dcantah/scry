use crate::annotate::Category;
use crate::app::{App, MENU_ITEMS, Screen};
use crate::proc::{extract_wchan, fmt_bytes};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, Wrap},
};

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    // The picker doesn't need the per-pid header, so give it the whole window.
    let header_h = if app.attached { 6 } else { 2 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_h),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(area);

    // Each body screen runs inside a bordered block, so the inner
    // (scrollable) area is two rows shorter than the chunk itself.
    app.body_inner_height = chunks[1].height.saturating_sub(2);
    app.body_y = chunks[1].y;
    if app.attached {
        draw_header(f, chunks[0], app);
    } else {
        draw_picker_header(f, chunks[0], app);
    }
    match app.screen {
        Screen::Picker => draw_picker(f, chunks[1], app),
        Screen::Menu => draw_menu(f, chunks[1], app),
        Screen::Maps => draw_maps(f, chunks[1], app),
        Screen::Threads => draw_threads(f, chunks[1], app),
        Screen::Fds => draw_fds(f, chunks[1], app),
        Screen::Limits => draw_limits(f, chunks[1], app),
        Screen::Cgroup => draw_cgroup(f, chunks[1], app),
        Screen::Environ => draw_environ(f, chunks[1], app),
        Screen::KernelStack => draw_kstack(f, chunks[1], app),
        Screen::Syscalls => draw_syscalls(f, chunks[1], app),
        Screen::Tree => draw_tree(f, chunks[1], app),
        Screen::SignalSend => draw_signals(f, chunks[1], app),
        Screen::Capabilities => draw_capabilities(f, chunks[1], app),
        Screen::Namespaces => draw_namespaces(f, chunks[1], app),
        Screen::Security => draw_security(f, chunks[1], app),
    }
    draw_footer(f, chunks[2], app);

    if app.show_help {
        draw_help(f, area, app);
    }
}

fn draw_signals(f: &mut Frame, area: Rect, app: &App) {
    let s = &app.signals;
    let filter_part = if s.editing_filter {
        format!(" · filter (typing): {}_", s.filter)
    } else if !s.filter.is_empty() {
        format!(" · filter: {}", s.filter)
    } else {
        String::new()
    };
    let title = format!(
        " send signal to pid {} ({}) · {}/{}{} ",
        app.pid,
        app.summary.info.name,
        s.view.len(),
        s.entries.len(),
        filter_part,
    );
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(
            title,
            Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if s.view.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "no signals match this filter",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(p, inner);
        return;
    }

    let items: Vec<ListItem> = s
        .view
        .iter()
        .map(|&i| {
            let e = &s.entries[i];
            let name_style = if e.name.starts_with("SIGRT") {
                Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::LightYellow).add_modifier(Modifier::BOLD)
            };
            let line = Line::from(vec![
                Span::styled(
                    format!(" {:>3} ", e.num),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(format!("{:<14}", e.name), name_style),
                Span::raw(e.desc.as_str()),
            ]);
            ListItem::new(line)
        })
        .collect();
    let list = List::new(items)
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    state.select(Some(s.selected.min(s.view.len().saturating_sub(1))));
    f.render_stateful_widget(list, inner, &mut state);
}

// ---------------------------------------------------------------------------
// Header. Always visible.
// ---------------------------------------------------------------------------

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let info = &app.summary.info;
    let stat = &app.summary.stat;
    let exe = info
        .exe_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "<unknown>".to_string());

    let frozen_tag = if app.frozen { " · ⏸ FROZEN" } else { "" };
    let title = format!(
        "scry · pid {} ({}) · ppid {} · state {} · {}{}",
        info.pid,
        info.name,
        stat.ppid,
        stat.state,
        if app.user.is_root {
            "[running as root]"
        } else {
            "[non-root]"
        },
        frozen_tag,
    );

    let cmd: &str = if app.summary.info.cmdline.is_empty() {
        "<empty>"
    } else {
        &app.summary.info.cmdline
    };
    let lines = vec![
        Line::from(Span::styled(title, Style::default().bold().fg(Color::Cyan))),
        Line::from(vec![label("Exe: "), Span::raw(exe)]),
        Line::from(vec![label("Cmd: "), Span::raw(cmd)]),
        Line::from(mem_line(app)),
        Line::from(io_line(app)),
    ];
    let p = Paragraph::new(lines).block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(p, area);
}

// Colour used for every label in the persistent header so values pop.
const LABEL_COLOR: Color = Color::LightMagenta;

fn label(text: &str) -> Span<'static> {
    Span::styled(
        text.to_string(),
        Style::default().fg(LABEL_COLOR).add_modifier(Modifier::BOLD),
    )
}

fn sep() -> Span<'static> {
    Span::styled(" · ", Style::default().fg(Color::DarkGray))
}

fn val(text: String) -> Span<'static> {
    Span::raw(text)
}

fn mem_line(app: &App) -> Vec<Span<'static>> {
    let info = &app.summary.info;
    let stat = &app.summary.stat;
    let fds_text = app
        .summary
        .open_fds
        .map(|n| n.to_string())
        .unwrap_or_else(|| "?".to_string());
    vec![
        label("Threads "),
        val(info.threads.to_string()),
        sep(),
        label("Fds "),
        val(fds_text),
        sep(),
        label("VmRSS "),
        val(fmt_kb(info.vm_rss_kb)),
        sep(),
        label("VmSize "),
        val(fmt_kb(info.vm_size_kb)),
        sep(),
        label("VmData "),
        val(fmt_kb(info.vm_data_kb)),
        sep(),
        label("VmStk "),
        val(fmt_kb(info.vm_stk_kb)),
        sep(),
        label("VmLib "),
        val(fmt_kb(info.vm_lib_kb)),
        sep(),
        label("Cpu "),
        val(format!("{:.1}%", app.summary.cpu_percent)),
        sep(),
        label("Nice "),
        val(stat.nice.to_string()),
    ]
}

fn io_line(app: &App) -> Vec<Span<'static>> {
    if app.summary.io.is_empty() {
        return vec![label("Io: "), val("<unavailable>".into())];
    }
    let stat = &app.summary.stat;
    vec![
        label("Io"),
        sep(),
        label("Rd "),
        val(fmt_bytes(app.summary.io.get("read_bytes").copied().unwrap_or(0))),
        sep(),
        label("Wr "),
        val(fmt_bytes(app.summary.io.get("write_bytes").copied().unwrap_or(0))),
        sep(),
        label("Syscr "),
        val(app.summary.io.get("syscr").copied().unwrap_or(0).to_string()),
        sep(),
        label("Syscw "),
        val(app.summary.io.get("syscw").copied().unwrap_or(0).to_string()),
        sep(),
        label("Minflt "),
        val(stat.minflt.to_string()),
        sep(),
        label("Majflt "),
        val(stat.majflt.to_string()),
    ]
}

// ---------------------------------------------------------------------------
// Picker screen
// ---------------------------------------------------------------------------

fn draw_picker_header(f: &mut Frame, area: Rect, app: &App) {
    let frozen_tag = if app.frozen { " · ⏸  FROZEN" } else { "" };
    let title = format!(
        "scry · pick a process · {}{}",
        if app.user.is_root {
            "[running as root]"
        } else {
            "[non-root: some views will be hidden]"
        },
        frozen_tag,
    );
    let lines = vec![
        Line::from(Span::styled(title, Style::default().bold().fg(Color::Cyan))),
        Line::from(Span::styled(
            "↑/↓ scroll · Enter to attach · / filter · s cycle sort · r reverse · Z pause · R refresh · q quit",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let p = Paragraph::new(lines).block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(p, area);
}

fn draw_picker(f: &mut Frame, area: Rect, app: &App) {
    let p = &app.picker;
    let filter_suffix = if !p.filter.is_empty() {
        format!(" · filter: {}", p.filter)
    } else {
        String::new()
    };
    let title = format!(
        " processes ({}/{}) · sort: {}{}{} ",
        p.view.len(),
        p.entries.len(),
        p.sort.label(),
        if p.sort_desc { " ↓" } else { " ↑" },
        filter_suffix,
    );

    let header = Row::new(
        ["PID", "USER", "STATE", "%CPU", "RSS", "COMMAND"]
            .iter()
            .map(|s| Cell::from(*s).style(Style::default().fg(Color::Yellow).bold())),
    )
    .height(1);

    let inner_width = area.width.saturating_sub(2) as usize;
    let fixed_cols = 8 + 12 + 7 + 7 + 9 + 5; // approx widths + separators
    let cmd_width = inner_width.saturating_sub(fixed_cols).max(20);

    let rows: Vec<Row> = p
        .view
        .iter()
        .map(|&i| {
            let e = &p.entries[i];
            let state_style = match e.state {
                'R' => Style::default().fg(Color::LightGreen),
                'S' => Style::default().fg(Color::DarkGray),
                'D' => Style::default().fg(Color::Yellow),
                'Z' => Style::default().fg(Color::Red),
                'T' | 't' => Style::default().fg(Color::Magenta),
                _ => Style::default(),
            };
            let cpu_style = if e.cpu_percent > 10.0 {
                Style::default().fg(Color::LightYellow)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(e.pid.to_string()),
                Cell::from(truncate(&e.user, 12)),
                Cell::from(e.state.to_string()).style(state_style),
                Cell::from(format!("{:>5.1}", e.cpu_percent)).style(cpu_style),
                Cell::from(fmt_kb(e.rss_kb)),
                Cell::from(truncate(&e.cmdline, cmd_width)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(9),
        Constraint::Min(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White).bold())
        .highlight_symbol("▶ ");

    let mut state = ratatui::widgets::TableState::default();
    if !p.view.is_empty() {
        state.select(Some(p.selected));
    }
    f.render_stateful_widget(table, area, &mut state);
}

// ---------------------------------------------------------------------------
// Menu screen
// ---------------------------------------------------------------------------

fn draw_menu(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" choose a view (↑/↓ + Enter, or scroll wheel + click) ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(inner);

    let items: Vec<ListItem> = MENU_ITEMS
        .iter()
        .map(|item| {
            let mut style = Style::default();
            let mut suffix = "";
            if item.needs_root && !app.user.is_root {
                style = style.fg(Color::DarkGray).add_modifier(Modifier::DIM);
                suffix = "   (needs root)";
            }
            ListItem::new(Line::from(vec![
                Span::styled(format!("  {}{}", item.label, suffix), style),
            ]))
        })
        .collect();
    let list = List::new(items)
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    state.select(Some(app.menu_selected));
    f.render_stateful_widget(list, cols[0], &mut state);

    // Right pane: description for the highlighted item
    let item = app.current_menu_item();
    let mut lines = vec![
        Line::from(Span::styled(
            item.label,
            Style::default().bold().fg(Color::Cyan),
        )),
        Line::from(""),
        Line::from(item.desc),
    ];
    if item.needs_root {
        lines.push(Line::from(""));
        if app.user.is_root {
            lines.push(Line::from(Span::styled(
                "Requires root. You have it ✓",
                Style::default().fg(Color::Green),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Requires root.",
                Style::default().fg(Color::Red),
            )));
        }
    }
    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::LEFT));
    f.render_widget(p, cols[1]);
}

// ---------------------------------------------------------------------------
// Maps screen
// ---------------------------------------------------------------------------

fn draw_maps(f: &mut Frame, area: Rect, app: &App) {
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    draw_maps_table(f, body[0], app);
    draw_maps_detail(f, body[1], app);
}

fn draw_maps_table(f: &mut Frame, area: Rect, app: &App) {
    let sort_col = app.maps.sort.column_header();
    let arrow = if app.maps.sort_desc { " ↓" } else { " ↑" };
    let make_header = |name: &str| -> Cell<'static> {
        if name == sort_col {
            Cell::from(format!("{name}{arrow}"))
                .style(Style::default().fg(Color::LightYellow).bold().underlined())
        } else {
            Cell::from(name.to_string()).style(Style::default().fg(Color::Yellow).bold())
        }
    };
    let header = Row::new([
        make_header("Address range"),
        make_header("Perm"),
        make_header("Size"),
        make_header("Rss"),
        make_header("Pss"),
        make_header("Swap"),
        make_header("Cat"),
        make_header("What"),
    ])
    .height(1);

    let inner_width = area.width.saturating_sub(2) as usize;
    let fixed_cols = 14 + 4 + 9 + 9 + 9 + 9 + 10 + 7;
    let what_width = inner_width.saturating_sub(fixed_cols).max(20);

    let maps = &app.maps;
    let rows: Vec<Row> = maps
        .view
        .iter()
        .map(|&i| {
            let m = &maps.mappings[i];
            let a = &maps.annotations[i];
            let perm = m.line.perms.render();
            let perm_style = perm_style(&perm);
            let cat_style = category_style(a.category);
            let what = truncate(&a.headline, what_width);
            Row::new(vec![
                Cell::from(format!("{:012x}-{:012x}", m.line.start, m.line.end)),
                Cell::from(perm).style(perm_style),
                Cell::from(fmt_kb(m.size() / 1024)),
                Cell::from(fmt_kb(m.smaps.rss_kb)),
                Cell::from(fmt_kb(m.smaps.pss_kb)),
                Cell::from(if m.smaps.swap_kb > 0 {
                    fmt_kb(m.smaps.swap_kb)
                } else {
                    "·".into()
                }),
                Cell::from(a.category.short()).style(cat_style),
                Cell::from(what),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(27),
        Constraint::Length(4),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(10),
        Constraint::Min(20),
    ];

    let filter_part = if maps.editing_filter {
        format!(" · filter (typing): {}_", maps.filter)
    } else if !maps.filter.is_empty() {
        format!(" · filter: {}", maps.filter)
    } else {
        String::new()
    };
    let title = format!(
        " mappings ({}/{}) · Sort: {} {}{} ",
        maps.view.len(),
        maps.mappings.len(),
        maps.sort.label(),
        if maps.sort_desc { "↓ desc" } else { "↑ asc" },
        filter_part,
    );

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(Style::default().bg(Color::DarkGray).fg(Color::White).bold())
        .highlight_symbol("▶ ");

    let mut state = ratatui::widgets::TableState::default();
    if !maps.view.is_empty() {
        state.select(Some(maps.selected));
    }
    f.render_stateful_widget(table, area, &mut state);
}

fn draw_maps_detail(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" details ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let maps = &app.maps;
    let Some(m) = maps.current_mapping() else {
        let p = Paragraph::new("no mapping selected");
        f.render_widget(p, inner);
        return;
    };
    let a = maps.current_annotation().expect("annotation pairs with mapping");

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(
            format!("[{}] ", a.category.short()),
            category_style(a.category).bold(),
        ),
        Span::raw(a.headline.as_str()),
    ]));
    lines.push(Line::from(""));
    lines.push(kv("range", &format!("{:#018x} – {:#018x}", m.line.start, m.line.end)));
    lines.push(kv(
        "size",
        &format!(
            "{} ({} pages × {} KB)",
            fmt_kb(m.size() / 1024),
            m.size() / (m.smaps.kernel_page_size_kb.max(4) * 1024),
            m.smaps.kernel_page_size_kb.max(4)
        ),
    ));
    lines.push(kv("perms", &m.line.perms.render()));
    lines.push(kv("offset", &format!("{:#x}", m.line.offset)));
    lines.push(kv("dev/inode", &format!("{} / {}", m.line.dev, m.line.inode)));
    lines.push(kv(
        "path",
        if m.line.path.is_empty() {
            "<anonymous>"
        } else {
            &m.line.path
        },
    ));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "resident memory",
        Style::default().fg(Color::Yellow).bold(),
    )));
    lines.push(kv("Rss", &fmt_kb(m.smaps.rss_kb)));
    lines.push(kv("Pss", &fmt_kb(m.smaps.pss_kb)));
    lines.push(kv("Anonymous", &fmt_kb(m.smaps.anonymous_kb)));
    lines.push(kv(
        "Shared C/D",
        &format!(
            "{} / {}",
            fmt_kb(m.smaps.shared_clean_kb),
            fmt_kb(m.smaps.shared_dirty_kb)
        ),
    ));
    lines.push(kv(
        "Private C/D",
        &format!(
            "{} / {}",
            fmt_kb(m.smaps.private_clean_kb),
            fmt_kb(m.smaps.private_dirty_kb)
        ),
    ));
    lines.push(kv(
        "Swap (Pss)",
        &format!(
            "{} ({})",
            fmt_kb(m.smaps.swap_kb),
            fmt_kb(m.smaps.swap_pss_kb)
        ),
    ));
    lines.push(kv("Referenced", &fmt_kb(m.smaps.referenced_kb)));
    lines.push(kv("AnonHugePages", &fmt_kb(m.smaps.anon_huge_pages_kb)));
    lines.push(kv("Locked", &fmt_kb(m.smaps.locked_kb)));

    if !m.smaps.vm_flags.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "VmFlags",
            Style::default().fg(Color::Yellow).bold(),
        )));
        lines.push(Line::from(m.smaps.vm_flags.join(" ")));
    }

    if !a.details.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "notes",
            Style::default().fg(Color::Yellow).bold(),
        )));
        for d in &a.details {
            lines.push(Line::from(format!("• {d}")));
        }
    }

    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

// ---------------------------------------------------------------------------
// Threads
// ---------------------------------------------------------------------------

fn draw_threads(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(["TID", "Name", "State", "CPU (s)"].iter().map(|s| {
        Cell::from(*s).style(Style::default().fg(Color::Yellow).bold())
    }))
    .height(1);

    let rows: Vec<Row> = app
        .threads
        .iter()
        .map(|t| {
            Row::new(vec![
                Cell::from(t.tid.to_string()),
                Cell::from(t.name.as_str()),
                Cell::from(t.state.as_str()),
                Cell::from(format!("{:.2}", t.cpu_ticks as f64 / 100.0)),
            ])
        })
        .collect();
    let title = format!(" threads ({}) ", app.threads.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(24),
            Constraint::Length(20),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));
    let mut state = ratatui::widgets::TableState::default()
        .with_offset(app.threads_scroll.offset);
    f.render_stateful_widget(table, area, &mut state);
}

// ---------------------------------------------------------------------------
// File descriptors
// ---------------------------------------------------------------------------

fn draw_fds(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(["FD", "Kind", "Target / endpoint", "State / flags"].iter().map(|s| {
        Cell::from(*s).style(Style::default().fg(Color::Yellow).bold())
    }))
    .height(1);

    let mut socket_count = 0usize;
    let mut joined = 0usize;
    let rows: Vec<Row> = app
        .fds
        .iter()
        .map(|fd| {
            let (kind, target, detail, target_style) = decode_fd(fd, app);
            if kind == "socket" {
                socket_count += 1;
                if !detail.is_empty() {
                    joined += 1;
                }
            }
            Row::new(vec![
                Cell::from(fd.fd.to_string()),
                Cell::from(kind).style(kind_style(kind)),
                Cell::from(target).style(target_style),
                Cell::from(detail),
            ])
        })
        .collect();
    let title = format!(
        " open file descriptors ({}) · sockets {}/{} joined ",
        app.fds.len(),
        joined,
        socket_count
    );
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(8),
            Constraint::Min(30),
            Constraint::Length(28),
        ],
    )
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));
    let mut state = ratatui::widgets::TableState::default()
        .with_offset(app.fds_scroll.offset);
    f.render_stateful_widget(table, area, &mut state);
}

/// Classify an FD target and, if it's a socket inode, decorate with the
/// joined endpoint info. Returns (kind_label, target_text, detail_text,
/// target_style).
fn decode_fd(fd: &crate::proc::FdEntry, app: &App) -> (&'static str, String, String, Style) {
    let t = &fd.target;
    // Sockets: "socket:[INODE]"
    if let Some(inner) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
        && let Ok(inode) = inner.parse::<u64>() {
            if let Some(s) = app.sockets.get(&inode) {
                let kind = "socket";
                let target = match s.proto {
                    crate::proc::SocketProto::Unix => {
                        format!("UNIX  {}", s.local)
                    }
                    _ => {
                        if s.remote == "0.0.0.0:0" || s.remote == "[::]:0" || s.remote.is_empty() {
                            format!("{:<5} {}", s.proto.short(), s.local)
                        } else {
                            format!("{:<5} {} → {}", s.proto.short(), s.local, s.remote)
                        }
                    }
                };
                let detail = format!("{}  (inode {})", s.state, s.inode);
                let style = match s.state.as_str() {
                    "LISTEN" => Style::default().fg(Color::LightGreen),
                    "ESTAB" => Style::default().fg(Color::White),
                    "TIME_WAIT" | "CLOSE_WAIT" => Style::default().fg(Color::DarkGray),
                    _ => Style::default(),
                };
                return (kind, target, detail, style);
            }
            // Couldn't join. Show the raw inode so the user can match against `ss`.
            return (
                "socket",
                format!("socket:[{inode}]  (unjoined)"),
                fd.flags.clone().unwrap_or_default(),
                Style::default().fg(Color::DarkGray),
            );
        }

    let kind = if t.starts_with("pipe:[") {
        "pipe"
    } else if t.starts_with("anon_inode:") {
        "anon"
    } else if t.starts_with("/dev/") {
        "dev"
    } else if t.starts_with('/') {
        "file"
    } else {
        "other"
    };
    let pos = fd.pos.map(|p| format!("pos {p}")).unwrap_or_default();
    let flags = fd.flags.clone().unwrap_or_default();
    let detail = if pos.is_empty() {
        flags
    } else if flags.is_empty() {
        pos
    } else {
        format!("{pos}  {flags}")
    };
    (kind, t.clone(), detail, Style::default())
}

fn kind_style(kind: &str) -> Style {
    match kind {
        "socket" => Style::default().fg(Color::LightCyan).bold(),
        "pipe" => Style::default().fg(Color::Magenta),
        "anon" => Style::default().fg(Color::Yellow),
        "dev" => Style::default().fg(Color::LightYellow),
        "file" => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::DarkGray),
    }
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

fn draw_limits(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" resource limits (/proc/<pid>/limits) ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let p = Paragraph::new(app.limits.as_str())
        .wrap(Wrap { trim: false })
        .scroll((app.limits_scroll.offset as u16, 0));
    f.render_widget(p, inner);
}

// ---------------------------------------------------------------------------
// Cgroup
// ---------------------------------------------------------------------------

fn draw_cgroup(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Cgroup membership + resource constraints ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();

    // Membership section
    lines.push(Line::from(Span::styled(
        "Membership  (hierarchy : controllers : path)",
        Style::default().fg(Color::Yellow).bold(),
    )));
    if app.summary.cgroup.is_empty() {
        lines.push(Line::from("  (no cgroup entries; kernel without cgroups?)"));
    }
    for (h, c, path) in &app.summary.cgroup {
        let kind = if h == "0" {
            "v2 unified"
        } else if c.is_empty() {
            "v1 named"
        } else {
            "v1"
        };
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(format!("{:>2}", h), Style::default().fg(Color::DarkGray)),
            Span::raw("  "),
            Span::styled(
                format!("{:<14}", kind),
                Style::default().fg(Color::LightBlue),
            ),
            Span::raw(if c.is_empty() {
                "-".to_string()
            } else {
                c.clone()
            }),
            Span::raw("  →  "),
            Span::styled(path.clone(), Style::default().fg(Color::Cyan)),
        ]));
    }
    lines.push(Line::from(""));

    // Resource sections
    let cg_path = app.summary.cgroup_path();
    lines.push(Line::from(vec![
        Span::styled("Source: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("/sys/fs/cgroup{}/", cg_path),
            Style::default().fg(Color::Cyan),
        ),
    ]));
    lines.push(Line::from(""));

    if app.cgroup_resources.is_empty() {
        lines.push(Line::from(Span::styled(
            "No resource files are readable here. Either controllers haven't been delegated to this cgroup, or it's a slim cgroup such as /init.scope.",
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        for section in &app.cgroup_resources {
            lines.push(Line::from(Span::styled(
                section.heading.to_string(),
                Style::default().fg(Color::Yellow).bold(),
            )));
            // Find widest key for nice alignment.
            let w = section
                .entries
                .iter()
                .map(|(k, _)| k.len())
                .max()
                .unwrap_or(0);
            for (k, v) in &section.entries {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        format!("{:<width$}  ", k, width = w),
                        Style::default().fg(Color::DarkGray),
                    ),
                    value_span(v),
                ]));
            }
            lines.push(Line::from(""));
        }
    }

    let p = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((app.cgroup_scroll.offset as u16, 0));
    f.render_widget(p, inner);
}

fn value_span(v: &str) -> Span<'static> {
    let style = if v.starts_with("max") || v.contains("unlimited") {
        Style::default().fg(Color::Green)
    } else if v.starts_with("(none)") || v.starts_with("(inherited)") {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::White)
    };
    Span::styled(v.to_string(), style)
}

// ---------------------------------------------------------------------------
// Environ
// ---------------------------------------------------------------------------

fn draw_environ(f: &mut Frame, area: Rect, app: &App) {
    let header = Row::new(["Key", "Value"].iter().map(|s| {
        Cell::from(*s).style(Style::default().fg(Color::Yellow).bold())
    }))
    .height(1);
    let rows: Vec<Row> = app
        .environ
        .iter()
        .map(|(k, v)| Row::new(vec![Cell::from(k.as_str()), Cell::from(v.as_str())]))
        .collect();
    let title = format!(
        " environment ({} keys; snapshot at exec, not live) ",
        app.environ.len()
    );
    let table = Table::new(rows, [Constraint::Length(24), Constraint::Min(30)])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    let mut state = ratatui::widgets::TableState::default()
        .with_offset(app.environ_scroll.offset);
    f.render_stateful_widget(table, area, &mut state);
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

fn draw_capabilities(f: &mut Frame, area: Rect, app: &App) {
    use crate::proc::CAP_NAMES;
    let caps = &app.capabilities;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(
            " capabilities · I=inheritable P=permitted E=effective B=bounding A=ambient · {} bits ",
            CAP_NAMES.len()
        ));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let header = Row::new(["#", "I", "P", "E", "B", "A", "Capability"].iter().map(|s| {
        Cell::from(*s).style(Style::default().fg(Color::Yellow).bold())
    }))
    .height(1);

    let mark = |present: bool| -> Cell<'static> {
        if present {
            Cell::from("✓").style(Style::default().fg(Color::LightGreen).bold())
        } else {
            Cell::from("·").style(Style::default().fg(Color::DarkGray))
        }
    };

    // Build one row per defined capability bit. Bits beyond CAP_NAMES.len()
    // are only shown if any set has them on, with a synthetic name.
    let max_bit = CAP_NAMES.len() as u32;
    let mut rows: Vec<Row> = Vec::new();
    for bit in 0..max_bit {
        let mask = 1u64 << bit;
        let present_any = ((caps.inheritable | caps.permitted | caps.effective | caps.bounding | caps.ambient) & mask) != 0;
        // Dim rows with no bit set in any mask, but still show them so the
        // full table is browseable.
        let name = CAP_NAMES[bit as usize];
        let name_style = if present_any {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        rows.push(Row::new(vec![
            Cell::from(format!("{:>2}", bit)).style(Style::default().fg(Color::DarkGray)),
            mark(caps.inheritable & mask != 0),
            mark(caps.permitted & mask != 0),
            mark(caps.effective & mask != 0),
            mark(caps.bounding & mask != 0),
            mark(caps.ambient & mask != 0),
            Cell::from(name).style(name_style),
        ]));
    }
    // Any bits set above our table get appended generically.
    let known_mask: u64 = if max_bit >= 64 { !0u64 } else { (1u64 << max_bit) - 1 };
    let unknown = (caps.inheritable | caps.permitted | caps.effective | caps.bounding | caps.ambient)
        & !known_mask;
    if unknown != 0 {
        for bit in max_bit..64 {
            let mask = 1u64 << bit;
            if unknown & mask == 0 {
                continue;
            }
            rows.push(Row::new(vec![
                Cell::from(format!("{:>2}", bit)).style(Style::default().fg(Color::DarkGray)),
                mark(caps.inheritable & mask != 0),
                mark(caps.permitted & mask != 0),
                mark(caps.effective & mask != 0),
                mark(caps.bounding & mask != 0),
                mark(caps.ambient & mask != 0),
                Cell::from(format!("CAP_{} (kernel-only)", bit))
                    .style(Style::default().fg(Color::Yellow)),
            ]));
        }
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(20),
        ],
    )
    .header(header);

    // Layout: table on top, a one-paragraph summary at the bottom.
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(5)])
        .split(inner);
    let mut state = ratatui::widgets::TableState::default()
        .with_offset(app.caps_scroll.offset);
    f.render_stateful_widget(table, layout[0], &mut state);

    let summary = capabilities_summary(caps);
    let p = Paragraph::new(summary).wrap(Wrap { trim: false });
    f.render_widget(p, layout[1]);
}

fn capabilities_summary(caps: &crate::proc::Capabilities) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let any = caps.inheritable
        | caps.permitted
        | caps.effective
        | caps.bounding
        | caps.ambient;
    if any == 0 {
        lines.push(Line::from(Span::styled(
            "No capabilities held in any set. This process has no extra privileges.",
            Style::default().fg(Color::DarkGray),
        )));
        return lines;
    }
    if caps.effective == 0 && caps.permitted == 0 {
        lines.push(Line::from(Span::styled(
            "No effective or permitted caps. Process cannot exercise privileged operations right now.",
            Style::default().fg(Color::Yellow),
        )));
    }
    if caps.effective != 0 {
        lines.push(Line::from(vec![
            Span::styled("Effective: ", Style::default().fg(Color::LightMagenta).bold()),
            Span::raw(list_caps(caps.effective)),
        ]));
    }
    if caps.permitted != caps.effective && caps.permitted != 0 {
        let only = caps.permitted & !caps.effective;
        if only != 0 {
            lines.push(Line::from(vec![
                Span::styled(
                    "Permitted-only (not currently effective): ",
                    Style::default().fg(Color::LightMagenta).bold(),
                ),
                Span::raw(list_caps(only)),
            ]));
        }
    }
    let full = u64::MAX;
    if caps.bounding != full && caps.bounding != any {
        let dropped = !caps.bounding & full;
        let known = (1u64 << crate::proc::CAP_NAMES.len() as u64) - 1;
        let dropped_known = dropped & known;
        if dropped_known != 0 {
            lines.push(Line::from(vec![
                Span::styled(
                    "Dropped from bounding: ",
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(list_caps(dropped_known)),
            ]));
        }
    }
    lines
}

fn list_caps(mask: u64) -> String {
    let mut names: Vec<&'static str> = Vec::new();
    for (i, name) in crate::proc::CAP_NAMES.iter().enumerate() {
        if (1u64 << i) & mask != 0 {
            names.push(name);
        }
    }
    names.join(", ")
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

fn draw_namespaces(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" namespaces (one inode per kind; differ = process is in its own ns) ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(ns) = app.namespaces.as_ref() else {
        let p = Paragraph::new(Line::from(Span::styled(
            "(no namespaces read yet)",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(p, inner);
        return;
    };

    let header = Row::new(
        ["Kind", "Inode", &format!("vs {}", ns.reference_source), "Raw link"]
            .iter()
            .map(|s| Cell::from(s.to_string()).style(Style::default().fg(Color::Yellow).bold())),
    )
    .height(1);

    // Count how many differ. Used by the summary line below.
    let mut differ = 0usize;
    let rows: Vec<Row> = ns
        .entries
        .iter()
        .map(|e| {
            let ref_inode = ns.reference.get(e.kind).copied();
            let cmp_cell = match ref_inode {
                None => Cell::from("(reference unreadable)")
                    .style(Style::default().fg(Color::DarkGray)),
                Some(r) if r == e.inode => Cell::from("shared")
                    .style(Style::default().fg(Color::DarkGray)),
                Some(_) => {
                    differ += 1;
                    Cell::from("DIFFERENT").style(
                        Style::default()
                            .fg(Color::LightYellow)
                            .add_modifier(Modifier::BOLD),
                    )
                }
            };
            let kind_style = match e.kind {
                "net" | "mnt" | "pid" => Style::default().fg(Color::LightCyan).bold(),
                _ => Style::default().fg(Color::Cyan),
            };
            Row::new(vec![
                Cell::from(e.kind).style(kind_style),
                Cell::from(e.inode.to_string()),
                cmp_cell,
                Cell::from(e.raw.clone()).style(Style::default().fg(Color::DarkGray)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(12),
            Constraint::Length(22),
            Constraint::Min(20),
        ],
    )
    .header(header);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(5), Constraint::Length(4)])
        .split(inner);
    f.render_widget(table, layout[0]);

    // Summary paragraph
    let mut summary: Vec<Line> = Vec::new();
    if ns.reference.is_empty() {
        summary.push(Line::from(Span::styled(
            "Could not read any reference namespace set (not even scry's). Differences below are unverified.",
            Style::default().fg(Color::Red),
        )));
    } else if differ == 0 {
        summary.push(Line::from(vec![
            Span::styled(
                "All namespaces shared with ",
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                ns.reference_source.to_string(),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                ". This process is not in a container or sandbox.",
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    } else {
        summary.push(Line::from(vec![
            Span::styled(
                format!("{differ} namespace(s) differ from "),
                Style::default().fg(Color::LightYellow),
            ),
            Span::styled(
                ns.reference_source.to_string(),
                Style::default().fg(Color::Cyan),
            ),
            Span::styled(
                ". Process is in a container, chroot, sandbox, or unshare(2)'d region.",
                Style::default().fg(Color::LightYellow),
            ),
        ]));
        if ns.reference_source == "scry" {
            summary.push(Line::from(Span::styled(
                "(reference is scry itself, not init pid 1. Re-run scry as root for a fuller picture.)",
                Style::default().fg(Color::DarkGray),
            )));
        }
    }
    f.render_widget(Paragraph::new(summary).wrap(Wrap { trim: false }), layout[1]);
}

// ---------------------------------------------------------------------------
// Security overview
// ---------------------------------------------------------------------------

fn draw_security(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" security overview · seccomp · no-new-privs · LSM · yama ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let Some(sec) = app.security.as_ref() else {
        let p = Paragraph::new(Line::from(Span::styled(
            "(no security info read yet)",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(p, inner);
        return;
    };

    let mut lines: Vec<Line> = Vec::new();

    // Seccomp
    let seccomp_value_style = if sec.seccomp_mode.is_active() {
        Style::default().fg(Color::LightGreen).bold()
    } else {
        Style::default().fg(Color::LightRed).bold()
    };
    let seccomp_main = format!(
        "{} (mode {})",
        sec.seccomp_mode.label(),
        match sec.seccomp_mode {
            crate::proc::SeccompMode::Disabled => 0,
            crate::proc::SeccompMode::Strict => 1,
            crate::proc::SeccompMode::Filter => 2,
            crate::proc::SeccompMode::Unknown(n) => n as i32,
        },
    );
    lines.push(security_row("Seccomp", &seccomp_main, seccomp_value_style));
    if let Some(n) = sec.seccomp_filters {
        let label = if n == 0 {
            String::from("0 attached")
        } else if n == 1 {
            String::from("1 attached")
        } else {
            format!("{n} attached (filters stack; the first to deny wins)")
        };
        lines.push(security_row(
            "Seccomp filters",
            &label,
            if n == 0 {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::LightGreen)
            },
        ));
    } else {
        lines.push(security_row(
            "Seccomp filters",
            "(not exposed; kernel < 5.9)",
            Style::default().fg(Color::DarkGray),
        ));
    }

    // NoNewPrivs
    let (nnp_text, nnp_style) = if sec.no_new_privs {
        ("set (setuid binaries can't grant new privileges)",
         Style::default().fg(Color::LightGreen).bold())
    } else {
        ("not set (setuid execve can still escalate)",
         Style::default().fg(Color::LightRed))
    };
    lines.push(security_row("NoNewPrivs", nnp_text, nnp_style));

    // LSM label
    let lsm_text = match (&sec.lsm_label, sec.lsm_kind) {
        (None, _) => "<unavailable> (process attr not readable)".to_string(),
        (Some(s), _) if s.is_empty() => "<empty> (no LSM loaded)".to_string(),
        (Some(s), kind) => format!("{}  [{}]", s, kind.label()),
    };
    let lsm_style = match sec.lsm_kind {
        crate::proc::LsmKind::None => Style::default().fg(Color::DarkGray),
        crate::proc::LsmKind::AppArmor
            if sec
                .lsm_label
                .as_deref()
                .map(|s| s.contains("(enforce)"))
                .unwrap_or(false) =>
        {
            Style::default().fg(Color::LightGreen).bold()
        }
        _ => Style::default().fg(Color::LightYellow),
    };
    lines.push(security_row("LSM label", &lsm_text, lsm_style));

    // Yama ptrace_scope
    let yama_text = match sec.yama_ptrace_scope {
        None => "<unavailable> (no /proc/sys/kernel/yama/ptrace_scope)".to_string(),
        Some(0) => "0: classic permissive (any same-uid task can ptrace).".to_string(),
        Some(1) => "1: restricted (parent/PR_SET_PTRACER/CAP_SYS_PTRACE only).".to_string(),
        Some(2) => "2: admin-only (requires CAP_SYS_PTRACE).".to_string(),
        Some(3) => "3: disabled (no ptrace at all until reboot).".to_string(),
        Some(n) => format!("{n}: unknown policy"),
    };
    let yama_style = match sec.yama_ptrace_scope {
        Some(0) => Style::default().fg(Color::LightYellow),
        Some(1) | Some(2) | Some(3) => Style::default().fg(Color::LightGreen),
        _ => Style::default().fg(Color::DarkGray),
    };
    lines.push(security_row("Yama ptrace_scope", &yama_text, yama_style));

    lines.push(Line::from(""));

    // Verdict
    let mut controls: Vec<&'static str> = Vec::new();
    if sec.seccomp_mode.is_active() {
        controls.push("Seccomp filter");
    }
    if sec.no_new_privs {
        controls.push("NoNewPrivs");
    }
    match (&sec.lsm_label, sec.lsm_kind) {
        (Some(s), crate::proc::LsmKind::AppArmor)
            if s.contains("(enforce)") =>
        {
            controls.push("AppArmor (enforce)");
        }
        (Some(s), crate::proc::LsmKind::AppArmor)
            if s.contains("(complain)") =>
        {
            controls.push("AppArmor (complain mode, logs only)");
        }
        (Some(s), crate::proc::LsmKind::SELinux) if !s.is_empty() => {
            controls.push("SELinux context");
        }
        _ => {}
    }
    if app.capabilities.bounding != u64::MAX
        && app.capabilities.bounding != 0
        && app.capabilities.bounding.count_ones() < crate::proc::CAP_NAMES.len() as u32
    {
        controls.push("trimmed capability bounding set");
    }

    let verdict_line: Line = if controls.is_empty() {
        Line::from(vec![
            Span::styled(
                "Verdict: ",
                Style::default().fg(Color::Yellow).bold(),
            ),
            Span::styled(
                "no sandboxing detected. Process runs with whatever its uid/cgroup allows.",
                Style::default().fg(Color::LightRed),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                "Verdict: ",
                Style::default().fg(Color::Yellow).bold(),
            ),
            Span::styled(
                format!("sandboxed by {}.", controls.join(" + ")),
                Style::default().fg(Color::LightGreen),
            ),
        ])
    };
    lines.push(verdict_line);

    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

fn security_row(label: &str, value: &str, value_style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {:<20}", label),
            Style::default().fg(Color::LightMagenta).bold(),
        ),
        Span::styled(value.to_string(), value_style),
    ])
}

// ---------------------------------------------------------------------------
// Process tree
// ---------------------------------------------------------------------------

fn draw_tree(f: &mut Frame, area: Rect, app: &App) {
    let title = format!(
        " child process tree of pid {} ({}) · {} total ",
        app.pid,
        app.summary.info.name,
        app.tree.len(),
    );
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.tree.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "no children, or /proc enumeration failed",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(p, inner);
        return;
    }

    // Build a List of styled lines, one per node, with pstree-style indents.
    let items: Vec<ListItem> = app
        .tree
        .iter()
        .map(|row| {
            let mut spans: Vec<Span> = Vec::new();
            // Ancestor columns: " │ " for active continuations, "   " for collapsed.
            for &was_last in row.last_at_depth.iter().skip(1) {
                spans.push(Span::styled(
                    if was_last { "   " } else { "│  " }.to_string(),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            // Leaf marker only when we're below the root.
            if row.depth > 0 {
                spans.push(Span::styled(
                    if row.is_last_sibling { "└─ " } else { "├─ " }.to_string(),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            let state_style = match row.state {
                'R' => Style::default().fg(Color::LightGreen),
                'S' => Style::default().fg(Color::DarkGray),
                'D' => Style::default().fg(Color::Yellow),
                'Z' => Style::default().fg(Color::Red),
                'T' | 't' => Style::default().fg(Color::Magenta),
                _ => Style::default(),
            };
            spans.push(Span::styled(
                format!("{}", row.pid),
                Style::default().fg(Color::LightYellow).bold(),
            ));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                row.comm.as_str(),
                Style::default().fg(Color::White),
            ));
            spans.push(Span::styled(
                format!(
                    "  [{}]  thr={}  uid={}",
                    row.state, row.threads, row.uid
                ),
                state_style,
            ));
            if !row.cmdline.is_empty() && row.cmdline != row.comm {
                spans.push(Span::styled(
                    format!("  · {}", truncate(&row.cmdline, 80)),
                    Style::default().fg(Color::DarkGray),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let list = List::new(items)
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");
    let mut state = ListState::default();
    state.select(Some(app.tree_selected.min(app.tree.len().saturating_sub(1))));
    f.render_stateful_widget(list, inner, &mut state);
}

// ---------------------------------------------------------------------------
// Kernel stack
// ---------------------------------------------------------------------------

fn draw_kstack(f: &mut Frame, area: Rect, app: &App) {
    let scope = if app.kstack_all_threads {
        "all threads"
    } else {
        "main thread"
    };
    let mode = if app.kstack_show_wchan {
        "wchan"
    } else {
        "stack"
    };
    let title = format!(" kernel stack · {scope} · {mode} (w toggle · t threads) ");
    let block = Block::default().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    // No data yet (first paint before the auto-tick has fired). Show a hint.
    if app.kstack_threads.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            "reading kernel stack...",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(p, inner);
        return;
    }

    // Single-thread + error: show the friendly permission message so the
    // root/CAP_SYS_ADMIN hint stays visible instead of a bare error line.
    if !app.kstack_all_threads
        && app.kstack_threads.len() == 1
        && let Some(err) = app.kstack_threads[0].err.clone()
    {
        let p = Paragraph::new(vec![
            Line::from(Span::styled(
                "could not read kernel stack",
                Style::default().fg(Color::Red).bold(),
            )),
            Line::from(""),
            Line::from(err),
            Line::from(""),
            Line::from(Span::styled(
                "/proc/<pid>/stack normally requires CAP_SYS_ADMIN (i.e. root).",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .wrap(Wrap { trim: false });
        f.render_widget(p, inner);
        return;
    }

    let lines = if app.kstack_show_wchan {
        build_wchan_lines(app)
    } else {
        build_stack_lines(app)
    };

    let p = Paragraph::new(lines)
        .scroll((app.kstack_scroll.offset as u16, 0))
        .wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

/// One row per thread: `TID  state  name  wchan-symbol`. Aligns columns so
/// the wchan symbols line up vertically. That's the whole point of this view.
fn build_wchan_lines(app: &App) -> Vec<Line<'_>> {
    let mut out = Vec::with_capacity(app.kstack_threads.len());
    let tid_w = app
        .kstack_threads
        .iter()
        .map(|t| t.tid.to_string().len())
        .max()
        .unwrap_or(5)
        .max(5);
    let name_w = app
        .kstack_threads
        .iter()
        .map(|t| t.name.len())
        .max()
        .unwrap_or(8)
        .clamp(8, 20);
    for t in &app.kstack_threads {
        let wchan: std::borrow::Cow<'_, str> = if let Some(err) = &t.err {
            format!("({err})").into()
        } else {
            t.stack
                .as_deref()
                .and_then(extract_wchan)
                .unwrap_or("-")
                .into()
        };
        let state = if t.state.is_empty() { "-" } else { &t.state };
        out.push(Line::from(vec![
            Span::styled(
                format!("{:>w$}", t.tid, w = tid_w),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{state:<2}"),
                Style::default().fg(state_color(state)),
            ),
            Span::raw("  "),
            Span::styled(
                format!("{:<w$}", trunc(&t.name, name_w), w = name_w),
                Style::default().fg(Color::Gray),
            ),
            Span::raw("  "),
            Span::styled(wchan, Style::default().fg(Color::Yellow)),
        ]));
    }
    out
}

/// Full per-thread stacks. In all-threads mode each thread gets a header row;
/// in main-only mode we emit just the stack body.
fn build_stack_lines(app: &App) -> Vec<Line<'_>> {
    let mut out = Vec::new();
    let multi = app.kstack_all_threads;
    for (i, t) in app.kstack_threads.iter().enumerate() {
        if multi {
            if i > 0 {
                out.push(Line::from(""));
            }
            let state = if t.state.is_empty() { "-" } else { &t.state };
            out.push(Line::from(vec![
                Span::styled(
                    format!("tid {}", t.tid),
                    Style::default().fg(Color::Cyan).bold(),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("[{state}]"),
                    Style::default().fg(state_color(state)),
                ),
                Span::raw("  "),
                Span::styled(t.name.as_str(), Style::default().fg(Color::Gray)),
            ]));
        }
        if let Some(err) = &t.err {
            out.push(Line::from(Span::styled(
                format!("  (cannot read: {err})"),
                Style::default().fg(Color::Red),
            )));
        } else if let Some(stack) = &t.stack {
            for raw in stack.lines() {
                let s = raw.trim_end();
                if s.is_empty() {
                    continue;
                }
                if multi {
                    out.push(Line::from(format!("  {s}")));
                } else {
                    out.push(Line::from(s.to_string()));
                }
            }
        }
    }
    out
}

/// Pick a color per Linux task-state letter. R=run, S=sleep, D=uninterruptible
/// (often interesting; disk wait, etc.), T=stopped, Z=zombie.
fn state_color(state: &str) -> Color {
    match state.chars().next().unwrap_or(' ') {
        'R' => Color::Green,
        'D' => Color::Red,
        'Z' => Color::Magenta,
        'T' | 't' => Color::Yellow,
        _ => Color::DarkGray,
    }
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

// ---------------------------------------------------------------------------
// Syscall trace (strace pipe)
// ---------------------------------------------------------------------------

fn draw_syscalls(f: &mut Frame, area: Rect, app: &App) {
    let status_suffix = if app.strace_paused { "  [PAUSED]" } else { "" };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" strace -p {}{} ", app.pid, status_suffix));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if let Some(err) = &app.strace_err {
        let p = Paragraph::new(vec![
            Line::from(Span::styled(
                "could not start strace",
                Style::default().fg(Color::Red).bold(),
            )),
            Line::from(""),
            Line::from(err.clone()),
            Line::from(""),
            Line::from(Span::styled(
                "strace needs to attach via ptrace. That requires root for processes owned by other users, and Yama ptrace_scope must allow it.",
                Style::default().fg(Color::DarkGray),
            )),
        ])
        .wrap(Wrap { trim: false });
        f.render_widget(p, inner);
        return;
    }

    let lines: Vec<String> = match &app.strace {
        Some(s) => s.snapshot(),
        None => vec!["(no strace session)".to_string()],
    };
    // Show the tail of the buffer that fits, offset by strace_scroll.
    let height = inner.height as usize;
    let total = lines.len();
    let end = total.saturating_sub(app.strace_scroll);
    let start = end.saturating_sub(height);
    let visible: Vec<Line> = lines[start..end]
        .iter()
        .map(|l| Line::from(l.clone()))
        .collect();
    let p = Paragraph::new(visible).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

// ---------------------------------------------------------------------------
// Footer + help
// ---------------------------------------------------------------------------

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    // Filter-editing modes take the whole footer so the typed text is obvious.
    if app.screen == Screen::Maps && app.maps.editing_filter {
        let line = Line::from(vec![
            Span::styled(
                "/",
                Style::default().fg(Color::LightYellow).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                app.maps.filter.clone(),
                Style::default().fg(Color::LightYellow),
            ),
            Span::styled(
                "_",
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::raw("   "),
            Span::styled(
                "matches path · category · annotation headline   (Enter accept · Esc cancel · Ctrl-U clear)",
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    if app.screen == Screen::Picker && app.picker.editing_filter {
        let line = Line::from(vec![
            Span::styled(
                "/",
                Style::default().fg(Color::LightYellow).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                app.picker.filter.clone(),
                Style::default().fg(Color::LightYellow),
            ),
            Span::styled(
                "_",
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::raw("   "),
            Span::styled(
                "matches pid · user · comm · cmdline   (Enter accept · Esc cancel · Ctrl-U clear)",
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }
    if app.screen == Screen::SignalSend && app.signals.editing_filter {
        let line = Line::from(vec![
            Span::styled(
                "/",
                Style::default().fg(Color::LightYellow).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                app.signals.filter.clone(),
                Style::default().fg(Color::LightYellow),
            ),
            Span::styled(
                "_",
                Style::default()
                    .fg(Color::LightYellow)
                    .add_modifier(Modifier::SLOW_BLINK),
            ),
            Span::raw("   "),
            Span::styled(
                "matches signal name · number · description   (Enter accept · Esc cancel · Ctrl-U clear)",
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }

    let common = " Q quit · Esc back · ? help · R refresh · Z pause";
    let screen_hints = match app.screen {
        Screen::Picker => "↑/↓ choose · Enter attach · s sort · r reverse · / filter",
        Screen::Menu => "↑/↓ choose · Enter open · P switch process",
        Screen::Maps => "↑/↓ move · g/G top/bot · s sort · r reverse · / filter",
        Screen::Threads | Screen::Fds | Screen::Environ | Screen::Limits | Screen::Cgroup
        | Screen::Capabilities | Screen::Namespaces | Screen::Security => "↑/↓ PgUp/PgDn",
        Screen::Tree => "↑/↓ move · Enter attach to child · auto-refreshes",
        Screen::KernelStack => "↑/↓ scroll · w wchan/stack · t one/all threads",
        Screen::Syscalls => "PgUp/PgDn scroll · Space pause · c clear",
        Screen::SignalSend => "↑/↓ move · Enter send · / filter",
    };

    let left = if !app.status.is_empty() {
        format!(" {}  ", app.status)
    } else {
        String::new()
    };
    let line = Line::from(vec![
        Span::styled(left, Style::default().fg(Color::LightGreen)),
        Span::styled(screen_hints, Style::default().fg(Color::DarkGray)),
        Span::raw("  "),
        Span::styled(common, Style::default().fg(Color::DarkGray)),
    ]);
    let p = Paragraph::new(line).alignment(Alignment::Left);
    f.render_widget(p, area);
}

fn draw_help(f: &mut Frame, area: Rect, app: &App) {
    let w = area.width.min(78);
    let h = area.height.min(22);
    let x = area.x + (area.width - w) / 2;
    let y = area.y + (area.height - h) / 2;
    let rect = Rect::new(x, y, w, h);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" help · {} ", app.screen.title()));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    let common = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Global (any screen)",
            Style::default().fg(Color::Yellow).bold(),
        )),
        Line::from("Z              freeze/unfreeze auto-refresh (htop-style)"),
        Line::from("R              manual refresh of current screen"),
        Line::from("?              toggle this help"),
        Line::from("q              quit from anywhere"),
        Line::from("Esc            back to menu (or quit from menu/picker)"),
    ];
    let mut lines = match app.screen {
        Screen::Picker => vec![
            Line::from("↑/↓ or j/k     move between processes"),
            Line::from("PgUp/PgDn      page"),
            Line::from("Home/End       top / bottom"),
            Line::from("Enter          attach to selected pid"),
            Line::from("s              cycle sort (cpu/rss/pid/name/user)"),
            Line::from("r              reverse current sort"),
            Line::from("/              filter (pid/user/comm/cmdline)"),
            Line::from("scroll wheel   moves selection"),
        ],
        Screen::Menu => vec![
            Line::from("↑/↓ or j/k     move between options"),
            Line::from("Enter or →     open selected view"),
            Line::from("P              jump back to process picker"),
            Line::from("scroll wheel   moves between options"),
        ],
        Screen::Maps => vec![
            Line::from("↑/↓, j/k       move"),
            Line::from("PgUp/PgDn      page"),
            Line::from("g / G          top / bottom"),
            Line::from("s              cycle sort (Address/Size/RSS/PSS/Category)"),
            Line::from("r              reverse sort"),
            Line::from("/              filter (path · category · annotation)"),
        ],
        Screen::Syscalls => vec![
            Line::from("Space          pause/resume display"),
            Line::from("c              clear buffer"),
            Line::from("PgUp/PgDn      scroll history"),
            Line::from("End            jump to tail"),
            Line::from("(q detaches strace and returns to menu)"),
        ],
        Screen::KernelStack => vec![
            Line::from("w              toggle wchan (one symbol/thread) vs full stack"),
            Line::from("t              toggle all-threads sweep (/proc/<pid>/task/*) vs main only"),
            Line::from("↑/↓, j/k       scroll"),
            Line::from("PgUp/PgDn      page"),
            Line::from("Home/End       top / bottom"),
            Line::from("Auto-refreshes every 1s. Press Z to freeze."),
        ],
        Screen::Cgroup => vec![
            Line::from("Auto-refreshes every 1s. Press Z to freeze."),
            Line::from("shows live values from /sys/fs/cgroup<path>/"),
        ],
        Screen::Threads | Screen::Fds => vec![
            Line::from("Auto-refreshes every 1s. Press Z to freeze."),
        ],
        Screen::Tree => vec![
            Line::from("↑/↓ or j/k     move between processes"),
            Line::from("PgUp/PgDn      page"),
            Line::from("Home/End       top / bottom"),
            Line::from("Enter          re-attach to the selected child"),
            Line::from("Auto-refreshes every 1s. Press Z to freeze."),
        ],
        Screen::SignalSend => vec![
            Line::from("↑/↓ or j/k     move between signals"),
            Line::from("PgUp/PgDn      page"),
            Line::from("Home/End       top / bottom"),
            Line::from("Enter          send the highlighted signal to this pid"),
            Line::from("/              filter (name, number, or description)"),
            Line::from(""),
            Line::from("SIGKILL and SIGSTOP cannot be caught or ignored."),
            Line::from("SIGRTMIN..SIGRTMAX are real-time signals (queueable, app-defined)."),
        ],
        _ => vec![
            Line::from("↑/↓, PgUp/PgDn scroll"),
        ],
    };
    lines.extend(common);
    let p = Paragraph::new(lines).wrap(Wrap { trim: false });
    f.render_widget(p, inner);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn kv(k: &str, v: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{:>13}: ", k), Style::default().fg(Color::DarkGray)),
        Span::raw(v.to_string()),
    ])
}

fn truncate(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(w.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn fmt_kb(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1}G", kb as f64 / (1024.0 * 1024.0))
    } else if kb >= 1024 {
        format!("{:.1}M", kb as f64 / 1024.0)
    } else if kb == 0 {
        "·".into()
    } else {
        format!("{kb}K")
    }
}

fn perm_style(p: &str) -> Style {
    let b = p.as_bytes();
    if b[2] == b'x' {
        Style::default().fg(Color::Red)
    } else if b[1] == b'w' {
        Style::default().fg(Color::LightYellow)
    } else if b[3] == b's' {
        Style::default().fg(Color::Magenta)
    } else if b[0] == b'-' {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Green)
    }
}

fn category_style(c: Category) -> Style {
    match c {
        Category::Heap => Style::default().fg(Color::LightRed),
        Category::MainStack | Category::ThreadStack => Style::default().fg(Color::LightMagenta),
        Category::GuardPage => Style::default().fg(Color::DarkGray).add_modifier(Modifier::DIM),
        Category::AnonPrivate => Style::default().fg(Color::LightYellow),
        Category::AnonShared => Style::default().fg(Color::Yellow),
        Category::Exe | Category::ExeData => Style::default().fg(Color::LightCyan),
        Category::LibText | Category::LibRodata | Category::LibRelro | Category::LibData => {
            Style::default().fg(Color::Cyan)
        }
        Category::Vdso | Category::Vvar | Category::Vsyscall | Category::KernelSpecial => {
            Style::default().fg(Color::Blue)
        }
        Category::Memfd | Category::Shm => Style::default().fg(Color::LightGreen),
        Category::LocaleData | Category::FileMapping => Style::default().fg(Color::Green),
        Category::Deleted => Style::default()
            .fg(Color::Red)
            .add_modifier(Modifier::CROSSED_OUT),
        Category::Unknown => Style::default(),
    }
}
