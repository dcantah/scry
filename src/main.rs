mod annotate;
mod app;
mod perms;
mod proc;
mod strace;
mod ui;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::{self, stdout};
use std::time::{Duration, Instant};

use crate::app::{App, MENU_ITEMS, Screen};

#[derive(Parser, Debug)]
#[command(
    name = "scry",
    about = "TUI process inspector. Memory map, threads, fds, limits, cgroup, kernel stack, syscall trace."
)]
struct Args {
    /// Target PID. If omitted, the TUI opens its process picker (or $SCRY_PID if set).
    //
    // `global` so a future subcommand can accept --pid in any position,
    // e.g. `scry --pid 123 cgroup` or `scry cgroup --pid 123`.
    #[arg(long, short, global = true)]
    pid: Option<i32>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let env_pid = std::env::var("SCRY_PID")
        .ok()
        .and_then(|s| s.parse().ok());
    let pid = args.pid.or(env_pid);

    let mut app = App::new(pid).context("initializing app")?;
    run_tui(&mut app)?;
    Ok(())
}

fn run_tui(app: &mut App) -> Result<()> {
    enable_raw_mode().context("enabling raw mode")?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;

    let res = event_loop(&mut terminal, app);

    disable_raw_mode().ok();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .ok();
    terminal.show_cursor().ok();

    res
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<()> {
    let mut last_tick = Instant::now();
    let tick_interval = Duration::from_millis(1000);

    loop {
        // Strace's reader runs on a background thread and pushes lines into a
        // shared buffer without touching `dirty`. To keep that screen live we
        // force a redraw whenever it's active.
        if app.dirty || app.screen == Screen::Syscalls {
            terminal.draw(|f| ui::draw(f, app))?;
            app.dirty = false;
        }

        if last_tick.elapsed() >= tick_interval {
            app.auto_tick();
            last_tick = Instant::now();
        }

        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                app.dirty = true;
                if handle_key(app, key)? {
                    return Ok(());
                }
            }
            Event::Mouse(m) => {
                app.dirty = true;
                handle_mouse(app, m);
            }
            _ => {}
        }
    }
}

/// Returns true if the program should exit.
fn handle_key(app: &mut App, key: event::KeyEvent) -> Result<bool> {
    // Filter-edit modes swallow most keys.
    if app.screen == Screen::SignalSend && app.signals.editing_filter {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.signals.editing_filter = false;
                app.signals.rebuild_view();
            }
            KeyCode::Backspace => {
                app.signals.filter.pop();
                app.signals.rebuild_view();
            }
            KeyCode::Char(c) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'u' {
                    app.signals.filter.clear();
                    app.signals.rebuild_view();
                } else {
                    app.signals.filter.push(c);
                    app.signals.rebuild_view();
                }
            }
            _ => {}
        }
        return Ok(false);
    }

    if app.screen == Screen::Maps && app.maps.editing_filter {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.maps.editing_filter = false;
                app.maps.rebuild_view();
            }
            KeyCode::Backspace => {
                app.maps.filter.pop();
                app.maps.rebuild_view();
            }
            KeyCode::Char(c) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'u' {
                    app.maps.filter.clear();
                    app.maps.rebuild_view();
                } else {
                    app.maps.filter.push(c);
                    app.maps.rebuild_view();
                }
            }
            _ => {}
        }
        return Ok(false);
    }
    if app.screen == Screen::Picker && app.picker.editing_filter {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.picker.editing_filter = false;
                app.picker.rebuild_view();
            }
            KeyCode::Backspace => {
                app.picker.filter.pop();
                app.picker.rebuild_view();
            }
            KeyCode::Char(c) => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && c == 'u' {
                    app.picker.filter.clear();
                    app.picker.rebuild_view();
                } else {
                    app.picker.filter.push(c);
                    app.picker.rebuild_view();
                }
            }
            _ => {}
        }
        return Ok(false);
    }

    // Global keys
    match key.code {
        KeyCode::Char('?') => {
            app.show_help = !app.show_help;
            return Ok(false);
        }
        // Accept both 'Z' and 'z' for freeze. Some terminal/keyboard combos
        // deliver Shift+Z as Char('z') + SHIFT rather than capitalizing it,
        // so binding only the uppercase form misses some setups.
        KeyCode::Char('Z') | KeyCode::Char('z') => {
            app.toggle_freeze();
            return Ok(false);
        }
        // q always quits, regardless of which screen you're on. Use Esc to
        // step back without quitting. Bind both cases for the same reason as
        // Z: some terminal/keyboard combos deliver Shift+Q as Char('q') + SHIFT.
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            if app.show_help {
                app.show_help = false;
                return Ok(false);
            }
            return Ok(true);
        }
        KeyCode::Esc => {
            if app.show_help {
                app.show_help = false;
                return Ok(false);
            }
            // From menu/picker Esc quits; from a sub-screen Esc returns to menu.
            if app.screen == Screen::Picker || app.screen == Screen::Menu {
                return Ok(true);
            }
            app.back_to_menu();
            return Ok(false);
        }
        _ => {}
    }

    match app.screen {
        Screen::Picker => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.picker.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => app.picker.move_cursor(-1),
            KeyCode::PageDown => app.picker.move_cursor(10),
            KeyCode::PageUp => app.picker.move_cursor(-10),
            KeyCode::Home => app.picker.selected = 0,
            KeyCode::End
                if !app.picker.view.is_empty() => {
                    app.picker.selected = app.picker.view.len() - 1;
                }
            KeyCode::Char('s') => {
                app.picker.sort = app.picker.sort.next();
                app.picker.rebuild_view();
            }
            KeyCode::Char('r') => {
                app.picker.sort_desc = !app.picker.sort_desc;
                app.picker.rebuild_view();
            }
            KeyCode::Char('/') => app.picker.editing_filter = true,
            KeyCode::Char('R') => app.picker.refresh(),
            KeyCode::Enter => app.picker_select(),
            _ => {}
        },
        Screen::Menu => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.menu_move(1),
            KeyCode::Up | KeyCode::Char('k') => app.menu_move(-1),
            KeyCode::Home => app.menu_selected = 0,
            KeyCode::End => app.menu_selected = MENU_ITEMS.len() - 1,
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => app.menu_enter(),
            KeyCode::Char('P') => app.menu_enter_picker(),
            _ => {}
        },
        Screen::Maps => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.maps.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => app.maps.move_cursor(-1),
            KeyCode::PageDown | KeyCode::Char(' ') => app.maps.move_cursor(10),
            KeyCode::PageUp => app.maps.move_cursor(-10),
            KeyCode::Char('g') | KeyCode::Home => app.maps.selected = 0,
            KeyCode::Char('G') | KeyCode::End
                if !app.maps.view.is_empty() => {
                    app.maps.selected = app.maps.view.len() - 1;
                }
            KeyCode::Char('s') => {
                app.maps.sort = app.maps.sort.next();
                app.maps.rebuild_view();
            }
            KeyCode::Char('r') => {
                app.maps.sort_desc = !app.maps.sort_desc;
                app.maps.rebuild_view();
            }
            KeyCode::Char('/') => app.maps.editing_filter = true,
            KeyCode::Char('R') => {
                if let Err(e) = app.refresh_active() {
                    app.status = format!("refresh failed: {e}");
                }
            }
            _ => {}
        },
        Screen::Syscalls => match key.code {
            KeyCode::Char(' ') => app.strace_paused = !app.strace_paused,
            KeyCode::Char('c') => {
                if let Some(s) = &app.strace {
                    s.clear();
                }
                app.strace_scroll = 0;
            }
            KeyCode::PageUp => app.strace_scroll = app.strace_scroll.saturating_add(20),
            KeyCode::PageDown => app.strace_scroll = app.strace_scroll.saturating_sub(20),
            KeyCode::End => app.strace_scroll = 0,
            KeyCode::Up | KeyCode::Char('k') => {
                app.strace_scroll = app.strace_scroll.saturating_add(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.strace_scroll = app.strace_scroll.saturating_sub(1);
            }
            _ => {}
        },
        Screen::KernelStack => match key.code {
            KeyCode::Char('R') => {
                let _ = app.refresh_active();
            }
            KeyCode::Char('w') | KeyCode::Char('W') => app.kstack_toggle_wchan(),
            KeyCode::Char('t') | KeyCode::Char('T') => app.kstack_toggle_all_threads(),
            KeyCode::Down | KeyCode::Char('j') => scroll_active(app, 1),
            KeyCode::Up | KeyCode::Char('k') => scroll_active(app, -1),
            KeyCode::PageDown => scroll_active(app, 10),
            KeyCode::PageUp => scroll_active(app, -10),
            KeyCode::Home => scroll_active(app, i32::MIN / 2),
            KeyCode::End => scroll_active(app, i32::MAX / 2),
            _ => {}
        },
        Screen::SignalSend => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.signals.move_cursor(1),
            KeyCode::Up | KeyCode::Char('k') => app.signals.move_cursor(-1),
            KeyCode::PageDown => app.signals.move_cursor(10),
            KeyCode::PageUp => app.signals.move_cursor(-10),
            KeyCode::Home => app.signals.selected = 0,
            KeyCode::End
                if !app.signals.view.is_empty() => {
                    app.signals.selected = app.signals.view.len() - 1;
                }
            KeyCode::Char('/') => app.signals.editing_filter = true,
            KeyCode::Enter => app.signals_send_selected(),
            _ => {}
        },
        Screen::Tree => match key.code {
            KeyCode::Down | KeyCode::Char('j') => app.tree_move(1),
            KeyCode::Up | KeyCode::Char('k') => app.tree_move(-1),
            KeyCode::PageDown => app.tree_move(10),
            KeyCode::PageUp => app.tree_move(-10),
            KeyCode::Home => app.tree_selected = 0,
            KeyCode::End
                if !app.tree.is_empty() => {
                    app.tree_selected = app.tree.len() - 1;
                }
            KeyCode::Enter => app.tree_attach_selected(),
            KeyCode::Char('R') => {
                let _ = app.refresh_active();
            }
            _ => {}
        },
        _ => match key.code {
            KeyCode::Char('R') => {
                let _ = app.refresh_active();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                scroll_active(app, 1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                scroll_active(app, -1);
            }
            KeyCode::PageDown => scroll_active(app, 10),
            KeyCode::PageUp => scroll_active(app, -10),
            _ => {}
        },
    }
    Ok(false)
}

fn scroll_active(app: &mut App, delta: i32) {
    let viewport = app.body_inner_height as usize;
    // Tables consume one row of the inner area for their header; subtract it
    // so the bottom row of data settles at the bottom of the visible area.
    let table_viewport = viewport.saturating_sub(1);
    match app.screen {
        Screen::Limits => {
            let lines = app.limits.lines().count();
            app.limits_scroll.scroll_by(delta, lines, viewport);
        }
        Screen::Cgroup => {
            // Conservative upper bound on the rendered line count for clamping.
            // Membership header + each membership row + source line + blanks +
            // per-section (heading + each entry + trailing blank).
            let mut total = 5 + app.summary.cgroup.len();
            for s in &app.cgroup_resources {
                total += 2 + s.entries.len();
            }
            app.cgroup_scroll.scroll_by(delta, total, viewport);
        }
        Screen::Environ => {
            app.environ_scroll
                .scroll_by(delta, app.environ.len(), table_viewport);
        }
        Screen::Threads => {
            app.threads_scroll
                .scroll_by(delta, app.threads.len(), table_viewport);
        }
        Screen::Fds => {
            app.fds_scroll
                .scroll_by(delta, app.fds.len(), table_viewport);
        }
        Screen::Capabilities => {
            // The caps screen reserves 5 rows at the bottom for the summary
            // paragraph, leaving viewport - 5 - 1 for the table data.
            let total = crate::proc::CAP_NAMES.len();
            let cap_viewport = viewport.saturating_sub(5 + 1);
            app.caps_scroll.scroll_by(delta, total, cap_viewport);
        }
        Screen::KernelStack => {
            let total = app.kstack_total_lines();
            app.kstack_scroll.scroll_by(delta, total, viewport);
        }
        _ => {}
    }
}

fn handle_mouse(app: &mut App, m: MouseEvent) {
    if let MouseEventKind::Down(MouseButton::Left) = m.kind {
        handle_click(app, m.row);
        return;
    }
    match (app.screen, m.kind) {
        (Screen::Picker, MouseEventKind::ScrollDown) => app.picker.move_cursor(3),
        (Screen::Picker, MouseEventKind::ScrollUp) => app.picker.move_cursor(-3),
        (Screen::Menu, MouseEventKind::ScrollDown) => app.menu_move(1),
        (Screen::Menu, MouseEventKind::ScrollUp) => app.menu_move(-1),
        (Screen::Maps, MouseEventKind::ScrollDown) => app.maps.move_cursor(3),
        (Screen::Maps, MouseEventKind::ScrollUp) => app.maps.move_cursor(-3),
        (Screen::Tree, MouseEventKind::ScrollDown) => app.tree_move(3),
        (Screen::Tree, MouseEventKind::ScrollUp) => app.tree_move(-3),
        (Screen::SignalSend, MouseEventKind::ScrollDown) => app.signals.move_cursor(3),
        (Screen::SignalSend, MouseEventKind::ScrollUp) => app.signals.move_cursor(-3),
        (Screen::Syscalls, MouseEventKind::ScrollUp) => {
            app.strace_scroll = app.strace_scroll.saturating_add(3);
        }
        (Screen::Syscalls, MouseEventKind::ScrollDown) => {
            app.strace_scroll = app.strace_scroll.saturating_sub(3);
        }
        (Screen::KernelStack, MouseEventKind::ScrollDown) => scroll_active(app, 3),
        (Screen::KernelStack, MouseEventKind::ScrollUp) => scroll_active(app, -3),
        _ => {}
    }
}

/// Translate a left-click at terminal row `click_row` into a row index inside
/// the active screen's list / table and act on it.
fn handle_click(app: &mut App, click_row: u16) {
    let body_top = app.body_y;
    let body_bottom = body_top.saturating_add(app.body_inner_height + 2);
    if click_row < body_top || click_row >= body_bottom {
        return; // click was on header or footer
    }
    let first_row = body_top + 1; // skip the top border
    if click_row < first_row {
        return;
    }
    let inner_row = (click_row - first_row) as usize;

    match app.screen {
        Screen::Menu
            if inner_row < crate::app::MENU_ITEMS.len() => {
                app.menu_selected = inner_row;
                // Single-click activates, like a real pointer-driven menu.
                app.menu_enter();
            }
        Screen::Picker => {
            // The picker is a Table with a header row, so first item lives at
            // inner_row == 1.
            if inner_row == 0 {
                return;
            }
            let i = inner_row - 1;
            if i < app.picker.view.len() {
                app.picker.selected = i;
            }
        }
        Screen::Maps => {
            if inner_row == 0 {
                return;
            }
            let i = inner_row - 1;
            if i < app.maps.view.len() {
                app.maps.selected = i;
            }
        }
        Screen::Tree
            if inner_row < app.tree.len() => {
                app.tree_selected = inner_row;
            }
        Screen::SignalSend
            if inner_row < app.signals.view.len() => {
                app.signals.selected = inner_row;
            }
        _ => {}
    }
}
