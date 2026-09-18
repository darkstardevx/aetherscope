mod app;
mod theme;
mod ui;

use aetherscope_core::capture::{self, CapturedFrame, Source};
use anyhow::Result;
use app::{App, Mode};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use theme::Theme;

#[derive(Parser, Debug)]
#[command(
    name = "proteus",
    version = "0.1.0",
    about = "Wireshark-style TUI packet analyzer — live capture, Follow TCP Stream, pcap export/import"
)]
struct Args {
    /// Interface to capture on live (e.g. wlp2s0, lo). Needs root or
    /// CAP_NET_RAW. Mutually exclusive with --read.
    #[arg(short, long)]
    interface: Option<String>,

    /// Load an existing .pcap file for offline analysis instead of
    /// capturing live — no root needed. Mutually exclusive with
    /// --interface.
    #[arg(short = 'r', long = "read")]
    read: Option<PathBuf>,

    /// List available capture interfaces and exit — no root needed.
    #[arg(long)]
    list_interfaces: bool,

    /// BPF filter expression for a live capture — the same syntax
    /// tcpdump/Wireshark use, e.g. "tcp port 22". Not used with --read.
    #[arg(short, long)]
    filter: Option<String>,

    /// Capture in promiscuous mode. Not used with --read.
    #[arg(long)]
    promisc: bool,

    /// Print every frame's summary line (and TCP stream grouping) as
    /// plain text and exit — no TUI, no terminal setup at all. Only
    /// meaningful with --read (a live capture never "finishes" for this
    /// to dump). For scripting/debugging, same convention as this
    /// session's other TUIs (Argus's `events`, Echo's `--list`).
    #[arg(long)]
    list: bool,

    /// With --read: re-export every loaded frame to this .pcap path and
    /// exit (no TUI) — the same export path the TUI's own `w` key uses,
    /// just batch/scriptable. Useful on its own (e.g. converting/
    /// filtering a capture) independent of --list.
    #[arg(long)]
    write: Option<PathBuf>,
}

fn list_interfaces() -> Result<()> {
    for (name, desc) in capture::list_interfaces()? {
        println!("{name:<16} {desc}");
    }
    Ok(())
}

fn run_tui(mut app: App, rx: Option<mpsc::Receiver<CapturedFrame>>) -> Result<()> {
    let theme = Theme::from_cybercore();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, &mut app, &theme, rx.as_ref());

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    theme: &Theme,
    rx: Option<&mpsc::Receiver<CapturedFrame>>,
) -> Result<()> {
    loop {
        if let Some(rx) = rx {
            while let Ok(frame) = rx.try_recv() {
                app.push_frame(frame);
            }
        }

        terminal.draw(|frame| ui::draw(frame, app, theme))?;

        if app.should_quit {
            return Ok(());
        }

        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                match app.mode {
                    Mode::Normal => handle_normal(app, key.code, key.modifiers),
                    Mode::Filter => handle_filter(app, key.code),
                    Mode::Detail => handle_close_popup(app, key.code),
                    Mode::Stream => handle_close_popup(app, key.code),
                    Mode::Help => handle_close_popup(app, key.code),
                    Mode::ExportPrompt => handle_export_prompt(app, key.code),
                }
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_normal(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    match code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('j') | KeyCode::Down => app.next(),
        KeyCode::Char('k') | KeyCode::Up => app.previous(),
        KeyCode::Char('/') => app.mode = Mode::Filter,
        KeyCode::Char('f') => app.toggle_follow(),
        KeyCode::Char('s') => app.follow_selected_stream(),
        KeyCode::Char('w') => {
            app.export_path_input = default_export_path();
            app.mode = Mode::ExportPrompt;
        }
        KeyCode::Enter | KeyCode::Char('l') => {
            if app.selected_frame().is_some() {
                app.mode = Mode::Detail;
            }
        }
        KeyCode::Char('?') => app.mode = Mode::Help,
        KeyCode::Char('c') if mods.contains(KeyModifiers::CONTROL) => app.should_quit = true,
        _ => {}
    }
}

fn default_export_path() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("/tmp/proteus-capture-{now}.pcap")
}

fn handle_filter(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => {
            app.filter_text.clear();
            app.apply_filter();
            app.mode = Mode::Normal;
        }
        KeyCode::Enter => app.mode = Mode::Normal,
        KeyCode::Backspace => {
            app.filter_text.pop();
            app.apply_filter();
        }
        KeyCode::Char(c) => {
            app.filter_text.push(c);
            app.apply_filter();
        }
        _ => {}
    }
}

fn handle_close_popup(app: &mut App, code: KeyCode) {
    if matches!(code, KeyCode::Esc | KeyCode::Char('q')) {
        app.mode = Mode::Normal;
    }
}

fn handle_export_prompt(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Esc => app.mode = Mode::Normal,
        KeyCode::Backspace => {
            app.export_path_input.pop();
        }
        KeyCode::Char(c) => app.export_path_input.push(c),
        KeyCode::Enter => {
            let path = PathBuf::from(app.export_path_input.clone());
            match export(&app.frames, &path) {
                Ok(count) => {
                    app.status = Some(format!("exported {count} packet(s) to {}", path.display()))
                }
                Err(e) => app.status = Some(format!("export failed: {e}")),
            }
            app.mode = Mode::Normal;
        }
        _ => {}
    }
}

/// Shared by the TUI's `w` export key and the `--write` batch CLI mode —
/// one export path, two ways to trigger it.
fn export(frames: &[CapturedFrame], path: &Path) -> Result<usize> {
    let mut savefile = capture::open_savefile_for_export(path)?;
    for frame in frames {
        capture::write_frame(&mut savefile, frame);
    }
    savefile.flush()?;
    Ok(frames.len())
}

fn run_live(interface: &str, promisc: bool, filter: Option<&str>) -> Result<()> {
    let source = Source::open_live(interface, promisc, filter)?;
    let (tx, rx) = mpsc::channel::<CapturedFrame>();

    thread::spawn(move || {
        let mut source = source;
        loop {
            match source.next_frame() {
                Ok(Some(frame)) => {
                    if tx.send(frame).is_err() {
                        break; // TUI exited, receiver dropped
                    }
                }
                Ok(None) => continue, // read timeout, try again
                Err(_) => break,      // real capture error, stop trying
            }
        }
    });

    let app = App::new(Vec::new(), None);
    run_tui(app, Some(rx))
}

fn load_offline(path: &Path) -> Result<Vec<CapturedFrame>> {
    let mut source = Source::open_file(path)?;
    let mut frames = Vec::new();
    while let Some(frame) = source.next_frame()? {
        frames.push(frame);
    }
    Ok(frames)
}

fn run_offline(path: &Path) -> Result<()> {
    let frames = load_offline(path)?;
    let app = App::new(frames, Some(path.to_path_buf()));
    run_tui(app, None)
}

/// `--list`: no terminal setup at all — prints each frame's summary line
/// plus how many distinct TCP streams were found, and exits. Exercises
/// the exact same load → parse → stream-grouping pipeline the TUI uses,
/// just without a TTY — this is also how the offline path got verified
/// during development, no root available to test live capture in that
/// environment.
fn run_list(path: &Path) -> Result<()> {
    let frames = load_offline(path)?;
    let mut stream_keys = std::collections::BTreeSet::new();

    for (i, frame) in frames.iter().enumerate() {
        let line = aetherscope_core::format::render(
            &frame.parsed,
            &frame.raw,
            aetherscope_core::format::OutputFormat::Summary,
            false,
            false,
        );
        println!("{:>4}  {line}", i + 1);
        if let Some(key) = aetherscope_core::stream::key_for(&frame.parsed) {
            stream_keys.insert(format!("{:?}", key));
        }
    }

    println!(
        "\n{} packet(s), {} distinct TCP stream(s)",
        frames.len(),
        stream_keys.len()
    );
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.list_interfaces {
        return list_interfaces();
    }

    if args.list {
        let Some(path) = &args.read else {
            eprintln!("proteus: --list needs --read <file.pcap>");
            std::process::exit(2);
        };
        return run_list(path);
    }

    if let Some(out_path) = &args.write {
        let Some(in_path) = &args.read else {
            eprintln!("proteus: --write needs --read <file.pcap>");
            std::process::exit(2);
        };
        let frames = load_offline(in_path)?;
        let count = export(&frames, out_path)?;
        println!("wrote {count} packet(s) to {}", out_path.display());
        return Ok(());
    }

    match (&args.interface, &args.read) {
        (Some(_), Some(_)) => {
            eprintln!("proteus: --interface and --read are mutually exclusive");
            std::process::exit(2);
        }
        (None, None) => {
            eprintln!("proteus: need --interface <iface> (live) or --read <file.pcap> (offline)\nRun `proteus --list-interfaces` to see available interfaces.");
            std::process::exit(2);
        }
        (Some(interface), None) => run_live(interface, args.promisc, args.filter.as_deref()),
        (None, Some(path)) => run_offline(path),
    }
}
