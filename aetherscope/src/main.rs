use aetherscope_core::capture::{self, Source};
use aetherscope_core::format::{self, OutputFormat};
use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "aetherscope",
    version = "0.1.0",
    about = "Packet capture and protocol inspection on your own interfaces"
)]
struct Args {
    /// Interface to capture on (e.g. wlp2s0, lo). See --list-interfaces.
    #[arg(short, long)]
    interface: Option<String>,

    /// List available capture interfaces and exit.
    #[arg(long)]
    list_interfaces: bool,

    /// BPF filter expression — the same syntax tcpdump/Wireshark use, e.g.
    /// "tcp port 22", "host 192.168.1.5", "udp and not port 53".
    #[arg(short, long)]
    filter: Option<String>,

    /// "summary" (default, one line per packet) | "hexdump" | "json"
    #[arg(long, default_value = "summary")]
    format: String,

    /// Pretty-print JSON output. Ignored by other formats.
    #[arg(long)]
    pretty: bool,

    /// Disable cybercore color output.
    #[arg(long)]
    no_color: bool,

    /// Stop after capturing this many packets. Default: run until Ctrl+C.
    #[arg(short, long)]
    count: Option<usize>,

    /// Capture in promiscuous mode (see all traffic on the segment, not
    /// just frames addressed to this host). Requires it to actually be
    /// your own network segment — this doesn't cross onto other people's
    /// traffic on a switched network you don't control either way, but
    /// combine with intent, not just because it's available.
    #[arg(long)]
    promisc: bool,

    /// Also write every captured frame to this path in real .pcap format
    /// (tcpdump/Wireshark-compatible), alongside the normal terminal
    /// output — same on-disk format `proteus` reads/writes, so a capture
    /// started here can be picked up there for stream reconstruction.
    #[arg(short = 'w', long)]
    write_pcap: Option<PathBuf>,
}

fn list_interfaces() -> ExitCode {
    match capture::list_interfaces() {
        Ok(devices) => {
            for (name, desc) in devices {
                println!("{name:<16} {desc}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to list interfaces: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<ExitCode> {
    let Some(format) = OutputFormat::parse(&args.format) else {
        eprintln!(
            "unknown --format \"{}\" (expected summary, hexdump, or json)",
            args.format
        );
        return Ok(ExitCode::FAILURE);
    };

    let Some(interface) = args.interface else {
        eprintln!("--interface is required (see --list-interfaces for available options)");
        return Ok(ExitCode::FAILURE);
    };

    let mut source = match Source::open_live(&interface, args.promisc, args.filter.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to open {interface} for capture: {e} (packet capture needs root or CAP_NET_RAW)");
            return Ok(ExitCode::FAILURE);
        }
    };

    let mut savefile = match &args.write_pcap {
        Some(path) => Some(source.savefile(path)?),
        None => None,
    };

    println!(
        "[aetherscope] capturing on {interface}{}{} — format={:?} {}",
        args.filter
            .as_ref()
            .map(|f| format!(" (filter: {f})"))
            .unwrap_or_default(),
        args.write_pcap
            .as_ref()
            .map(|p| format!(" (writing to {})", p.display()))
            .unwrap_or_default(),
        format,
        if args.no_color { "" } else { "(color on)" }
    );

    let color = !args.no_color;
    let mut seen = 0usize;

    loop {
        let Some(frame) = source.next_frame()? else {
            continue; // live-capture read timeout — just poll again
        };

        println!(
            "{}",
            format::render(&frame.parsed, &frame.raw, format, args.pretty, color)
        );
        if let Some(savefile) = &mut savefile {
            capture::write_frame(savefile, &frame);
        }

        seen += 1;
        if let Some(limit) = args.count {
            if seen >= limit {
                break;
            }
        }
    }

    if let Some(mut savefile) = savefile {
        savefile.flush()?;
    }

    Ok(ExitCode::SUCCESS)
}

fn main() -> Result<ExitCode> {
    let args = Args::parse();
    if args.list_interfaces {
        return Ok(list_interfaces());
    }
    run(args)
}
