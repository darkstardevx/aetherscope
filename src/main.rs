mod format;
mod packet;

use clap::Parser;
use format::OutputFormat;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "aetherscope", version = "0.1.0", about = "Packet capture and protocol inspection on your own interfaces")]
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
}

fn list_interfaces() -> ExitCode {
    match pcap::Device::list() {
        Ok(devices) => {
            for d in devices {
                let desc = d.desc.unwrap_or_default();
                println!("{:<16} {}", d.name, desc);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to list interfaces: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> ExitCode {
    let Some(format) = OutputFormat::parse(&args.format) else {
        eprintln!("unknown --format \"{}\" (expected summary, hexdump, or json)", args.format);
        return ExitCode::FAILURE;
    };

    let Some(interface) = args.interface else {
        eprintln!("--interface is required (see --list-interfaces for available options)");
        return ExitCode::FAILURE;
    };

    let device = match pcap::Device::list().ok().and_then(|devs| devs.into_iter().find(|d| d.name == interface)) {
        Some(d) => d,
        None => {
            eprintln!("no such interface \"{interface}\" — see --list-interfaces");
            return ExitCode::FAILURE;
        }
    };

    let capture = pcap::Capture::from_device(device)
        .and_then(|c| c.promisc(args.promisc).snaplen(65535).timeout(1000).open());

    let mut capture = match capture {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to open {interface} for capture: {e} (packet capture needs root or CAP_NET_RAW)");
            return ExitCode::FAILURE;
        }
    };

    if let Some(filter) = &args.filter {
        if let Err(e) = capture.filter(filter, true) {
            eprintln!("invalid BPF filter \"{filter}\": {e}");
            return ExitCode::FAILURE;
        }
    }

    println!(
        "[aetherscope] capturing on {interface}{} — format={:?} {}",
        args.filter.as_ref().map(|f| format!(" (filter: {f})")).unwrap_or_default(),
        format,
        if args.no_color { "" } else { "(color on)" }
    );

    let color = !args.no_color;
    let mut seen = 0usize;

    loop {
        match capture.next_packet() {
            Ok(raw) => {
                let ts_micros = raw.header.ts.tv_sec as i64 * 1_000_000 + raw.header.ts.tv_usec as i64;
                let parsed = packet::parse(raw.data, ts_micros);
                println!("{}", format::render(&parsed, raw.data, format, args.pretty, color));

                seen += 1;
                if let Some(limit) = args.count {
                    if seen >= limit {
                        break;
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                eprintln!("[aetherscope] capture error: {e}");
                break;
            }
        }
    }

    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.list_interfaces {
        return list_interfaces();
    }
    run(args)
}
