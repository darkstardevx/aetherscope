//! Turns a `ParsedPacket` (plus the original raw bytes, for hexdump) into
//! text. Colors come from `cybercore::palette` — same convention as
//! WraithFlow — keyed by protocol rather than direction, since there's no
//! "pipeline" here, just packets crossing an interface.

use crate::packet::{IpHeader, ParsedPacket, TransportHeader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// One line per packet: src:port > dst:port PROTO \[flags\] len=N — a
    /// tcpdump-style summary, the default.
    Summary,
    /// Full hex + ASCII dump of the raw frame.
    Hexdump,
    /// The parsed structure as JSON.
    Json,
}

impl OutputFormat {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "summary" | "compact" => Some(Self::Summary),
            "hexdump" | "hex" => Some(Self::Hexdump),
            "json" => Some(Self::Json),
            _ => None,
        }
    }
}

fn protocol_color(transport: Option<&TransportHeader>) -> String {
    match transport {
        Some(TransportHeader::Tcp { .. }) => cybercore::palette::acid_green(),
        Some(TransportHeader::Udp { .. }) => cybercore::palette::cyan(),
        Some(TransportHeader::Icmp { .. }) | Some(TransportHeader::Icmpv6 { .. }) => {
            cybercore::palette::orange()
        }
        _ => cybercore::palette::white(),
    }
}

fn reset() -> &'static str {
    cybercore::palette::RESET
}

pub fn render(
    pkt: &ParsedPacket,
    raw: &[u8],
    format: OutputFormat,
    pretty: bool,
    color: bool,
) -> String {
    match format {
        OutputFormat::Summary => render_summary(pkt, color),
        OutputFormat::Hexdump => render_hexdump(pkt, raw, color),
        OutputFormat::Json => render_json(pkt, pretty),
    }
}

fn render_summary(pkt: &ParsedPacket, color: bool) -> String {
    let (c, r) = if color {
        (protocol_color(pkt.transport.as_ref()), reset().to_string())
    } else {
        (String::new(), String::new())
    };

    let Some(ip) = &pkt.ip else {
        let ethertype = pkt
            .eth
            .as_ref()
            .map(|e| format!("ethertype=0x{:04x}", e.ethertype))
            .unwrap_or_else(|| "non-ethernet".to_string());
        return format!("{c}[unparsed] {ethertype} len={}{r}", pkt.len);
    };

    let body = match &pkt.transport {
        Some(TransportHeader::Tcp {
            src_port,
            dst_port,
            flags,
            ..
        }) => {
            format!(
                "{}:{} > {}:{} TCP [{}]",
                addr(ip, true),
                src_port,
                addr(ip, false),
                dst_port,
                flags.short()
            )
        }
        Some(TransportHeader::Udp {
            src_port, dst_port, ..
        }) => {
            format!(
                "{}:{} > {}:{} UDP",
                addr(ip, true),
                src_port,
                addr(ip, false),
                dst_port
            )
        }
        Some(TransportHeader::Icmp { icmp_type, code }) => {
            format!(
                "{} > {} ICMP type={} code={}",
                ip.src, ip.dst, icmp_type, code
            )
        }
        Some(TransportHeader::Icmpv6 { icmp_type, code }) => {
            format!(
                "{} > {} ICMPv6 type={} code={}",
                ip.src, ip.dst, icmp_type, code
            )
        }
        Some(TransportHeader::Other { protocol }) => {
            format!("{} > {} proto={}", ip.src, ip.dst, protocol)
        }
        None => format!("{} > {} (unparsed transport)", ip.src, ip.dst),
    };

    format!("{c}{body} len={}{r}", pkt.len)
}

fn addr(ip: &IpHeader, src: bool) -> String {
    if src {
        ip.src.to_string()
    } else {
        ip.dst.to_string()
    }
}

fn render_hexdump(pkt: &ParsedPacket, raw: &[u8], color: bool) -> String {
    let (c, r) = if color {
        (protocol_color(pkt.transport.as_ref()), reset().to_string())
    } else {
        (String::new(), String::new())
    };
    let mut out = format!("\n{c}[frame - {} bytes]{r}\n", raw.len());
    for chunk in raw.chunks(16) {
        let hex_string: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let ascii_string: String = chunk
            .iter()
            .map(|&b| {
                if (32..=126).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!(
            "  {:48} | {}\n",
            hex_string.join(" "),
            ascii_string
        ));
    }
    out
}

fn render_json(pkt: &ParsedPacket, pretty: bool) -> String {
    if pretty {
        serde_json::to_string_pretty(pkt).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    } else {
        serde_json::to_string(pkt).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}
