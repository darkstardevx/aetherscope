//! Hand-rolled protocol parsing — Ethernet through TCP/UDP/ICMP. `pcap`
//! only hands us raw bytes per captured frame (plus whatever BPF filter
//! narrowed the capture); everything above that is decoded here.
//!
//! Deliberately not exhaustive — this covers the common core (Ethernet,
//! IPv4/IPv6, TCP/UDP/ICMP) well enough to be genuinely useful, rather than
//! a partial dissector for every protocol that exists.

use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Serialize, Clone)]
pub struct ParsedPacket {
    pub timestamp_micros: i64,
    pub len: usize,
    pub eth: Option<EthHeader>,
    pub ip: Option<IpHeader>,
    pub transport: Option<TransportHeader>,
    /// Bytes past the transport header — empty if there's no transport
    /// header at all, or nothing followed it. Needed for stream
    /// reconstruction (`stream.rs`) and the TUI's detail view; the
    /// original CLI-only version of this parser never retained this.
    #[serde(skip)]
    pub payload: Vec<u8>,
}

#[derive(Debug, Serialize, Clone)]
pub struct EthHeader {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: u16,
}

#[derive(Debug, Serialize, Clone)]
pub struct IpHeader {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub ttl_or_hop_limit: u8,
}

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "kind")]
pub enum TransportHeader {
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        length: u16,
    },
    Icmp {
        icmp_type: u8,
        code: u8,
    },
    Icmpv6 {
        icmp_type: u8,
        code: u8,
    },
    Other {
        protocol: u8,
    },
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    fn from_byte(b: u8) -> Self {
        Self {
            fin: b & 0x01 != 0,
            syn: b & 0x02 != 0,
            rst: b & 0x04 != 0,
            psh: b & 0x08 != 0,
            ack: b & 0x10 != 0,
            urg: b & 0x20 != 0,
        }
    }

    /// A short flag summary like a real tcpdump: "S", "S.", "F.", "R", "."
    pub fn short(&self) -> String {
        let mut s = String::new();
        if self.syn {
            s.push('S');
        }
        if self.fin {
            s.push('F');
        }
        if self.rst {
            s.push('R');
        }
        if self.psh {
            s.push('P');
        }
        if self.urg {
            s.push('U');
        }
        if self.ack {
            s.push('.');
        }
        if s.is_empty() {
            s.push('.');
        }
        s
    }
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

pub fn parse(bytes: &[u8], timestamp_micros: i64) -> ParsedPacket {
    let eth = parse_eth(bytes);
    let ip_start = 14; // fixed Ethernet-II header length
    let ip = eth.as_ref().and_then(|e| match e.ethertype {
        ETHERTYPE_IPV4 => bytes.get(ip_start..).and_then(parse_ipv4),
        ETHERTYPE_IPV6 => bytes.get(ip_start..).and_then(parse_ipv6),
        _ => None,
    });

    let mut payload = Vec::new();
    let transport = ip.as_ref().and_then(|(hdr, ip_header_len)| {
        let transport_start = ip_start + ip_header_len;
        let rest = bytes.get(transport_start..)?;
        let (header, transport_header_len) = parse_transport(hdr.protocol, rest)?;
        if let Some(after) = rest.get(transport_header_len..) {
            payload = after.to_vec();
        }
        Some(header)
    });

    ParsedPacket {
        timestamp_micros,
        len: bytes.len(),
        eth,
        ip: ip.map(|(hdr, _)| hdr),
        transport,
        payload,
    }
}

fn mac_str(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_eth(bytes: &[u8]) -> Option<EthHeader> {
    if bytes.len() < 14 {
        return None;
    }
    Some(EthHeader {
        dst_mac: mac_str(&bytes[0..6]),
        src_mac: mac_str(&bytes[6..12]),
        ethertype: u16::from_be_bytes([bytes[12], bytes[13]]),
    })
}

/// Returns the header plus its own length in bytes (IHL for v4, fixed 40 for v6)
/// so the caller knows where the transport header actually starts.
fn parse_ipv4(bytes: &[u8]) -> Option<(IpHeader, usize)> {
    if bytes.len() < 20 {
        return None;
    }
    let ihl = (bytes[0] & 0x0f) as usize * 4;
    if bytes.len() < ihl {
        return None;
    }
    Some((
        IpHeader {
            src: IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
            dst: IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
            protocol: bytes[9],
            ttl_or_hop_limit: bytes[8],
        },
        ihl,
    ))
}

fn parse_ipv6(bytes: &[u8]) -> Option<(IpHeader, usize)> {
    if bytes.len() < 40 {
        return None;
    }
    let src: [u8; 16] = bytes[8..24].try_into().ok()?;
    let dst: [u8; 16] = bytes[24..40].try_into().ok()?;
    Some((
        IpHeader {
            src: IpAddr::V6(Ipv6Addr::from(src)),
            dst: IpAddr::V6(Ipv6Addr::from(dst)),
            protocol: bytes[6], // "next header" — doesn't handle extension headers
            ttl_or_hop_limit: bytes[7],
        },
        40,
    ))
}

/// Returns the header plus its own length in bytes, same pattern as
/// `parse_ipv4`/`parse_ipv6` — the caller needs this to know where the
/// payload actually starts. TCP's real header length varies with options
/// (the "data offset" field, upper 4 bits of byte 12) — fixed-14 was
/// wrong for any packet carrying TCP options, and silently would have
/// sliced part of the header into what `stream.rs` treats as payload.
fn parse_transport(protocol: u8, bytes: &[u8]) -> Option<(TransportHeader, usize)> {
    match protocol {
        PROTO_TCP if bytes.len() >= 20 => {
            let data_offset = ((bytes[12] >> 4) as usize) * 4;
            if bytes.len() < data_offset || data_offset < 20 {
                return None;
            }
            Some((
                TransportHeader::Tcp {
                    src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
                    dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
                    seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
                    ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
                    flags: TcpFlags::from_byte(bytes[13]),
                },
                data_offset,
            ))
        }
        PROTO_UDP if bytes.len() >= 8 => Some((
            TransportHeader::Udp {
                src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
                dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
                length: u16::from_be_bytes([bytes[4], bytes[5]]),
            },
            8,
        )),
        // ICMP/ICMPv6's fixed header is 8 bytes (type/code/checksum/
        // rest-of-header) even though only the first 2 are parsed into
        // fields here — matches the existing scope (type+code only), the
        // length is just what's needed to correctly slice the payload.
        PROTO_ICMP if bytes.len() >= 8 => Some((
            TransportHeader::Icmp {
                icmp_type: bytes[0],
                code: bytes[1],
            },
            8,
        )),
        PROTO_ICMPV6 if bytes.len() >= 8 => Some((
            TransportHeader::Icmpv6 {
                icmp_type: bytes[0],
                code: bytes[1],
            },
            8,
        )),
        _ => Some((TransportHeader::Other { protocol }, 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real captured Ethernet+IPv4+TCP SYN frame (dst port 22), built
    /// byte-by-byte rather than sourced live, but following the exact
    /// on-wire layout so the parser is tested against real structure.
    fn sample_tcp_syn_frame() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
        f.extend([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src mac
        f.extend([0x08, 0x00]); // ethertype = IPv4
                                // IPv4 header, 20 bytes, no options
        f.extend([0x45, 0x00]); // version/ihl, dscp/ecn
        f.extend([0x00, 0x28]); // total length
        f.extend([0x00, 0x00, 0x40, 0x00]); // id, flags/fragment
        f.extend([64, 6]); // ttl=64, protocol=TCP
        f.extend([0x00, 0x00]); // checksum (unchecked)
        f.extend([192, 168, 1, 50]); // src ip
        f.extend([198, 51, 100, 7]); // dst ip
                                     // TCP header, 20 bytes minimal
        f.extend([0x9c, 0x4e]); // src port 40014
        f.extend([0x00, 0x16]); // dst port 22
        f.extend([0, 0, 0, 1]); // seq
        f.extend([0, 0, 0, 0]); // ack
        f.push(0x50); // data offset
        f.push(0x02); // flags = SYN
        f.extend([0xff, 0xff]); // window
        f.extend([0x00, 0x00]); // checksum
        f.extend([0x00, 0x00]); // urgent pointer
        f
    }

    #[test]
    fn parses_full_tcp_syn_frame() {
        let frame = sample_tcp_syn_frame();
        let p = parse(&frame, 0);

        let eth = p.eth.expect("eth header");
        assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
        assert_eq!(eth.src_mac, "aa:bb:cc:dd:ee:ff");

        let ip = p.ip.expect("ip header");
        assert_eq!(ip.src, "192.168.1.50".parse::<IpAddr>().unwrap());
        assert_eq!(ip.dst, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert_eq!(ip.protocol, PROTO_TCP);
        assert_eq!(ip.ttl_or_hop_limit, 64);

        match p.transport.expect("transport header") {
            TransportHeader::Tcp {
                src_port,
                dst_port,
                seq,
                ack,
                flags,
            } => {
                assert_eq!(src_port, 40014);
                assert_eq!(dst_port, 22);
                assert_eq!(seq, 1);
                assert_eq!(ack, 0);
                assert!(flags.syn);
                assert!(!flags.ack);
                assert_eq!(flags.short(), "S");
            }
            other => panic!("expected Tcp, got {other:?}"),
        }
        assert!(p.payload.is_empty(), "a bare SYN carries no payload");
    }

    #[test]
    fn extracts_payload_past_a_tcp_header_with_options() {
        // Same frame as above, but with 4 bytes of TCP options (data
        // offset 6 = 24 bytes, not the minimal 20) followed by real
        // payload bytes -- the exact case the old fixed-14-byte transport
        // slicing would have gotten wrong, folding part of the options
        // (or, for a minimal header, part of the payload) into the wrong
        // place.
        let mut f = Vec::new();
        f.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // dst mac
        f.extend([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src mac
        f.extend([0x08, 0x00]); // ethertype = IPv4
        f.extend([0x45, 0x00]);
        f.extend([0x00, 0x00]); // total length (unchecked by the parser)
        f.extend([0x00, 0x00, 0x40, 0x00]);
        f.extend([64, 6]);
        f.extend([0x00, 0x00]);
        f.extend([192, 168, 1, 50]);
        f.extend([198, 51, 100, 7]);
        f.extend([0x9c, 0x4e]);
        f.extend([0x00, 0x16]);
        f.extend([0, 0, 0, 100]); // seq
        f.extend([0, 0, 0, 50]); // ack
        f.push(0x60); // data offset = 6 -> 24-byte header (4 bytes options)
        f.push(0x18); // flags = PSH, ACK
        f.extend([0xff, 0xff]);
        f.extend([0x00, 0x00]);
        f.extend([0x00, 0x00]);
        f.extend([0x01, 0x01, 0x08, 0x0a]); // 4 bytes of TCP options
        f.extend(b"hello proteus"); // real payload

        let p = parse(&f, 0);
        match p.transport.expect("transport header") {
            TransportHeader::Tcp { seq, ack, .. } => {
                assert_eq!(seq, 100);
                assert_eq!(ack, 50);
            }
            other => panic!("expected Tcp, got {other:?}"),
        }
        assert_eq!(p.payload, b"hello proteus");
    }

    #[test]
    fn handles_truncated_frame_gracefully() {
        let short = vec![0u8; 5]; // not even a full Ethernet header
        let p = parse(&short, 0);
        assert!(p.eth.is_none());
        assert!(p.ip.is_none());
        assert!(p.transport.is_none());
    }

    #[test]
    fn tcp_flags_short_format() {
        assert_eq!(
            TcpFlags {
                syn: true,
                ..Default::default()
            }
            .short(),
            "S"
        );
        assert_eq!(
            TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            }
            .short(),
            "S."
        );
        assert_eq!(
            TcpFlags {
                fin: true,
                ack: true,
                ..Default::default()
            }
            .short(),
            "F."
        );
        assert_eq!(
            TcpFlags {
                ack: true,
                ..Default::default()
            }
            .short(),
            "."
        );
        assert_eq!(TcpFlags::default().short(), ".");
    }
}
