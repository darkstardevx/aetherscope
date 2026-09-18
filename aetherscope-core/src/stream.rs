//! Groups captured packets into TCP conversations ("Follow TCP Stream" —
//! Wireshark's own name for this). A stream is identified by its 5-tuple
//! (well, 4 for TCP since the protocol is fixed), normalized so both
//! directions of one conversation hash to the *same* key regardless of
//! which side happened to send the packet being looked at.
//!
//! Deliberately timestamp-ordered per capture, not sequence-number-aware
//! reassembly — real TCP reassembly (handling retransmits, out-of-order
//! segments, gaps) is genuine TCP-stack complexity, out of scope for this
//! pass. For a live local capture, arrival order and send order coincide
//! closely enough that this is a real, useful reconstruction, just not a
//! bulletproof one — same "known limitation, not silently wrong" spirit
//! as the existing IPv6-extension-header gap.

use crate::packet::{IpHeader, ParsedPacket, TransportHeader};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

/// Normalized so `StreamKey::for_tcp` returns the same key regardless of
/// which endpoint sent the specific packet it was computed from —
/// `a <= b` by `Ord`, not "whoever was src in this packet."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamKey {
    pub a: Endpoint,
    pub b: Endpoint,
}

impl StreamKey {
    pub fn for_tcp(ip: &IpHeader, src_port: u16, dst_port: u16) -> Self {
        let src = Endpoint {
            ip: ip.src,
            port: src_port,
        };
        let dst = Endpoint {
            ip: ip.dst,
            port: dst_port,
        };
        if src <= dst {
            StreamKey { a: src, b: dst }
        } else {
            StreamKey { a: dst, b: src }
        }
    }
}

/// The key for a packet's TCP stream, or `None` if it isn't TCP (or
/// doesn't have a parsed IP header — nothing to key on).
pub fn key_for(pkt: &ParsedPacket) -> Option<StreamKey> {
    let ip = pkt.ip.as_ref()?;
    match &pkt.transport {
        Some(TransportHeader::Tcp {
            src_port, dst_port, ..
        }) => Some(StreamKey::for_tcp(ip, *src_port, *dst_port)),
        _ => None,
    }
}

/// Whether `pkt` was sent from `key.a` (true) or `key.b` (false) — for
/// coloring a reconstructed stream by direction. Panics-free: a packet
/// that doesn't actually belong to `key` (caller's bug, not a real input
/// case) is treated as `a`-direction rather than panicking.
pub fn is_from_a(pkt: &ParsedPacket, key: &StreamKey) -> bool {
    let Some(ip) = &pkt.ip else { return true };
    let Some(TransportHeader::Tcp { src_port, .. }) = &pkt.transport else {
        return true;
    };
    let src = Endpoint {
        ip: ip.src,
        port: *src_port,
    };
    src == key.a
}

/// Every packet (by index into `packets`) sharing `key`, in capture order.
pub fn packets_in_stream(packets: &[ParsedPacket], key: &StreamKey) -> Vec<usize> {
    packets
        .iter()
        .enumerate()
        .filter(|(_, pkt)| key_for(pkt).as_ref() == Some(key))
        .map(|(i, _)| i)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{EthHeader, TcpFlags};

    fn tcp_packet(
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        seq: u32,
    ) -> ParsedPacket {
        ParsedPacket {
            timestamp_micros: 0,
            len: 0,
            eth: Some(EthHeader {
                src_mac: String::new(),
                dst_mac: String::new(),
                ethertype: 0x0800,
            }),
            ip: Some(IpHeader {
                src: src_ip.parse().unwrap(),
                dst: dst_ip.parse().unwrap(),
                protocol: 6,
                ttl_or_hop_limit: 64,
            }),
            transport: Some(TransportHeader::Tcp {
                src_port,
                dst_port,
                seq,
                ack: 0,
                flags: TcpFlags::default(),
            }),
            payload: Vec::new(),
        }
    }

    #[test]
    fn both_directions_of_one_conversation_share_a_key() {
        let client_to_server = tcp_packet("192.168.1.50", 40014, "198.51.100.7", 22, 1);
        let server_to_client = tcp_packet("198.51.100.7", 22, "192.168.1.50", 40014, 1);

        let key1 = key_for(&client_to_server).unwrap();
        let key2 = key_for(&server_to_client).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn a_different_conversation_gets_a_different_key() {
        let stream_one = tcp_packet("192.168.1.50", 40014, "198.51.100.7", 22, 1);
        let stream_two = tcp_packet("192.168.1.50", 41000, "198.51.100.7", 22, 1);

        assert_ne!(key_for(&stream_one), key_for(&stream_two));
    }

    #[test]
    fn packets_in_stream_finds_only_the_matching_conversation_in_order() {
        let packets = vec![
            tcp_packet("192.168.1.50", 40014, "198.51.100.7", 22, 1), // stream A, pkt 0
            tcp_packet("10.0.0.5", 55000, "10.0.0.1", 443, 1),        // stream B, pkt 1
            tcp_packet("198.51.100.7", 22, "192.168.1.50", 40014, 1), // stream A, pkt 2
        ];
        let key = key_for(&packets[0]).unwrap();
        let indices = packets_in_stream(&packets, &key);
        assert_eq!(indices, vec![0, 2]);
    }

    #[test]
    fn is_from_a_correctly_identifies_direction() {
        let client_to_server = tcp_packet("192.168.1.50", 40014, "198.51.100.7", 22, 1);
        let key = key_for(&client_to_server).unwrap();
        let server_to_client = tcp_packet("198.51.100.7", 22, "192.168.1.50", 40014, 1);

        // Exactly one of the two directions is "a" -- they must disagree.
        assert_ne!(
            is_from_a(&client_to_server, &key),
            is_from_a(&server_to_client, &key)
        );
    }

    #[test]
    fn non_tcp_packets_have_no_stream_key() {
        let mut pkt = tcp_packet("192.168.1.50", 40014, "198.51.100.7", 22, 1);
        pkt.transport = Some(TransportHeader::Icmp {
            icmp_type: 8,
            code: 0,
        });
        assert!(key_for(&pkt).is_none());
    }
}
