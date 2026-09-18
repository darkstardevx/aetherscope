//! Wraps `pcap::Capture` for both live interfaces and offline `.pcap`
//! files behind one interface — both are `Activated` in the `pcap` crate
//! and share the same `next_packet()` shape (verified against the real
//! docs.rs source before writing this, not assumed), so one capture loop
//! and one export path serve both a live capture and "load a file for
//! offline analysis," exactly as the plan called for.

use crate::packet::{self, ParsedPacket};
use anyhow::{anyhow, Result};
use std::path::Path;

/// A captured frame plus everything needed to write it back out to a
/// `.pcap` file later. `pcap::Packet::new` takes borrowed `header`/`data`
/// tied to the capture handle's own buffer lifetime — this owns copies so
/// a frame can be kept around (for the TUI's packet list, for later
/// export) well past the moment it was captured.
pub struct CapturedFrame {
    pub parsed: ParsedPacket,
    pub raw: Vec<u8>,
    ts_sec: i64,
    ts_usec: i64,
    caplen: u32,
    orig_len: u32,
}

impl CapturedFrame {
    fn pcap_header(&self) -> pcap::PacketHeader {
        pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: self.ts_sec as libc::time_t,
                tv_usec: self.ts_usec as libc::suseconds_t,
            },
            caplen: self.caplen,
            len: self.orig_len,
        }
    }
}

pub enum Source {
    Live(pcap::Capture<pcap::Active>),
    Offline(pcap::Capture<pcap::Offline>),
}

impl Source {
    /// Opens a live interface by name — needs root or `CAP_NET_RAW` to
    /// actually succeed, same requirement as the `aetherscope` CLI today.
    pub fn open_live(interface: &str, promisc: bool, filter: Option<&str>) -> Result<Self> {
        let device = pcap::Device::list()?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| anyhow!("no such interface \"{interface}\" — see list_interfaces()"))?;
        let mut capture = pcap::Capture::from_device(device)?
            .promisc(promisc)
            .snaplen(65535)
            .timeout(1000)
            .open()?;
        if let Some(f) = filter {
            capture.filter(f, true)?;
        }
        Ok(Source::Live(capture))
    }

    /// Opens an existing `.pcap` file for offline analysis — no
    /// privilege needed at all, unlike live capture.
    pub fn open_file(path: &Path) -> Result<Self> {
        Ok(Source::Offline(pcap::Capture::from_file(path)?))
    }

    /// Blocks until the next packet for a live source; reads the next
    /// record for an offline one. `Ok(None)` means "nothing right now" —
    /// a live capture's read timeout (retry, not an error) or an offline
    /// source reaching end-of-file (genuinely done, not an error either).
    pub fn next_frame(&mut self) -> Result<Option<CapturedFrame>> {
        let raw = match self {
            Source::Live(c) => match c.next_packet() {
                Ok(p) => p,
                Err(pcap::Error::TimeoutExpired) => return Ok(None),
                Err(e) => return Err(e.into()),
            },
            Source::Offline(c) => match c.next_packet() {
                Ok(p) => p,
                Err(pcap::Error::NoMorePackets) => return Ok(None),
                Err(e) => return Err(e.into()),
            },
        };

        let ts_sec: i64 = raw.header.ts.tv_sec;
        // tv_usec is i64 on Linux glibc but i32 on macOS/BSD libc -- .into()
        // handles both without a platform-specific cfg; it's a genuine
        // widening conversion on macOS and a no-op on Linux, where clippy
        // would otherwise (correctly, for that one platform) flag it.
        #[allow(clippy::useless_conversion)]
        let ts_usec: i64 = raw.header.ts.tv_usec.into();
        let parsed = packet::parse(raw.data, ts_sec * 1_000_000 + ts_usec);

        Ok(Some(CapturedFrame {
            parsed,
            raw: raw.data.to_vec(),
            ts_sec,
            ts_usec,
            caplen: raw.header.caplen,
            orig_len: raw.header.len,
        }))
    }

    /// Opens a `.pcap` file for writing, using this source's own link-
    /// layer type (required by `pcap` — `Savefile` is created *from* an
    /// active/offline capture, live or file-loaded both work).
    pub fn savefile(&self, path: &Path) -> Result<pcap::Savefile> {
        match self {
            Source::Live(c) => Ok(c.savefile(path)?),
            Source::Offline(c) => Ok(c.savefile(path)?),
        }
    }
}

/// Writes one previously-captured frame to an open savefile — used both
/// for streaming export during a live capture and for exporting a
/// filtered subset of already-loaded packets after the fact.
pub fn write_frame(savefile: &mut pcap::Savefile, frame: &CapturedFrame) {
    let header = frame.pcap_header();
    let packet = pcap::Packet::new(&header, &frame.raw);
    savefile.write(&packet);
}

/// Opens a `.pcap` file for writing, independent of any live or offline
/// `Source` — for exporting frames a caller already has in hand (e.g.
/// Proteus's own in-memory packet list) when the `Source` that originally
/// captured them isn't available anymore (moved into a background
/// capture thread, in Proteus's case). Uses `pcap`'s own documented
/// "dead" capture handle (a fake handle that exists only to carry a
/// link-layer type) — Ethernet, since that's the only link layer this
/// codebase's parser understands.
pub fn open_savefile_for_export(path: &Path) -> Result<pcap::Savefile> {
    let dead = pcap::Capture::dead(pcap::Linktype::ETHERNET)?;
    Ok(dead.savefile(path)?)
}

pub fn list_interfaces() -> Result<Vec<(String, String)>> {
    Ok(pcap::Device::list()?
        .into_iter()
        .map(|d| (d.name, d.desc.unwrap_or_default()))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trips a real synthetic frame through Source::open_live's
    /// sibling path: write via a savefile, read it back via
    /// Source::open_file, confirm the bytes and parsed fields survive.
    /// No root needed -- pure file I/O, no live interface involved.
    #[test]
    fn savefile_round_trip_preserves_a_real_frame() {
        // Build a real Ethernet+IPv4+TCP SYN frame, same layout as
        // packet.rs's own test fixtures.
        let mut frame_bytes = Vec::new();
        frame_bytes.extend([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        frame_bytes.extend([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        frame_bytes.extend([0x08, 0x00]);
        frame_bytes.extend([
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00,
        ]);
        frame_bytes.extend([192, 168, 1, 50]);
        frame_bytes.extend([198, 51, 100, 7]);
        frame_bytes.extend([0x9c, 0x4e, 0x00, 0x16]);
        frame_bytes.extend([0, 0, 0, 1, 0, 0, 0, 0]);
        frame_bytes.extend([0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);

        let dir =
            std::env::temp_dir().join(format!("aetherscope-capture-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pcap_path = dir.join("roundtrip.pcap");

        {
            let mut savefile = open_savefile_for_export(&pcap_path).unwrap();
            let header = pcap::PacketHeader {
                ts: libc::timeval {
                    tv_sec: 12345,
                    tv_usec: 6789,
                },
                caplen: frame_bytes.len() as u32,
                len: frame_bytes.len() as u32,
            };
            let packet = pcap::Packet::new(&header, &frame_bytes);
            savefile.write(&packet);
            savefile.flush().unwrap();
        }

        let mut source = Source::open_file(&pcap_path).unwrap();
        let frame = source
            .next_frame()
            .unwrap()
            .expect("one frame written, one frame read back");
        assert_eq!(frame.raw, frame_bytes);
        let ip = frame.parsed.ip.expect("ip header");
        assert_eq!(ip.src, "192.168.1.50".parse::<std::net::IpAddr>().unwrap());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Exercises the real production path Proteus's own `w` export key
    /// uses: load frames from one file via `Source::open_file` +
    /// `next_frame`, write them back out via `open_savefile_for_export` +
    /// `write_frame`, and confirm re-reading the export produces the
    /// same frames in the same order — a full export round-trip, not
    /// just the lower-level pcap API in isolation.
    #[test]
    fn write_frame_round_trips_multiple_captured_frames() {
        let dir =
            std::env::temp_dir().join(format!("aetherscope-capture-test2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let source_pcap = dir.join("source.pcap");
        let exported_pcap = dir.join("exported.pcap");

        let mut frame_a = Vec::new();
        frame_a.extend([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
        ]);
        frame_a.extend([
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00,
        ]);
        frame_a.extend([192, 168, 1, 50, 198, 51, 100, 7]);
        frame_a.extend([
            0x9c, 0x4e, 0x00, 0x16, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);

        let mut frame_b = frame_a.clone();
        frame_b[34] = 0x02; // tweaks the TCP source port byte so frame_b != frame_a

        {
            let mut savefile = open_savefile_for_export(&source_pcap).unwrap();
            for bytes in [&frame_a, &frame_b] {
                let header = pcap::PacketHeader {
                    ts: libc::timeval {
                        tv_sec: 1,
                        tv_usec: 0,
                    },
                    caplen: bytes.len() as u32,
                    len: bytes.len() as u32,
                };
                savefile.write(&pcap::Packet::new(&header, bytes));
            }
            savefile.flush().unwrap();
        }

        // Load, then re-export via the real write_frame() path.
        let mut source = Source::open_file(&source_pcap).unwrap();
        let mut loaded = Vec::new();
        while let Some(frame) = source.next_frame().unwrap() {
            loaded.push(frame);
        }
        assert_eq!(loaded.len(), 2);

        {
            let mut export = open_savefile_for_export(&exported_pcap).unwrap();
            for frame in &loaded {
                write_frame(&mut export, frame);
            }
            export.flush().unwrap();
        }

        let mut reread = Source::open_file(&exported_pcap).unwrap();
        let re_a = reread
            .next_frame()
            .unwrap()
            .expect("first re-exported frame");
        let re_b = reread
            .next_frame()
            .unwrap()
            .expect("second re-exported frame");
        assert_eq!(re_a.raw, frame_a);
        assert_eq!(re_b.raw, frame_b);
        assert!(reread.next_frame().unwrap().is_none());

        std::fs::remove_dir_all(&dir).ok();
    }
}
