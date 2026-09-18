use aetherscope_core::capture::CapturedFrame;
use aetherscope_core::packet::TransportHeader;
use aetherscope_core::stream::{self, StreamKey};
use std::path::PathBuf;

pub enum Mode {
    Normal,
    Filter,
    Detail,
    Stream,
    ExportPrompt,
    Help,
}

pub struct StreamLine {
    pub from_a: bool,
    pub text: String,
}

pub struct App {
    pub frames: Vec<CapturedFrame>,
    pub filtered: Vec<usize>,
    pub selected: usize,
    pub filter_text: String,
    pub mode: Mode,
    pub status: Option<String>,
    pub should_quit: bool,
    /// When true (the default), a newly-arrived live frame moves the
    /// selection to it — "follow" mode, same split as Echo's own
    /// follow-live/browse-history toggle. Off = keep browsing where you
    /// are while capture continues in the background.
    pub follow_live: bool,
    pub stream_key: Option<StreamKey>,
    pub stream_lines: Vec<StreamLine>,
    pub export_path_input: String,
    /// `None` for a live capture (nothing more will ever arrive once the
    /// process exits anyway); `Some` when loaded from a file, so the
    /// title bar can say so.
    pub loaded_from: Option<PathBuf>,
}

impl App {
    pub fn new(initial_frames: Vec<CapturedFrame>, loaded_from: Option<PathBuf>) -> Self {
        let mut app = Self {
            frames: initial_frames,
            filtered: Vec::new(),
            selected: 0,
            filter_text: String::new(),
            mode: Mode::Normal,
            status: None,
            should_quit: false,
            follow_live: true,
            stream_key: None,
            stream_lines: Vec::new(),
            export_path_input: String::new(),
            loaded_from,
        };
        app.apply_filter();
        app
    }

    /// Appends a newly-captured live frame and, in follow mode, jumps the
    /// selection to it.
    pub fn push_frame(&mut self, frame: CapturedFrame) {
        self.frames.push(frame);
        self.apply_filter();
        if self.follow_live && !self.filtered.is_empty() {
            self.selected = self.filtered.len() - 1;
        }
    }

    /// Oldest-first, matching how every real packet-capture tool
    /// (tcpdump, Wireshark) numbers and lists packets — a deliberate
    /// difference from this session's other TUIs (Argus/Echo), which
    /// show event logs newest-first. A live feed of numbered packets
    /// reads naturally growing downward; an event log you glance at
    /// reads better with the newest thing right in front of you. Two
    /// different domains, two different defaults, not an inconsistency.
    pub fn apply_filter(&mut self) {
        let needle = self.filter_text.to_lowercase();
        self.filtered = self
            .frames
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                needle.is_empty()
                    || aetherscope_core::format::render(
                        &f.parsed,
                        &f.raw,
                        aetherscope_core::format::OutputFormat::Summary,
                        false,
                        false,
                    )
                    .to_lowercase()
                    .contains(&needle)
            })
            .map(|(i, _)| i)
            .collect();
        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
    }

    pub fn toggle_follow(&mut self) {
        self.follow_live = !self.follow_live;
        self.status = Some(if self.follow_live {
            "following live capture".to_string()
        } else {
            "browsing — new packets won't move your selection".to_string()
        });
    }

    pub fn selected_frame(&self) -> Option<&CapturedFrame> {
        self.filtered
            .get(self.selected)
            .and_then(|&i| self.frames.get(i))
    }

    pub fn next(&mut self) {
        if !self.filtered.is_empty() {
            self.selected = (self.selected + 1) % self.filtered.len();
        }
    }

    pub fn previous(&mut self) {
        if !self.filtered.is_empty() {
            self.selected = if self.selected == 0 {
                self.filtered.len() - 1
            } else {
                self.selected - 1
            };
        }
    }

    /// Builds the Follow TCP Stream view for the selected packet, if it's
    /// TCP — every frame sharing its `StreamKey`, in capture order,
    /// payload bytes rendered as lossy text and tagged by direction for
    /// the UI to color.
    pub fn follow_selected_stream(&mut self) {
        let Some(frame) = self.selected_frame() else {
            return;
        };
        let Some(key) = stream::key_for(&frame.parsed) else {
            self.status = Some("not a TCP packet — nothing to follow".to_string());
            return;
        };

        let indices = stream::packets_in_stream(
            &self
                .frames
                .iter()
                .map(|f| f.parsed.clone())
                .collect::<Vec<_>>(),
            &key,
        );
        self.stream_lines = indices
            .into_iter()
            .filter_map(|i| {
                let frame = &self.frames[i];
                if frame.parsed.payload.is_empty() {
                    return None; // SYN/ACK-only packets add no readable content
                }
                Some(StreamLine {
                    from_a: stream::is_from_a(&frame.parsed, &key),
                    text: lossy_text(&frame.parsed.payload),
                })
            })
            .collect();
        self.stream_key = Some(key);
        self.mode = Mode::Stream;
    }
}

fn lossy_text(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (32..=126).contains(&b) || b == b'\n' || b == b'\r' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

pub fn detail_lines(frame: &CapturedFrame) -> String {
    let mut lines = vec![format!("length: {} bytes", frame.parsed.len)];

    if let Some(eth) = &frame.parsed.eth {
        lines.push(String::new());
        lines.push("Ethernet".to_string());
        lines.push(format!("  src mac: {}", eth.src_mac));
        lines.push(format!("  dst mac: {}", eth.dst_mac));
        lines.push(format!("  ethertype: 0x{:04x}", eth.ethertype));
    }

    if let Some(ip) = &frame.parsed.ip {
        lines.push(String::new());
        lines.push("IP".to_string());
        lines.push(format!("  src: {}", ip.src));
        lines.push(format!("  dst: {}", ip.dst));
        lines.push(format!("  protocol: {}", ip.protocol));
        lines.push(format!("  ttl/hop limit: {}", ip.ttl_or_hop_limit));
    }

    match &frame.parsed.transport {
        Some(TransportHeader::Tcp {
            src_port,
            dst_port,
            seq,
            ack,
            flags,
        }) => {
            lines.push(String::new());
            lines.push("TCP".to_string());
            lines.push(format!("  src port: {src_port}"));
            lines.push(format!("  dst port: {dst_port}"));
            lines.push(format!("  seq: {seq}"));
            lines.push(format!("  ack: {ack}"));
            lines.push(format!("  flags: {}", flags.short()));
        }
        Some(TransportHeader::Udp {
            src_port,
            dst_port,
            length,
        }) => {
            lines.push(String::new());
            lines.push("UDP".to_string());
            lines.push(format!("  src port: {src_port}"));
            lines.push(format!("  dst port: {dst_port}"));
            lines.push(format!("  length: {length}"));
        }
        Some(TransportHeader::Icmp { icmp_type, code }) => {
            lines.push(String::new());
            lines.push(format!("ICMP  type={icmp_type} code={code}"));
        }
        Some(TransportHeader::Icmpv6 { icmp_type, code }) => {
            lines.push(String::new());
            lines.push(format!("ICMPv6  type={icmp_type} code={code}"));
        }
        Some(TransportHeader::Other { protocol }) => {
            lines.push(String::new());
            lines.push(format!("transport protocol {protocol} (unparsed)"));
        }
        None => {}
    }

    if !frame.parsed.payload.is_empty() {
        lines.push(String::new());
        lines.push(format!("Payload ({} bytes)", frame.parsed.payload.len()));
        lines.push(lossy_text(&frame.parsed.payload));
    }

    lines.push(String::new());
    lines.push("Hex dump".to_string());
    for chunk in frame.raw.chunks(16) {
        let hex_string: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
        let ascii_string = lossy_text(chunk);
        lines.push(format!("  {:48} | {}", hex_string.join(" "), ascii_string));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aetherscope_core::capture::Source;

    /// `CapturedFrame`'s fields beyond `parsed`/`raw` are deliberately
    /// private (internal bookkeeping for pcap-header reconstruction on
    /// export) -- so, same as `aetherscope-core`'s own tests, real test
    /// frames come from round-tripping real bytes through a scratch pcap
    /// file via the actual production `Source`/savefile code path, not a
    /// struct literal shortcut.
    fn write_and_reload(frame_bytes: &[Vec<u8>], suffix: &str) -> Vec<CapturedFrame> {
        let dir = std::env::temp_dir().join(format!(
            "proteus-app-test-{}-{}",
            std::process::id(),
            suffix
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("frames.pcap");

        let mut savefile = aetherscope_core::capture::open_savefile_for_export(&path).unwrap();
        for (i, bytes) in frame_bytes.iter().enumerate() {
            let header = pcap::PacketHeader {
                ts: libc::timeval {
                    tv_sec: i as libc::time_t,
                    tv_usec: 0,
                },
                caplen: bytes.len() as u32,
                len: bytes.len() as u32,
            };
            savefile.write(&pcap::Packet::new(&header, bytes));
        }
        savefile.flush().unwrap();

        let mut source = Source::open_file(&path).unwrap();
        let mut frames = Vec::new();
        while let Some(frame) = source.next_frame().unwrap() {
            frames.push(frame);
        }
        std::fs::remove_dir_all(&dir).ok();
        frames
    }

    /// Builds a minimal Ethernet+IPv4+TCP frame, optionally carrying a
    /// text payload -- same on-wire layout as `aetherscope-core`'s own
    /// test fixtures.
    struct TcpFrameSpec<'a> {
        src: ([u8; 4], u16),
        dst: ([u8; 4], u16),
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &'a [u8],
    }

    fn tcp_frame(spec: TcpFrameSpec) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00,
        ]);
        f.extend([
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6, 0x00, 0x00,
        ]);
        f.extend(spec.src.0);
        f.extend(spec.dst.0);
        f.extend(spec.src.1.to_be_bytes());
        f.extend(spec.dst.1.to_be_bytes());
        f.extend(spec.seq.to_be_bytes());
        f.extend(spec.ack.to_be_bytes());
        f.push(0x50); // data offset 5 -> 20-byte header, no options
        f.push(spec.flags);
        f.extend([0xff, 0xff, 0x00, 0x00, 0x00, 0x00]);
        f.extend(spec.payload);
        f
    }

    #[test]
    fn apply_filter_matches_src_dst_or_protocol_substring() {
        let frames = write_and_reload(
            &[
                tcp_frame(TcpFrameSpec {
                    src: ([192, 168, 1, 50], 40014),
                    dst: ([198, 51, 100, 7], 22),
                    seq: 1,
                    ack: 0,
                    flags: 0x02,
                    payload: b"",
                }),
                tcp_frame(TcpFrameSpec {
                    src: ([10, 0, 0, 5], 55000),
                    dst: ([10, 0, 0, 1], 443),
                    seq: 1,
                    ack: 0,
                    flags: 0x02,
                    payload: b"",
                }),
            ],
            "filter",
        );
        let mut app = App::new(frames, None);
        assert_eq!(app.filtered.len(), 2);

        app.filter_text = "198.51.100.7".to_string();
        app.apply_filter();
        assert_eq!(app.filtered.len(), 1);
        assert_eq!(
            app.frames[app.filtered[0]]
                .parsed
                .ip
                .as_ref()
                .unwrap()
                .dst
                .to_string(),
            "198.51.100.7"
        );
    }

    #[test]
    fn follow_selected_stream_reconstructs_both_directions_in_order_with_correct_colors() {
        let client = ([192, 168, 1, 50], 51000u16);
        let server = ([198, 51, 100, 7], 80u16);
        let request = b"GET /hello HTTP/1.1\r\n\r\n";
        let response = b"HTTP/1.1 200 OK\r\n\r\nhi";

        let frames = write_and_reload(
            &[
                tcp_frame(TcpFrameSpec {
                    src: client,
                    dst: server,
                    seq: 1,
                    ack: 0,
                    flags: 0x02,
                    payload: b"",
                }), // SYN
                tcp_frame(TcpFrameSpec {
                    src: client,
                    dst: server,
                    seq: 1,
                    ack: 1,
                    flags: 0x18,
                    payload: request,
                }), // PSH,ACK + request
                tcp_frame(TcpFrameSpec {
                    src: server,
                    dst: client,
                    seq: 1,
                    ack: 1 + request.len() as u32,
                    flags: 0x18,
                    payload: response,
                }), // response
            ],
            "stream",
        );
        let mut app = App::new(frames, None);

        // Select the request packet (index 1) and follow its stream.
        app.selected = 1;
        app.follow_selected_stream();

        assert!(matches!(app.mode, Mode::Stream));
        // The bare SYN has no payload, so only the request+response lines
        // should appear -- exactly the "no readable content" filtering
        // `follow_selected_stream` does.
        assert_eq!(app.stream_lines.len(), 2);
        assert!(app.stream_lines[0].from_a);
        assert!(app.stream_lines[0].text.contains("GET /hello"));
        assert!(!app.stream_lines[1].from_a);
        assert!(app.stream_lines[1].text.contains("200 OK"));
    }
}
