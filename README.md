# 🔭 AetherScope

`Rust` · `libpcap` · `nftables`-adjacent

**Packet capture and protocol inspection on your own interfaces.** Not a
proxy like [WraithFlow](https://github.com/darkstardevx/wraithflow) — that
only sees traffic explicitly routed through one of its pipelines. This
sits directly on a network interface and sees everything crossing it:
UDP, ICMP, ARP, any TCP connection, not just the ones you've deliberately
proxied.

**Scope, on purpose:** general packet/protocol capture on an interface you
own — the same category of tool as `tcpdump`/Wireshark. **Not** an 802.11
monitor-mode wireless sniffer — that's a different, meaningfully more
sensitive category (capturing *other devices'* ambient wireless traffic,
not just your own machine's). Given this box regularly connects to
networks that aren't the user's own (a neighbor's, the local library),
that distinction matters: this tool only ever sees traffic on an interface
this machine itself is a party to, same as `tcpdump` would.

## 🚀 What it does

- Captures on a named interface via `libpcap` (the `pcap` crate) — the exact same capture engine `tcpdump`/Wireshark use
- **BPF filter syntax** — the same filter language as `tcpdump` (`tcp port 22`, `host 192.168.1.5`, `udp and not port 53`), for free from libpcap, not reimplemented
- Hand-rolled protocol parsing: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP/ICMPv6
- Three output formats: `summary` (one line, tcpdump-style), `hexdump`, `json`
- Colors sourced from the shared `cybercore` CYBERGRID palette (by protocol: TCP=acid_green, UDP=cyan, ICMP=orange) — same convention as WraithFlow

## ▶️ Running

Needs root or `CAP_NET_RAW` to actually open a capture device — everything
else (`--list-interfaces`) works unprivileged.

```bash
cargo build --release
aetherscope --list-interfaces
sudo aetherscope --interface wlp2s0
sudo aetherscope --interface lo --filter "tcp port 8765" --format json --pretty
sudo aetherscope --interface wlp2s0 --count 50 --format hexdump
```

### Flags

| Flag | What it does |
|---|---|
| `--interface, -i` | Interface to capture on (required) |
| `--list-interfaces` | List available interfaces and exit — no root needed |
| `--filter, -f` | A BPF filter expression |
| `--format` | `summary` (default) \| `hexdump` \| `json` |
| `--pretty` | Pretty-print JSON output |
| `--no-color` | Disable cybercore colors |
| `--count, -c` | Stop after N packets (default: runs until Ctrl+C) |
| `--promisc` | Capture in promiscuous mode |

## 🧩 Layout

```
src/packet.rs   Ethernet/IPv4/IPv6/TCP/UDP/ICMP parsing — no I/O, unit-tested
                against a hand-built real frame layout
src/format.rs   summary/hexdump/json rendering, cybercore color wiring
src/main.rs     CLI + the pcap capture loop
```

## 🗺 Roadmap / known limitations

- [x] Ethernet/IPv4/IPv6/TCP/UDP/ICMP parsing, unit-tested
- [x] BPF filtering via libpcap
- [x] summary/hexdump/json output, cybercore-themed colors
- [ ] IPv6 extension header handling (currently reads "next header" directly, doesn't walk extension header chains)
- [ ] Higher-level protocol dissection (HTTP, DNS, TLS ClientHello, etc.) — currently stops at the transport-layer header
- [ ] pcap file output (`-w`, tcpdump-compatible) for loading into Wireshark

## 📄 License

MIT
