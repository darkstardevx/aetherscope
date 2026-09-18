//! Shared parsing/capture engine behind both `aetherscope` (the CLI) and
//! `proteus` (the TUI) — one packet-parsing pipeline, one capture/savefile
//! abstraction, reused by both rather than each having its own copy.

pub mod capture;
pub mod format;
pub mod packet;
pub mod stream;
