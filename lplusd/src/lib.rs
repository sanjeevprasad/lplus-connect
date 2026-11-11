//! L+ connect daemon: the phone-facing protocol stack and the loopback
//! backend. Everything machine-facing speaks only `lplus-ipc` (the
//! `protos/lplus.proto` contract served on :1421, the channel dispatcher,
//! the event ring, the live frame bus). The `lplus` binary wires it up.

/// Backend orchestration: daemon threads, liveness, product entry.
pub mod backend;
pub mod config;
pub mod d2d;
pub mod odmf_pc;
pub mod rpc;
pub mod rtsp;
pub mod scp;
pub mod scpc;
pub mod state;
pub mod svc;
pub mod ukey2;
