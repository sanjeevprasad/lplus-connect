//! L+ connect daemon: the phone-facing protocol stack and the loopback
//! backend. Everything machine-facing speaks only `lplus-ipc` (the
//! `protos/lplus.proto` contract served on :1421, the channel dispatcher,
//! the event ring, the live frame bus). The `lplus` binary wires it up.

pub mod ble;
pub mod d2d;
pub mod gui;
pub mod kms;
pub mod odmf_pc;
pub mod rpc;
pub mod rtsp;
pub mod scp;
pub mod scpc;
pub mod sdpd;
pub mod state;
pub mod ukey2;
pub mod wfd_sink;
