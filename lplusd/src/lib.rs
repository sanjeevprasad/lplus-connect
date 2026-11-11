//! L+ connect daemon: the phone-facing protocol stack and the loopback
//! backend. The GPUI window lives in `lplus-ui`; both sides speak only
//! through `lplus-ipc` (prost `/rpc` envelope, channel dispatcher,
//! ui-click queue, live frame bus). The `lplus` binary wires the two.

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
