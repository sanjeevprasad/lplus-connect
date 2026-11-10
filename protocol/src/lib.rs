//! Phone↔PC wire contract for L+ Connect: everything the two ends say to
//! each other and nothing they say internally.
//!
//! - [`protos`] — hand-rolled prost messages (UKEY2 handshake, D2D,
//!   securemessage envelope).
//! - [`appfn`] — AppFunction (`OPSynergyAppFunction`) call-result envelopes
//!   the phone returns over the adb CLI.
//! - [`odmf`] — transport-bus JSON frames: `send` envelope, SDP/candidate
//!   signaling, keepalives, identity-auth request/response shapes.
//! - [`pair`] — pairing-QR payload (`base64({"HeySynergy":…})`, V1 bean).
//! - [`rtsp`] — cast lane: RTSP messages on the `rtsp-types` codec
//!   (RFC 7826 types/parser/serializer), WFD params, SDP, RTP depacketizer.
//!
//! Deliberately absent: the daemon↔gui registry (`gui/api.rs` in the
//! `lplus` bin), device-event bus types, and the `/__ipc` envelope — those
//! are our own boundary, not the phone's.

pub mod appfn;
pub mod odmf;
pub mod pair;
pub mod protos;
pub mod rtsp;
