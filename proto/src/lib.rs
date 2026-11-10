//! Phone↔PC wire contract for L+ Connect: everything the two ends say to
//! each other and nothing they say internally.
//!
//! - Protobuf messages (UKEY2 handshake, D2D, securemessage envelope) —
//!   100 % prost-generated from `protos/` (Google's Apache-2.0 protos from
//!   AOSP beto-rust + `oplus.proto`, the single phone-forked message;
//!   provenance in `protos/README.md`). No handwritten wire structs;
//!   divergences are pinned by `tests/proto_cross.rs`.
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
pub mod rtsp;

/// prost-generated protobuf wire types. `missing_docs`/`clippy` are waived
/// only inside: it is machine output.
pub mod protos {
    #![allow(missing_docs, clippy::all)]

    mod securegcm {
        #![allow(dead_code)]
        include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
    }
    mod securemessage {
        // Official-only messages we never construct (RSA/DH key types) stay
        // generated-but-unused by design.
        #![allow(dead_code)]
        include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
    }
    mod opluswire {
        include!(concat!(env!("OUT_DIR"), "/opluswire.rs"));
    }

    pub use securegcm::ukey2_client_init::CipherCommitment;
    pub use securegcm::{
        DeviceToDeviceMessage, GcmMetadata, Ukey2ClientInit, Ukey2HandshakeCipher, Ukey2Message,
        Ukey2ServerInit, ukey2_message,
    };
    pub use securemessage::{
        EcP256PublicKey, EncScheme, GenericPublicKey, Header, HeaderAndBody, PublicKeyType,
        SecureMessage, SigScheme,
    };
    // The one forked message — see protos/oplus.proto (iv_spec is decode-only).
    pub use opluswire::Ukey2ClientFinished;
}
pub use protos::*;
