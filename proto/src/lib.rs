//! Phone↔PC wire contract for L+ Connect: everything the two ends say to
//! each other and nothing they say internally.
//!
//! - Protobuf messages (UKEY2 handshake, D2D, securemessage envelope,
//!   SCP `ScpMessage`/`Hello`/`ScpSyncData`/`ScpSyncSecure`, UMS card
//!   service) —
//!   100 % prost-generated from `protos/` (Google's Apache-2.0 protos from
//!   AOSP beto-rust + `oplus.proto`, the single phone-forked message +
//!   recovered `card.proto`/`scp.proto`;
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
    // UMS card-service wire types (proto2), recovered from vendor
    // descriptor blobs — see protos/card.proto header.
    mod card {
        #![allow(dead_code)]
        include!(concat!(
            env!("OUT_DIR"),
            "/com.oplus.pantanal.ums.cardservice.valueobject.model.rs"
        ));
    }
    // SCP wire types — hand-tagged mirror of the phone's protobuf-lite
    // classes (device-verified); see protos/scp.proto header.
    mod scpwire {
        include!(concat!(
            env!("OUT_DIR"),
            "/com.oplus.pantaconnect.connection.scp.rs"
        ));
    }
    pub use card::card_action_proto::Action;
    pub use card::card_config_info_list_proto::{
        CardConfigInfoProto,
        card_config_info_proto::{CardMaintainProto, Category, Operation, Size},
    };
    pub use card::{CardActionProto, CardConfigInfoListProto, UiDataClientProto, UiDataProto};
    pub use scpwire::{Hello, LinkType, ScpMessage, SyncData, SyncSecure};

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

#[cfg(test)]
mod card_wire_tests {
    use super::{Action, CardActionProto};
    use prost::Message;
    use std::collections::HashMap;

    /// Vendor byte pin for the recovered proto2 `CardActionProto`
    /// (protos/card.proto): required int32 fields 1–4 as varints, then map
    /// field 5 carrying one entry (`param: {"a":"b"}`, entry = key field 1 +
    /// value field 2). Byte-exact per the vendor descriptor.
    #[test]
    fn card_action_proto_wire_bytes() {
        let msg = CardActionProto {
            card_type: 7,
            card_id: 9,
            host_id: 1,
            action: Action::Click as i32,
            param: [("a".to_string(), "b".to_string())]
                .into_iter()
                .collect::<HashMap<_, _>>(),
        };
        let want: Vec<u8> = vec![
            0x08, 0x07, 0x10, 0x09, 0x18, 0x01, 0x20, 0x01, 0x2a, 0x06, 0x0a, 0x01, b'a', 0x12,
            0x01, b'b',
        ];
        assert_eq!(msg.encode_to_vec(), want);
        assert_eq!(CardActionProto::decode(&want[..]).unwrap(), msg);
    }
}
