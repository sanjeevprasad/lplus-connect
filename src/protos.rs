//! Hand-rolled prost types for Google UKEY2 (v2 handshake) + D2D connection protos.
//! Field numbers/semantics transcribed from the upstream definitions:
//! github.com/google/ukey2 `src/main/proto/{ukey,device_to_device_messages}.proto`
//! and github.com/google/securemessage `src/main/proto/securemessage.proto`.

use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2Message {
    #[prost(enumeration = "ukey2_message::Type", optional, tag = "1")]
    pub message_type: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub message_data: Option<Vec<u8>>,
}

pub mod ukey2_message {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        Alert = 1,
        ClientInit = 2,
        ServerInit = 3,
        ClientFinish = 4,
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2ClientInit {
    #[prost(uint32, optional, tag = "1")]
    pub version: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub random: Option<Vec<u8>>,
    #[prost(message, repeated, tag = "3")]
    pub cipher_commitments: Vec<CipherCommitment>,
    #[prost(string, optional, tag = "4")]
    pub next_protocol: Option<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct CipherCommitment {
    #[prost(enumeration = "Ukey2HandshakeCipher", optional, tag = "1")]
    pub handshake_cipher: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub commitment: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Ukey2HandshakeCipher {
    Reserved = 0,
    P256Sha512 = 100,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2ServerInit {
    #[prost(uint32, optional, tag = "1")]
    pub version: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub random: Option<Vec<u8>>,
    #[prost(enumeration = "Ukey2HandshakeCipher", optional, tag = "3")]
    pub handshake_cipher: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub public_key: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ukey2ClientFinished {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub public_key: Option<Vec<u8>>,
    /// Phone's fork carries the 16-byte AES IV for the post-ukey2 frame
    /// cryptor here (Google's Ukey2ClientFinished has no such field).
    #[prost(bytes = "vec", optional, tag = "2")]
    pub iv_spec: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct GenericPublicKey {
    #[prost(enumeration = "generic_public_key::Type", optional, tag = "1")]
    pub key_type: Option<i32>,
    /// cryptauth `GenericPublicKey.ec_p256_public_key`: a nested message
    /// with raw x/y coordinates, NOT SEC1 bytes (the phone re-parses this
    /// with `q3.h.parseFrom`; a bytes-typed field 2 dies there as
    /// `invalid tag (zero)` → BAD_PUBLIC_KEY).
    #[prost(message, optional, tag = "2")]
    pub ec_p256_public_key: Option<EcP256PublicKey>,
}

/// cryptauth `GenericPublicKey.EcP256PublicKey`: `{1: x, 2: y}` (unsigned
/// 32-byte big-endian coordinates, no leading zero).
#[derive(Clone, PartialEq, Message)]
pub struct EcP256PublicKey {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub x: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub y: Option<Vec<u8>>,
}

pub mod generic_public_key {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum Type {
        EcP256 = 1,
        Rsa2048 = 2,
        Rsa4096 = 3,
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct DeviceToDeviceMessage {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub message: Option<Vec<u8>>,
    #[prost(int32, optional, tag = "2")]
    pub sequence_number: Option<i32>,
}

/// securemessage SecureMessage envelope used by D2DCryptoOps signcrypt.
#[derive(Clone, PartialEq, Message)]
pub struct SecureMessage {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub header_and_body: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub signature: Option<Vec<u8>>,
}

/// RawSecureMessage wire packing (header||body before signing).
#[derive(Clone, PartialEq, Message)]
pub struct HeaderAndBody {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub header: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub body: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Header {
    #[prost(enumeration = "SigScheme", optional, tag = "1")]
    pub signature_scheme: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub verification_key_id: Option<Vec<u8>>,
    #[prost(enumeration = "EncScheme", optional, tag = "3")]
    pub encryption_scheme: Option<i32>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub decryption_key_id: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub public_metadata: Option<Vec<u8>>,
    #[prost(uint32, optional, tag = "6")]
    pub associated_data_length: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "7")]
    pub iv: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum SigScheme {
    HmacSha256 = 1,
    EcdsaP256Sha256 = 2,
    Rsa2048Sha256 = 3,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum EncScheme {
    None = 1,
    Aes256Cbc = 2,
}

#[derive(Clone, PartialEq, Message)]
pub struct GcmMetadata {
    #[prost(uint32, optional, tag = "1")]
    pub type_field: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub version: Option<u32>,
}

// --- LinkSwitch LinkInfo plane (PROTOCOL.md §7; prost tags from the
// interconnect protobuf schemas recovered in PROTOCOL.md).

#[derive(Clone, PartialEq, prost::Message)]
pub struct LinkInfoPayloadHeader {
    #[prost(uint32, optional, tag = "1")]
    pub version: Option<u32>,
    #[prost(int32, optional, tag = "2")]
    pub link_type: Option<i32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct CompactLinkStatus {
    #[prost(uint32, optional, tag = "1")]
    pub bitmap: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub ip: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub mac: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct LinkStatus {
    #[prost(uint32, optional, tag = "1")]
    pub state: Option<u32>,
    #[prost(uint32, optional, tag = "2")]
    pub freq: Option<u32>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub mac: Option<Vec<u8>>,
    #[prost(string, optional, tag = "4")]
    pub dev_name: Option<String>,
    #[prost(string, optional, tag = "5")]
    pub ip: Option<String>,
    #[prost(uint32, optional, tag = "6")]
    pub prefix_len: Option<u32>,
    #[prost(string, optional, tag = "7")]
    pub gateway: Option<String>,
    #[prost(uint32, optional, tag = "11")]
    pub field11: Option<u32>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct LinkInfoPayloadData {
    #[prost(message, optional, tag = "1")]
    pub status: Option<LinkStatus>,
    #[prost(message, repeated, tag = "2")]
    pub compact_links: Vec<CompactLinkStatus>,
    #[prost(string, optional, tag = "3")]
    pub gateway: Option<String>,
    #[prost(bool, optional, tag = "4")]
    pub bool4: Option<bool>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct LinkInfoPublish {
    #[prost(uint32, optional, tag = "1")]
    pub seq: Option<u32>,
    #[prost(uint64, optional, tag = "2")]
    pub timestamp: Option<u64>,
    #[prost(message, optional, tag = "3")]
    pub header: Option<LinkInfoPayloadHeader>,
    #[prost(message, optional, tag = "4")]
    pub data: Option<LinkInfoPayloadData>,
}
