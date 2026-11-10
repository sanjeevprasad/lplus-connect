//! SCP (secure connection pairing) wire messages, as spoken over the cpbus
//! channel `active_connection` (namespace `com.heytap.accessory`).
//!
//! Wire: each message travels in a cpbus data frame `[40 30][len u16be]
//! [type u16be][seq u16be][7b || protobuf]`. `ScpMessage` selects the
//! protocol step; `q` is the hello envelope; `SyncData` carries the device
//! advertisement. Field numbers verified against the live phone build
//! (`OnePlus/CPH2745IN:17/CP2A.260605.016`, `com.heytap.accessory`
//! AccessoryFramework.apk sha256 `e6dc3c55c710850a…778f3b51`): generated
//! protobuf-lite classes `com.oplus.pantaconnect.connection.scp.{f0,q,
//! ScpSyncData,d0}` declare MSGTYPE=1/DATA=2; SEQUENCENO=1/CHANNEL=2/
//! NAMESPACE=3/SERVICENAME=4; DEVICENAME=1..LINKTYPE=7; DEVICEID=1/KSC=2/
//! KSCALIAS=3, and `ScpSyncData.LinkType` = P2P,WLAN,CLOUD,USB,SPP (0–4).

use prost::Message;

/// ScpMessageType values.
pub const MSG_HELLO: u32 = 0;
pub const MSG_SYNC: u32 = 1;
pub const MSG_SYNC_SECURE: u32 = 2;
pub const MSG_UKEY2_INIT: u32 = 3;
pub const MSG_UKEY2_FINISHED: u32 = 4;
/// Wire value is 65535, not the Java ordinal 8
/// (`new ScpMessageType("DISCONNECT", 8, 65535)`).
pub const MSG_DISCONNECT: u32 = 65535;

/// ScpKeyType values.
pub const KEY_EMPTY: u32 = 0;
pub const KEY_UKEY2: u32 = 1;
pub const KEY_OOBKEY: u32 = 2;
pub const KEY_BOTH: u32 = 3;

/// Device type codes (sdp/1 DT and ScpSyncData.deviceType).
pub const DEVICE_PC: u32 = 6;

/// `ScpSyncData.LinkType` proto enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum LinkType {
    P2p = 0,
    Wlan = 1,
    Cloud = 2,
    Usb = 3,
    Spp = 4,
}

/// `f0`: SCP envelope carried as the cpbus payload after the `7b` marker.
#[derive(Clone, PartialEq, Message)]
pub struct ScpMessage {
    /// Optional so a HELLO (msg_type=0) is still force-emitted; the phone drops
    /// a frame whose msg_type field is absent.
    #[prost(uint32, tag = "1", optional)]
    pub msg_type: Option<u32>,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

/// `q`: hello payload with channel routing and sequence number. The peer
/// requires strictly increasing `sequence_no` (it tracks last+1).
#[derive(Clone, PartialEq, Message)]
pub struct Hello {
    #[prost(uint32, tag = "1")]
    pub sequence_no: u32,
    #[prost(string, tag = "2")]
    pub channel: String,
    #[prost(string, tag = "3")]
    pub namespace: String,
    #[prost(string, tag = "4")]
    pub service_name: String,
}

/// `ScpSyncData`: device advertisement sent right after HELLO.
#[derive(Clone, PartialEq, Message)]
pub struct SyncData {
    #[prost(string, tag = "1")]
    pub device_name: String,
    /// Real `ScpSyncData`: key_type/device_type/active_trigger_mode are proto
    /// `int` (varint), NOT strings (the decompiled getters return `int`).
    #[prost(int32, tag = "2")]
    pub key_type: i32,
    /// Real `ScpSyncData`: proto3 `optional bytes`; the phone's own SYNC
    /// omits fields 3 and 7 entirely and its old parser rejects an
    /// unexpected `1a`-typed field there (`invalid tag (zero)` at stage
    /// ReadSync), so omit unless explicitly set.
    #[prost(bytes = "vec", optional, tag = "3")]
    pub custom_data: Option<Vec<u8>>,
    #[prost(int32, tag = "4")]
    pub device_type: i32,
    #[prost(int32, tag = "5")]
    pub active_trigger_mode: i32,
    #[prost(string, tag = "6")]
    pub model_id: String,
    /// proto `LinkType` enum: P2P=0, WLAN=1, CLOUD=2, USB=3, SPP=4. Optional
    /// for the same reason as `custom_data`.
    #[prost(enumeration = "LinkType", optional, tag = "7")]
    pub link_type: Option<i32>,
}

/// cpbus Packet token prefix after the `7b` marker: field-1 varint 2477,
/// stable across all frames of an engine pair (seen in every observed frame).
pub const TOKEN: [u8; 3] = [0x08, 0xad, 0x12];

/// Extract the `q` routing header (ScpMessage field 2) from a cpbus payload
/// (`7b || TOKEN || ...`), if present. Used to echo the peer's sequenceNo.
pub fn q_from_payload(payload: &[u8]) -> Option<Hello> {
    let b = payload.strip_prefix(&[0x7b])?;
    let b = b.strip_prefix(&TOKEN).unwrap_or(b);
    // The peer's HELLO is `ScpMessage { 2: q }` with msg_type omitted; let
    // prost do the field-2 framing. SYNC payloads start with field 1, so
    // the guard rejects them just as the hand-rolled scan did.
    if b.first() != Some(&0x12) {
        return None;
    }
    let sm = ScpMessage::decode(b).ok()?;
    if sm.msg_type.is_some() {
        return None;
    }
    Hello::decode(sm.data.as_slice()).ok()
}

/// HELLO frame with an explicit sequence number (echo the peer's).
/// Build our HELLO frame. `server` selects the header role:
/// `true` → `isServer=1` (`0x34`), delivered to the phone's CLIENT-side
/// ScpItem on the socket where the phone dialed us (its `waiting4Hello`
/// awaits our HELLO); `false` → `0x30`, the client-role frames for the
/// socket where we dialed out and the phone's SERVER item awaits our HELLO
/// (`scp server, hello req is null` until it arrives).
pub fn hello_frame_ex(seq: u32, channel: &str, namespace: &str, server: bool) -> Vec<u8> {
    let hello = ScpMessage {
        // Force-emit msg_type=HELLO(0): prost omits a plain 0, and the phone's
        // parser drops a frame whose msg_type field is absent (the server then
        // never leaves waiting4Hello).
        msg_type: Some(MSG_HELLO),
        data: Hello {
            sequence_no: seq,
            channel: channel.into(),
            namespace: namespace.into(),
            service_name: String::new(),
        }
        .encode_to_vec(),
    };
    let mut v = TOKEN.to_vec();
    v.extend_from_slice(&hello.encode_to_vec());
    if server {
        frame_server(2, 0, &v)
    } else {
        frame_t(2, 0, &v)
    }
}

/// [`hello_frame_ex`] with `server = true`.
pub fn hello_frame(seq: u32, channel: &str, namespace: &str) -> Vec<u8> {
    hello_frame_ex(seq, channel, namespace, true)
}

/// SYNC frame with an explicit sequence number. Per `RealScpProtocol.l`, the
/// wire envelope is `ScpWrapData{ msg_type, data }` = `{1:msg_type, 2:data}`
/// (mirrors the phone's own HELLO which is `token || {2:q}` with msg_type
/// omitted). So SYNC data sits at field 2, NOT alongside a separate q — the
/// earlier `ScpMessageQ{1,2:q,3:data}` put q where data belongs and the phone
/// parsed q-bytes as SyncData ("sync req is null").
pub fn sync_frame_ex(
    _seq: u32,
    _channel: &str,
    _namespace: &str,
    device_name: &str,
    model_id: &str,
    server: bool,
    key_type: i32,
) -> Vec<u8> {
    let sync = ScpMessage {
        msg_type: Some(MSG_SYNC),
        data: SyncData {
            device_name: device_name.into(),
            key_type,
            custom_data: None,
            device_type: DEVICE_PC as i32,
            active_trigger_mode: 1,
            model_id: model_id.into(),
            link_type: None,
        }
        .encode_to_vec(),
    };
    let mut v = TOKEN.to_vec();
    v.extend_from_slice(&sync.encode_to_vec());
    if server {
        frame_server(0, 0, &v)
    } else {
        frame_t(0, 0, &v)
    }
}

/// [`sync_frame_ex`] with `server = true` and keyType BOTH.
pub fn sync_frame(
    seq: u32,
    channel: &str,
    namespace: &str,
    device_name: &str,
    model_id: &str,
) -> Vec<u8> {
    sync_frame_ex(
        seq,
        channel,
        namespace,
        device_name,
        model_id,
        true,
        KEY_BOTH as i32,
    )
}

/// Split a TCP read into individual cpbus frames:
/// `[40][flags][len u16be][ftype u16][fseq u16][token 4][body len]`,
/// total `12 + len` bytes. The peer transmits OPEN+SYNC back-to-back and
/// they coalesce into one `read()`; a single-frame parser silently drops
/// every frame after the first (observed: their SYNC never answered,
/// `syn ack null`). Returns byte ranges of each complete frame; a trailing
/// partial frame is left for the next read (caller re-buffers).
pub fn split_frames(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 12 <= buf.len() {
        if buf[pos] != 0x40 {
            break;
        }
        let len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let end = pos + 12 + len;
        if end > buf.len() || len < 4 {
            break;
        }
        out.push((pos, end));
        pos = end;
    }
    out
}

/// Wrap `ScpMessage{msg_type,data}` (token-prefixed) in a server-role frame.
pub fn msg_frame(mt: u32, data: Vec<u8>) -> Vec<u8> {
    let sm = ScpMessage {
        msg_type: Some(mt),
        data,
    };
    let mut v = TOKEN.to_vec();
    v.extend_from_slice(&sm.encode_to_vec());
    frame_server(2, 0, &v)
}

/// Post-ukey2 encrypted frame: the phone's ScpAddressing AES-256-GCMs the
/// entire `ScpWrapData` bytes and puts the ciphertext directly after the
/// token (no second ScpWrapData), with the encrypted header bit (0x08) set.
/// See `d2d::cryptor_seal`; frame flags = isServer `0x34` | encrypted.
pub fn msg_frame_sealed(sealed: Vec<u8>) -> Vec<u8> {
    let mut v = TOKEN.to_vec();
    v.extend_from_slice(&sealed);
    let mut fr = frame_server(2, 0, &v);
    // Routed by isServer=1 (0x3C): their i()/receiveSyncSecure consumes it
    // (0x38 is not picked up there at all -> their 5 s timeout).
    fr[1] = 0x3c;
    fr
}

/// `ScpSyncSecure` (phone `connection/scp/d0`): `{1: deviceId string,
/// 2: ksc bytes, 3: kscAlias bytes}` — field numbers from generated
/// `*_FIELD_NUMBER` constants.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SyncSecure {
    #[prost(string, optional, tag = "1")]
    pub device_id: Option<String>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub ksc: Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub ksc_alias: Option<Vec<u8>>,
}

/// Server reply to the peer's SYNC_SECURE (`e.java:57` → `n()` `d.java:729`):
/// own PDID as deviceId, ksc/kscAlias byte-exact echo of the peer's.
pub fn sync_secure_echo(
    peer_d0: &[u8],
    our_device_id: &str,
) -> Result<Vec<u8>, prost::DecodeError> {
    let peer = SyncSecure::decode(peer_d0)?;
    let echo = SyncSecure {
        device_id: Some(our_device_id.into()),
        ksc: peer.ksc,
        ksc_alias: peer.ksc_alias,
    };
    Ok(msg_frame(2, echo.encode_to_vec()))
}

/// Shared monotonic sequence base (wall-clock ms, positive int32).
pub fn now_base() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u32 & 0x7fff_ffff)
        .unwrap_or(1000)
}

/// Build the HELLO and SYNC cpbus payloads (`TOKEN || ScpMessage`).
pub fn hello_sync_bytes(
    channel: &str,
    namespace: &str,
    device_name: &str,
    model_id: &str,
) -> (Vec<u8>, Vec<u8>) {
    let base = now_base();
    let q = Hello {
        sequence_no: base,
        channel: channel.into(),
        namespace: namespace.into(),
        service_name: String::new(),
    };
    let hello = ScpMessage {
        msg_type: Some(MSG_HELLO),
        data: q.clone().encode_to_vec(),
    };
    let sync = ScpMessage {
        msg_type: Some(MSG_SYNC),
        data: SyncData {
            device_name: device_name.into(),
            key_type: KEY_BOTH as i32,
            custom_data: None,
            device_type: DEVICE_PC as i32,
            active_trigger_mode: 1,
            model_id: model_id.into(),
            link_type: None,
        }
        .encode_to_vec(),
    };
    let wrap = |m: ScpMessage| {
        let mut v = TOKEN.to_vec();
        v.extend_from_slice(&m.encode_to_vec());
        v
    };
    let mut syncv = TOKEN.to_vec();
    syncv.extend_from_slice(&sync.encode_to_vec());
    (wrap(hello), syncv)
}

/// Wrap a protobuf payload in the cpbus data frame (`7b` marker + header).
pub fn frame(seq: u16, protobuf: &[u8]) -> Vec<u8> {
    frame_t(1, seq, protobuf)
}

/// As [`frame_t`], with the `isServer` header bit (byte1 = `0x34`).
///
/// The phone routes inbound frames to the ScpItem registered under
/// `agentAddress + !isServer`. The phone dials us as the SCP *client*
/// (`b.java` sends HELLO/SYNC itself and awaits ours), so frames we emit on
/// the accepted socket must set `isServer=1` to reach the phone's client-side
/// item; `0x30` frames are delivered to the phone's server item instead
/// (observed: our HELLOs poisoned the server leg's `receiveSync` —
/// `msgType[0]` — while the client leg timed out after 5 s).
pub fn frame_server(ftype: u16, seq: u16, protobuf: &[u8]) -> Vec<u8> {
    let mut fr = frame_t(ftype, seq, protobuf);
    fr[1] = 0x34;
    fr
}

/// As [`frame`], with an explicit frame type (0x0002 = open request,
/// 0x0001 = payload/data).
pub fn frame_t(ftype: u16, seq: u16, protobuf: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(protobuf.len() + 1);
    body.push(0x7b);
    body.extend_from_slice(protobuf);
    let mut fr = Vec::with_capacity(body.len() + 8);
    fr.extend_from_slice(&[0x40, 0x30]);
    // Their rule (confirmed on their own frames): len counts bytes after the
    // 8-byte header minus the 7b marker and the 3-byte token prefix.
    fr.extend_from_slice(&((body.len() - 4) as u16).to_be_bytes());
    fr.extend_from_slice(&ftype.to_be_bytes());
    fr.extend_from_slice(&seq.to_be_bytes());
    fr.extend_from_slice(&body);
    fr
}

/// Human-readable ScpMessageType name.
pub fn msg_name(t: u32) -> &'static str {
    match t {
        MSG_HELLO => "HELLO",
        MSG_SYNC => "SYNC",
        MSG_SYNC_SECURE => "SYNC_SECURE",
        MSG_UKEY2_INIT => "UKEY2_INIT",
        MSG_UKEY2_FINISHED => "UKEY2_FINISHED", // gitleaks:allow (proto name, not a key)
        5 => "OOBKEY_BUILD",
        6 => "OOBKEY_PROCESS",
        7 => "OOBKEY_FINISHED",
        8 => "DISCONNECT",
        MSG_DISCONNECT => "DISCONNECT",
        _ => "?",
    }
}

/// Decode a cpbus payload (`7b || TOKEN || ScpMessage`) as an SCP message.
pub fn decode_payload(payload: &[u8]) -> Option<ScpMessage> {
    let b = payload.strip_prefix(&[0x7b])?;
    let b = b.strip_prefix(&TOKEN).unwrap_or(b);
    ScpMessage::decode(b)
        .ok()
        .filter(|m| matches!(m.msg_type.unwrap_or(0), 0..=8 | 65535))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_encodes_expected_fields() {
        let (hello, _sync) = hello_sync_bytes("c", "n", "d", "m");
        assert_eq!(&hello[..3], &TOKEN);
        let m = ScpMessage::decode(&hello[3..]).unwrap();
        assert_eq!(m.msg_type, Some(MSG_HELLO));
        let h = Hello::decode(m.data.as_slice()).unwrap();
        assert_eq!(h.channel, "c");
        assert_eq!(h.namespace, "n");
    }

    #[test]
    fn sync_roundtrips_device_identity() {
        let (h, sync) = hello_sync_bytes("c", "n", "L+ PC", "M");
        let hm = ScpMessage::decode(&h[3..]).unwrap();
        let _hq = Hello::decode(hm.data.as_slice()).unwrap();
        let m = ScpMessage::decode(&sync[3..]).unwrap();
        assert_eq!(m.msg_type, Some(MSG_SYNC));
        let s = SyncData::decode(m.data.as_slice()).unwrap();
        assert_eq!(s.device_name, "L+ PC");
        assert_eq!(s.key_type, KEY_BOTH as i32);
        assert_eq!(s.device_type, DEVICE_PC as i32);
        assert_eq!(s.link_type, None);
        assert_eq!(s.custom_data, None);
    }

    #[test]
    fn frame_has_len_excluding_token_prefix() {
        let proto = [0x08u8, 0xad, 0x12, 0x00]; // TOKEN || msg
        let f = frame(7, &proto);
        assert_eq!(&f[0..2], &[0x40, 0x30]);
        assert_eq!(&f[2..4], &[0x00, 0x01]); // body(5) - 4
        assert_eq!(&f[4..6], &[0x00, 0x01]); // default data type
        assert_eq!(&f[6..8], &[0x00, 0x07]);
        assert_eq!(f[8], 0x7b);
        assert_eq!(&f[9..12], &TOKEN);
    }

    #[test]
    fn split_frames_separates_coalesced_messages() {
        let h = hello_frame_ex(1, "active_connection", "com.heytap.accessory", true);
        let s = sync_frame_ex(
            2,
            "active_connection",
            "com.heytap.accessory",
            "L+ PC",
            "M",
            true,
            1,
        );
        let mut buf = h.clone();
        buf.extend_from_slice(&s);
        let frames = split_frames(&buf);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], (0, h.len()));
        assert_eq!(frames[1], (h.len(), buf.len()));
        // Trailing partial frame waits for the next read.
        buf.extend_from_slice(&h[..h.len() - 3]);
        assert_eq!(split_frames(&buf).len(), 2);
        // Each split frame decodes to its own message type.
        let (a, b) = (frames[0], frames[1]);
        let ma = ScpMessage::decode(&buf[a.0 + 9..a.1]).unwrap();
        let mb = ScpMessage::decode(&buf[b.0 + 9..b.1]).unwrap();
        assert_eq!(ma.msg_type, Some(MSG_HELLO));
        assert_eq!(mb.msg_type, Some(MSG_SYNC));
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    #[test]
    fn mt4_frame_is_wellformed() {
        let f = msg_frame(4, vec![]);
        // header(8) + 7b + token(3) + ScpMessage{4} = 8+1+3+2 = 14
        assert_eq!(f.len(), 14, "{f:02x?}");
        assert_eq!(&f[..2], &[0x40, 0x34]);
        assert_eq!(u16::from_be_bytes([f[2], f[3]]) as usize, f.len() - 12);
        assert_eq!(&f[8..14], &[0x7b, 0x08, 0xad, 0x12, 0x08, 0x04]);
    }
}
