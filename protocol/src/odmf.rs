//! ODMF/NearX transport-bus JSON frames (`[u16BE len]{json}`) and the
//! identity-auth handshake shapes (odmf.jar `BTTransferThread` /
//! `SigIdentityAuthHelper`). Pure frames — sockets, keepalive pacing and
//! the GCM lanes live in the `lplus` binary (`src/wfd_sink.rs`).

use serde::{Deserialize, Serialize};

/// `{"cmd":"send","msg":"<inner json>"}` — odmfr/odmfb.java CMD_SEND → odmfc(msg).
#[derive(Debug, Deserialize)]
pub struct Envelope {
    pub cmd: String,
    #[serde(default)]
    pub msg: String,
}

/// SDP blob exchanged by `offer`/`answer` frames. A struct (not a newtype
/// `String`) so the internally tagged `type` field can merge into it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sdp {
    pub sdp: String,
}

/// ICE candidate string carried by `candidate` frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
}

/// SDP/candidate signaling frames (internally tagged on `type`); anything
/// else — including tagless bus frames — is `Other` and ignored here.
/// `Offer` is the PC→phone direction (we create it); an inbound `offer`
/// still lands in the same variant and stays ignored.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Signaled {
    Offer(Sdp),
    Answer(Sdp),
    Candidate(IceCandidate),
    #[serde(other)]
    Other,
}

/// Frames on the JSON transport bus (nearx/tbus, reverse-engineered from
/// BTTransferThread). Only `ping` needs an answer; everything else stays
/// unanswered (capture). Live 2026-11-09 keepalives are exactly
/// `{"cmd":"ping"}`, so a tagged parse is safe where the old substring
/// sniff would also have ponged frames merely *mentioning* "ping".
#[derive(Debug, Deserialize)]
#[serde(tag = "cmd")]
pub enum BusCmd {
    #[serde(rename = "ping")]
    Ping,
    #[serde(other)]
    Other,
}

/// Keepalive reply table: ping → pong. Unknown frames unanswered (capture).
pub fn json_reply(json: &str) -> Option<String> {
    matches!(serde_json::from_str::<BusCmd>(json), Ok(BusCmd::Ping))
        .then(|| "{\"cmd\":\"pong\"}".to_string())
}

/// PC → phone answer to the encrypted `PairRequest` (odmfr/odmfc.java
/// `notifyClientPairSuccess`), sealed into an encrypted frame. The tag
/// first, then name/id/bus — the key order the live engine accepted from
/// the hand-built string.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "cmd")]
pub enum PairMsg {
    #[serde(rename = "PairSuccess")]
    PairSuccess {
        remote_user_name: String,
        remote_user_id: String,
        remote_transportbus_id: String,
    },
}

/// Outbound counterpart of [`Envelope`]: `{"cmd":"send","msg":…}` —
/// odmfs/odmfa.java `odmfb(String)` only dispatches nested SDP/candidate
/// JSON through this wrapper (`onSocketMessage` case CMD_SEND → odmfc(msg)).
#[derive(Debug, Serialize)]
pub struct SendEnvelope<'a> {
    pub cmd: &'static str,
    pub msg: &'a str,
}

/// Datachannel JSON from the phone (q2/i.java `p(b)`); we only need the
/// RTSP-style `COMMAND` it carries — width/height/fps/rotatesWithContent
/// and friends stay unparsed.
#[derive(Debug, Deserialize)]
pub struct ChannelMsg<'a> {
    #[serde(rename = "COMMAND", default)]
    pub command: Option<&'a str>,
}

/// PC → phone D2D CHANNEL consult reply (the phone gates screen capture
/// until this lands): `COMMAND` + our sink geometry. Key order matches the
/// frame the phone accepted live.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsultReply {
    #[serde(rename = "COMMAND")]
    pub command: String,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub fold_rotates_with_content: bool,
    pub rotates_with_content: bool,
}

/// `ODMF_AUTH_FILE` as pushed by `odmf_push.py` (`rsp_odmf_key` payload);
/// only `id` is mandatory — `auth_version` falls back to 1 like the old
/// manual `as_i64().unwrap_or(1)` peek.
#[derive(Debug, Deserialize)]
pub struct AuthInfoFile {
    pub id: String,
    #[serde(default)]
    pub auth_version: Option<i64>,
}

/// Phone `OdmfAuthResponse` (SigIdentityAuthHelper): auth fields either
/// nested as an escaped JSON string under `auth_info` or flat on the frame.
/// The `local_*` identities feed the cross-pair `PEERS` registry in the
/// binary and the AuthSuccess `remote_transportbus_id` echo.
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    #[serde(default)]
    pub auth_info: Option<String>,
    #[serde(flatten)]
    pub fields: AuthFields,
    #[serde(default)]
    pub local_transportbus_id: Option<String>,
    #[serde(default)]
    pub local_user_name: Option<String>,
    #[serde(default)]
    pub local_user_id: Option<String>,
}

/// The SigIdentityAuthHelper auth fields themselves (`NearFieldAuthInfo`
/// wire shape); every one is optional here so a partial frame reaches the
/// missing-field warn instead of failing the whole parse.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct AuthFields {
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub iv: Option<String>,
    #[serde(default)]
    pub encrypt_cipher: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    /// Peer-negotiated auth version; echoed into our AuthSuccess when the
    /// frame carries it (old `as_i64().unwrap_or(self.auth_version)` peek).
    #[serde(default)]
    pub auth_version: Option<i64>,
}

impl AuthFields {
    /// First required auth field the phone omitted, in the order the old
    /// manual `src.get(k).is_none()` loop checked them.
    pub fn missing_field_name(&self) -> Option<&'static str> {
        [
            ("public_key", &self.public_key),
            ("iv", &self.iv),
            ("encrypt_cipher", &self.encrypt_cipher),
            ("timestamp", &self.timestamp),
        ]
        .into_iter()
        .find(|(_, v)| v.is_none())
        .map(|(k, _)| k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_answers_only_tagged_ping() {
        assert_eq!(
            json_reply(
                r#"{"cmd":"ping"}").as_deref(), Some("{\"cmd\":\"pong\"}"));
        // tagless mention of ping must not pong (tagged parse, not sniff)
        assert_eq!(json_reply(r#"{"a":"ping"}"), None);
        assert_eq!(json_reply(r#"{"cmd":"pair_info_flag","a":1}"#
            ),
            None
        );
    }

    #[test]
    fn envelope_only_unwraps_nonempty_send() {
        let e: Envelope =
            serde_json::from_str(r#"{"cmd":"send","msg":"{\"type\":\"answer\"}"}"#).unwrap();
        assert_eq!(e.cmd, "send");
        assert_eq!(e.msg, "{\"type\":\"answer\"}");
        let no_msg: Envelope = serde_json::from_str(r#"{"cmd":"send"}"#).unwrap();
        assert!(no_msg.msg.is_empty());
    }

    #[test]
    fn signaled_classifies_answer_candidate_and_other() {
        let a: Signaled = serde_json::from_str(r#"{"type":"answer","sdp":"v=0"}"#).unwrap();
        assert!(matches!(a, Signaled::Answer(Sdp { sdp }) if sdp == "v=0"));
        let c: Signaled =
            serde_json::from_str(r#"{"type":"candidate","candidate":"candidate:1"}"#).unwrap();
        assert!(matches!(c, Signaled::Candidate(IceCandidate { .. })));
        let o: Signaled = serde_json::from_str(r#"{"type":"offer","sdp":"v=0"}"#).unwrap();
        assert!(matches!(o, Signaled::Offer(..)));
        let u: Signaled = serde_json::from_str(r#"{"type":"unknown"}"#).unwrap();
        assert!(matches!(u, Signaled::Other));
        // tagless bus frames must not match at all (dispatch ignores them)
        assert!(serde_json::from_str::<Signaled>(r#"{"cmd":"ping"}"#).is_err());
    }

    #[test]
    fn outbound_frames_match_captured_wire() {
        let inner = serde_json::to_string(&Signaled::Offer(Sdp { sdp: "v=0".into() })).unwrap();
        assert_eq!(inner, r#"{"type":"offer","sdp":"v=0"}"#);
        let env = serde_json::to_string(&SendEnvelope {
            cmd: "send",
            msg: &inner,
        })
        .unwrap();
        assert_eq!(
            env,
            r#"{"cmd":"send","msg":"{\"type\":\"offer\",\"sdp\":\"v=0\"}"}"#
        );
        let consult = serde_json::to_string(&ConsultReply {
            command: "SET_PARAMETER".into(),
            width: 1272,
            height: 2772,
            fps: 30,
            fold_rotates_with_content: false,
            rotates_with_content: false,
        })
        .unwrap();
        assert_eq!(
            consult,
            r#"{"COMMAND":"SET_PARAMETER","width":1272,"height":2772,"fps":30,"foldRotatesWithContent":false,"rotatesWithContent":false}"#
        );
    }

    #[test]
    fn pair_success_wire_shape_matches_handbuilt_string() {
        let m = PairMsg::PairSuccess {
            remote_user_name: "heycast_odmf".into(),
            remote_user_id: "u1".into(),
            remote_transportbus_id: "0000006734474".into(),
        };
        assert_eq!(
            serde_json::to_string(&m).unwrap(),
            "{\"cmd\":\"PairSuccess\",\"remote_user_name\":\"heycast_odmf\",\"remote_user_id\":\"u1\",\"remote_transportbus_id\":\"0000006734474\"}"
        );
    }

    #[test]
    fn auth_fields_report_missing_in_check_order() {
        let full: AuthFields = serde_json::from_str(
            r#"{"public_key":"P","iv":"I","encrypt_cipher":"C","timestamp":"T","auth_version":1}"#,
        )
        .unwrap();
        assert_eq!(full.missing_field_name(), None);
        let no_iv: AuthFields =
            serde_json::from_str(r#"{"public_key":"P","timestamp":"T","encrypt_cipher":"C"}"#)
                .unwrap();
        assert_eq!(no_iv.missing_field_name(), Some("iv"));
        let empty: AuthFields = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.missing_field_name(), Some("public_key"));
    }

    #[test]
    fn auth_response_accepts_flat_and_local_identities() {
        let r: AuthResponse = serde_json::from_str(
            r#"{"cmd":"OdmfAuthResponse","public_key":"P","iv":"I","encrypt_cipher":"C","timestamp":"T","auth_version":1,"local_transportbus_id":"0000006734474","local_user_name":"heycast_odmf","local_user_id":"u"}"#,
        )
        .unwrap();
        assert_eq!(r.auth_info, None);
        assert_eq!(r.fields.missing_field_name(), None);
        assert_eq!(r.fields.auth_version, Some(1));
        assert_eq!(r.local_transportbus_id.as_deref(), Some("0000006734474"));
        assert_eq!(r.local_user_name.as_deref(), Some("heycast_odmf"));
    }
}
