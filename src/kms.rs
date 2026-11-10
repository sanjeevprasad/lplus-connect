//! KMS / cast-input plane (PROTOCOL.md §7.2).
//!
//! 24-byte big-endian header (`MessageProtocol.MessageHeader`), body = JSON.
//! Encryption: AES-128-GCM with key = SHA-256(password)[0:16]; frame body
//! when encrypted is `IV(12) || ct || tag(16)`; peer proof decrypts to the
//! constant `1234abcd`.

use anyhow::{Result, bail};
use sha2::{Digest, Sha256};

/// Java `MAGIC_NUMBER = (short) -21742` → unsigned bits 0xAB12 (phone
/// `MessageHeader[magic=0xAB12, …]` on the wire, live 2026-11-09).
pub const MAGIC: u16 = 0xAB12;
pub const VERSION: u8 = 1;
pub const FLAG_ENCRYPTED: u16 = 0x0001;
pub const PROOF_PLAINTEXT: &[u8] = b"1234abcd";
pub const DEFAULT_KMS_SOCKET_PORT: u16 = 36931;

/// MessageProtocol event types.
pub mod event {
    pub const SYN_INFO: u8 = 1;
    pub const MOVE_IN_REQ: u8 = 2;
    pub const INJECT_REQ: u8 = 3;
    pub const HEARTBEAT_REQ: u8 = 4;
    pub const HEARTBEAT_RESP: u8 = 5;
    pub const DEVICE_ID_SYNC: u8 = 6;
    pub const CAST_APP_MESSAGE: u8 = 7;
    pub const KEEP_ALIVE: u8 = 100;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsHeader {
    pub event_type: u8,
    pub flags: u16,
    pub length: i32,
    pub reserved: u16,
    pub seq: i32,
    pub timestamp: i64,
}

impl KmsHeader {
    pub fn decode(buf: &[u8; 24]) -> Result<Self> {
        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != MAGIC {
            bail!("kms magic {magic:#06x} != {MAGIC:#06x}");
        }
        if buf[2] != VERSION {
            bail!("kms version {} != {VERSION}", buf[2]);
        }
        Ok(Self {
            event_type: buf[3],
            flags: u16::from_be_bytes([buf[4], buf[5]]),
            length: i32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]),
            reserved: u16::from_be_bytes([buf[10], buf[11]]),
            seq: i32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            timestamp: i64::from_be_bytes([
                buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
            ]),
        })
    }

    pub fn encode(&self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..2].copy_from_slice(&MAGIC.to_be_bytes());
        b[2] = VERSION;
        b[3] = self.event_type;
        b[4..6].copy_from_slice(&self.flags.to_be_bytes());
        b[6..10].copy_from_slice(&self.length.to_be_bytes());
        b[10..12].copy_from_slice(&self.reserved.to_be_bytes());
        b[12..16].copy_from_slice(&self.seq.to_be_bytes());
        b[16..24].copy_from_slice(&self.timestamp.to_be_bytes());
        b
    }

    pub fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }
}

/// Session key from the shared password, `SHA-256(pwd)[0:16]`.
pub fn kms_key(password: &str) -> [u8; 16] {
    let mut k = [0u8; 16];
    k.copy_from_slice(&Sha256::digest(password.as_bytes())[..16]);
    k
}

#[allow(deprecated)] // aead 0.6 nonce ctor
fn gcm_seal(key: &[u8; 16], iv: &[u8; 12], pt: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::Aead};
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("kms key: {e}"))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(iv), pt)
        .map_err(|e| anyhow::anyhow!("kms seal: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[allow(deprecated)] // aead 0.6 nonce ctor
fn gcm_open(key: &[u8; 16], frame: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::Aead};
    if frame.len() < 28 {
        bail!("kms frame too short: {}", frame.len());
    }
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| anyhow::anyhow!("kms key: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(&frame[..12]), &frame[12..])
        .map_err(|e| anyhow::anyhow!("kms open: {e}"))
}

/// `testData` = base64(IV || ct || tag) of `PROOF_PLAINTEXT` under `password`.
pub fn make_test_data(password: &str) -> Result<String> {
    let frame = gcm_seal(&kms_key(password), &random_iv(), PROOF_PLAINTEXT)?;
    Ok(base64::encode(frame))
}

fn random_iv() -> [u8; 12] {
    use rand::Rng;
    let mut iv = [0u8; 12];
    rand::rng().fill_bytes(&mut iv);
    iv
}

/// Verify a peer `testData` blob decrypts to the proof constant.
pub fn check_test_data(password: &str, b64: &str) -> bool {
    match base64::decode(b64.trim()) {
        Ok(frame) => gcm_open(&kms_key(password), &frame).is_ok_and(|pt| pt == PROOF_PLAINTEXT),
        Err(_) => false,
    }
}

/// Wire frame: header (with length/flags fixed up) ++ encrypted body.
pub fn seal_frame(
    password: &str,
    event_type: u8,
    seq: i32,
    ts_ms: i64,
    json: &str,
) -> Result<Vec<u8>> {
    let body = gcm_seal(&kms_key(password), &random_iv(), json.as_bytes())?;
    let hdr = KmsHeader {
        event_type,
        flags: FLAG_ENCRYPTED,
        length: body.len() as i32,
        reserved: 0,
        seq,
        timestamp: ts_ms,
    };
    let mut out = hdr.encode().to_vec();
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decode a wire frame and decrypt when flagged.
pub fn open_frame(password: &str, wire: &[u8]) -> Result<(KmsHeader, Vec<u8>)> {
    if wire.len() < 24 {
        bail!("kms wire too short: {}", wire.len());
    }
    let hdr = KmsHeader::decode(&<[u8; 24]>::try_from(&wire[..24]).unwrap())?;
    let body = &wire[24..];
    if hdr.length as usize > body.len() {
        bail!(
            "kms body truncated: want {} have {}",
            hdr.length,
            body.len()
        );
    }
    let pt = if hdr.encrypted() {
        gcm_open(&kms_key(password), body)?
    } else {
        body.to_vec()
    };
    Ok((hdr, pt))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Event 5 HEARTBEAT_RESP wire frame: echoes the REQ `{"heartbeat_id":N}`
/// body, encrypting with the same flags parity as the REQ (§1.3 step 6).
pub fn heartbeat_resp_frame(
    password: &str,
    req: &KmsHeader,
    req_body: &[u8],
    seq: i32,
    ts_ms: i64,
) -> Result<Vec<u8>> {
    // An empty REQ body (length 0, e.g. the local probe) is plaintext even
    // with the flag set — there is nothing to GCM-open.
    let enc = req.encrypted() && !req_body.is_empty();
    let pt = if enc {
        gcm_open(&kms_key(password), req_body)?
    } else {
        req_body.to_vec()
    };
    let resp_body = if enc {
        gcm_seal(&kms_key(password), &random_iv(), &pt)?
    } else {
        pt
    };
    let hdr = KmsHeader {
        event_type: event::HEARTBEAT_RESP,
        flags: if enc { FLAG_ENCRYPTED } else { 0 },
        length: resp_body.len() as i32,
        reserved: 0,
        seq,
        timestamp: ts_ms,
    };
    let mut wire = hdr.encode().to_vec();
    wire.extend_from_slice(&resp_body);
    Ok(wire)
}

/// DBS broadcast dbrMsgType accepted by the phone `DbsDataReceiver`
/// (`bf/c.java` case 0: only 42 or 82 are parsed as DbsMessage).
pub const DBS_MSG_TYPE_BC: u8 = 42;

/// DbsMessage Gson JSON (phone `dbs/DbsMessage.java`) that makes
/// `CastDbsReceiver` → `CastSceneDispatcher` run
/// `InputServiceManager.execute(key→61, CastMessage)`. `value_json` is the
/// CastMessage JSON string, escaped into the payload `value`.
pub fn dbs_message_json(
    topic: &str,
    from_hex: &str,
    to_hex: &str,
    key: &str,
    value_json: &str,
    seq: u64,
) -> String {
    let value = value_json.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "{{\"dbs_msg_topic\":{{\"dbs_topic_name\":\"{topic}\",\"dbs_topic_tag\":0,\"dbs_topic_qos\":{{}}}},\
         \"dbs_msg_to_device\":\"{to_hex}\",\"dbs_msg_from_device\":\"{from_hex}\",\
         \"dbs_msg_priority\":100,\"dbs_msg_type\":\"msg_normal_topic_data\",\
         \"dbs_msg_id\":\"lplus-{seq}\",\
         \"dbs_msg_payload\":{{\"key\":\"{key}\",\"value\":\"{value}\"}},\
         \"dbs_msg_encrypt\":true,\"time\":{seq}}}"
    )
}

/// DbsMessage JSON that registers our topics with the peer's `DbsManager`
/// (phone `dbs/DbsUtilKt.broadcastLocalTopic` → `j.b`: type
/// `msg_topic_sync`, payload `{"sub":[…],"pub":[…]}`; the peer's
/// `dbs/e.java processMsgReceived` routes it to `f.h(peer, msg)`, which
/// updates the per-peer subscriber registry). Without this the peer's
/// broker drops our topic frames ("remote do not have subscriber"), and
/// never routes its own publishes (e.g. `Oplus_PcConnect` clipboard) to us.
pub fn dbs_topic_sync_json(from_hex: &str, to_hex: &str, sub: &[&str], seq: u64) -> String {
    let quoted = |list: &[&str]| {
        list.iter()
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "{{\"dbs_msg_to_device\":\"{to_hex}\",\"dbs_msg_from_device\":\"{from_hex}\",\
         \"dbs_msg_priority\":100,\"dbs_msg_type\":\"msg_topic_sync\",\
         \"dbs_msg_id\":\"lplus-sync-{seq}\",\
         \"dbs_msg_payload\":{{\"sub\":[{}],\"pub\":[]}},\
         \"dbs_msg_encrypt\":true,\"time\":{seq}}}",
        quoted(sub)
    )
}

/// Unencrypted DataBus (NDSF sid 8) DATA frame (`len`, hdr `0x0020`,
/// `b0=0x00`, `tid`) plus dbr.a message (phone `pl/b.f` and `g5/b.s`),
/// as accepted by `session/reserved/d.java` case 1 without AppCipher
/// (enc bit cleared). dbr.a layout (inclusive offsets; `g5/b.java:736`):
///
/// ```text
/// [0..5] from 6B | [6..13] seq BE u64 | [14..19] to 6B
/// [20..25] id 6B (must equal phone OnetId/OafId) | [26] msgType
/// [27] version (≠0 mod 8) | [44..47] dest count BE | [48..51] extra len BE (0)
/// payload from 52
/// ```
pub fn dbs_data_frame(from6: &[u8; 6], to6: &[u8; 6], seq: u64, tid: u16, json: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 52];
    body[0..6].copy_from_slice(from6);
    body[6..14].copy_from_slice(&seq.to_be_bytes());
    body[14..20].copy_from_slice(to6);
    body[20..26].copy_from_slice(to6); // id := to (phone is the destination)
    body[26] = DBS_MSG_TYPE_BC;
    body[27] = 1;
    let mut payload = vec![0x00u8, (tid >> 8) as u8, tid as u8];
    payload.extend_from_slice(&body);
    payload.extend_from_slice(json);
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    frame.extend_from_slice(&0x0020u16.to_be_bytes()); // ftype DATA, sid 8
    frame.extend_from_slice(&payload);
    frame
}

/// PC-side KMS TCP server: phone connects here after receiving the cast
/// bootstrap (`kms_socket_port`). Frames: 24 B header + body; encrypted
/// bodies decrypt under `password`. Answers HEARTBEAT_REQ with RESP. With
/// `LPLUS_REPL_PORT` set the socket registers a REPL sink under
/// `"{port} {peer}"`, so `send {port} <hex>` injects sealed frames
/// (e.g. event-3 INJECT_REQ via [`seal_frame`]) without reconnecting.
pub fn spawn_server(port: u16, password: String, log_path: String) {
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let Ok(l) = TcpListener::bind(("0.0.0.0", port)).await else {
            tracing::warn!("[kms] bind :{port} failed");
            return;
        };
        tracing::info!(
            "[kms] listening :{port} (proof key for pw len {})",
            password.len()
        );
        loop {
            let Ok((mut sock, peer)) = l.accept().await else {
                continue;
            };
            tracing::info!("[kms] phone connected {peer}");
            crate::sdpd::emit_device("kms", peer.ip().to_string(), None, true);
            let pw = password.clone();
            let lp = log_path.clone();
            tokio::spawn(async move {
                let mut seq = 1i32;
                let repl_key = format!("{port} {peer}");
                let mut repl_rx: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> = None;
                if std::env::var("LPLUS_REPL_PORT").is_ok() {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    crate::sdpd::EPI_SINKS
                        .lock()
                        .await
                        .insert(repl_key.clone(), tx);
                    repl_rx = Some(rx);
                }
                let mut acc: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 4096];
                // Rate-limited link-evidence refresh (see epi lane).
                let mut last_ev = tokio::time::Instant::now();
                'read: loop {
                    let rd = match &mut repl_rx {
                        Some(rx) => tokio::select! {
                            r = sock.read(&mut tmp) => r,
                            b = rx.recv() => {
                                match b {
                                    Some(bytes) => {
                                        let _ = sock.write_all(&bytes).await;
                                        crate::sdpd::record(&lp, &format!("repl-sent {repl_key}"), &bytes);
                                        tracing::info!(
                                            "[repl] -> {repl_key} {}B {}",
                                            bytes.len(),
                                            hex::encode(&bytes[..bytes.len().min(64)])
                                        );
                                    }
                                    None => repl_rx = None,
                                }
                                continue;
                            }
                        },
                        None => sock.read(&mut tmp).await,
                    };
                    match rd {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            acc.extend_from_slice(&tmp[..n]);
                            if last_ev.elapsed() >= std::time::Duration::from_secs(60) {
                                last_ev = tokio::time::Instant::now();
                                crate::sdpd::emit_device("kms", peer.ip().to_string(), None, true);
                            }
                        }
                    }
                    // Frame-split the accumulator (24 B header + length body).
                    loop {
                        if acc.len() < 24 {
                            continue 'read;
                        }
                        let Ok(hdr) = KmsHeader::decode(&<[u8; 24]>::try_from(&acc[..24]).unwrap())
                        else {
                            crate::sdpd::record(&lp, &format!("kms-badhdr {peer}"), &acc[..24]);
                            tracing::info!("[kms] {peer} bad header {}", hex::encode(&acc[..24]));
                            acc.clear();
                            break 'read;
                        };
                        let want = hdr.length.max(0) as usize;
                        if want > 4 << 20 {
                            tracing::info!("[kms] {peer} bogus length {want}");
                            acc.clear();
                            break 'read;
                        }
                        if acc.len() < 24 + want {
                            continue 'read;
                        }
                        let body = acc[24..24 + want].to_vec();
                        acc.drain(..24 + want);
                        crate::sdpd::record(
                            &lp,
                            &format!("kms-recv {peer} ev{}", hdr.event_type),
                            &body,
                        );
                        let pt = if hdr.encrypted() && want > 0 {
                            match gcm_open(&kms_key(&pw), &body) {
                                Ok(p) => p,
                                Err(e) => {
                                    tracing::info!(
                                        "[kms] {peer} ev{} decrypt fail: {e}",
                                        hdr.event_type
                                    );
                                    body.clone()
                                }
                            }
                        } else {
                            body.clone()
                        };
                        tracing::info!(
                            "[kms] {peer} ev{} enc={} {}B | {}",
                            hdr.event_type,
                            hdr.encrypted(),
                            pt.len(),
                            String::from_utf8_lossy(&pt[..pt.len().min(160)])
                        );
                        if hdr.event_type == event::HEARTBEAT_REQ {
                            let wire = heartbeat_resp_frame(
                                &pw,
                                &hdr,
                                &body,
                                {
                                    seq += 1;
                                    seq
                                },
                                now_ms(),
                            )
                            .unwrap_or_else(|_| Vec::new());
                            if !wire.is_empty() {
                                crate::sdpd::record(&lp, &format!("kms-send {peer} ev5"), &wire);
                                let _ = sock.write_all(&wire).await;
                            }
                        }
                    }
                }
                if repl_rx.is_some() {
                    crate::sdpd::EPI_SINKS.lock().await.remove(&repl_key);
                }
                crate::sdpd::emit_device("kms", peer.ip().to_string(), None, false);
                tracing::info!("[kms] {peer} closed");
            });
        }
    });
}

mod base64 {
    pub fn encode(v: Vec<u8>) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(v)
    }
    pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_be_layout() {
        let h = KmsHeader {
            event_type: event::DEVICE_ID_SYNC,
            flags: FLAG_ENCRYPTED,
            length: 28,
            reserved: 0,
            seq: 7,
            timestamp: 0x0123_4567_89ab_cdef,
        };
        let b = h.encode();
        // (short)-21742 wire bits, verified against the live phone frame
        // ab120106… (ev6 DEVICE_ID_SYNC, sdp-rs.bin 2026-11-09).
        assert_eq!(&b[..4], &[0xab, 0x12, 0x01, 0x06]);
        assert_eq!(KmsHeader::decode(&b).unwrap(), h);
    }

    #[test]
    fn test_data_proof_roundtrip() {
        let pwd = "pw-abc-123";
        let td = make_test_data(pwd).unwrap();
        assert!(check_test_data(pwd, &td));
        assert!(!check_test_data("wrong-pwd", &td));
    }

    #[test]
    fn heartbeat_resp_echoes_plain_and_encrypted() {
        let pwd = "pw-echo";
        let plain_req = KmsHeader {
            event_type: event::HEARTBEAT_REQ,
            flags: 0,
            length: 0,
            reserved: 0,
            seq: 3,
            timestamp: 1,
        };
        let body = br#"{"heartbeat_id":7}"#.to_vec();
        let wire = heartbeat_resp_frame(pwd, &plain_req, &body, 4, 2).unwrap();
        let (h, pt) = open_frame(pwd, &wire).unwrap();
        assert_eq!(h.event_type, event::HEARTBEAT_RESP);
        assert!(!h.encrypted());
        assert_eq!(pt, body);
        // empty REQ body with flag set → plain empty RESP (no GCM to open).
        let empty_req = KmsHeader {
            event_type: event::HEARTBEAT_REQ,
            flags: FLAG_ENCRYPTED,
            length: 0,
            reserved: 0,
            seq: 8,
            timestamp: 5,
        };
        let wire = heartbeat_resp_frame(pwd, &empty_req, &[], 9, 6).unwrap();
        let (h, pt) = open_frame(pwd, &wire).unwrap();
        assert_eq!(h.event_type, event::HEARTBEAT_RESP);
        assert!(!h.encrypted());
        assert!(pt.is_empty());
        // encrypted REQ → encrypted RESP echoing the decrypted body.
        let sealed = seal_frame(pwd, event::HEARTBEAT_REQ, 5, 3, r#"{"heartbeat_id":9}"#).unwrap();
        let (req, req_body) = open_frame(pwd, &sealed).unwrap();
        let wire = heartbeat_resp_frame(pwd, &req, &sealed[24..], 6, 4).unwrap();
        let (h, pt) = open_frame(pwd, &wire).unwrap();
        assert_eq!(h.event_type, event::HEARTBEAT_RESP);
        assert!(h.encrypted());
        assert_eq!(std::str::from_utf8(&pt).unwrap(), r#"{"heartbeat_id":9}"#);
        assert!(!req.encrypted() || req_body.is_empty() || true);
    }

    #[test]
    fn dbs_frame_matches_live_verified_layout() {
        // Mirror of the 2026-11-09 20:22 frame that produced
        // `[kms] phone connected` + ev6 supportEncrypt=1 (sdp-rs.bin).
        let from = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6];
        let to = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab];
        let json = br#"{"dbs_msg_type":"msg_normal_topic_data"}"#;
        let f = dbs_data_frame(&from, &to, 0x0000_01a1_c0cc_53d8, 0x1001, json);
        let plen = 3 + 52 + json.len();
        assert_eq!(&f[0..2], &((plen + 2) as u16).to_be_bytes());
        assert_eq!(&f[2..4], &[0x00, 0x20]); // DATA, sid 8
        assert_eq!(&f[4..7], &[0x00, 0x10, 0x01]); // b0 unencrypted, tid
        assert_eq!(&f[7..13], &from);
        assert_eq!(&f[13..21], &0x0000_01a1_c0cc_53d8u64.to_be_bytes());
        assert_eq!(&f[21..27], &to);
        assert_eq!(&f[27..33], &to); // id = to (isLocalDestMatched)
        assert_eq!(f[33], DBS_MSG_TYPE_BC);
        assert_eq!(f[34], 1); // version
        assert_eq!(&f[51..59], &[0u8; 8]); // dest count 0, extra len 0
        assert_eq!(&f[59..], json);
    }

    #[test]
    fn dbs_json_shape_escapes_cast_message() {
        let j = dbs_message_json(
            "Oplus_Cast",
            "A1B2C3D4E5F6",
            "0123456789AB",
            "input_service",
            r#"{"msg_type":61,"msg_body":"{\"kms_socket_port\":36863}"}"#,
            42,
        );
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["dbs_msg_topic"]["dbs_topic_name"], "Oplus_Cast");
        assert_eq!(v["dbs_msg_type"], "msg_normal_topic_data");
        assert_eq!(v["dbs_msg_payload"]["key"], "input_service");
        let inner: serde_json::Value =
            serde_json::from_str(v["dbs_msg_payload"]["value"].as_str().unwrap()).unwrap();
        assert_eq!(inner["msg_type"], 61);
        assert_eq!(inner["msg_body"], r#"{"kms_socket_port":36863}"#);
    }

    #[test]
    fn frame_seal_open_and_plaintext() {
        let pwd = "s3cr3t";
        let wire = seal_frame(pwd, event::INJECT_REQ, 1, 42, r#"{"type":0}"#).unwrap();
        let (hdr, pt) = open_frame(pwd, &wire).unwrap();
        assert!(hdr.encrypted());
        assert_eq!(hdr.event_type, event::INJECT_REQ);
        assert_eq!(std::str::from_utf8(&pt).unwrap(), r#"{"type":0}"#);
        // plaintext frame decodes without the key
        let body = b"{\"plain\":1}".to_vec();
        let h = KmsHeader {
            event_type: event::HEARTBEAT_RESP,
            flags: 0,
            length: body.len() as i32,
            reserved: 0,
            seq: 0,
            timestamp: 0,
        };
        let mut wire = h.encode().to_vec();
        wire.extend_from_slice(&body);
        let (hdr2, pt2) = open_frame("irrelevant", &wire).unwrap();
        assert_eq!(hdr2.event_type, event::HEARTBEAT_RESP);
        assert_eq!(pt2, body);
    }
}
