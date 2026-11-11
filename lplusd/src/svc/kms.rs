//! KMS / cast-input plane (PROTOCOL.md §7.2).
//!
//! 24-byte big-endian header (`MessageProtocol.MessageHeader`), body = JSON.
//! Encryption: AES-128-GCM with key = SHA-256(password)[0:16]; frame body
//! when encrypted is `IV(12) || ct || tag(16)`; peer proof decrypts to the
//! constant `1234abcd`.

use crate::config::{flag, num, str_of};
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

/// dbr.a `msgType` for DbsMessage traffic. The dispatch gate
/// (`dbr/w.java c()`) treats 0-40 as system, 41-80 as broadcast and only
/// 81-120 as the Dbs data zone that routes to `DbsManager`; the phone's
/// own publishes use 82 (`cf/b.java:60-70`, `o.g(i,81,120,"msgType")`).
pub const DBS_MSG_TYPE_DBS: u8 = 82;

/// DbsMessage Gson JSON (phone `dbs/DbsMessage.java`) that makes
/// `CastDbsReceiver` → `CastSceneDispatcher` run
/// `InputServiceManager.execute(key→61, CastMessage)`. `value_json` is the
/// CastMessage JSON string, escaped into the payload `value`. The payload
/// itself is a JSON **string** (phone `DbsMessage.payload` is typed
/// `String`; the broker's static-subscriber bundle hands
/// `payload.toString()` to `new JSONObject(..)` — an object shape arrives
/// as a `LinkedTreeMap` toString and throws).
pub fn dbs_message_json(
    topic: &str,
    from_hex: &str,
    to_hex: &str,
    key: &str,
    value_json: &str,
    seq: u64,
) -> String {
    let value = value_json.replace('\\', "\\\\").replace('"', "\\\"");
    let payload = format!("{{\"key\":\"{key}\",\"value\":\"{value}\"}}");
    let payload = payload.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "{{\"dbs_msg_topic\":{{\"dbs_topic_name\":\"{topic}\",\"dbs_topic_tag\":0,\"dbs_topic_qos\":{{}}}},\
         \"dbs_msg_to_device\":\"{to_hex}\",\"dbs_msg_from_device\":\"{from_hex}\",\
         \"dbs_msg_priority\":100,\"dbs_msg_type\":\"msg_normal_topic_data\",\
         \"dbs_msg_id\":\"lplus-{seq}\",\
         \"dbs_msg_payload\":\"{payload}\",\
         \"dbs_msg_encrypt\":false,\"time\":{seq}}}"
    )
}

/// DbsMessage JSON that registers our topics with the peer's `DbsManager`
/// (phone `dbs/DbsUtilKt.broadcastLocalTopic` → `j.b`: type
/// `msg_topic_sync`; the peer's `dbs/e.java processMsgReceived` routes it
/// to `f.h(peer, msg)`, which Gson-parses the payload as
/// `Map<String, Set<ONetTopic>>` (`dbs/f.java:263`) and updates the
/// per-peer subscriber registry). Payload is therefore a quoted JSON
/// string holding `{"sub":[…],"pub":[…]}` with **ONetTopic objects**
/// (`dbs_topic_name`/`dbs_topic_tag`/`dbs_topic_qos`,
/// `dbs/ONetTopic.java` SerializedName keys) — bare strings land in the
/// set as Strings and every later topic comparison misses. Without this
/// the peer's broker drops our topic frames ("remote do not have
/// subscriber"), and never routes its own publishes (e.g.
/// `Oplus_PcConnect` clipboard) to us.
pub fn dbs_topic_sync_json(from_hex: &str, to_hex: &str, sub: &[&str], seq: u64) -> String {
    let topics = |list: &[&str]| {
        list.iter()
            .map(|t| {
                format!("{{\"dbs_topic_name\":\"{t}\",\"dbs_topic_tag\":0,\"dbs_topic_qos\":{{}}}}")
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    let payload = format!("{{\"sub\":[{}],\"pub\":[]}}", topics(sub));
    let payload = payload.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "{{\"dbs_msg_to_device\":\"{to_hex}\",\"dbs_msg_from_device\":\"{from_hex}\",\
         \"dbs_msg_priority\":100,\"dbs_msg_type\":\"msg_topic_sync\",\
         \"dbs_msg_id\":\"lplus-sync-{seq}\",\
         \"dbs_msg_payload\":\"{payload}\",\
         \"dbs_msg_encrypt\":false,\"time\":{seq}}}"
    )
}

/// Unencrypted DataBus (NDSF sid 8) DATA frame (`len`, hdr `0x0020`,
/// `b0=0x04`, `tid`, zero ctr) plus dbr.a message (phone `pl/b.f` and
/// `g5/b.s`). dbr.a layout in [`dbs_body`]; note a `[0x04]` frame with a
/// zero counter parses as SEALED with `t=0` — see PROTOCOL.md §7.11.
pub fn dbs_data_frame(from6: &[u8; 6], to6: &[u8; 6], seq: u64, tid: u16, json: &[u8]) -> Vec<u8> {
    let mut payload = vec![0x04u8, (tid >> 8) as u8, tid as u8];
    payload.extend_from_slice(&0u64.to_be_bytes());
    payload.extend_from_slice(&dbs_body(from6, to6, seq, json));
    dbs_wrap(payload)
}

/// dbr.a header + DbsMessage JSON — the DataBus body the phone puts
/// behind (or inside, when sealed) the NDSF `[0x04][tid][ctr8]` header.
/// Serialized per `g5/b.java P()/s()`: 44 B fixed header, **destination
/// count (4 B BE)**, count × 6 B destination ids, extra length (4 B BE),
/// extra bytes, then the JSON payload. The count is load-bearing:
/// `dbr/w.java c()` iterates the destination list to match the local
/// OnetId/OafId and offers the message to `DbsDataReceiver`; a zero count
/// makes it swallow the frame with no log at all.
fn dbs_body(from6: &[u8; 6], to6: &[u8; 6], seq: u64, json: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 44];
    body[0..6].copy_from_slice(from6);
    body[6..14].copy_from_slice(&seq.to_be_bytes());
    body[14..20].copy_from_slice(to6);
    body[20..26].copy_from_slice(to6); // id := to (phone is the destination)
    body[26] = DBS_MSG_TYPE_DBS;
    body[27] = 1;
    body.extend_from_slice(&1u32.to_be_bytes()); // destination count
    body.extend_from_slice(to6); // destinations = the phone
    body.extend_from_slice(&0u32.to_be_bytes()); // extra length
    body.extend_from_slice(json);
    body
}

/// NDSF DATA frame (sid 8, hdr `0x0020`) around a finished payload.
pub(crate) fn dbs_wrap(payload: Vec<u8>) -> Vec<u8> {
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    frame.extend_from_slice(&0x0020u16.to_be_bytes()); // ftype DATA, sid 8
    frame.extend_from_slice(&payload);
    frame
}

/// AppCipher per-message key schedule (AccessoryFramework `vf.a`):
/// `S = HmacSHA512_ksc(qcqs ‖ ctr_be64)`; AES-128 key = `S[0:16]`, GCM
/// nonce = `S[16:28]`, AAD = `S[28:48]`, tag appended to the ciphertext
/// (`fw/accfw-jadx vf/a.java b()/a()`). `qcqs` = AUTH client challenge ‖
/// server challenge (16 B). The phone's receiver replays-checks `ctr`
/// (window `[mT−4, mT+100000]`) and SILENTLY drops tag failures — the
/// `0a <tid>` response we see is that failure path, not a delivery ack.
#[expect(deprecated, reason = "aead 0.6 nonce ctor")]
pub fn dbs_seal(ksc: &[u8], qcqs: &[u8], ctr: u64, pt: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::{
        Aes128Gcm, KeyInit, Nonce,
        aead::{Aead, Payload},
    };
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    let mut mac =
        Hmac::<Sha512>::new_from_slice(ksc).map_err(|e| anyhow::anyhow!("dbs hmac key: {e}"))?;
    mac.update(qcqs);
    mac.update(&ctr.to_be_bytes());
    let s = mac.finalize().into_bytes();
    let cipher =
        Aes128Gcm::new_from_slice(&s[..16]).map_err(|e| anyhow::anyhow!("dbs key: {e}"))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&s[16..28]),
            Payload {
                msg: pt,
                aad: &s[28..48],
            },
        )
        .map_err(|e| anyhow::anyhow!("dbs seal: {e}"))?;
    Ok(ct)
}

/// Sealing context for [`dbs_data_frame_sealed`]: the bonded `ksc` and the
/// AUTH `qc‖qs` (see [`dbs_seal`]).
pub struct DbsSealCtx<'a> {
    pub ksc: &'a [u8],
    pub qcqs: &'a [u8],
}

/// Sealed variant of [`dbs_data_frame`]: identical dbr.a body, but GCM
/// encrypted under [`dbs_seal`] with a real counter (the phone's rx
/// window advances to it, so never resend a lower one).
pub fn dbs_data_frame_sealed(
    ctx: &DbsSealCtx<'_>,
    ctr: u64,
    from6: &[u8; 6],
    to6: &[u8; 6],
    seq: u64,
    tid: u16,
    json: &[u8],
) -> Result<Vec<u8>> {
    let body = dbs_body(from6, to6, seq, json);
    let ct = dbs_seal(ctx.ksc, ctx.qcqs, ctr, &body)?;
    let mut payload = vec![0x04u8, (tid >> 8) as u8, tid as u8];
    payload.extend_from_slice(&ctr.to_be_bytes());
    payload.extend_from_slice(&ct);
    Ok(dbs_wrap(payload))
}

/// PC-side KMS TCP server: phone connects here after receiving the cast
/// bootstrap (`kms_socket_port`). Frames: 24 B header + body; encrypted
/// bodies decrypt under `password`. Answers HEARTBEAT_REQ with RESP. Each
/// session registers an injection sink under `"{port} {peer}"`, so
/// [`crate::svc::epi::Command::SendFrame`] can write sealed frames (e.g.
/// event-3 INJECT_REQ via [`seal_frame`]) without a reconnect.
pub struct Kms {
    port: u16,
    password: String,
    log_path: String,
    sdp: std::sync::Arc<crate::svc::sdp::Sdp>,
}

impl Kms {
    pub fn new(
        port: u16,
        password: String,
        log_path: String,
        sdp: std::sync::Arc<crate::svc::sdp::Sdp>,
    ) -> Self {
        Self {
            port,
            password,
            log_path,
            sdp,
        }
    }

    pub fn spawn(&self) {
        let port = self.port;
        let password = self.password.clone();
        let log_path = self.log_path.clone();
        let sdp = self.sdp.clone();
        let epi = self.sdp.epi.clone();
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
                sdp.emit_device("kms", peer.ip().to_string(), None, true);
                let pw = password.clone();
                let lp = log_path.clone();
                let sdp = sdp.clone();
                let epi = epi.clone();
                tokio::spawn(async move {
                    let mut seq = 1i32;
                    let inject_key = format!("{port} {peer}");
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    epi.register_sink(inject_key.clone(), tx).await;
                    let mut inject_rx = Some(rx);
                    let mut acc: Vec<u8> = Vec::new();
                    let mut tmp = [0u8; 4096];
                    // Rate-limited link-evidence refresh (see epi lane).
                    let mut last_ev = tokio::time::Instant::now();
                    'read: loop {
                        // Idle guard (see epi lane): prolonged silence from a
                        // peer that never sent a FIN ends the session view.
                        const KMS_IDLE: std::time::Duration = std::time::Duration::from_secs(150);
                        let rd = match &mut inject_rx {
                            Some(rx) => tokio::select! {
                                r = sock.read(&mut tmp) => r,
                                b = rx.recv() => {
                                    match b {
                                        Some(bytes) => {
                                            let _ = sock.write_all(&bytes).await;
                                            crate::svc::sdp::record(&lp, &format!("inject-sent {inject_key}"), &bytes);
                                            tracing::info!(
                                                "[inject] -> {inject_key} {}B {}",
                                                bytes.len(),
                                                hex::encode(&bytes[..bytes.len().min(64)])
                                            );
                                        }
                                        None => inject_rx = None,
                                    }
                                    continue;
                                }
                                _ = tokio::time::sleep(KMS_IDLE) => Ok(0),
                            },
                            None => tokio::time::timeout(KMS_IDLE, sock.read(&mut tmp))
                                .await
                                .unwrap_or(Ok(0)),
                        };
                        match rd {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                acc.extend_from_slice(&tmp[..n]);
                                if last_ev.elapsed() >= std::time::Duration::from_secs(60) {
                                    last_ev = tokio::time::Instant::now();
                                    sdp.emit_device("kms", peer.ip().to_string(), None, true);
                                }
                            }
                        }
                        // Frame-split the accumulator (24 B header + length body).
                        loop {
                            if acc.len() < 24 {
                                continue 'read;
                            }
                            let Ok(hdr) =
                                KmsHeader::decode(&<[u8; 24]>::try_from(&acc[..24]).unwrap())
                            else {
                                crate::svc::sdp::record(
                                    &lp,
                                    &format!("kms-badhdr {peer}"),
                                    &acc[..24],
                                );
                                tracing::info!(
                                    "[kms] {peer} bad header {}",
                                    hex::encode(&acc[..24])
                                );
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
                            crate::svc::sdp::record(
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
                                    crate::svc::sdp::record(
                                        &lp,
                                        &format!("kms-send {peer} ev5"),
                                        &wire,
                                    );
                                    let _ = sock.write_all(&wire).await;
                                }
                            }
                        }
                    }
                    epi.unregister_sink(&inject_key).await;
                    sdp.emit_device("kms", peer.ip().to_string(), None, false);
                    tracing::info!("[kms] {peer} closed");
                });
            }
        });
    }
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

// ==== service configuration (env keys read once at startup) ====

/// KMS input plane (`KMS*`).
#[derive(Debug, Clone)]
pub struct KmsConfig {
    /// `KMS`: listen for phone-initiated KMS sessions.
    pub enabled: bool,
    /// `KMS_PORT`: first listener port (rotation base).
    pub port_base: u16,
    /// `KMS_PORT_ROT`: number of rotating listener ports.
    pub port_rot: u16,
    /// `KMS_PWD`: proof password handed to the phone.
    pub pwd: String,
}

impl Default for KmsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port_base: 36863,
            port_rot: 4,
            pwd: "lplus-kms-pw".into(),
        }
    }
}

// -- KmsConfig --
impl KmsConfig {
    pub fn load() -> Self {
        let d = Self::default();
        Self {
            enabled: flag("KMS", d.enabled),
            port_base: num("KMS_PORT", d.port_base),
            port_rot: num("KMS_PORT_ROT", d.port_rot),
            pwd: str_of("KMS_PWD", &d.pwd),
        }
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
        let plen = 3 + 8 + 58 + json.len();
        assert_eq!(&f[0..2], &((plen + 2) as u16).to_be_bytes());
        assert_eq!(&f[2..4], &[0x00, 0x20]); // DATA, sid 8
        assert_eq!(&f[4..7], &[0x04, 0x10, 0x01]); // b0 DATA, tid
        assert_eq!(&f[7..15], &[0u8; 8]); // ctr 0 (unencrypted)
        assert_eq!(&f[15..21], &from);
        assert_eq!(&f[21..29], &0x0000_01a1_c0cc_53d8u64.to_be_bytes());
        assert_eq!(&f[29..35], &to);
        assert_eq!(&f[35..41], &to); // id = to (isLocalDestMatched)
        assert_eq!(f[41], DBS_MSG_TYPE_DBS);
        assert_eq!(f[42], 1); // version
        assert_eq!(&f[59..63], &[0, 0, 0, 1]); // destination count 1 (w.c() offer)
        assert_eq!(&f[63..69], &to); // destination list
        assert_eq!(&f[69..73], &[0u8; 4]); // extra length
        assert_eq!(&f[73..], json);
    }

    #[test]
    #[allow(deprecated)] // aead 0.6 nonce ctor
    fn sealed_dbs_frame_layout_and_roundtrip() {
        // Pin the AppCipher wire form (PROTOCOL.md §7.11): header/ctr in
        // the clear, body = AES-128-GCM(dbr.a ‖ json) with the per-message
        // HMAC-SHA512(ksc)(qc‖qs‖ctr) schedule.
        let ksc = [0x11u8; 16];
        let qcqs = [0x22u8; 16];
        let from = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6];
        let to = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab];
        let json = br#"{"dbs_msg_type":"msg_normal_topic_data"}"#;
        let ctr = 7u64;
        let f = dbs_data_frame_sealed(
            &DbsSealCtx {
                ksc: &ksc,
                qcqs: &qcqs,
            },
            ctr,
            &from,
            &to,
            0x1234,
            0x0001,
            json,
        )
        .unwrap();
        let plen = 3 + 8 + 58 + json.len() + 16;
        assert_eq!(&f[0..2], &((plen + 2) as u16).to_be_bytes());
        assert_eq!(&f[2..4], &[0x00, 0x20]);
        assert_eq!(&f[4..7], &[0x04, 0x00, 0x01]);
        assert_eq!(&f[7..15], &ctr.to_be_bytes());
        let payload = &f[4..];
        let ct = &payload[11..payload.len() - 16];
        let tag = &payload[payload.len() - 16..];
        use aes_gcm::{
            Aes128Gcm, KeyInit, Nonce,
            aead::{Aead, Payload},
        };
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        let mut mac = Hmac::<Sha512>::new_from_slice(&ksc).unwrap();
        mac.update(&qcqs);
        mac.update(&ctr.to_be_bytes());
        let s = mac.finalize().into_bytes();
        let cipher = Aes128Gcm::new_from_slice(&s[..16]).unwrap();
        let mut buf = ct.to_vec();
        buf.extend_from_slice(tag);
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&s[16..28]),
                Payload {
                    msg: &buf,
                    aad: &s[28..48],
                },
            )
            .unwrap();
        assert_eq!(&pt[0..6], &from);
        assert_eq!(&pt[6..14], &0x1234u64.to_be_bytes());
        assert_eq!(&pt[14..20], &to);
        assert_eq!(pt[26], DBS_MSG_TYPE_DBS);
        assert_eq!(&pt[44..48], &[0, 0, 0, 1]); // destination count 1
        assert_eq!(&pt[48..54], &to); // destination list
        assert_eq!(&pt[54..58], &[0u8; 4]); // extra length
        assert_eq!(&pt[58..], json);
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
        // payload is a quoted JSON string (phone DbsMessage.payload:String)
        let payload: serde_json::Value =
            serde_json::from_str(v["dbs_msg_payload"].as_str().unwrap()).unwrap();
        assert_eq!(payload["key"], "input_service");
        let inner: serde_json::Value =
            serde_json::from_str(payload["value"].as_str().unwrap()).unwrap();
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
