//! ODMF sink lane (PROTOCOL.md §7.9).
//!
//! Direction is flipped vs the classic WFD RTSP lane: after the PC pushes
//! `rsp_odmf_key` over DataBus (see `local://video-lane-research.md`), the
//! phone's `heycast_CastOdmfEngine` DIALS US on TCP :7236
//! ("connect to odmf, ip:port=*(8)0.11:**36"). We accept, dump EVERY byte
//! both ways to `<out>/odmf-session.bin` with `[odmf]` tracing, and answer
//! just enough WFD/RTSP server semantics (OPTIONS / GET_PARAMETER wfd caps /
//! SETUP / PLAY) for the phone to start pushing RTP (H.265 — engine logged
//! "Set codec format H265") to UDP `ODMF_RTP_PORT` (default 15550).
//! Depacketized Annex-B lands in `<out>/video_odmf.h265`.
//!
//! Opt-in: `ODMF_SINK=1` (+ `ODMF_LISTEN=0.0.0.0:7236`, `ODMF_RTP_PORT=15550`,
//! `ODMF_OUT=../capture`, `ODMF_RESPOND=1|0`). `ODMF_RESPOND=0` = pure
//! wire-capture. The rtsp.rs client lane is independent and untouched.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::rtsp::{RtspMethod, RtspMsg};
use strum::IntoEnumIterator;

const START_CODE: &[u8] = b"\x00\x00\x00\x01";
const MAX_NAL: usize = 4 * 1024 * 1024;

/// Arm the sink once (called from sdpd startup when `ODMF_SINK` is set).
pub fn spawn(listen: SocketAddr, out_dir: String, respond: bool) {
    tokio::spawn(async move {
        match run(listen, out_dir, respond).await {
            Ok(()) => tracing::info!("[odmf] listener ended"),
            Err(e) => tracing::warn!("[odmf] listener failed: {e:#}"),
        }
    });
}

async fn run(listen: SocketAddr, out_dir: String, respond: bool) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("odmf bind {listen}"))?;
    tracing::info!(
        "[odmf] listening {listen} (rtp via webrtc lane, out {out_dir}, respond {respond})"
    );
    let dump = Arc::new(Mutex::new(open_dump(&out_dir)?));
    // Informational: auth material is (re)loaded per OdmfAuthResponse so a
    // fresh /tmp/odmf_authinfo.json push works without relaunching.
    tracing::info!(
        "[odmf] identity auth at startup: {}",
        if OdmfAuth::load().is_some() {
            "loaded"
        } else {
            "MISSING (push odmf_auth_info; ODMF_AUTH_FILE/ODMF_PRIV_PEM)"
        }
    );
    loop {
        let (sock, peer) = listener.accept().await.context("accept")?;
        tracing::info!("[odmf] phone connected {peer}");
        let dump = dump.clone();
        tokio::spawn(async move {
            if let Err(e) = session(sock, peer, dump, respond).await {
                tracing::warn!("[odmf] session {peer} ended: {e:#}");
            }
        });
    }
}

fn open_dump(out_dir: &str) -> Result<std::fs::File> {
    let p = format!("{out_dir}/odmf-session.bin");
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p)
        .with_context(|| format!("open {p}"))
}

fn dump_bytes(dump: &Mutex<std::fs::File>, data: &[u8]) {
    if let Ok(mut f) = dump.lock() {
        let _ = f.write_all(data);
        let _ = f.flush();
    }
}

fn hex_preview(b: &[u8], n: usize) -> String {
    let take = b.len().min(n);
    let mut s = String::with_capacity(take * 3);
    for x in &b[..take] {
        s.push_str(&format!("{x:02x} "));
    }
    if b.len() > take {
        s.push('…');
    }
    s
}

/// One phone control connection: dump, frame RTSP requests, answer them.
async fn session(
    mut sock: TcpStream,
    peer: SocketAddr,
    dump: Arc<Mutex<std::fs::File>>,
    respond: bool,
) -> Result<()> {
    let _ = sock.set_nodelay(true);
    let mut buf = vec![0u8; 16384];
    let mut acc: Vec<u8> = Vec::new();
    let mut session_hdr: Option<String> = None;
    let mut got_nonrtsp = false;
    let mut prelude_sent = false;
    let mut media_key: Option<[u8; 32]> = None;
    let mut local_bus = String::new();
    let peer_ip = peer.ip().to_string();
    let tag = peer.to_string();
    let mut sig_rx = crate::odmf_pc::sig_subscribe();
    let mut total_rx: usize = 0;
    let mut frames_logged: usize = 0;
    loop {
        let n = tokio::select! {
            r = sock.read(&mut buf) => r.context("tcp read")?,
            m = sig_rx.recv() => {
                // WebRTC task downlink: sealed offer targeted at this socket.
                if let Ok((t, payload)) = m && t == tag {
                    let framed = match media_key.as_ref().and_then(|k| encrypt_frame(k, &payload)) {
                        Some(p) => p,
                        None => {
                            // Pre-auth (should not happen for offers): plain frame.
                            payload.into_bytes()
                        }
                    };
                    let mut out = Vec::with_capacity(framed.len() + 2);
                    out.extend_from_slice(&(framed.len() as u16).to_be_bytes());
                    out.extend_from_slice(&framed);
                    dump_bytes(&dump, &out);
                    sock.write_all(&out).await.context("tcp write sig")?;
                    tracing::info!("[odmf] tx webrtc-sig {}B → {tag}", out.len());
                }
                continue;
            }
        };
        if n == 0 {
            tracing::info!("[odmf] phone closed {peer} (rx {total_rx}B)");
            return Ok(());
        }
        total_rx += n;
        dump_bytes(&dump, &buf[..n]);
        tracing::info!("[odmf] rx {n}B {peer} | {}", hex_preview(&buf[..n], 96));
        acc.extend_from_slice(&buf[..n]);
        // Frame whole RTSP requests off the head of acc; anything else stays
        // buffered for the wire log (phase-1 capture of unknown framing).
        while let Some((req, used)) = try_parse_request(&acc) {
            acc.drain(..used);
            tracing::info!(
                "[odmf] {} {} (CSeq {}) body={}B",
                req.method,
                req.uri,
                req.header("CSeq").unwrap_or("-"),
                req.body.len()
            );
            if respond {
                let replies = build_replies(&req, &mut session_hdr);
                for r in replies {
                    let bytes = r.to_bytes();
                    dump_bytes(&dump, &bytes);
                    sock.write_all(&bytes).await.context("tcp write")?;
                    tracing::info!(
                        "[odmf] tx {}B | {} {}",
                        bytes.len(),
                        r.status.unwrap_or(0),
                        r.reason.clone().unwrap_or_default()
                    );
                }
            }
        }
        // NearX/ODMF transport-bus framing: [u16BE len][json] — observed
        // live 2026-11-09 23:08: `000e {"cmd":"ping"}` keepalives every 3 s.
        // Answer keepalives with same-framed pongs; log everything else.
        while let Some((json, used)) = try_parse_json_frame(&acc) {
            acc.drain(..used);
            if frames_logged < 12 {
                frames_logged += 1;
                tracing::info!("[odmf] frame {peer} | {}", redact(&json));
            }
            crate::odmf_pc::handle_inbound(&json);
            // identity-auth lane: phone answered our OdmfAuthRequest
            if respond && json.contains("\"OdmfAuthResponse\"") {
                match (
                    OdmfAuth::load(),
                    serde_json::from_str::<serde_json::Value>(&json),
                ) {
                    (Some(a), Ok(v)) => {
                        if let Some((reply, k)) = a.auth_success_json(&v) {
                            media_key = Some(k);
                            local_bus = v
                                .get("local_transportbus_id")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .to_string();
                            peer_note(
                                &peer_ip,
                                &local_bus,
                                v.get("local_user_name")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("heycast_odmf"),
                                v.get("local_user_id").and_then(|x| x.as_str()).unwrap_or(""),
                            );
                            let mut out = Vec::with_capacity(reply.len() + 2);
                            out.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                            out.extend_from_slice(reply.as_bytes());
                            dump_bytes(&dump, &out);
                            sock.write_all(&out).await.context("tcp write auth")?;
                            tracing::info!(
                                "[odmf] tx AuthSuccess {}B | {}",
                                out.len(),
                                redact(&reply)
                            );
                        } else {
                            tracing::warn!("[odmf] auth: AuthSuccess build failed for {peer}");
                        }
                    }
                    (None, _) => {
                        tracing::warn!("[odmf] auth: load failed (odmf_authinfo.json / priv pem)")
                    }
                    (_, Err(e)) => tracing::warn!("[odmf] auth: frame JSON parse: {e}"),
                }
            }
            if respond && let Some(reply) = json_reply(&json) {
                let mut out = Vec::with_capacity(reply.len() + 2);
                out.extend_from_slice(&(reply.len() as u16).to_be_bytes());
                out.extend_from_slice(reply.as_bytes());
                dump_bytes(&dump, &out);
                sock.write_all(&out).await.context("tcp write json")?;
                tracing::info!("[odmf] tx json {}B | {}", out.len(), redact(&reply));
                if !prelude_sent {
                    prelude_sent = true;
                    for frame in prelude_frames() {
                        let mut out = Vec::with_capacity(frame.len() + 2);
                        out.extend_from_slice(&(frame.len() as u16).to_be_bytes());
                        out.extend_from_slice(frame.as_bytes());
                        dump_bytes(&dump, &out);
                        sock.write_all(&out).await.context("tcp write prelude")?;
                        tracing::info!("[odmf] tx prelude {}B | {}", out.len(), redact(&frame));
                    }
                }
            }
        }
        // Post-auth encrypted signaling lane: the phone seals every message
        // after identity auth with getEncryptMsg under the key it adopted
        // from our AuthSuccess. Live 18:24:38Z: `{"cmd":"PairRequest"}`
        // arrived as a 68B 0x01 frame; the ODMF server contract answers it
        // with an encrypted PairSuccess (odmfr/odmfc.java
        // notifyClientPairSuccess).
        while let Some((plain, used)) = try_parse_enc_frame(&acc, media_key.as_ref()) {
            acc.drain(..used);
            tracing::info!("[odmf] frame {peer} (enc) | {}", redact(&plain));
            crate::odmf_pc::handle_inbound(&plain);
            if respond && plain.contains("PairRequest") {
                let Some(k) = media_key.as_ref() else { continue };
                let (rb, rn, rid) = peer_other(&peer_ip, &local_bus);
                let reply = format!(
                    "{{\"cmd\":\"PairSuccess\",\"remote_user_name\":\"{rn}\",\"remote_user_id\":\"{rid}\",\"remote_transportbus_id\":\"{rb}\"}}"
                );
                match encrypt_frame(k, &reply) {
                    Some(payload) => {
                        let mut out = Vec::with_capacity(payload.len() + 2);
                        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                        out.extend_from_slice(&payload);
                        dump_bytes(&dump, &out);
                        sock.write_all(&out).await.context("tcp write pair")?;
                        tracing::info!("[odmf] tx PairSuccess (enc) {}B", out.len());
                        crate::odmf_pc::paired(&tag);
                    }
                    None => tracing::warn!("[odmf] pair: PairSuccess seal failed"),
                }
            }
        }
        if !got_nonrtsp
            && acc.len() >= 16
            && !RtspMethod::iter().any(|m| acc.starts_with(m.as_ref().as_bytes()))
            && !acc.starts_with(b"GET ")
        {
            got_nonrtsp = true;
            tracing::info!(
                "[odmf] non-RTSP framing from {peer}; first 32B: {}",
                hex_preview(&acc[..32], 32)
            );
        }
    }
}

/// One length-prefixed JSON frame `[u16BE len]{json}` if buffered.
fn try_parse_json_frame(buf: &[u8]) -> Option<(String, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if !(2..=8192).contains(&len) {
        return None;
    }
    if buf[2] != b'{' || buf.len() < 2 + len {
        return None;
    }
    let json = std::str::from_utf8(&buf[2..2 + len]).ok()?.to_string();
    // reject non-JSON garbage fast
    if !json.ends_with('}') {
        return None;
    }
    Some((json, 2 + len))
}

/// Keepalive reply table: ping → pong. Unknown frames unanswered (capture).
fn json_reply(json: &str) -> Option<String> {
    if json.contains("\"ping\"") {
        return Some("{\"cmd\":\"pong\"}".to_string());
    }
    None
}

/// Server-side bus hello sent once per connection after the first pong
/// (NearTransportBus `sendUserInfo` equivalent, reverse-engineered from
/// odmf.jar BTTransferThread: dispatch keys are `cmd` values such as
/// `pair_info_flag`/`auth_info_flag`/`auth_success_flag`). Env-overridable
/// for response-variant iteration: `ODMF_PRELUDE` = JSON-array of frames.
fn prelude_frames() -> Vec<String> {
    prelude_frames_from(std::env::var("ODMF_PRELUDE").ok())
}

/// Pure body of [`prelude_frames`]: the `ODMF_PRELUDE` value is passed in
/// so the variants are testable without mutating the process environment.
fn prelude_frames_from(prelude: Option<String>) -> Vec<String> {
    if let Some(v) = prelude {
        return serde_json::from_str::<Vec<String>>(&v).unwrap_or_default();
    }
    // Identity-auth flow (odmf.jar SigIdentityAuthHelper + OdmfSignalingClient):
    // the SERVER drives — request the client's auth info; the phone answers
    // {"cmd":"OdmfAuthResponse",..} which we verify and ack with AuthSuccess.
    vec!["{\"cmd\":\"OdmfAuthRequest\"}".to_string()]
}

/// PC-side identity for the ODMF near-field auth handshake, mirroring
/// `com.oplus.odmf.def.NearFieldAuthInfo` (id/PublicKey/privateKey).
/// Loaded from the same material `odmf_push.py` sent in `rsp_odmf_key`:
/// `ODMF_AUTH_FILE` (default /tmp/odmf_authinfo.json: `{"id","public_key",
/// "auth_version"}`) and `ODMF_PRIV_PEM` (default /tmp/odmf_priv.pem).
struct OdmfAuth {
    id_b64: String,
    priv_scalar: [u8; 32],
    auth_version: i64,
}

/// AES-256-GCM open with runtime nonce size (Java's `GCMParameterSpec` takes
/// an arbitrary-length IV; the phone's auth IV is 16 B while aes-gcm's
/// `Aes256Gcm` alias hardcodes 12). `N` is `U12` or `U16` only.
fn gcm_open<N>(key: &[u8], iv: &[u8], aad: &[u8], ct: &[u8]) -> Option<Vec<u8>>
where
    N: aes_gcm::aead::array::ArraySize,
    aes_gcm::AesGcm<aes::Aes256, N>:
        aes_gcm::KeyInit
        + aes_gcm::aead::Aead
        + aes_gcm::aead::AeadCore<NonceSize = N>,
    aes_gcm::Nonce<N>: TryFrom<Vec<u8>>,
{
    use aes_gcm::aead::Aead;
    let cipher = <aes_gcm::AesGcm<aes::Aes256, N> as aes_gcm::KeyInit>::new_from_slice(key).ok()?;
    let nonce = aes_gcm::Nonce::<N>::try_from(iv.to_vec()).ok()?;
    cipher
        .decrypt(&nonce, aes_gcm::aead::Payload { msg: ct, aad })
        .ok()
}

/// Seal with a runtime nonce size (mirrors [`gcm_open`]).
fn gcm_seal<N>(key: &[u8], iv: &[u8], aad: &[u8], msg: &[u8]) -> Option<Vec<u8>>
where
    N: aes_gcm::aead::array::ArraySize,
    aes_gcm::AesGcm<aes::Aes256, N>:
        aes_gcm::KeyInit
        + aes_gcm::aead::Aead
        + aes_gcm::aead::AeadCore<NonceSize = N>,
    aes_gcm::Nonce<N>: TryFrom<Vec<u8>>,
{
    use aes_gcm::aead::Aead;
    let cipher = <aes_gcm::AesGcm<aes::Aes256, N> as aes_gcm::KeyInit>::new_from_slice(key).ok()?;
    let nonce = aes_gcm::Nonce::<N>::try_from(iv.to_vec()).ok()?;
    cipher
        .encrypt(&nonce, aes_gcm::aead::Payload { msg, aad })
        .ok()
}

fn b64std(s: &str) -> Option<Vec<u8>> {
    let e = base64::engine::general_purpose::STANDARD;
    e.decode(s).ok().or_else(|| {
        // tolerate absent '=' padding
        let pad = (4 - s.len() % 4) % 4;
        e.decode(format!("{s}{}", "=".repeat(pad))).ok()
    })
}

fn b64s(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Post-auth ODMF signaling frame (SigIdentityAuthHelper.getEncryptMsg,
/// odmf.jar odmfr/odmfe.java): `[0x01][ts 13B ascii millis][iv][ct||16B
/// tag]`, AES-256-GCM under the key the peer adopted from our AuthSuccess
/// (`setKey(b64decode(json.key))`), AAD = the ts bytes. The phone's
/// `getEncryptIvBitSize` picks 12 or 16 by version, so try both.
fn decrypt_enc_frame(key: &[u8; 32], payload: &[u8]) -> Option<String> {
    use aes_gcm::aead::consts::{U12, U16};
    if payload.first() != Some(&1u8) || payload.len() < 14 + 12 + 16 {
        return None;
    }
    let ts = &payload[1..14];
    if !ts.iter().all(u8::is_ascii_digit) {
        return None;
    }
    for ivlen in [16usize, 12] {
        if payload.len() < 14 + ivlen + 16 {
            continue;
        }
        let iv = &payload[14..14 + ivlen];
        let ct = &payload[14 + ivlen..];
        let pt = if ivlen == 16 {
            gcm_open::<U16>(key, iv, ts, ct)
        } else {
            gcm_open::<U12>(key, iv, ts, ct)
        };
        if let Some(pt) = pt {
            return String::from_utf8(pt).ok();
        }
    }
    None
}

/// Mirror of [`decrypt_enc_frame`] for our own replies (`sendMessage` seals
/// via getEncryptMsg once authSuccess).
fn encrypt_frame(key: &[u8; 32], json: &str) -> Option<Vec<u8>> {
    use aes_gcm::aead::consts::U16;
    use rand::Rng;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis()
        .to_string();
    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);
    let sealed = gcm_seal::<U16>(key, &iv, ts.as_bytes(), json.as_bytes())?;
    let mut out = Vec::with_capacity(15 + iv.len() + sealed.len());
    out.push(1u8);
    out.extend_from_slice(ts.as_bytes());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&sealed);
    Some(out)
}

/// One length-prefixed encrypted frame `[u16BE len][0x01…]` if buffered and
/// openable under `key`.
fn try_parse_enc_frame(buf: &[u8], key: Option<&[u8; 32]>) -> Option<(String, usize)> {
    let key = key?;
    let len = usize::from(u16::from_be_bytes([*buf.first()?, *buf.get(1)?]));
    if len < 43 || buf.len() < 2 + len || buf.get(2) != Some(&1u8) {
        return None;
    }
    let plain = decrypt_enc_frame(key, &buf[2..2 + len])?;
    Some((plain, 2 + len))
}

/// Identities the phone announced (`OdmfAuthResponse.local_*`) per source
/// IP. The ODMF signaling server pairs the phone's A/B sockets crosswise:
/// each `PairSuccess` carries the *other* socket's identity
/// (`OdmfSignalingServer.notifyClientPairSuccess`, odmfr/odmfc.java), which
/// the client then adopts as its `remoteTransportBusId` before flushing its
/// queued session messages (`odmft`).
static PEERS: std::sync::Mutex<Vec<(String, String, String, String)>> = std::sync::Mutex::new(Vec::new());

fn peer_note(ip: &str, bus: &str, user_name: &str, user_id: &str) {
    let Ok(mut v) = PEERS.lock() else { return };
    if !v.iter().any(|(i, b, _, _)| i == ip && b == bus) {
        v.push((ip.to_string(), bus.to_string(), user_name.to_string(), user_id.to_string()));
    }
}

/// The other socket's identity for `ip` (cross-pair); falls back to `own`
/// when only one socket has announced itself.
fn peer_other(ip: &str, own_bus: &str) -> (String, String, String) {
    let def = (own_bus.to_string(), "heycast_odmf".to_string(), String::new());
    let Ok(v) = PEERS.lock() else { return def };
    v.iter()
        .find(|(i, b, _, _)| i == ip && b != own_bus)
        .map(|(_, b, n, uid)| (b.clone(), n.clone(), uid.clone()))
        .unwrap_or(def)
}

/// Accept both raw SEC1 (0x04/0x02/0x03 point) and X.509 SPKI DER
/// (`X509EncodedKeySpec`, the format odmf.jar puts in `public_key`).
fn spki_to_sec1(der: &[u8]) -> Option<&[u8]> {
    if matches!(der.first(), Some(0x02..=0x04)) {
        return Some(der);
    }
    // BIT STRING 03 42 00 || 04 X Y  (uncompressed P-256, 66 bytes)
    let pat = [0x03u8, 0x42, 0x00];
    let i = der.windows(pat.len()).position(|w| w == pat)? + pat.len();
    der.get(i..i + 65)
}

/// Extract the P-256 private scalar from a PKCS#8 PEM (`openssl ecparam
/// -name prime256v1 -genkey` output).
fn p256_scalar_from_pem(pem: &str) -> Option<[u8; 32]> {
    let der = b64std(
        pem.lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
            .as_str(),
    )?;
    // Accept SEC1 ("BEGIN EC PRIVATE KEY"): 04 20 <32B scalar> a0 0a 06 08 2a 86 48 ce 3d 03 01 07
    // and PKCS8: 30 0d 06 09 2a 86 48 86 f7 0d 01 01 07 04 12 30 1f 02 01 01 04 20 <32B>
    let sec1_tail = [
        0xa0u8, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let pkcs8_pat = [
        0x30u8, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07, 0x04, 0x12,
    ];
    let sec1 = der
        .windows(sec1_tail.len())
        .position(|w| w == sec1_tail)
        .and_then(|i| {
            let end = i.checked_sub(32)?;
            der.get(end..i)
        });
    let pkcs8 = der
        .windows(pkcs8_pat.len())
        .position(|w| w == pkcs8_pat)
        .and_then(|i| der.get(i + pkcs8_pat.len()..i + pkcs8_pat.len() + 32));
    let k = sec1.or(pkcs8)?;
    let mut k32 = [0u8; 32];
    k32.copy_from_slice(k);
    Some(k32)
}

impl OdmfAuth {
    fn load() -> Option<Self> {
        let info_path =
            std::env::var("ODMF_AUTH_FILE").unwrap_or_else(|_| "/tmp/odmf_authinfo.json".into());
        let pem_path =
            std::env::var("ODMF_PRIV_PEM").unwrap_or_else(|_| "/tmp/odmf_priv.pem".into());
        let info = std::fs::read_to_string(&info_path).ok()?;
        let v: serde_json::Value = serde_json::from_str(&info).ok()?;
        let id_b64 = v.get("id")?.as_str()?.to_string();
        // Any length: SigIdentityAuthHelper compares raw id bytes; the push
        // flow uses "lplus-pc-<n>" (11+ bytes), random ids are 8.
        b64std(&id_b64)?;
        let pem = std::fs::read_to_string(&pem_path).ok()?;
        let priv_scalar = p256_scalar_from_pem(&pem)?;
        let auth_version = v.get("auth_version").and_then(|x| x.as_i64()).unwrap_or(1);
        Some(Self {
            id_b64,
            priv_scalar,
            auth_version,
        })
    }

    /// Build `{"cmd":"AuthSuccess",..}` as the response to the phone's
    /// `OdmfAuthResponse` — mirror of SigIdentityAuthHelper
    /// .signalingServerAuthSuccessResponse (odmf.jar odmfr/odmfe.java):
    /// AES-256-GCM (tag 128, iv 12B for auth_version=1) under the raw
    /// ECDH(shared X) secret, AAD = the timestamp string, plaintext
    /// `{"id":<PC id b64>,"key":<PC-chosen 32B AES key b64>}` — the phone
    /// adopts that key for all later encrypted frames. The peer's own
    /// response plaintext is raw id bytes, not JSON.
    #[allow(deprecated)] // aead 0.6 nonce ctor (same pattern as kms::gcm_seal)
    fn auth_success_json(&self, resp: &serde_json::Value) -> Option<(String, [u8; 32])> {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
        use p256::PublicKey;
        use rand::Rng;
        // Live transcript 17:57:25Z: the phone nests the SigIdentityAuthHelper
        // auth fields as an *escaped JSON string* under "auth_info", beside
        // local/remote transport-bus ids. Accept both nestings.
        let src = match resp.get("auth_info") {
            Some(serde_json::Value::String(s)) => {
                match serde_json::from_str::<serde_json::Value>(s) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("[odmf] auth: auth_info not JSON: {e}");
                        return None;
                    }
                }
            }
            Some(v) => v.clone(),
            None => resp.clone(),
        };
        for k in ["public_key", "iv", "encrypt_cipher", "timestamp"] {
            if src.get(k).is_none() {
                tracing::warn!(
                    "[odmf] auth: missing field {k}, have {:?}",
                    src.as_object().map(|m| m.keys().collect::<Vec<_>>())
                );
                return None;
            }
        }
        let pk_b64 = src.get("public_key")?.as_str()?;
        let iv_b64 = src.get("iv")?.as_str()?;
        let ct_b64 = src.get("encrypt_cipher")?.as_str()?;
        let ts = src.get("timestamp")?.as_str()?.to_string();
        let pk_der = b64std(pk_b64)?;
        // Ground truth (odmf.jar odmfi/odmfg::odmfb "decryptForIphone"): the
        // phone's public_key is a 65-byte raw uncompressed point
        // (0x04||X||Y), parsed via ECPoint — SPKI only appears in the
        // PC-generated auth info. Accept both.
        let peer_sec1: &[u8] = if pk_der.len() == 65 && pk_der[0] == 0x04 {
            &pk_der
        } else {
            match spki_to_sec1(&pk_der) {
                Some(s) => s,
                None => {
                    tracing::warn!("[odmf] auth: bad peer public_key framing (len {})", pk_der.len());
                    return None;
                }
            }
        };
        let peer_pub = PublicKey::from_sec1_bytes(peer_sec1)
            .map_err(|_| tracing::warn!("[odmf] auth: bad peer public_key"))
            .ok()?;
        let scalar = p256::NonZeroScalar::try_from(self.priv_scalar.as_slice()).ok()?;
        let shared = p256::elliptic_curve::ecdh::diffie_hellman(scalar, peer_pub.as_affine());
        let key = shared.raw_secret_bytes().to_vec();
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        // peer's inner payload: {"id":<phone id>,"key":<K>} (verifiable, but
        // we only need to echo K back authenticated)
        let ct = b64std(ct_b64)?;
        let iv_in = b64std(iv_b64)?;
        // Ground truth (odmfi/odmfg::odmfb): Java `Cipher("AES/GCM/NoPadding",
        // GCMParameterSpec(128, iv))` with `updateAAD(timestamp)` iff the
        // timestamp string is non-null — the IV is GCM's arbitrary length
        // (the phone sends 16 B), NOT a CBC block. Key = raw ECDH X bytes.
        use aes_gcm::aead::consts::{U12, U16};
        let try_open = |with_aad: bool| -> Option<Vec<u8>> {
            let aad: &[u8] = if with_aad { ts.as_bytes() } else { b"" };
            match iv_in.len() {
                12 => gcm_open::<U12>(&key, &iv_in, aad, &ct),
                16 => gcm_open::<U16>(&key, &iv_in, aad, &ct),
                n => {
                    tracing::warn!("[odmf] auth: unsupported GCM iv len {n}");
                    None
                }
            }
        };
        let plain = try_open(true).or_else(|| try_open(false)).unwrap_or_else(|| {
            tracing::warn!("[odmf] auth: peer cipher GCM open fail (iv {}B)", iv_in.len());
            Vec::new()
        });
        if plain.is_empty() {
            return None;
        }
        // Ground truth (SigIdentityAuthHelper.getAuthInfo, odmf.jar
        // odmfr/odmfe.java): the peer's encrypt_cipher plaintext is the raw
        // near-field ID bytes, NOT JSON — only OUR AuthSuccess plaintext is
        // the JSON {"id","key"} pair. Log it for forensics and move on.
        tracing::info!(
            "[odmf] auth: peer cipher opened, plaintext {}B {:?}",
            plain.len(),
            String::from_utf8_lossy(&plain)
        );
        // server response (fresh iv, timestamp, same shared key). The phone
        // does setKey(b64decode(json.key)) on this and uses it for every
        // later encrypted signaling frame (SigIdentityAuthHelper
        // signalingServerAuthSuccessAction), so the PC picks the key. The
        // phone keeps ONE SigIdentityAuthHelper across the two sockets it
        // dials (live 18:27:46Z: the second AuthSuccess overwrote the first
        // socket's adopted key, and that socket's PairSuccess then died in
        // onSocketMessage with a JSONException) — so the key must be picked
        // once and echoed identically on both sockets.
        static MEDIA_KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        let media_key = *MEDIA_KEY.get_or_init(|| {
            let mut k = [0u8; 32];
            rand::rng().fill_bytes(&mut k);
            k
        });
        let key_b64 = b64s(&media_key);
        tracing::info!(
            "[odmf] auth: media key selected (32B, b64={key_b64}) — future encrypted frames use it"
        );
        let inner_out = format!("{{\"id\":\"{}\",\"key\":\"{}\"}}", self.id_b64, key_b64);
        let ts_out = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis()
            .to_string();
        // NearFieldAuthInfo.getEncryptIvBitSize: v1 ⇒ 12, else 16.
        let mut iv = vec![0u8; if self.auth_version == 1 { 12 } else { 16 }];
        rand::rng().fill_bytes(&mut iv);
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: inner_out.as_bytes(),
                    aad: ts_out.as_bytes(),
                },
            )
            .ok()?;
        let local_bus = resp
            .get("local_transportbus_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        Some((
            format!(
                "{{\"timestamp\":\"{ts_out}\",\"iv\":\"{}\",\"cmd\":\"AuthSuccess\",\"encrypt_cipher\":\"{}\",\"auth_version\":{},\"local_transportbus_id\":\"lplus\",\"remote_transportbus_id\":\"{local_bus}\"}}",
                b64s(&iv),
                b64s(&sealed),
                src.get("auth_version")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(self.auth_version)
            ),
            media_key,
        ))
    }
}

/// Trim long values so key material never lands in the log (§7.9 redaction).
fn redact(json: &str) -> String {
    let mut s = json.to_string();
    if s.len() > 200 {
        s.truncate(197); // '…' is 3 bytes
        s.push('…');
    }
    s
}

/// Parse one RTSP request from the head of `buf` if complete and recognizable.
fn try_parse_request(buf: &[u8]) -> Option<(RtspMsg, usize)> {
    if buf.len() < 16 {
        return None;
    }
    let head = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let first =
        std::str::from_utf8(&buf[..buf.iter().position(|b| *b == b'\r').unwrap_or(head)]).ok()?;
    if !first.contains("RTSP/1.0") {
        return None;
    }
    if !RtspMethod::iter().any(|m| first.starts_with(m.as_ref())) {
        return None;
    }
    RtspMsg::parse(buf).ok()
}

/// Minimal WFD-sink answers; values are deliberately conservative and are
/// iterated against the live engine (see §7.9 transcript).
fn build_replies(req: &RtspMsg, session_hdr: &mut Option<String>) -> Vec<RtspMsg> {
    let cseq: u32 = req
        .header("CSeq")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1);
    let mut rsp = RtspMsg::response(200, "OK", cseq, None, &[]);
    match req.method_enum() {
        Some(RtspMethod::Options) => rsp.headers.push((
            "Public".into(),
            "org.wfa.wfd1.0, GET_PARAMETER, SET_PARAMETER, SETUP, PLAY, TEARDOWN".into(),
        )),
        Some(RtspMethod::GetParameter) => {
            // WFD capability exchange: echo requested params (values we can
            // honour), pin our RTP sink port, no HDCP.
            let asked = String::from_utf8_lossy(&req.body).to_string();
            let mut body = String::new();
            for line in asked.lines() {
                let Some((k, v)) = line.split_once(':') else {
                    continue;
                };
                let k = k.trim();
                let v = match k.to_ascii_lowercase().as_str() {
                    "wfd_content_protection" => "none".to_string(),
                    "wfd_uibc_capability" => "none".to_string(),
                    "wfd_display_edid" => String::new(), // omit: no EDID
                    _ => v.trim().to_string(),           // echo the source's value
                };
                if !v.is_empty() {
                    body.push_str(&format!("{k}: {v}\r\n"));
                }
            }
            if body.is_empty() {
                body.push_str("wfd_content_protection: none\r\n");
            }
            // Always advertise our RTP sink (source may omit the ask).
            body.push_str(&format!(
                "wfd_client_rtp_ports: RTP/AVP/UDP;unicast {} 0 mode=play\r\n",
                std::env::var("ODMF_RTP_PORT")
                    .ok()
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(15550)
            ));
            let bytes = body.into_bytes();
            rsp.headers
                .push(("Content-Type".into(), "text/parameters".into()));
            rsp.headers
                .push(("Content-Length".into(), bytes.len().to_string()));
            rsp.body = bytes;
        }
        Some(RtspMethod::Setup) => {
            let id = format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32 & 0x7fff_ffff)
                    .unwrap_or(1234)
            );
            *session_hdr = Some(format!("{id};timeout=60"));
            if let Some(t) = req.header("Transport") {
                rsp.headers.push(("Transport".into(), t.to_string()));
            }
            rsp.headers
                .push(("Session".into(), session_hdr.clone().unwrap()));
            tracing::info!(
                "[odmf] SETUP transport={:?} — awaiting RTP",
                req.header("Transport")
            );
        }
        Some(RtspMethod::Play) => {
            if let Some(s) = session_hdr.clone() {
                rsp.headers.push(("Session".into(), s));
            }
            rsp.headers.push((
                "RTP-Info".into(),
                format!("url={};seq=1;rtptime=0", req.uri),
            ));
            rsp.headers.push(("Range".into(), "npt=0.000-".into()));
            tracing::info!("[odmf] PLAY acked — expecting RTP now");
        }
        Some(RtspMethod::Teardown) => rsp.reason = Some("bye".into()),
        // Unknown/extension methods and responses: bare 200.
        _ => {}
    }
    vec![rsp]
}

// ------------------------------------------------- H.265 depacketizer ----

/// RFC 7798 aggregation (AP=32) / fragmentation (FU=33) units, plus the
/// vendor variants 49/48 the ODMF engine is known to emit. H.265 NAL headers
/// are 2 bytes; FU packets carry a 2-octet FU indicator + 1-octet FU header.
#[derive(Default)]
pub struct H265Depacketizer {
    fu: Vec<u8>,
    fu_type: u8,
    fu_active: bool,
}

impl H265Depacketizer {
    /// Feed one RTP payload; returns complete Annex-B AUs (may be empty).
    pub fn push(&mut self, payload: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if payload.len() < 3 {
            self.fu_active = false;
            return out;
        }
        let t = (payload[0] >> 1) & 0x3F;
        if matches!(t, 46..=49) {
            // Vendor FU (the phone emits type 49; 46/47/48 accepted too):
            // [ind0][ind1][fu-hdr][data…]
            let fuh = payload[2];
            let start = fuh & 0x80 != 0;
            let end = fuh & 0x40 != 0;
            let ot = fuh & 0x3F;
            if start {
                self.fu.clear();
                self.fu_type = ot;
                self.fu_active = true;
                // Rebuild 2-byte NAL header from indicator + FU header.
                self.fu.push((payload[0] & 0x81) | (ot << 1));
                self.fu.push(payload[1]);
                self.fu.extend_from_slice(&payload[3..]);
            } else if self.fu_active && ot == self.fu_type {
                self.fu.extend_from_slice(&payload[3..]);
            } else {
                self.fu.clear(); // mid-FU without context: drop
                self.fu_active = false;
                return out;
            }
            if self.fu.len() > MAX_NAL {
                self.fu.clear();
                self.fu_active = false;
                return out;
            }
            if end && !self.fu.is_empty() {
                let mut au = Vec::with_capacity(self.fu.len() + 4);
                au.extend_from_slice(START_CODE);
                au.append(&mut self.fu);
                self.fu_active = false;
                out.push(au);
            }
        } else {
            // Single NAL unit packet (the phone sends VPS/SPS/PPS/slices
            // singly; there is no aggregation packet in this stream).
            self.fu.clear();
            self.fu_active = false;
            let mut au = Vec::with_capacity(payload.len() + 4);
            au.extend_from_slice(START_CODE);
            au.extend_from_slice(payload);
            out.push(au);
        }
        out
    }
}

// ---------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtsp::parse_rtp;

    /// Regression: reproduce Java `BtIdentityAuthHelper` (odmfi/odmfg::odmfb)
    /// exactly — raw 65-B uncompressed peer point, raw ECDH X as AES-256 key,
    /// AES/GCM/NoPadding tag-128 with the phone's arbitrary-length (16 B) IV
    /// and updateAAD(timestamp) — and verify our AuthSuccess reply.
    #[test]
    fn auth_success_opens_phone_gcm_cipher_and_picks_media_key() {
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes256Gcm, KeyInit};
        use base64::Engine as _;
        use base64::engine::general_purpose;
        use p256::SecretKey;

        let mut pc_scalar = [0u8; 32];
        pc_scalar[31] = 7;
        let pc_secret = SecretKey::from_bytes(&pc_scalar.into()).expect("pc key");
        let a = OdmfAuth {
            id_b64: b64s(b"lplus-pc-1"),
            priv_scalar: pc_scalar,
            auth_version: 1,
        };

        let phone = SecretKey::from_bytes(&[9u8; 32].into()).expect("phone key");
        let phone_pub = phone.public_key();
        let peer_b64 = general_purpose::STANDARD.encode(phone_pub.to_sec1_bytes());
        let shared = p256::elliptic_curve::ecdh::diffie_hellman(
            phone.to_nonzero_scalar(),
            pc_secret.public_key().as_affine(),
        );
        let key = shared.raw_secret_bytes().to_vec();
        assert_eq!(
            key.as_slice(),
            p256::elliptic_curve::ecdh::diffie_hellman(
                p256::NonZeroScalar::try_from(pc_scalar.as_slice()).expect("pc nz"),
                p256::PublicKey::from_sec1_bytes(&phone_pub.to_sec1_bytes())
                    .expect("peer")
                    .as_affine(),
            )
            .raw_secret_bytes()
            .as_slice(),
            "both directions derive the same raw X key"
        );

        let ts = "1794247520934";
        let iv = vec![0xABu8; 16];
        // SigIdentityAuthHelper.getAuthInfo: the peer's plaintext is its raw
        // near-field id bytes — NOT JSON (the old echo assumption).
        let inner = "phone-id-raw-bytes";
        let sealed = gcm_seal::<aes_gcm::aead::consts::U16>(&key, &iv, ts.as_bytes(), inner.as_bytes())
            .expect("seal");
        let auth_info = serde_json::json!({
            "timestamp": ts,
            "iv": general_purpose::STANDARD.encode(&iv),
            "encrypt_cipher": general_purpose::STANDARD.encode(&sealed),
            "public_key": peer_b64,
            "auth_version": 1,
        })
        .to_string();
        let resp = serde_json::json!({
            "cmd": "OdmfAuthResponse",
            "auth_info": auth_info,
            "local_transportbus_id": "0000006734474",
        });

        let (out, picked_key) = a.auth_success_json(&resp).expect("AuthSuccess built");
        let v: serde_json::Value = serde_json::from_str(&out).expect("valid json");
        assert_eq!(v["cmd"], "AuthSuccess");
        assert_eq!(v["remote_transportbus_id"], "0000006734474");
        let out_key = v["encrypt_cipher"].as_str().expect("cipher field");
        let sealed_out = general_purpose::STANDARD.decode(out_key).expect("b64");
        let iv_out = general_purpose::STANDARD
            .decode(v["iv"].as_str().expect("iv field"))
            .expect("b64");
        let ts_out = v["timestamp"].as_str().expect("ts");
        let nonce: aes_gcm::aead::array::Array<u8, aes_gcm::aead::consts::U12> =
            iv_out.as_slice().try_into().expect("12-byte iv");
        let plain = Aes256Gcm::new_from_slice(&key)
            .expect("cipher")
            .decrypt(
                &nonce,
                Payload {
                    msg: &sealed_out,
                    aad: ts_out.as_bytes(),
                },
            )
            .expect("phone can open our AuthSuccess");
        let echoed: serde_json::Value = serde_json::from_slice(&plain).expect("inner json");
        assert_eq!(echoed["id"], a.id_b64, "PC echoes its own near-field id");
        let media_key = general_purpose::STANDARD
            .decode(echoed["key"].as_str().expect("key field"))
            .expect("key is b64");
        assert_eq!(
            media_key, picked_key.to_vec(),
            "the phone adopts b64decode(json.key); the session must seal replies with the very same bytes"
        );
        assert_eq!(media_key.len(), 32, "PC picks a 256-bit media key");
    }

    /// Live wire regression (18:24:38Z, socket to :7236 from the phone): the
    /// first post-auth frame from CPH2745 — the ODMF PairRequest, sealed by
    /// SigIdentityAuthHelper.getEncryptMsg under the media key we offered in
    /// AuthSuccess. If this stops opening, the sink silently drops pairing.
    #[test]
    fn decrypts_live_phone_pair_request() {
        let key: [u8; 32] = b64std("b/2WmsTae8aqIAPU1QNhrW8Rhr73mpZBOmWF6azoKn8=")
            .expect("key b64")
            .try_into()
            .expect("32B key");
        let payload = hex::decode(
            "013137393432343836373734363666231ba62358544aada4a6a61c0483c09913aa9f71df8c82d2\
             0a40ecae859518ff39950bd382d7ae0cf24e5de6bcfd796b029cbd5b",
        )
        .expect("hex");
        assert_eq!(payload.len(), 67);
        let plain = decrypt_enc_frame(&key, &payload).expect("phone PairRequest opens");
        assert_eq!(plain, "{\"cmd\":\"PairRequest\"}");
        // and the framed variant consumed off the socket accumulator
        let mut buf = Vec::new();
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(&payload);
        let (p2, used) = try_parse_enc_frame(&buf, Some(&key)).expect("framed");
        assert_eq!(p2, plain);
        assert_eq!(used, buf.len());
        // no key yet ⇒ frame must stay buffered, not be consumed
        assert!(try_parse_enc_frame(&buf, None).is_none());
    }

    /// notifyClientPairSuccess pairs the phone's A/B sockets crosswise: the
    /// PairSuccess for socket A must carry socket B's announced identity.
    #[test]
    fn peer_registry_cross_assigns_pair_success_ids() {
        peer_note("192.0.2.13", "busA", "heycast_odmf", "uidA");
        peer_note("192.0.2.13", "busB", "heycast_odmf2", "uidB");
        peer_note("192.0.2.13", "busB", "dup", "dup"); // dedupe
        assert_eq!(
            peer_other("192.0.2.13", "busA"),
            ("busB".to_string(), "heycast_odmf2".to_string(), "uidB".to_string())
        );
        assert_eq!(
            peer_other("192.0.2.13", "busB").0,
            "busA",
            "second socket must receive the first socket's identity"
        );
        // unknown peer falls back to its own id
        assert_eq!(peer_other("192.0.2.14", "solo").0, "solo");
    }

    #[test]
    fn encrypt_frame_roundtrips_through_decrypt() {
        let key = [0x5au8; 32];
        let msg = "{\"cmd\":\"PairSuccess\",\"remote_transportbus_id\":\"87179489\"}";
        let payload = encrypt_frame(&key, msg).expect("seal");
        assert_eq!(payload[0], 1);
        assert!(payload[1..14].iter().all(u8::is_ascii_digit));
        assert_eq!(decrypt_enc_frame(&key, &payload).as_deref(), Some(msg));
        // wrong key must not open
        assert!(decrypt_enc_frame(&[0x11u8; 32], &payload).is_none());
    }

    #[test]
    fn prelude_frames_env_and_default() {
        let f = prelude_frames_from(Some(
            r#"["{\"cmd\":\"a\"}","{\"cmd\":\"b\"}"]"#.to_string(),
        ));
        assert_eq!(f.len(), 2);
        assert!(f[0].contains("\"a\"") && f[1].contains("\"b\""));
        assert!(prelude_frames_from(Some("not json".to_string())).is_empty());
        let d = prelude_frames_from(None);
        assert_eq!(d.len(), 1);
        assert!(d[0].contains("OdmfAuthRequest"));
    }

    /// Guards the live keystore pair used by odmf_push.py: scalar parsed from
    /// the SEC1 PEM must derive the b64 X509 public key we hand the phone.
    #[test]
    fn odmf_keystore_pair_matches() {
        let (Ok(pem), Ok(pub_b64)) = (
            std::fs::read_to_string("/tmp/odmf_priv.pem"),
            std::fs::read_to_string("/tmp/odmf_pub.b64"),
        ) else {
            return; // keystore not provisioned on this machine
        };
        let scalar = p256_scalar_from_pem(&pem).expect("scalar from pem");
        let sk = p256::SecretKey::from_bytes((&scalar).into()).expect("valid scalar");
        let der = b64std(pub_b64.trim()).expect("pub b64");
        let peer = p256::PublicKey::from_sec1_bytes(spki_to_sec1(&der).expect("spki"))
            .expect("peer pub parse");
        assert_eq!(
            p256::PublicKey::from(&sk).to_sec1_bytes(),
            peer.to_sec1_bytes()
        );
    }

    fn rtp_payload(pts: &[u8]) -> Vec<u8> {
        // minimal RTP fixed header (V=2, PT 96, seq 1, ts, ssrc) + payload
        let mut p = vec![0x80, 96, 0, 1, 0, 0, 0x0b, 0xad, 0x0c, 0xfe, 0xe, 0xd0];
        p.extend_from_slice(pts);
        p
    }

    #[test]
    fn h265_single_nal_passthrough() {
        let mut d = H265Depacketizer::default();
        // type 19 (IDR_W_RADL): b0 = 19<<1 = 0x26
        let aus = d.push(&[0x26, 0x01, 0xAA, 0xBB]);
        assert_eq!(aus.len(), 1);
        assert_eq!(aus[0], b"\x00\x00\x00\x01\x26\x01\xAA\xBB".to_vec());
    }

    #[test]
    fn h265_fu_reassembles_two_octet_header() {
        let mut d = H265Depacketizer::default();
        // Live phone FU indicator: type 49 → 49<<1 = 0x62, ind1 = 0x01.
        let f1 = d.push(&[0x62, 0x01, 0x80 | 19, 0xAA, 0xBB]); // S, orig type 19
        assert!(f1.is_empty());
        let f2 = d.push(&[0x62, 0x01, 0x40 | 19, 0xCC]); // E
        assert_eq!(f2.len(), 1);
        // Rebuilt NAL header: b0 = (0x62 & 0x81) | (19<<1) = 0x26, b1 = 0x01.
        assert_eq!(f2[0], b"\x00\x00\x00\x01\x26\x01\xAA\xBB\xCC".to_vec());
    }

    #[test]
    fn h265_fu_vendor_variant_48() {
        let mut d = H265Depacketizer::default();
        // vendor FU type 48 → ind0 = 48<<1 = 0x60
        d.push(&[0x60, 0x01, 0x80 | 21, 0x11]);
        let f2 = d.push(&[0x60, 0x01, 0x40 | 21, 0x22]);
        assert_eq!(f2.len(), 1);
        assert_eq!(f2[0], b"\x00\x00\x00\x01\x2A\x01\x11\x22".to_vec());
    }

    #[test]
    fn h265_fu_mid_fragment_without_context_is_dropped() {
        let mut d = H265Depacketizer::default();
        assert!(d.push(&[0x62, 0x01, 0x40 | 19, 0xCC]).is_empty()); // E, no S
        assert!(d.fu.is_empty() && !d.fu_active);
    }

    #[test]
    fn h265_param_sets_pass_through_singly() {
        // Live stream: VPS/SPS/PPS arrive as single NAL packets (types
        // 32/33/34) — they must not be consumed as FU indicators.
        let mut d = H265Depacketizer::default();
        let sps = [0x42, 0x01, 0x01, 0x01, 0x60, 0x00, 0x03, 0x00, 0xb0];
        let aus = d.push(&sps);
        assert_eq!(aus.len(), 1);
        assert_eq!(aus[0], [b"\x00\x00\x00\x01".to_vec(), sps.to_vec()].concat());
        let pps = [0x44, 0x01, 0xc1, 0xe3, 0x0f, 0x09, 0x41, 0xef, 0x61, 0x28];
        let aus = d.push(&pps);
        assert_eq!(aus.len(), 1);
        assert_eq!(aus[0], [b"\x00\x00\x00\x01".to_vec(), pps.to_vec()].concat());
    }

    #[test]
    fn h265_interleaved_single_nal_resets_fu() {
        let mut d = H265Depacketizer::default();
        d.push(&[0x62, 0x01, 0x80 | 19, 0xAA]); // S
        let one = d.push(&[0x26, 0x01, 0x55]); // single NAL resets
        assert_eq!(one.len(), 1);
        // trailing E with no context must not resurrect the stale FU
        assert!(d.push(&[0x62, 0x01, 0x40 | 19, 0xBB]).is_empty());
    }

    #[test]
    fn try_parse_frames_only_known_methods() {
        let req = b"GET_PARAMETER rtsp://192.0.2.1:7236/wfd1.0 RTSP/1.0\r\n\
                    CSeq: 3\r\nContent-Length: 22\r\n\r\nwfd_video_formats: x\r\n"
            .to_vec();
        let (m, used) = try_parse_request(&req).unwrap();
        assert_eq!(m.method_enum(), Some(RtspMethod::GetParameter));
        assert_eq!(used, req.len());
        assert!(try_parse_request(b"nonsense bytes 0123456789abcdef").is_none());
        // partial headers → not yet
        assert!(try_parse_request(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n").is_none());
    }

    #[test]
    fn json_frame_framing_and_pong_reply() {
        let mut f = Vec::new();
        let p = "{\"cmd\":\"ping\"}";
        f.extend_from_slice(&(p.len() as u16).to_be_bytes());
        f.extend_from_slice(p.as_bytes());
        let (json, used) = try_parse_json_frame(&f).unwrap();
        assert_eq!(json, p);
        assert_eq!(used, f.len());
        assert_eq!(json_reply(&json).unwrap(), "{\"cmd\":\"pong\"}");
        assert!(json_reply("{\"cmd\":\"start\",\"x\":1}").is_none());
        // short/partial buffers
        assert!(try_parse_json_frame(&[0x00, 0x0e, b'{']).is_none());
        assert!(try_parse_json_frame(&[0x10, 0x20, b'{', b'}']).is_none()); // len 4152>8192? no: >cap path
        // redact caps long payloads
        let long = format!("{{\"k\":\"{}\"}}", "A".repeat(400));
        assert!(redact(&long).len() <= 201);
    }

    #[test]
    fn get_parameter_reply_carries_rtp_ports() {
        let mut req = RtspMsg::request(RtspMethod::GetParameter, "rtsp://x/wfd1.0", 4, &[]);
        req.body = b"wfd_content_protection: HDCP2.1\r\n".to_vec();
        let mut sess = None;
        let rs = build_replies(&req, &mut sess);
        assert_eq!(rs[0].status, Some(200));
        let body = String::from_utf8(rs[0].body.clone()).unwrap();
        assert!(body.contains("wfd_content_protection: none"), "{body}");
        assert!(
            body.contains("wfd_client_rtp_ports: RTP/AVP/UDP;unicast"),
            "{body}"
        );
    }

    #[test]
    fn setup_play_reply_chain_covers_session() {
        let mut sess = None;
        let mut setup = RtspMsg::request(RtspMethod::Setup, "rtsp://x/wfd1.0/streamid=0", 5, &[]);
        setup.headers.push((
            "Transport".into(),
            "RTP/AVP/UDP;unicast;client_port=15550-15551".into(),
        ));
        let rs = build_replies(&setup, &mut sess);
        assert_eq!(
            rs[0].header("Transport").unwrap(),
            "RTP/AVP/UDP;unicast;client_port=15550-15551"
        );
        assert!(
            rs[0]
                .header("Session")
                .unwrap()
                .starts_with(|c: char| c.is_ascii_digit())
        );
        let play = RtspMsg::request(RtspMethod::Play, "rtsp://x/wfd1.0/streamid=0", 6, &[]);
        let rs = build_replies(&play, &mut sess);
        assert!(rs[0].header("RTP-Info").unwrap().contains("seq=1"));
        // rtp payload helper sanity
        let p = rtp_payload(&[0x26, 0x01]);
        assert_eq!(parse_rtp(&p).unwrap().pt, 96);
    }
}
