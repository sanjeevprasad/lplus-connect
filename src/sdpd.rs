//! pantaconnect LAN SDP (`sdp/1`) responder.
//!
//! The phone advertises its presence plane on UDP 10150 joined to the SSDP
//! multicast group and listens on 10151 (see `AccessoryFramework.apk`
//! `pantaconnect.discovery.adapter.lan`). It periodically sends
//! `QUERY * HTTP/1.1` with `MAN: "sdp/1"`, `NS: scp.device`, plus the
//! single-letter headers `NS DSP CSP DMS PDID AD DT DN` that both engines
//! validate (`sdp_manager.rs`). We answer queries, announce ourselves as a
//! PC (DT 6) so the phone lists us, and log everything that arrives on the
//! SDP plane and on the TCP session port (CSP) for wire analysis.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use strum::{Display, EnumString};
use tokio::net::{TcpListener, UdpSocket};

/// Configuration for one responder instance.
pub struct SdpdConfig {
    pub ns: String,
    pub pdid: String,
    pub ad: String,
    pub dt: i32,
    pub name: String,
    pub csp: u16,
    pub vip: String,
    pub group: Ipv4Addr,
    pub sdp_port: u16,
    pub uni_port: u16,
    pub log_path: String,
    pub announce_secs: u64,
}

impl Default for SdpdConfig {
    fn default() -> Self {
        Self {
            ns: "scp.device".into(),
            pdid: "A1B2C3D4E5F6".into(),
            ad: "696B95".into(),
            dt: 6,
            name: "L+ PC".into(),
            csp: 8080,
            vip: "192.0.2.1".into(),
            group: Ipv4Addr::new(239, 255, 255, 250),
            sdp_port: 10150,
            uni_port: 10151,
            log_path: "sdp.bin".into(),
            announce_secs: 3,
        }
    }
}

/// `ScpSyncData.modelId` as sent on the wire. Their validator
/// (`appcore/utils/g.java:318`) requires exactly 3 bytes, so the device
/// name must never be used here. Override with `SCP_MODEL`.
fn scp_model() -> String {
    // The phone hex-decodes SyncData.model_id and demands exactly 3 bytes
    // (discovery.ext.a.b); "000" makes it throw 2506.
    std::env::var("SCP_MODEL").unwrap_or_else(|_| "2B1488".to_string())
}

/// Render one sdp/1 message: request/verb line + our identity headers.
pub fn render(verb_line: &str, cfg: &SdpdConfig, extra: &[(&str, &str)]) -> String {
    let mut msg = format!("{verb_line}\r\nMAN: \"sdp/1\"\r\n");
    if !cfg.vip.is_empty() {
        // DiscoveryResultProcessor rejects REGISTER without SA ("No contain
        // SA key in query"); SA is the source address ip:port.
        msg.push_str(&format!("SA: {}\r\n", cfg.vip));
    }
    if !extra.iter().any(|(k, _)| *k == "NS") {
        msg.push_str(&format!("NS: {}\r\n", cfg.ns));
    }
    msg.push_str(&format!("DSP: {}\r\n", cfg.uni_port));
    msg.push_str(&format!("CSP: {}\r\n", cfg.csp));
    msg.push_str("DMS: 0\r\n");
    msg.push_str(&format!("PDID: {}\r\n", cfg.pdid));
    msg.push_str(&format!("AD: {}\r\n", cfg.ad));
    msg.push_str(&format!("DT: {}\r\n", cfg.dt));
    msg.push_str(&format!("DN: {}\r\n", cfg.name));
    // Their cpkit discovery record keeps `modelId` as 3 bytes (TypeTag
    // `ModelId`, hex); SDP peers may carry it as a header. A/B via env.
    if let Ok(mh) = std::env::var("SCP_MODEL_HEX") {
        msg.push_str(&format!("ModelId: {mh}\r\n"));
    }
    msg.push_str(&format!("VIRTUAL_IP: {}\r\n", cfg.vip));
    for (k, v) in extra {
        msg.push_str(&format!("{k}: {v}\r\n"));
    }
    msg.push_str("\r\n");
    msg
}

/// Primary-interface IPv4 address: dial-out trick (no packets leave),
/// falling back to loopback when there is no default route.
pub fn default_vip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:53")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".into())
}

/// The machine's own name: Linux kernel hostname, `/etc/hostname`, or
/// the Windows/Node-style env vars, in that order.
pub fn system_hostname() -> Option<String> {
    let from_file = |p: &str| -> Option<String> {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    from_file("/proc/sys/kernel/hostname")
        .or_else(|| from_file("/etc/hostname"))
        .or_else(|| {
            std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("NODENAME"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
}

/// First line of an sdp/1 datagram: e.g. `QUERY * HTTP/1.1`.
pub fn first_line(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    text.split("\r\n").next().unwrap_or("").to_string()
}

/// lplus-local probe verbs (not in `rtsp::RtspMethod`): the sdp/1 QUERY
/// that both engines answer with an ANNOUNCE line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "UPPERCASE")]
enum ProbeVerb {
    Query,
}

/// Reply shapes to try for a request verb, mirroring the acceptors the
/// engines validate (`No contain NS key in service-ack`, etc.).
pub fn reply_variants(verb: &str) -> Vec<(String, Vec<(&'static str, &'static str)>)> {
    let mut out = vec![
        (format!("{verb}-ACK * HTTP/1.1"), vec![("NSData", "0")]),
        ("HTTP/1.1 200 OK".into(), vec![("NSData", "0")]),
        ("ANNOUNCE * HTTP/1.1".into(), vec![]),
    ];
    if ProbeVerb::from_str(verb) != Ok(ProbeVerb::Query) {
        out.retain(|(line, _)| !line.starts_with(proto::rtsp::RtspMethod::Announce.as_ref()));
    }
    out
}

/// Per-peer KSC bond, vendor parity. The PC generates `ksc` (16 B) and
/// `kscAlias` (6 B) once per pairing (`SecureRandom`, vendor
/// `pair/scp/b.java:271-295`), persists them (`ksc_<HEX(deviceId)>` in
/// `cpbus_ksc_storage_*`), and replays both **verbatim** on every later
/// connection: the phone only writes its `KscRepository` row inside a
/// user-confirmed pairing (`ScpLanConnectionCallback.persistKscAfterUserConfirm`)
/// and authenticates the channel lane against the stored copy, so any key
/// rotation outside a fresh pairing is a self-inflicted
/// `Session KSC not match` / AUTH `mac check: false`.
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct KscRecord {
    pub device_id: String,
    pub alias: String,
    pub ksc: String,
}

fn ksc_store() -> std::collections::HashMap<String, KscRecord> {
    std::fs::read(crate::state::ksc_store_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn ksc_stored(peer_key: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let r = ksc_store().remove(peer_key)?;
    let ksc = hex::decode(&r.ksc).ok()?;
    let alias = hex::decode(&r.alias).ok()?;
    (ksc.len() == 16 && alias.len() == 6).then_some((ksc, alias))
}

fn ksc_store_put(peer_key: &str, device_id: &str, ksc: &[u8], alias: &[u8]) {
    tracing::info!(
        "[ksc] bond {peer_key} dev={device_id} ksc={} alias={}",
        hex::encode(ksc),
        hex::encode(alias)
    );
    let mut store = ksc_store();
    store.insert(
        peer_key.to_string(),
        KscRecord {
            device_id: device_id.to_string(),
            alias: hex::encode(alias),
            ksc: hex::encode(ksc),
        },
    );
    if let Ok(json) = serde_json::to_vec_pretty(&store) {
        let _ = std::fs::write(crate::state::ksc_store_path(), json);
    }
}

fn ksc_rand(n: usize) -> Vec<u8> {
    use rand::Rng;
    let mut v = vec![0u8; n];
    rand::rng().fill_bytes(&mut v);
    v
}

/// Operator pin: `SCP_KSC` hex forces the key for every peer (pairing
/// material restored from `settings.json` arrives here via the seed).
fn ksc_pin() -> Option<Vec<u8>> {
    std::env::var("SCP_KSC")
        .ok()
        .and_then(|h| hex::decode(h.trim().replace(':', "")).ok())
        .filter(|v| v.len() == 16)
}

/// The key pair to present to (and verify against) `peer_key`. Stored
/// bond wins so resumption always replays what the phone persisted; a
/// first pairing mints the random pair and persists it (vendor `b.java`
/// behavior). `SCP_KSC` pins over everything for restored bonds.
pub(crate) fn issue_ksc(peer_key: &str, device_id: &str) -> (Vec<u8>, Vec<u8>) {
    if let Some(pair) = ksc_stored(peer_key) {
        return pair;
    }
    let ksc = ksc_pin().unwrap_or_else(|| ksc_rand(16));
    let alias = ksc_rand(6);
    ksc_store_put(peer_key, device_id, &ksc, &alias);
    (ksc, alias)
}

/// Persist an accepted verification key under `peer_key`, keeping the
/// alias already bonded to it (AUTH proves possession of the bond, so
/// adopting the peer's claimed device id here is safe and self-heals the
/// store on first successful auth).
pub(crate) fn remember_ksc(peer_key: &str, device_id: &str, ksc: &[u8]) {
    let alias = ksc_stored(peer_key).map_or_else(|| ksc_rand(6), |(_, a)| a);
    ksc_store_put(peer_key, device_id, ksc, &alias);
}

/// Keys we may have bonded with this peer, in trust order: the bond
/// stored for the peer socket, then the bond stored under the device id
/// it claims. AUTH succeeds only against a bond we handed out — an
/// unpaired peer gets no response and the phone surfaces `KSC_ERROR`,
/// which is the correct nudge to re-pair.
pub(crate) fn ksc_candidates(peer_key: &str, dev_key: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for key in [peer_key, dev_key] {
        if let Some((ksc, _)) = ksc_stored(key)
            && !out.contains(&ksc)
        {
            out.push(ksc);
        }
    }
    // The settings-restored pin (main.rs seeds SCP_KSC from settings.json)
    // must keep verifying until a successful AUTH promotes it into a bond.
    if let Some(k) = ksc_pin() {
        out.push(k);
    }
    out
}

/// `datatrans/security/a.d`: `HmacSHA512(ksc, data)[0..8]` (the truncated
/// challenge MAC used for `s`/`t` auth proofs).
fn ksc_mac8(ksc: &[u8], data: &[u8]) -> [u8; 8] {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha512;
    let mut m = Hmac::<Sha512>::new_from_slice(ksc).expect("hmac key");
    m.update(data);
    let r = m.finalize().into_bytes();
    let mut o = [0u8; 8];
    o.copy_from_slice(&r[..8]);
    o
}

fn be8(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

/// Capability-exchange QUERY: `01 | queryType u8 | checksum u32be (present
/// iff queryType==3) | recordNum u8 | recordNum x (profileId UTF-8 + 0x3B)`.
/// Mirrors `wf/i.d(3, 0, list)` + `datatrans/service/f.y()` composer; the
/// phone parses it in `datatrans/service/f.k` via `security.d`.
pub(crate) fn capex_query(profiles: &[&str]) -> Vec<u8> {
    let mut q: Vec<u8> = vec![0x01, 0x03, 0, 0, 0, 0, profiles.len() as u8];
    for p in profiles {
        q.extend_from_slice(p.as_bytes());
        q.push(0x3b);
    }
    q
}

/// Capability-exchange CONFIRM: `04 | accessoryId u16be | statusCode u8`.
/// Phone (`f.i`) only enforces statusCode == 0.
pub(crate) fn capex_confirm(accessory_id: u16, status: u8) -> Vec<u8> {
    vec![0x04, (accessory_id >> 8) as u8, accessory_id as u8, status]
}

/// Rebuild the link-detection reply by mirroring the phone's own probe
/// (bincode `LinkInfoPayloadData`; the phone's decoder is strict — its
/// `local_link_info_decode` rejects hand-built frames with
/// `UnexpectedVariant { type_name: "Option<T>", allowed: 0..1, found: 11 }`).
/// Substitutes our identity in place of the phone's: 12-char PDID string,
/// the `0b 01 fd | mac6` entry (MAC stored little-endian) and the
/// `0b 01 fc | ip` entry (IPv4 stored little-endian). `probe` excludes the
/// 2-byte `[00][len]` header. None when the probe doesn't match the shape.
fn link_reply_mirror(
    probe: &[u8],
    pdid12: &[u8; 12],
    mac6: &[u8; 6],
    ip4: &[u8; 4],
    link_ip4: Option<&[u8; 4]>,
    kpd: &[Vec<u8>],
) -> Option<Vec<u8>> {
    if probe.len() < 40 || probe[0] != 0x0c {
        return None;
    }
    let mut r = probe.to_vec();
    r[1..13].copy_from_slice(pdid12);
    // The `0b 01 fd` entry carries the MAC; swap to ours (LE as observed).
    let fdi = r.windows(3).rposition(|w| w == [0x0b, 0x01, 0xfd])?;
    if fdi + 3 + 6 > r.len() {
        return None;
    }
    r[fdi + 3..fdi + 3 + 6].copy_from_slice(&mac6.iter().rev().copied().collect::<Vec<_>>());
    // The `0b 01 fc` entry carries the peer link IPv4 (LE first 4 bytes) —
    // LinkSwitchMgr installs `to <link_ip> dev wlan0 src <vgate>` for it, so
    // publishing our real IP there black-holes every phone->PC TCP lane
    // (no vgate endpoint on this PC). `link_ip4` lets us publish a harmless
    // address for the route while keeping the usable IP in v_gateway below.
    let route_ip = link_ip4.unwrap_or(ip4);
    let fci = r.windows(3).rposition(|w| w == [0x0b, 0x01, 0xfc])?;
    if fci + 3 + 4 > r.len() {
        return None;
    }
    r[fci + 3..fci + 3 + 4].copy_from_slice(&route_ip.iter().rev().copied().collect::<Vec<_>>());
    // The trailing `01 fc | gw6` entry is the peer virtual-gateway IP: the
    // phone stores it in peer_devices and dials the active_connection lane
    // to it (ConnectConfig.peerAddress). Left mirrored, the phone would
    // store its own vgate IP (192.0.2.17) and dial itself -> ksc row
    // lookup inverts (deviceId = phone PDID) and SecurityServerFsm dies with
    // KSC_ERROR/-2104. Publish our IP there instead.
    let fci2 = r.windows(2).rposition(|w| w == [0x01, 0xfc])?;
    if fci2 >= fci && fci2 + 2 + 4 <= r.len() {
        r[fci2 + 2..fci2 + 2 + 4].copy_from_slice(&ip4.iter().rev().copied().collect::<Vec<_>>());
    }
    // `known_peer_devices`: trailing `[count u8][len u8 + id]*` block (79B
    // live frame carried count=1 "A1B2C3D4E5F6"). Echo the peer ids the phone
    // publishes so its response validation reciprocates our membership.
    if !kpd.is_empty() {
        if r.len() > fci2 + 2 + 6 {
            r.truncate(fci2 + 2 + 6);
        }
        let mut t = vec![kpd.len() as u8];
        for id in kpd {
            t.push(id.len() as u8);
            t.extend_from_slice(id);
        }
        r.extend_from_slice(&t);
    }
    Some(r)
}

/// Session-layer frame for the phone's NDSF session reader (`a8/f` ->
/// `le/e` -> `bm/h` -> `ProtocolFrameUtils.parseProtocolHeader`):
/// `[len u16 BE covering header+payload][hdr u16 BE (frameType << 9 |
/// sessionId << 2 | fragmentation)][payload]`. Verified live 2026-11-09:
/// sending the capex QUERY with the bare `[00][len]` EPI framing made the
/// reader consume our first payload bytes as its header
/// (`sessionId: 64, fragmentation: 3` from `01 03`) and drop with
/// `Session Details not present for 64` — sessionId 2 is the capex
/// listener (`f643a`), so the header must encode sid = 2.
fn sess_frame(payload: &[u8], session_id: u16) -> Vec<u8> {
    let hdr: u16 = session_id << 2;
    let l = (payload.len() + 2) as u16;
    let mut v = Vec::with_capacity(4 + payload.len());
    v.extend_from_slice(&l.to_be_bytes());
    v.extend_from_slice(&hdr.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Capex frames ride the session lane unless `EPI_CAPEX_FRAME=bare`.
pub(crate) fn capex_frame(payload: &[u8]) -> Vec<u8> {
    if std::env::var("EPI_CAPEX_FRAME").as_deref() == Ok("bare") {
        dt_frame(payload)
    } else {
        sess_frame(payload, 2)
    }
}

/// SessionDeviceInfoResponse (msgType 101): body is the device name as raw
/// UTF-8 after the msgType byte (`session/a.java:878` reader takes the
/// remainder as `deviceName`). Fills the phone's blank PC card name.
fn session_info_frame(name: &str, session_id: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + name.len());
    body.push(101);
    body.extend_from_slice(name.as_bytes());
    sess_frame(&body, session_id)
}

/// IEEE CRC32 (matches `java.util.zip.CRC32` used by `wf/i.c`).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Wire/bean field values we register for every accessory profile. The
/// phone only log-warns on checksum mismatch (`f.k`/`f.l`), so exact DB
/// parity is not required to reach `initial sync complete`.
const CAPEX_F: i32 = 10;
const CAPEX_ROLE: i32 = 1;
const CAPEX_VER: &str = "1.0";
const CAPEX_PKG: &str = "com.oplus.pantaconnect";
const CAPEX_NAME: &str = "A1B2C3D4E5F6000000000000000000FF";

/// `wf/i.c`: CRC32 over `pkg+profileId+f+i+h+e+l+m` per matched record
/// (sorted), then the received query profile strings (sorted), UTF-8.
fn capex_checksum(profiles: &[&str]) -> u32 {
    let mut rows: Vec<String> = profiles
        .iter()
        .map(|p| format!("{CAPEX_PKG}{p}{CAPEX_F}{CAPEX_ROLE}{CAPEX_VER}000"))
        .collect();
    rows.sort();
    let mut list: Vec<&str> = profiles.to_vec();
    list.sort_unstable();
    let mut s = rows.concat();
    for p in list {
        s.push_str(p);
    }
    crc32(s.as_bytes())
}

/// Capex RESPONSE (`datatrans/service/f.l` on the phone):
/// `02|queryType u8|checksum u32be|recordNum u16be|
///  (pkg+0x3B)(name+0x3B)(count u16be x (version u16be, profileId+0x3B,
///  m u16be, flags u8, f u16be))...` — layout verified byte-for-byte
/// against the phone's own response 2026-11-09 15:49.
pub(crate) fn capex_response(profiles: &[&str]) -> Vec<u8> {
    let mut v: Vec<u8> = vec![0x02, 0x03, 0, 0, 0, 0];
    v.extend_from_slice(&1u16.to_be_bytes());
    v.extend_from_slice(CAPEX_PKG.as_bytes());
    v.push(0x3b);
    v.extend_from_slice(CAPEX_NAME.as_bytes());
    v.push(0x3b);
    v.extend_from_slice(&(profiles.len() as u16).to_be_bytes());
    for p in profiles {
        v.extend_from_slice(&0x0100u16.to_be_bytes()); // h "1.0" -> 1<<8
        v.extend_from_slice(p.as_bytes());
        v.push(0x3b);
        v.extend_from_slice(&0x0100u16.to_be_bytes()); // m
        v.push(0x01); // flags = role & 3
        v.extend_from_slice(&(CAPEX_F as u16).to_be_bytes()); // f
    }
    let ck = capex_checksum(profiles);
    v[2..6].copy_from_slice(&ck.to_be_bytes());
    v
}

/// Frame one datatrans payload honoring `EPI_FRAMING` (default connector
/// 2-byte `[00][len]`; `raw3`/`3b` legacy variants).
fn dt_frame(payload: &[u8]) -> Vec<u8> {
    let l = payload.len() as u16;
    if std::env::var("EPI_FRAMING").as_deref() == Ok("raw3") {
        let mut v = vec![0x00, (l >> 8) as u8, (l & 0xff) as u8];
        v.extend_from_slice(payload);
        v
    } else if std::env::var("EPI_FRAMING").as_deref() == Ok("3b") {
        let mut crc: u16 = 0;
        for &b in payload {
            crc = CRC16_TABLE[((crc as u8) ^ b) as usize] ^ (crc >> 8);
        }
        let mut v = vec![0x00, (l >> 8) as u8, (l & 0xff) as u8, 0, 0, 0];
        v.extend_from_slice(payload);
        v.push((crc >> 8) as u8);
        v.push((crc & 0xff) as u8);
        v.push(0);
        v
    } else {
        let mut v = vec![0x00, payload.len() as u8];
        v.extend_from_slice(payload);
        v
    }
}

/// datatrans/security/b.s: mac over `challengeCode || time u64 LE`.
/// (Wire `n()` writes time BE, but the mix loops in `s`/`t` shift by
/// `v*8` with v ascending — LE; pinned by the live AUTH_REQUEST vector.)
pub(crate) fn ksc_s(ksc: &[u8], code: &[u8], ts: u64) -> [u8; 8] {
    let mut d = code.to_vec();
    d.extend_from_slice(&ts.to_le_bytes());
    ksc_mac8(ksc, &d)
}

/// datatrans/security/b.t: server proof over `qc || qs || time u64 LE`.
/// (Caller stores 16B "sessionKey" as `Rs || zeros8` — Arrays.copyOfRange
/// pads the 8-byte MAC, mirroring the phone.)
pub(crate) fn ksc_t(ksc: &[u8], qc: &[u8], qs: &[u8], ts: u64) -> [u8; 8] {
    let mut d = qc.to_vec();
    d.extend_from_slice(qs);
    d.extend_from_slice(&ts.to_le_bytes());
    ksc_mac8(ksc, &d)
}

const fn crc16_table() -> [u16; 256] {
    // Reflected CRC-16, poly 0xA001, init 0 (eg/e.java table g).
    let mut t = [0u16; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u16;
        let mut j = 0;
        while j < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xA001
            } else {
                c >> 1
            };
            j += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}
static CRC16_TABLE: [u16; 256] = crc16_table();

/// Parse the dbr.a DbsMessage out of a DataBus sid-8 payload (after the
/// `[b0, tid u16be]` prefix: 52 B body, JSON from 55; `kms::dbs_data_frame`
/// docs). Only broadcast msgTypes 42/82 carry a DbsMessage — the phone's
/// `DbsDataReceiver` (`bf/c.java` case 0) parses nothing else.
fn dbs_payload_json(payload: &[u8]) -> Option<serde_json::Value> {
    let body = payload.get(3..55)?;
    if !matches!(body[26], 42 | 82) {
        return None;
    }
    serde_json::from_slice(payload.get(55..)?).ok()
}

/// Best-effort system clipboard write: wl-copy (wayland) then xclip (X11).
fn set_system_clipboard(text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};
    for (bin, args) in [
        // wl-copy serves the clipboard selection by default; xclip needs the
        // selection named explicitly.
        ("wl-copy", &["-t", "text/plain"][..]),
        ("xclip", &["-selection", "clipboard"][..]),
    ] {
        let Ok(mut child) = Command::new(bin).args(args).stdin(Stdio::piped()).spawn() else {
            continue;
        };
        if let Some(mut si) = child.stdin.take()
            && si.write_all(text.as_bytes()).is_ok()
            && let Ok(st) = child.wait()
            && st.success()
        {
            return true;
        }
    }
    false
}

pub(crate) fn record(log_path: &str, tag: &str, bytes: &[u8]) {
    let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path) else {
        return;
    };
    // Exact-boundary framing: header terminated by NUL, body raw, NUL
    // terminator after the body (no newline ambiguity in offline replay).
    let _ = write!(f, "\n=== {tag} {}B ===\0", bytes.len());
    let _ = f.write_all(bytes);
    let _ = f.write_all(b"\0");
    let _ = f.flush();
}

/// Live TCP sink registry for manual frame injection (`LPLUS_REPL_PORT`).
/// Key: `"{epi_port} {peer}"`; consumers unregister on socket death.
pub(crate) static EPI_SINKS: std::sync::LazyLock<
    tokio::sync::Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
> = std::sync::LazyLock::new(tokio::sync::Mutex::default);

/// Abort handles for the live session pump tasks, per peer IP: a GUI/REPL
/// Disconnect must close our side of the vendor session (FIN/RST), not
/// just push a DISCONNECT frame the phone may ignore.
pub(crate) static SESSION_KILLERS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, Vec<tokio::task::AbortHandle>>>,
> = std::sync::LazyLock::new(std::sync::Mutex::default);

/// Last LAN peer that probed the SDP planes (the phone). Used to resolve
/// the REPL's `connect phone` shorthand.
pub(crate) static PHONE_IP: std::sync::LazyLock<std::sync::Mutex<Option<String>>> =
    std::sync::LazyLock::new(std::sync::Mutex::default);

/// Presence events for in-process consumers (the product embeds the daemon;
/// headless users can subscribe over the NDJSON port `LPLUS_EVENTS_PORT`).
#[derive(Clone, Debug, serde::Serialize)]
pub struct DeviceEvent {
    pub kind: &'static str,
    pub ip: String,
    pub name: Option<String>,
    pub connected: bool,
    pub ts_ms: i64,
}

static DEVICE_TX: std::sync::LazyLock<tokio::sync::broadcast::Sender<DeviceEvent>> =
    std::sync::LazyLock::new(|| tokio::sync::broadcast::channel(64).0);

/// Subscribe to the presence event stream.
pub fn subscribe_devices() -> tokio::sync::broadcast::Receiver<DeviceEvent> {
    DEVICE_TX.subscribe()
}

/// UI/headless control plane: the single-binary GUI (and dev tools) drive
/// the phone through the backend (LAN SCP dial, EPI sink push) instead of
/// touching the transport themselves.
#[derive(Debug, Clone)]
pub enum Command {
    /// Drive the phone's PC-panel row for our advertised name (AppFunction).
    Connect {
        ip: String,
    },
    Disconnect {
        ip: String,
    },
    /// Push the CastMessage msg_type=61 DataBus bootstrap on the live
    /// :46888 session so the phone dials our KMS server.
    KmsBootstrap {
        ip: String,
    },
    /// Inject the RpcFrame candidate set (compat-scp + cpbus.networking
    /// connect/acceptConnection) onto every live :46888 session.
    RpcConnect {
        ip: String,
    },
    /// Inject raw hex onto every EPI sink whose key contains the substring.
    SendFrame {
        key_substr: String,
        hex: String,
    },
    /// Invoke a named GUI element action (REPL `click <id>`), executed by
    /// the window's own handlers — see `AppState::handle_ui_click`.
    UiClick {
        id: String,
    },
}

/// Clicks queued by the REPL for the GUI lane to drain (element ids like
/// `connect:0`, `disconnect:0`, `confirm`). Only meaningful in the unified
/// process that hosts the window.
static UI_CLICKS: std::sync::LazyLock<std::sync::Mutex<Vec<String>>> =
    std::sync::LazyLock::new(std::sync::Mutex::default);

pub fn take_ui_clicks() -> Vec<String> {
    UI_CLICKS
        .lock()
        .map(|mut q| std::mem::take(&mut *q))
        .unwrap_or_default()
}

static CMD_TX: std::sync::LazyLock<tokio::sync::broadcast::Sender<Command>> =
    std::sync::LazyLock::new(|| tokio::sync::broadcast::channel(32).0);

pub fn send_command(cmd: Command) -> bool {
    CMD_TX.send(cmd).is_ok()
}

pub fn subscribe_commands() -> tokio::sync::broadcast::Receiver<Command> {
    CMD_TX.subscribe()
}

/// CastMessage msg_type=61 wrapped in the proven DbsMessage/DataBus frame
/// (PROTOCOL.md §7.2). `from` is our peer id, `to` the phone PDID.
pub(crate) fn kms_bootstrap_frame(
    kms_port: u16,
    pwd: &str,
    local_ip: &str,
    from_hex: &str,
    to_hex: &str,
) -> Result<Vec<u8>> {
    let td = crate::kms::make_test_data(pwd)?;
    let body = format!(
        "{{\"kms_socket_port\":{kms_port},\"local_ip\":\"{local_ip}\",\"display_id\":0,\
         \"randomPwd\":\"{pwd}\",\"testData\":\"{td}\",\"event_type\":\"connect\"}}"
    );
    let cast = format!(
        "{{\"msg_type\":61,\"msg_cmd\":\"synergy_pc_input_mode_start\",\"msg_body\":{}}}",
        serde_json::to_string(&body)?
    );
    let seq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1);
    let json =
        crate::kms::dbs_message_json("Oplus_Cast", from_hex, to_hex, "input_service", &cast, seq);
    let from6: [u8; 6] = hex::decode(from_hex)?.as_slice().try_into()?;
    let to6: [u8; 6] = hex::decode(to_hex)?.as_slice().try_into()?;
    Ok(crate::kms::dbs_data_frame(
        &from6,
        &to6,
        seq,
        1,
        json.as_bytes(),
    ))
}

/// Resolve the REPL/GUI `"phone"` shorthand to the last LAN peer seen on
/// the SDP planes; anything else is already an address.
fn resolve_phone_ip(ip: &str) -> String {
    if ip != "phone" {
        return ip.to_string();
    }
    PHONE_IP
        .lock()
        .ok()
        .and_then(|g| g.clone())
        .unwrap_or_else(|| {
            tracing::warn!("[cmd] no phone seen yet on the SDP planes; using 127.0.0.1");
            "127.0.0.1".into()
        })
}

fn spawn_command_runner(dev_name: String, kms_pwd: String, local_ip: String, kms_port: u16) {
    tokio::spawn(async move {
        let mut rx = subscribe_commands();
        while let Ok(cmd) = rx.recv().await {
            match cmd {
                Command::Connect { ip } => {
                    let ip = resolve_phone_ip(&ip);
                    crate::scpc::spawn_dial(ip.clone(), dev_name.clone());
                    // Session lane (proven): KMS bootstrap DataBus push is
                    // the trigger the phone's engine acts on (it dialed our
                    // :10152 with a completed handshake after this frame,
                    // PROTOCOL §7.2), and the RpcFrame candidate set rides
                    // the same live :46888 session (§7.10). Both no-op with
                    // no live session; the direct dial above covers that.
                    let _ = send_command(Command::KmsBootstrap { ip: ip.clone() });
                    let _ = send_command(Command::RpcConnect { ip });
                }
                Command::Disconnect { ip } => {
                    let ip = resolve_phone_ip(&ip);
                    // Vendor disconnect = cpbus DISCONNECT (msgType 65535)
                    // on the live session lanes; no live lane → no-op.
                    let frame = crate::scp::msg_frame(65535, Vec::new());
                    let mut sent = 0usize;
                    {
                        let mut sinks = EPI_SINKS.lock().await;
                        for (k, tx) in sinks.iter() {
                            if k.contains(&ip) && tx.send(frame.clone()).is_ok() {
                                sent += 1;
                            }
                        }
                        // Drop our injection handles for this peer; lanes
                        // that observe the closed channel end themselves.
                        sinks.retain(|k, _| !k.contains(&ip));
                    }
                    // Close our side of every live session with this peer so
                    // the phone sees the link actually go down (a DISCONNECT
                    // frame alone leaves the vendor UI at "Connected").
                    let killers = SESSION_KILLERS
                        .lock()
                        .map(|m| m.get(&ip).cloned().unwrap_or_default())
                        .unwrap_or_default();
                    let mut closed = 0usize;
                    for h in killers {
                        if !h.is_finished() {
                            h.abort();
                            closed += 1;
                        }
                    }
                    emit_device("epi", ip.clone(), None, false);
                    tracing::info!(
                        "[cmd] disconnect {ip}: DISCONNECT pushed to {sent} sink(s), {closed} session(s) closed"
                    );
                }
                Command::RpcConnect { ip } => {
                    let ip = resolve_phone_ip(&ip);
                    tokio::spawn(async move {
                        for (label, wire) in crate::scpc::rpc_frames(&ip) {
                            let mut sent = 0usize;
                            for (k, tx) in EPI_SINKS.lock().await.iter() {
                                if k.contains("46888") && tx.send(wire.clone()).is_ok() {
                                    sent += 1;
                                }
                            }
                            tracing::info!("[cmd] rpc {label}: pushed to {sent} sink(s)");
                            if sent == 0 {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
                        }
                    });
                }
                Command::KmsBootstrap { ip } => {
                    let from =
                        std::env::var("LINK_DET_PEER").unwrap_or_else(|_| "A1B2C3D4E5F6".into());
                    let to = std::env::var("LINK_KPD")
                        .ok()
                        .and_then(|s| s.split(',').next().map(str::to_string))
                        .unwrap_or_else(|| "0123456789AB".into());
                    match kms_bootstrap_frame(kms_port, &kms_pwd, &local_ip, &from, &to) {
                        Ok(frame) => {
                            let mut sent = 0usize;
                            for (k, tx) in EPI_SINKS.lock().await.iter() {
                                if k.contains("46888") && tx.send(frame.clone()).is_ok() {
                                    sent += 1;
                                }
                            }
                            if sent == 0 {
                                tracing::info!(
                                    "[cmd] kms bootstrap {ip}: no live :46888 sink (frame {}B dropped)",
                                    frame.len()
                                );
                            } else {
                                record(
                                    &std::env::var("LPLUS_LOG").unwrap_or_default(),
                                    "cmd-kms-bootstrap",
                                    &frame,
                                );
                                tracing::info!(
                                    "[cmd] kms bootstrap {ip}: pushed {}B to {sent} sink(s)",
                                    frame.len()
                                );
                            }
                        }
                        Err(e) => tracing::warn!("[cmd] kms bootstrap {ip} build FAILED: {e:#}"),
                    }
                }
                Command::SendFrame { key_substr, hex } => match hex::decode(hex.trim()) {
                    Ok(bytes) => {
                        let mut sent = 0usize;
                        for (k, tx) in EPI_SINKS.lock().await.iter() {
                            if k.contains(&key_substr) && tx.send(bytes.clone()).is_ok() {
                                sent += 1;
                            }
                        }
                        tracing::info!(
                            "[cmd] send {key_substr:?}: {sent} sink(s) {}B",
                            bytes.len()
                        );
                    }
                    Err(e) => tracing::info!("[cmd] send {key_substr:?} bad hex: {e}"),
                },
                Command::UiClick { id } => {
                    tracing::info!("[cmd] ui click queued {id:?}");
                    if let Ok(mut q) = UI_CLICKS.lock() {
                        q.push(id);
                    }
                }
            }
        }
    });
}

/// "ip:port" Display value -> host part.
fn event_host(peer: &impl std::fmt::Display) -> String {
    let s = peer.to_string();
    s.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or(s)
}

pub(crate) fn emit_device(kind: &'static str, ip: String, name: Option<String>, connected: bool) {
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let _ = DEVICE_TX.send(DeviceEvent {
        kind,
        ip,
        name,
        connected,
        ts_ms,
    });
}

/// NDJSON bridge for `LPLUS_EVENTS_PORT`: one DeviceEvent JSON per line to
/// every loopback subscriber. Lets a sidecar (not just in-proc) consume.
pub fn spawn_events_bridge() {
    let Ok(ps) = std::env::var("LPLUS_EVENTS_PORT") else {
        return;
    };
    let Ok(port) = ps.parse::<u16>() else {
        tracing::info!("[events] bad LPLUS_EVENTS_PORT={ps}");
        return;
    };
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let Ok(l) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await else {
            tracing::warn!("[events] bind :{port} failed");
            return;
        };
        tracing::info!("[events] NDJSON bridge :{port}");
        loop {
            let Ok((mut sock, _)) = l.accept().await else {
                continue;
            };
            let mut rx = subscribe_devices();
            tokio::spawn(async move {
                while let Ok(ev) = rx.recv().await {
                    let Ok(line) = serde_json::to_string(&ev) else {
                        continue;
                    };
                    if sock
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
    });
}

/// Exact-word REPL commands (the prefix forms `connect [ip]` etc. are
/// parsed separately above this match).
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "lowercase")]
enum ReplCmd {
    Connect,
    Disconnect,
    Kms,
    Rpc,
}

/// Loopback line REPL to probe open pipes without redoing handshakes:
/// `list` enumerates live epi sessions; `send <substr> <hex>` injects raw
/// bytes into every session whose key contains <substr>.
pub fn spawn_repl() {
    let Ok(ps) = std::env::var("LPLUS_REPL_PORT") else {
        return;
    };
    let Ok(port) = ps.parse::<u16>() else {
        tracing::info!("[repl] bad LPLUS_REPL_PORT={ps}");
        return;
    };
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let Ok(l) = TcpListener::bind(("127.0.0.1", port)).await else {
            tracing::warn!("[repl] bind :{port} failed");
            return;
        };
        tracing::info!("[repl] listening 127.0.0.1:{port}");
        loop {
            let Ok((c, _)) = l.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let mut rd = tokio::io::BufReader::new(c);
                let mut line = String::new();
                loop {
                    line.clear();
                    match rd.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let t = line.trim().to_string();
                    if t.is_empty() {
                        continue;
                    }
                    let out: String;
                    if t == "list" {
                        let m = EPI_SINKS.lock().await;
                        let mut keys: Vec<&String> = m.keys().collect();
                        keys.sort();
                        out = format!("peers {}\n", keys.len())
                            + &keys.iter().map(|k| format!("  {k}\n")).collect::<String>();
                    } else if let Some(rest) = t.strip_prefix("send ") {
                        let Some((sub, hx)) = rest.split_once(' ') else {
                            out = "usage: send <substr> <hex>\n".into();
                            let _ = rd.get_mut().write_all(out.as_bytes()).await;
                            continue;
                        };
                        match hex::decode(hx.trim().replace(':', "")) {
                            Ok(d) => {
                                let m = EPI_SINKS.lock().await;
                                let mut n = 0usize;
                                for (k, tx) in m.iter() {
                                    if k.contains(sub) && tx.send(d.clone()).is_ok() {
                                        n += 1;
                                    }
                                }
                                out = format!("sent {n} {}B\n", d.len());
                            }
                            Err(e) => out = format!("bad hex: {e}\n"),
                        }
                    } else if let Some(rest) = t
                        .strip_prefix("connect ")
                        .or_else(|| t.strip_prefix("disconnect "))
                        .or_else(|| t.strip_prefix("kms "))
                        .or_else(|| t.strip_prefix("rpc "))
                    {
                        let ip = rest.trim().to_string();
                        let ip = if ip.is_empty() {
                            "phone".to_string()
                        } else {
                            ip
                        };
                        let cmd = if t.starts_with("connect") {
                            Command::Connect { ip }
                        } else if t.starts_with("disconnect") {
                            Command::Disconnect { ip }
                        } else if t.starts_with("rpc") {
                            Command::RpcConnect { ip }
                        } else {
                            Command::KmsBootstrap { ip }
                        };
                        out = format!("queued {}\n", send_command(cmd));
                    } else if let Some(id) = t.strip_prefix("click ") {
                        let id = id.trim().to_string();
                        if id.is_empty() {
                            out = "usage: click <element-id> (device-connect:<i>|card-disconnect:<i>|menu-delete:<i>|card-more:<i>|confirm|cancel)\n"
                                .into();
                        } else {
                            out = format!("queued {}\n", send_command(Command::UiClick { id }));
                        }
                    } else if let Ok(repl) = ReplCmd::from_str(t.as_str()) {
                        let cmd = match repl {
                            ReplCmd::Connect => Command::Connect { ip: "phone".into() },
                            ReplCmd::Disconnect => Command::Disconnect { ip: "phone".into() },
                            ReplCmd::Kms => Command::KmsBootstrap { ip: "phone".into() },
                            ReplCmd::Rpc => Command::RpcConnect { ip: "phone".into() },
                        };
                        out = format!("queued {}\n", send_command(cmd));
                    } else {
                        out =
                            "commands: list | send <substr> <hex> | connect|disconnect|kms|rpc [ip] | click <element-id>\n"
                                .into();
                    }
                    let _ = rd.get_mut().write_all(out.as_bytes()).await;
                }
            });
        }
    });
}

/// `LINK_ACK` reply flavours for the link-detect probe socket.
#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "lowercase")]
enum AckMode {
    Echo,
    Dup,
    #[strum(default)]
    Other(String),
}

/// Run the responder until the process is killed.
pub async fn run(mut cfg: SdpdConfig) -> Result<()> {
    if cfg.vip.trim().is_empty() {
        cfg.vip = default_vip();
        tracing::info!("[sdpd] vip auto-resolved to {}", cfg.vip);
    }
    let mcast = UdpSocket::bind(("0.0.0.0", cfg.sdp_port)).await?;
    mcast.join_multicast_v4(cfg.group, Ipv4Addr::UNSPECIFIED)?;
    let uni = UdpSocket::bind(("0.0.0.0", cfg.uni_port)).await?;
    // The engine dials the announced port *and* port+1 (TcpManager connects
    // socketPort+1 after the SCP channel request), plus probes the SDP port
    // itself; listen on all of them and log every session.
    let mut tcp_ports: Vec<u16> = Vec::new();
    for p in [
        cfg.csp,
        cfg.csp.wrapping_add(1),
        cfg.uni_port,
        cfg.uni_port.wrapping_add(1),
        cfg.sdp_port,
        cfg.sdp_port.wrapping_add(1),
        // datatrans channel dial list, ee.a.f6613c: the phone's
        // TcpSocketConnectionImpl connects here after SCP; refusal → -1110.
        46888u16,
        47888,
        48888,
    ] {
        if !tcp_ports.contains(&p) {
            tcp_ports.push(p);
        }
    }
    let log_path = cfg.log_path.clone();
    spawn_repl();
    spawn_events_bridge();
    {
        let kms_port = std::env::var("KMS_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(36863u16);
        let kms_pwd = std::env::var("KMS_PWD").unwrap_or_else(|_| "lplus-kms-pw".into());
        spawn_command_runner(cfg.name.clone(), kms_pwd, cfg.vip.clone(), kms_port);
    }
    if std::env::var("KMS").is_ok() {
        let port = std::env::var("KMS_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(36863u16);
        let pwd = std::env::var("KMS_PWD").unwrap_or_else(|_| "lplus-kms-pw".into());
        crate::kms::spawn_server(port, pwd, log_path.clone());
    }
    if std::env::var("ODMF_SINK").is_ok() {
        let listen: std::net::SocketAddr = std::env::var("ODMF_LISTEN")
            .unwrap_or_else(|_| "0.0.0.0:7236".into())
            .parse()
            .unwrap_or(([0, 0, 0, 0], 7236).into());
        let out = std::env::var("ODMF_OUT").unwrap_or_else(|_| "../capture".into());
        let respond = std::env::var("ODMF_RESPOND")
            .map(|v| v != "0")
            .unwrap_or(true);
        crate::wfd_sink::spawn(listen, out, respond);
    }
    let probe_reg = std::sync::Arc::new(render("REGISTER * HTTP/1.1", &cfg, &[]).into_bytes());
    let dev_name = cfg.name.clone();
    for &p in &tcp_ports {
        let listener = TcpListener::bind(("0.0.0.0", p))
            .await
            .with_context(|| format!("tcp bind :{p}"))?;
        let log_path = log_path.clone();
        let dev_name = dev_name.clone();
        let probe_reg = probe_reg.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((sock, peer)) = listener.accept().await {
                    tracing::info!("[tcp] accept :{p} <- {peer}");
                    let epi = std::env::var("EPI").is_ok() && matches!(p, 46888 | 47888 | 48888);
                    spawn_session_logger(
                        sock,
                        peer,
                        log_path.clone(),
                        dev_name.clone(),
                        probe_reg.as_ref().clone(),
                        epi,
                        p,
                    );
                }
            }
        });
    }
    tracing::info!(
        "sdpd up: :{} (mcast {}) :{} (uni) tcp{:?}",
        cfg.sdp_port,
        cfg.group,
        cfg.uni_port,
        tcp_ports
    );

    let cfg = std::sync::Arc::new(cfg);
    let mut seen: HashMap<(String, String), Instant> = HashMap::new();
    let mut ns_i: u64 = 0;
    let mut last_phone: Option<SocketAddr> = None;
    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.announce_secs));
    // Record anything arriving on the phone stack's other UDP ports in
    // background tasks (the native LinkSwitch service plane may use them).
    for p in [10150u16, 10151, 10152, 10153, 10162, 1900, 5353] {
        let log_path = log_path.clone();
        tokio::spawn(async move {
            let Ok(sock) = UdpSocket::bind(("0.0.0.0", p)).await else {
                return;
            };
            let group: Ipv4Addr = if p == 5353 {
                Ipv4Addr::new(224, 0, 0, 251)
            } else {
                Ipv4Addr::new(239, 255, 255, 250)
            };
            let _ = sock.join_multicast_v4(group, Ipv4Addr::UNSPECIFIED);
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                if n > 0 && !from.ip().is_loopback() {
                    tracing::info!(
                        "[udp:{p}] {from} {}B | {}",
                        n,
                        hex::encode(&buf[..n.min(96)])
                    );
                    record(&log_path, &format!("udp{p} from {from}"), &buf[..n]);
                }
            }
        });
    }
    // Link-detection responder: the phone's `link_detection_sender_start`
    // hashes the peer IP into 4 UDP ports ("Calculated target ports for
    // <ip>: [..]") and its `establish_link` fails outright when the probes
    // ICMP-refuse. Bind those ports and answer; reply body is LINKPUB raw
    // bytes when set, else an echo of the request (sender treats any reply
    // datagram as `Received response:`).
    // SERVICE-PUBLISH of the LinkSwitch LinkInfoPayload (TLV+bincode bytes,
    // base64 in NSData), sent fast so a mid-session window can't miss it.
    let link_pub_bytes: Option<Vec<u8>> = std::env::var("LINKPUB")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| hex::decode(&s).unwrap_or_else(|_| s.as_bytes().to_vec()))
        .or_else(|| {
            Some(link_info_payload(
                &link_mac_spec(),
                &cfg.vip,
                &gateway_of(&cfg.vip),
            ))
        });
    if let Ok(spec) = std::env::var("LINK_PORTS") {
        // Reply template: mirror the phone's own 66B link-detection frame
        // (captured live): `[00 40][0c][PDID ascii 12][01 38 02 01 00]
        //  entry{0b 01 fd | mac6 LE | 0*8} entry{0b 01 fc | ip4 LE 0*2 0*6}
        //  entry{01 fc | gw-ish 6B}` with our identity substituted.
        let link_reply: Vec<u8> = link_pub_bytes.clone().unwrap_or_else(|| {
            let mac = std::env::var("LINK_MAC")
                .ok()
                .or_else(|| {
                    std::fs::read_to_string("/sys/class/net/eth0/address")
                        .ok()
                        .map(|s| s.trim().to_string())
                })
                .unwrap_or_else(|| "aa:bb:cc:dd:ee:ff".into());
            let mut macb: Vec<u8> = mac
                .split(':')
                .map(|h| u8::from_str_radix(h, 16).unwrap_or(0))
                .collect();
            macb.resize(6, 0);
            let octets: Vec<u8> = cfg
                .vip
                .split('.')
                .map(|s| s.parse().unwrap_or(0u8))
                .collect();
            let mut ip6 = vec![0u8; 6];
            if octets.len() == 4 {
                ip6[..4].copy_from_slice(&octets);
            }
            let mut gw6 = vec![0u8; 6];
            if octets.len() == 4 {
                gw6[0] = 1;
                gw6[1..4].copy_from_slice(&octets[..3]);
            }
            let mut r: Vec<u8> = vec![0x00, 0x40, 0x0c];
            r.extend_from_slice(format!("{:0<12}", cfg.pdid).as_bytes());
            r.extend_from_slice(&[0x01, 0x38, 0x02, 0x01, 0x00]);
            r.extend_from_slice(&[0x0b, 0x01, 0xfd]);
            // MAC stored little-endian as observed.
            r.extend(macb.iter().rev());
            r.extend(std::iter::repeat_n(0u8, 8));
            r.extend_from_slice(&[0x0b, 0x01, 0xfc]);
            r.extend(ip6);
            r.extend(std::iter::repeat_n(0u8, 6));
            r.extend_from_slice(&[0x01, 0xfc]);
            r.extend(gw6);
            let total = (r.len() - 2) as u16;
            r[0..2].copy_from_slice(&total.to_be_bytes());
            r
        });
        tracing::info!("[link-det] reply {}B prepared", link_reply.len());
        // Mirror-reply identity (phone's bincode decoder only accepts its
        // own self-consistent payload shape; see link_reply_mirror).
        let mirror_on = std::env::var("LINK_REPLY_MIRROR").as_deref() != Ok("0");
        let mut pdid12 = [b'0'; 12];
        let pdid_s = format!("{:0<12}", cfg.pdid).to_uppercase();
        pdid12.copy_from_slice(&pdid_s.as_bytes()[..12]);
        let mac_spec = std::env::var("LINK_MAC")
            .ok()
            .or_else(|| {
                std::fs::read_to_string("/sys/class/net/eth0/address")
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "aa:bb:cc:dd:ee:ff".into());
        let mut mac6 = [0u8; 6];
        for (i, h) in mac_spec.split(':').take(6).enumerate() {
            mac6[i] = u8::from_str_radix(h, 16).unwrap_or(0);
        }
        let mut ip4o = [0u8; 4];
        let oct: Vec<u8> = cfg
            .vip
            .split('.')
            .map(|s| s.parse().unwrap_or(0u8))
            .collect();
        if oct.len() == 4 {
            ip4o.copy_from_slice(&oct);
        }
        // Peer link_ip published for LinkSwitchMgr's route install; the phone
        // has no vgate return path for our LAN IP, so route-poison with an
        // unreachable address unless LINK_POISON_IP=off.
        let poison: Option<[u8; 4]> = match std::env::var("LINK_POISON_IP").as_deref() {
            Ok("off") => None,
            _ => {
                let spec = std::env::var("LINK_POISON_IP").unwrap_or_else(|_| "192.0.2.16".into());
                let o: Vec<u8> = spec.split('.').map(|s| s.parse().unwrap_or(0u8)).collect();
                if o.len() == 4 {
                    Some([o[0], o[1], o[2], o[3]])
                } else {
                    Some([192, 0, 2, 16])
                }
            }
        };
        let ack_mode = std::env::var("LINK_ACK").unwrap_or_default();
        let link_hex: Option<Vec<u8>> = std::env::var("LINK_REPLY_HEX")
            .ok()
            .filter(|s| !s.is_empty())
            .and_then(|s| hex::decode(s.replace(':', "")).ok());
        let link_type: Option<u8> = std::env::var("LINK_REPLY_TYPE")
            .ok()
            .and_then(|s| s.parse().ok());
        // Hot-swappable reply override: file path re-read on every probe so a sweep
        // can change the reply without restarting the daemon.
        let link_hex_file: Option<String> = std::env::var("LINK_REPLY_HEX_FILE")
            .ok()
            .filter(|s| !s.is_empty());
        // known_peer_devices ids for the mirror reply (comma-separated).
        let kpd: Vec<Vec<u8>> = std::env::var("LINK_KPD")
            .ok()
            .filter(|s| !s.is_empty())
            .map(|s| s.split(',').map(|x| x.trim().as_bytes().to_vec()).collect())
            .unwrap_or_default();
        for ps in spec.split(',').map(|s| s.trim()) {
            let Ok(p): Result<u16, _> = ps.parse() else {
                continue;
            };
            let log_path = log_path.clone();
            let reply_src = link_reply.clone();
            let ack_mode = ack_mode.clone();
            let kpd = kpd.clone();
            let link_hex = link_hex.clone();
            let link_hex_file = link_hex_file.clone();
            let (mirror_on, pdid12, mac6, ip4o, poison) = (mirror_on, pdid12, mac6, ip4o, poison);
            tokio::spawn(async move {
                let Ok(sock) = UdpSocket::bind(("0.0.0.0", p)).await else {
                    tracing::warn!("[link-det] bind :{p} failed");
                    return;
                };
                tracing::info!("[link-det] listening :{p}");
                let mut buf = vec![0u8; 2048];
                loop {
                    if let Ok((n, from)) = sock.recv_from(&mut buf).await {
                        if n == 0 || from.ip().to_string().starts_with("127.") {
                            continue;
                        }
                        tracing::info!(
                            "[link-det] {from} {n}B | {}",
                            hex::encode(&buf[..n.min(96)])
                        );
                        record(&log_path, &format!("linkdet:{p} from {from}"), &buf[..n]);
                        let mut out: Vec<u8> = Vec::new();
                        if mirror_on
                            && n > 2
                            && let Some(pl) = link_reply_mirror(
                                &buf[2..n],
                                &pdid12,
                                &mac6,
                                &ip4o,
                                poison.as_ref(),
                                &kpd,
                            )
                        {
                            out.push(0x00);
                            out.push(pl.len() as u8);
                            out.extend_from_slice(&pl);
                        }
                        if out.is_empty() {
                            out = reply_src.clone();
                        }
                        if let Some(h) = &link_hex {
                            out = h.clone();
                        }
                        if let Some(f) = &link_hex_file
                            && let Ok(s) = std::fs::read_to_string(f)
                            && let Ok(h) = hex::decode(s.trim().replace(':', ""))
                            && !h.is_empty()
                        {
                            out = h;
                        }
                        if let Some(t) = link_type
                            && out.len() > 1
                        {
                            out[1] = t;
                        }
                        match sock.send_to(&out, from).await {
                            Ok(w) => tracing::info!(
                                "[link-det] replied {w}B to {from} | {}",
                                hex::encode(&out)
                            ),
                            Err(e) => tracing::info!("[link-det] reply fail: {e}"),
                        }
                        match AckMode::from_str(&ack_mode) {
                            Ok(AckMode::Echo) => {
                                let _ = sock.send_to(&buf[..n], from).await;
                                tracing::info!("[link-det] ack-echo {n}B to {from}");
                            }
                            Ok(AckMode::Dup) => {
                                let _ = sock.send_to(&out, from).await;
                                tracing::info!("[link-det] ack-dup to {from}");
                            }
                            _ => {}
                        }
                    }
                }
            });
        }
    }
    let linkns = std::env::var("LINKNS").unwrap_or_else(|_| "LinkSwitchMgr".into());
    let link_b64 = link_pub_bytes.as_ref().map(|raw| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(raw)
    });
    let mut pub_ticker = tokio::time::interval(Duration::from_millis(300));
    pub_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut mbuf = vec![0u8; 2048];
    let mut ubuf = vec![0u8; 2048];
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let extras: Vec<(&str, &str)> = match &link_b64 {
                    Some(b64) => vec![("NSData", b64.as_str())],
                    None => vec![],
                };
                let msg = render("ANNOUNCE * HTTP/1.1", &cfg, &extras);
                let reg = render("REGISTER * HTTP/1.1", &cfg, &extras);
                let _ = mcast.send_to(msg.as_bytes(), (cfg.group, cfg.sdp_port)).await;
                let _ = mcast.send_to(reg.as_bytes(), (cfg.group, cfg.sdp_port)).await;
                if let Some(phone) = last_phone {
                    let _ = uni.send_to(msg.as_bytes(), phone).await;
                    let _ = uni.send_to(reg.as_bytes(), phone).await;
                }
            }
            _ = pub_ticker.tick(), if link_pub_bytes.is_some() => {
                if let Some(phone) = last_phone {
                    // Rotate candidate service-id formats: the phone logs
                    // `Invalid service id format: <value>` per rejection,
                    // so the pass-through candidate is whichever one stops
                    // appearing there (and shows up in dispatch logs).
                    let ns_candidates: [&str; 12] = [
                        "com.oplus.linkswitchmgr",
                        "com.oplus.linkswitchmgr.sdp",
                        "com.heytap.linkswitchmgr.sdp",
                        "com.oplus.pantaconnect.LinkSwitchMgr",
                        "LinkSwitchMgr.sdp",
                        "PeripheralDiscoveryService.sdp",
                        "AlwaysOnFusionService",
                        "0000fd70-0000-1000-8000-00805f9b34fb",
                        "e83b6f1c2d4a5b9087654321abcdef01",
                        "linkswitchmgr@sdp",
                        "TGlua1N3aXRjaE1ncg==",
                        "sdp:LinkSwitchMgr",
                    ];
                    let ns_use = if linkns == "LinkSwitchMgr" {
                        { ns_i += 1; ns_candidates[(ns_i as usize) % ns_candidates.len()] }
                    } else {
                        linkns.as_str()
                    };
                    let msg = render(
                        "SERVICE-PUBLISH * HTTP/1.1",
                        &cfg,
                        &[
                            ("NS", ns_use),
                            ("SDP", "LinkSwitchMgr"),
                            ("NSData", link_b64.as_deref().unwrap_or("0")),
                        ],
                    );
                    let _ = uni.send_to(msg.as_bytes(), phone).await;
                }
            }
            r = mcast.recv_from(&mut mbuf) => {
                if let Ok((n, from)) = r {
                    if from.ip() == Ipv4Addr::UNSPECIFIED || from.port() == cfg.sdp_port {
                        continue;
                    }
                    handle(&cfg, &uni, &link_b64, &mut seen, &mut last_phone, "mcast", from, &mbuf[..n]).await;
                }
            }
            r = uni.recv_from(&mut ubuf) => {
                if let Ok((n, from)) = r {
                    handle(&cfg, &uni, &link_b64, &mut seen, &mut last_phone, "uni", from, &ubuf[..n]).await;
                }
            }
        }
    }
}

/// `SCP_INTERACT` reply flavours for the interact-channel handshake A/B.
/// Spellings are exact (case-sensitive): the phone echoes its own literals
/// back verbatim, so each knob keeps its wire form.
#[derive(Debug, Clone, PartialEq, Eq, EnumString)]
enum InteractMode {
    #[strum(serialize = "accept")]
    Accept,
    #[strum(serialize = "ACCEPT")]
    UpperAccept,
    #[strum(serialize = "only_ACCEPT")]
    OnlyAccept,
    #[strum(serialize = "REJECT_lit")]
    RejectLit,
    #[strum(serialize = "hello_accept")]
    HelloAccept,
    #[strum(default)]
    Other(String),
}

/// `RESP` reply-body flavours for the SCP channel-open A/B (lowercase env
/// spellings); unknown values behave like `echo` (payload echo).
#[derive(Debug, Clone, PartialEq, Eq, Display, EnumString)]
#[strum(serialize_all = "lowercase")]
enum RespVariant {
    Off,
    Accept,
    Empty2,
    Ok2,
    Ok1,
    Echo,
    Type3,
    Type1,
    #[strum(default)]
    Other(String),
}

fn spawn_session_logger(
    mut sock: tokio::net::TcpStream,
    peer: SocketAddr,
    path: String,
    dev_name: String,
    reg59399: Vec<u8>,
    epi: bool,
    epi_port: u16,
) {
    tracing::info!("[tcp] connection from {peer}");
    let session_ip = peer.ip().to_string();
    let task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if epi {
            // EPI PD OFFER over the datatrans channel (jf/b.java writer,
            // ProtocolVersion<=10 so the 39B account block is skipped):
            // [0]msgType [1..3)proto u16be [3..39)PeerId 36B [39]SapModes
            // [40]featureCount=0.
            let mtype: u8 = std::env::var("EPI_TYPE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1);
            let proto: u16 = std::env::var("EPI_PROTO")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10);
            let peer_id: String =
                std::env::var("EPI_PEERID").unwrap_or_else(|_| "A1B2C3D4E5F6".repeat(3));
            let mut peer_id = peer_id.clone();
            if peer_id.len() < 36 {
                while peer_id.len() < 36 {
                    peer_id.push('0');
                }
            }
            peer_id.truncate(36);
            let mut frame: Vec<u8> = if let Ok(h) = std::env::var("EPI_MSG") {
                hex::decode(h).unwrap_or_default()
            } else {
                let mut v = vec![mtype, (proto >> 8) as u8, (proto & 0xff) as u8];
                v.extend_from_slice(peer_id.as_bytes());
                v.push(0x00); // SapLayerModes: CL=0 TL=0
                v.push(0x00); // no negotiated params
                v
            };
            if !frame.is_empty() {
                // Datatrans channel framing. The live phone stack (classes4
                // connector TcpSocketConnectionImpl) writes/reads
                // [0x00][len u8][payload] — proven against its :46888 EpiServerFsm.
                // EPI_FRAMING=3b selects the legacy classes3 form:
                // [b0][len_hi][len_lo][00 00 00 len-crc][payload][crc16 2B][0].
                let len = frame.len() as u16;
                let out: Vec<u8> = if std::env::var("EPI_FRAMING").as_deref() == Ok("raw3") {
                    // Live client-socket reader form (setCrcEnabled=false):
                    // 3-byte length field only, no crc fields.
                    let mut v = vec![0x00, (len >> 8) as u8, (len & 0xff) as u8];
                    v.append(&mut frame);
                    v
                } else if std::env::var("EPI_FRAMING").as_deref() == Ok("3b") {
                    let mut crc: u16 = 0;
                    for &b in &frame {
                        crc = CRC16_TABLE[((crc as u8) ^ b) as usize] ^ (crc >> 8);
                    }
                    let mut v = vec![0x00, (len >> 8) as u8, (len & 0xff) as u8, 0x00, 0x00, 0x00];
                    v.append(&mut frame.clone());
                    v.push((crc >> 8) as u8);
                    v.push((crc & 0xff) as u8);
                    v.push(0x00);
                    v
                } else {
                    let mut v = vec![0x00, frame.len() as u8];
                    v.append(&mut frame);
                    v
                };
                match sock.write_all(&out).await {
                    Ok(()) => tracing::info!("[epi] :{epi_port} -> {peer} sent {}B", out.len()),
                    Err(e) => tracing::info!("[epi] :{epi_port} write fail: {e}"),
                }
                record(&path, &format!("sent epi{epi_port} {peer}"), &out);
            }
            // PD server role on our channel port: EpiClientFsm (phone) waits
            // for our OFFER, answers with msgType 2, we finalize with
            // CONFIRM msgType 4 [4][proto u16be][status=1]. Accept both the
            // connector 2B header [00][len][payload] and the legacy 3B form.
            let peer_id2 = peer_id.clone();
            let epi_session = tokio::spawn(async move {
                let mut acc: Vec<u8> = Vec::new();
                let mut tmp = [0u8; 4096];
                let mut confirmed = false;
                // Late-PROBE state (PROBE after auth).
                let mut probe_pending = false;
                let mut probe_peer: Vec<u8> = Vec::new();
                // datatrans/security lane session key: set only when an
                // AUTH MAC matches a bond in the per-peer KSC store
                // (`ksc.json`) — unpaired peers get no AUTH response.
                let mut ksc: Option<Vec<u8>> = None;
                // Manual-injection sink: REPL `send` bytes are written onto
                // this live socket from the read loop's select, no
                // re-handshake needed. Key: "{port} {peer}".
                let repl_on = std::env::var("LPLUS_REPL_PORT").is_ok();
                let repl_key = format!("{epi_port} {peer}");
                // Rate-limited link-evidence refresh: devices.rs drops
                // `is_connected` when a row goes quiet, so live traffic
                // must re-assert presence (≤1/min, cheap broadcast).
                let mut last_ev = tokio::time::Instant::now();
                emit_device("epi", event_host(&peer), None, true);
                let mut repl_rx: Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> = None;
                if repl_on {
                    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                    EPI_SINKS.lock().await.insert(repl_key.clone(), tx);
                    repl_rx = Some(rx);
                }
                // Expected rc_2 = s(ksc, qc, ts) for the pending AUTH_CONFIRM.
                let mut expect_rc2: Option<[u8; 8]> = None;
                // FrameType byte for our AUTH_RESPONSE; phone dispatches on
                // {16,17,18,19,20}; server proof frame is 18 (0x12).
                let resp_type: u8 = std::env::var("EPI_AUTH_RESP")
                    .ok()
                    .and_then(|s| u8::from_str_radix(s.trim(), 16).ok())
                    .unwrap_or(0x11);
                // Server-side confirm echo sent after rc_2 verifies; 0 = off.
                let auth_ack: u8 = std::env::var("EPI_AUTH_ACK")
                    .ok()
                    .and_then(|s| u8::from_str_radix(s.trim(), 16).ok())
                    .unwrap_or(0x12);
                // Capability exchange (datatrans/service/f): after auth+PD the
                // phone enters QUERYING and dies after 10 s (errorCode 258,
                // "Capex waiting for query timed out") unless the server sends
                // a capex QUERY; we then must answer its RESPONSE with a
                // CONFIRM (statusCode 0) to reach AVAILABLE/ATTACHED.
                let capex_on = std::env::var("EPI_CAPEX").as_deref() != Ok("0");
                // Clipboard lane (opt-in CLIPBOARD=1): subscribe our side to
                // `Oplus_PcConnect` via `msg_topic_sync` once the DataBus
                // session is live, then apply published ClipboardBean text to
                // the system clipboard.
                let clipboard_on = std::env::var("CLIPBOARD").is_ok();
                let mut clip_subscribed = false;
                let capex_profiles: Vec<String> = std::env::var("EPI_CAPEX_PROFILES")
                    .ok()
                    .map(|s| {
                        s.split(',')
                            .map(|p| p.trim().to_string())
                            .filter(|p| !p.is_empty())
                            .collect()
                    })
                    .unwrap_or_else(|| {
                        [
                            "com.oplus.pantaconnect.globaldevice.discovery",
                            "uuid.icdf.service1",
                            "app:oplus.pantaconnect.app_service",
                            "vdc.service.sync",
                            "oaf.service.iphone.call",
                            "icdf.videocall.service",
                        ]
                        .iter()
                        .map(|p| p.to_string())
                        .collect()
                    });
                let capex_profiles: Vec<&str> = capex_profiles.iter().map(String::as_str).collect();
                // 0 = idle, 1 = QUERY sent (await RESPONSE), 2 = CONFIRM sent.
                let mut capex: u8 = 0;
                let mut capex_attempts: u8 = 0;
                loop {
                    let rd = if capex == 1 && capex_attempts < 3 {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            sock.read(&mut tmp),
                        )
                        .await
                        {
                            Ok(r) => r,
                            Err(_) => {
                                capex_attempts += 1;
                                let qf = capex_frame(&capex_query(&capex_profiles));
                                let _ = sock.write_all(&qf).await;
                                tracing::info!(
                                    "[epi] :{epi_port} -> CAPEX QUERY resend #{capex_attempts} ({} profiles)",
                                    capex_profiles.len(),
                                );
                                record(
                                    &path,
                                    &format!("epicapexq{epi_port} {peer}#{capex_attempts}"),
                                    &qf,
                                );
                                continue;
                            }
                        }
                    } else {
                        // Idle guard: a peer that vanishes without a FIN
                        // must not pin the row's connected flag — silence
                        // for `EPI_IDLE` is treated as a closed link.
                        const EPI_IDLE: std::time::Duration = std::time::Duration::from_secs(90);
                        match &mut repl_rx {
                            Some(rx) => {
                                tokio::select! {
                                    r = sock.read(&mut tmp) => r,
                                    b = rx.recv() => {
                                        match b {
                                            Some(bytes) => {
                                                let _ = sock.write_all(&bytes).await;
                                                record(&path, &format!("repl-sent {repl_key}"), &bytes);
                                                tracing::info!(
                                                    "[repl] -> {repl_key} {}B {}",
                                                    bytes.len(),
                                                    hex::encode(&bytes[..bytes.len().min(64)])
                                                );
                                            }
                                            // Registry dropped: stop selecting.
                                            None => repl_rx = None,
                                        }
                                        continue;
                                    }
                                    _ = tokio::time::sleep(EPI_IDLE) => Ok(0),
                                }
                            }
                            None => tokio::time::timeout(EPI_IDLE, sock.read(&mut tmp))
                                .await
                                .unwrap_or(Ok(0)),
                        }
                    };
                    match rd {
                        Ok(0) | Err(_) => {
                            if repl_on {
                                EPI_SINKS.lock().await.remove(&repl_key);
                            }
                            emit_device("epi", event_host(&peer), None, false);
                            break;
                        }
                        Ok(n) => {
                            acc.extend_from_slice(&tmp[..n]);
                            if last_ev.elapsed() >= std::time::Duration::from_secs(60) {
                                last_ev = tokio::time::Instant::now();
                                emit_device("epi", event_host(&peer), None, true);
                            }
                            tracing::info!(
                                "[epi] :{epi_port} <- {peer} {n}B | {}",
                                hex::encode(&tmp[..n.min(64)])
                            );
                            record(&path, &format!("epircv{epi_port} {peer}"), &tmp[..n]);
                        }
                    }
                    loop {
                        if acc.len() < 3 {
                            break;
                        }
                        let (hlen, plen) = if acc.len() >= 4
                            && acc[2] == 0x00
                            && (acc[3] == 0x08 || acc[3] == 0x20)
                            && u16::from_be_bytes([acc[0], acc[1]]) as usize >= 6
                        {
                            // Session lane (capex): [len u16BE][hdr 0x0008][payload];
                            // 0x0020 = DataBus session (sid 8).
                            (4usize, u16::from_be_bytes([acc[0], acc[1]]) as usize - 2)
                        } else if acc[0] == 0 && acc[1] == 0 && acc[2] > 0 {
                            (3usize, acc[2] as usize)
                        } else if acc[0] == 0 && acc[1] > 0 {
                            (2usize, acc[1] as usize)
                        } else {
                            // Resync to the next plausible session frame start
                            // (its leading length bytes are unrestricted).
                            let mut next = None;
                            for i in 1..acc.len().saturating_sub(3) {
                                if acc[i + 2] == 0x00
                                    && (acc[i + 3] == 0x08 || acc[i + 3] == 0x20)
                                    && u16::from_be_bytes([acc[i], acc[i + 1]]) as usize >= 6
                                {
                                    next = Some(i);
                                    break;
                                }
                            }
                            match next {
                                Some(i) => {
                                    acc.drain(..i);
                                    continue;
                                }
                                None => {
                                    acc.clear();
                                    break;
                                }
                            }
                        };
                        if acc.len() < hlen + plen {
                            break;
                        }
                        let sid8 = hlen == 4 && acc[3] == 0x20;
                        let payload = acc[hlen..hlen + plen].to_vec();
                        acc.drain(..hlen + plen);
                        let Some(&mt) = payload.first() else { continue };
                        if sid8 {
                            // DataBus session (NDSF sid 8): [b0=(msgType<<3)|enc|comp]
                            // [tid u16BE][u64 AppCipher ctr][AES-GCM ct||tag].
                            // Peer parity: DATA frames get the plain ACK
                            // [0x0A][tid] back (phone reserved/d.java case 1);
                            // status is never inspected by the phone sender.
                            let tid = if payload.len() >= 3 {
                                [payload[1], payload[2]]
                            } else {
                                [0, 1]
                            };
                            let ack = sess_frame(&[0x0a, tid[0], tid[1]], 8);
                            let _ = sock.write_all(&ack).await;
                            record(
                                &path,
                                &format!(
                                    "epidatabusframe{epi_port} {peer} b0={mt:02x} tid={:02x}{:02x}",
                                    tid[0], tid[1]
                                ),
                                &payload,
                            );
                            if clipboard_on {
                                // dbr.a DbsMessage from the peer (if any).
                                if let Some(v) = dbs_payload_json(&payload) {
                                    match v
                                        .get("dbs_msg_type")
                                        .and_then(|x| x.as_str())
                                        .unwrap_or("")
                                    {
                                        "msg_topic_sync" => tracing::info!(
                                            "[clip] :{epi_port} peer topic sync: {}",
                                            String::from_utf8_lossy(
                                                payload
                                                    .get(55..payload.len().min(215))
                                                    .unwrap_or(&[])
                                            )
                                        ),
                                        "msg_normal_topic_data" => {
                                            let topic = v
                                                .pointer("/dbs_msg_topic/dbs_topic_name")
                                                .and_then(|x| x.as_str())
                                                .unwrap_or("");
                                            if topic == "Oplus_PcConnect"
                                                && let Some(s) = v
                                                    .pointer("/dbs_msg_payload/value")
                                                    .and_then(|x| x.as_str())
                                                && let Some(text) = proto::odmf::clipboard_text(s)
                                            {
                                                if set_system_clipboard(&text) {
                                                    tracing::info!(
                                                        "[clip] :{epi_port} phone→PC clipboard set ({}B)",
                                                        text.len()
                                                    );
                                                } else {
                                                    tracing::warn!(
                                                        "[clip] :{epi_port} phone→PC clipboard ({}B) — no wl-copy/xclip: {text:?}",
                                                        text.len()
                                                    );
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                // Register our subscription once the session
                                // carries a frame: the peer's dbr.a `to`/`from`
                                // give us both ids verbatim.
                                if !clip_subscribed && payload.len() >= 23 {
                                    let phone6: [u8; 6] =
                                        payload[3..9].try_into().expect("6B phone id");
                                    let ours6: [u8; 6] =
                                        payload[17..23].try_into().expect("6B our id");
                                    let seq = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .map(|d| d.as_millis() as u64)
                                        .unwrap_or(1);
                                    let json = crate::kms::dbs_topic_sync_json(
                                        &hex::encode(ours6),
                                        &hex::encode(phone6),
                                        &["Oplus_PcConnect"],
                                        seq,
                                    );
                                    let f = crate::kms::dbs_data_frame(
                                        &ours6,
                                        &phone6,
                                        seq,
                                        0x1001,
                                        json.as_bytes(),
                                    );
                                    let _ = sock.write_all(&f).await;
                                    record(&path, &format!("clipsubscribe{epi_port} {peer}"), &f);
                                    tracing::info!(
                                        "[clip] :{epi_port} msg_topic_sync sub=[Oplus_PcConnect] sent"
                                    );
                                    clip_subscribed = true;
                                }
                            }
                            tracing::info!(
                                "[epi] :{epi_port} <- DATABUS sid8 b0={mt:02x} tid={:02x}{:02x} len={}B -> ack {}",
                                tid[0],
                                tid[1],
                                plen,
                                hex::encode(&ack)
                            );
                            record(&path, &format!("epidatabusack{epi_port} {peer}"), &ack);
                            // Opt-in cast video lane: the first DATABUS
                            // sid-8 frame means the DataBus channel (and
                            // thus the cast session) is live; start the
                            // RTSP client once if RTSP=1 was passed.
                            if std::env::var("RTSP").is_ok()
                                && epi_port == 46888
                                && let Ok(t) = std::env::var("RTSP_TARGET")
                                && !t.trim().is_empty()
                            {
                                let out = std::env::var("RTSP_OUT")
                                    .unwrap_or_else(|_| "../capture".to_string());
                                crate::rtsp::spawn_lane(t.trim().to_string(), out);
                            }
                            continue;
                        }
                        tracing::info!(
                            "[epi] :{epi_port} frame mt={mt} {}B {}",
                            payload.len(),
                            hex::encode(&payload[..payload.len().min(48)])
                        );
                        match mt {
                            2 | 3 if !probe_pending && !confirmed => {
                                // Server role: remember peer bytes; PROBE is
                                // delivered only after the auth lane completes
                                // ([03][proto u16be][PeerId 36]; parseProbeMessage
                                // minlen 39, jf/b.d). The phone drops EPI
                                // frames while its security client FSM is
                                // pending.
                                probe_peer = if payload.len() >= 39 {
                                    payload[3..39].to_vec()
                                } else {
                                    peer_id2.as_bytes().to_vec()
                                };
                                probe_pending = true;
                            }
                            1 if !confirmed && capex == 0 => {
                                // peer offered first (client-initiated PD):
                                // answer with our peer id, sap 0x20, no params.
                                let mut an: Vec<u8> = vec![2, 0, 10];
                                an.extend_from_slice(peer_id2.as_bytes());
                                an.push(0x20);
                                an.push(0x00);
                                let outa = if std::env::var("EPI_FRAMING").as_deref() == Ok("raw3")
                                {
                                    let l = an.len() as u16;
                                    let mut v = vec![0x00, (l >> 8) as u8, (l & 0xff) as u8];
                                    v.append(&mut an);
                                    v
                                } else if std::env::var("EPI_FRAMING").as_deref() == Ok("3b") {
                                    let mut crc: u16 = 0;
                                    for &b in &an {
                                        crc = CRC16_TABLE[((crc as u8) ^ b) as usize] ^ (crc >> 8);
                                    }
                                    let l = an.len() as u16;
                                    let mut v =
                                        vec![0x00, (l >> 8) as u8, (l & 0xff) as u8, 0, 0, 0];
                                    v.append(&mut an);
                                    v.push((crc >> 8) as u8);
                                    v.push((crc & 0xff) as u8);
                                    v.push(0);
                                    v
                                } else {
                                    let mut v = vec![0x00, an.len() as u8];
                                    v.append(&mut an);
                                    v
                                };
                                let _ = sock.write_all(&outa).await;
                                tracing::info!("[epi] :{epi_port} -> ANSWER sent");
                            }
                            4 if capex < 2 => {
                                tracing::info!(
                                    "[epi] :{epi_port} <- CONFIRM from peer (PD complete)"
                                );
                            }
                            // ---- datatrans/security lane (b.e switch
                            // {16,17,18,19,20}) ----
                            0x14 => {
                                // AUTH_KSC_ERROR [20][authVersion]: the
                                // phone client found no ksc for us. With a
                                // stored (deviceId, alias) row this frame
                                // must disappear — keep it visible.
                                tracing::info!(
                                    "[epi] :{epi_port} <- AUTH KSC_ERROR (authVersion {})",
                                    payload.get(1).copied().unwrap_or(0),
                                );
                            }
                            0x10 => {
                                // AUTH_REQUEST [16][ver][qc8][ts8][mac8][dev6][alias6]
                                if payload.len() < 38 {
                                    tracing::info!(
                                        "[epi] :{epi_port} AUTH_REQUEST short {}B",
                                        payload.len()
                                    );
                                    continue;
                                }
                                let ver = payload[1];
                                let qc = &payload[2..10];
                                let ts = u64::from_be_bytes(payload[10..18].try_into().unwrap());
                                let mac = &payload[18..26];
                                let dev = &payload[26..32];
                                let alias = &payload[32..38];
                                tracing::info!(
                                    "[epi] :{epi_port} <- AUTH_REQUEST ver={ver} qc={} ts={ts} mac={} dev={} alias={}",
                                    hex::encode(qc),
                                    hex::encode(mac),
                                    hex::encode(dev),
                                    hex::encode(alias),
                                );
                                // The phone keys this MAC on the row its
                                // KscRepository persisted for us
                                // (SecurityClientFsm → getKscKey(deviceId,
                                // alias)). Accept any key we ever bonded
                                // with this peer; the matching key becomes
                                // the session key for the s/t proofs.
                                let peer_ip = peer.ip().to_string();
                                let mac8 = <[u8; 8]>::try_from(mac).unwrap_or([0; 8]);
                                let accepted = ksc_candidates(&peer_ip, &hex::encode(dev))
                                    .into_iter()
                                    .find(|c| ksc_s(c, qc, ts) == mac8);
                                if let Some(k) = accepted {
                                    ksc = Some(k.clone());
                                    remember_ksc(&peer_ip, &hex::encode(dev), &k);
                                    remember_ksc(&hex::encode(dev), &hex::encode(dev), &k);
                                }
                                let Some(ksc) = ksc.clone() else {
                                    tracing::info!(
                                        "[epi] :{epi_port} AUTH_REQUEST but no ksc; skipping response"
                                    );
                                    continue;
                                };
                                let mac_ok = ksc_s(&ksc, qc, ts) == mac8;
                                tracing::info!("[epi] :{epi_port} client mac check: {mac_ok}");
                                let mut qs = [0u8; 8];
                                use rand::Rng;
                                rand::rng().fill_bytes(&mut qs);
                                let ts2 = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_millis() as u64)
                                    .unwrap_or(1);
                                let rs = ksc_t(&ksc, qc, &qs, ts2);
                                // Client computes rc_2 = s(ksc, qs, ts) with
                                // ts = ITS OWN request time (checkResponseParams
                                // copies uf/a.c into vf/b.e); qs (our server
                                // challenge) is the code. Pinned by live
                                // confirm 12 02 00 cf.. on 2026-11-09.
                                expect_rc2 = Some(ksc_s(&ksc, &qs, ts));
                                let mut resp: Vec<u8> = vec![resp_type, ver, 0x00];
                                resp.extend_from_slice(&qs);
                                resp.extend_from_slice(&be8(ts2));
                                resp.extend_from_slice(&rs);
                                let out = dt_frame(&resp);
                                let _ = sock.write_all(&out).await;
                                tracing::info!(
                                    "[epi] :{epi_port} -> AUTH_RESPONSE {resp_type:#04x} ver={ver} qs={} ts={ts2} rs={} (sessionKey {}+zeros)",
                                    hex::encode(qs),
                                    hex::encode(rs),
                                    hex::encode(rs),
                                );
                                record(&path, &format!("epiauthresp{epi_port} {peer}"), &out);
                            }
                            0x11..=0x13 => {
                                // AUTH_CONFIRM [t][ver][status][rc_2 8] — live
                                // wire shows the client sends 18 (0x12) with
                                // status 0 after accepting our response.
                                if payload.len() < 11 {
                                    tracing::info!(
                                        "[epi] :{epi_port} AUTH confirm {mt:#04x} short {}B",
                                        payload.len()
                                    );
                                    continue;
                                }
                                let rc2 = &payload[3..11];
                                let ok = expect_rc2
                                    .map(|e| e == <[u8; 8]>::try_from(rc2).unwrap_or([0; 8]))
                                    .unwrap_or(false);
                                tracing::info!(
                                    "[epi] :{epi_port} <- AUTH_CONFIRM {mt:#04x} status={} rc_2={} expect_ok={ok}{}",
                                    payload[2],
                                    hex::encode(rc2),
                                    if ok { " (CHANNEL AUTHENTICATED)" } else { "" },
                                );
                                if ok && auth_ack != 0 {
                                    // Complete the confirm leg: some client
                                    // FSMs sit in WAITING until the server's
                                    // own confirm arrives (else -2108 timeout
                                    // + close ~15s later). Echo rc_2 under
                                    // EPI_AUTH_ACK (0=off).
                                    let mut ack: Vec<u8> = vec![auth_ack, payload[1], 0x00];
                                    ack.extend_from_slice(rc2);
                                    let out = dt_frame(&ack);
                                    let _ = sock.write_all(&out).await;
                                    tracing::info!(
                                        "[epi] :{epi_port} -> AUTH ack {auth_ack:#04x} rc_2={}",
                                        hex::encode(rc2)
                                    );
                                    record(&path, &format!("epiauthack{epi_port} {peer}"), &out);
                                }
                                if ok && probe_pending {
                                    // PD leg: deliver the deferred PROBE now
                                    // that the security lane is complete —
                                    // client answers it with CONFIRM(4).
                                    let mut cf = vec![3u8, 0, 10];
                                    cf.extend_from_slice(&probe_peer);
                                    let outc = dt_frame(&cf);
                                    let _ = sock.write_all(&outc).await;
                                    tracing::info!("[epi] :{epi_port} -> PROBE sent (post-auth)");
                                    record(&path, &format!("epiprobe{epi_port} {peer}"), &outc);
                                    probe_pending = false;
                                    confirmed = true;
                                    if capex_on {
                                        let qf = capex_frame(&capex_query(&capex_profiles));
                                        let _ = sock.write_all(&qf).await;
                                        tracing::info!(
                                            "[epi] :{epi_port} -> CAPEX QUERY ({} profiles)",
                                            capex_profiles.len(),
                                        );
                                        record(&path, &format!("epicapexq{epi_port} {peer}"), &qf);
                                        capex = 1;
                                        capex_attempts = 1;
                                    }
                                }
                            }
                            // ---- capability exchange lane (datatrans/service/f) ----
                            1 if confirmed || capex >= 1 => {
                                // Phone-initiated capex QUERY (session 2):
                                // `01|qt u8|cksum u32be|recnum u8|ids`. Answer
                                // our capability RESPONSE then CONFIRM so the
                                // phone stops its `Capex attempt count` retry
                                // (which ends in the 258 accessory kill).
                                tracing::info!(
                                    "[epi] :{epi_port} <- CAPEX QUERY from phone {}B",
                                    payload.len(),
                                );
                                record(&path, &format!("epicapexqin{epi_port} {peer}"), &payload);
                                let theirs: Vec<String> = if payload.len() > 7 {
                                    payload[7..]
                                        .split(|b| *b == 0x3b)
                                        .map(|s| String::from_utf8_lossy(s).trim().to_string())
                                        .filter(|s| !s.is_empty())
                                        .collect()
                                } else {
                                    Vec::new()
                                };
                                let mut mine: Vec<&str> = capex_profiles
                                    .iter()
                                    .copied()
                                    .filter(|p| theirs.iter().any(|t| t == *p))
                                    .collect();
                                if mine.is_empty() {
                                    mine = capex_profiles.clone();
                                }
                                let rf = capex_frame(&capex_response(&mine));
                                let _ = sock.write_all(&rf).await;
                                tracing::info!(
                                    "[epi] :{epi_port} -> CAPEX RESPONSE ({} profiles, ck={})",
                                    mine.len(),
                                    hex::encode(&rf[6..10]),
                                );
                                record(&path, &format!("epicapexprspo{epi_port} {peer}"), &rf);
                                let cf = capex_frame(&capex_confirm(0, 0));
                                let _ = sock.write_all(&cf).await;
                                tracing::info!(
                                    "[epi] :{epi_port} -> CAPEX CONFIRM (post-response)"
                                );
                                record(&path, &format!("epicapexcfm2{epi_port} {peer}"), &cf);
                                capex = 2;
                            }
                            2 if capex == 1 => {
                                // Capex RESPONSE: `02 | 03 | checksum u32be |
                                // recordNum u16be | records`. Payload content is
                                // informational; answer with CONFIRM(status 0) to
                                // complete initial sync (phone: w() -> AVAILABLE).
                                tracing::info!(
                                    "[epi] :{epi_port} <- CAPEX RESPONSE {}B {}",
                                    payload.len(),
                                    hex::encode(&payload[..payload.len().min(64)]),
                                );
                                record(&path, &format!("epicapexprsp{epi_port} {peer}"), &payload);
                                let cf = capex_frame(&capex_confirm(0, 0));
                                let _ = sock.write_all(&cf).await;
                                tracing::info!("[epi] :{epi_port} -> CAPEX CONFIRM (status 0)");
                                record(&path, &format!("epicapexcfm{epi_port} {peer}"), &cf);
                                capex = 2;
                            }
                            3 if capex >= 1 => {
                                tracing::info!(
                                    "[epi] :{epi_port} <- CAPEX INCREMENTAL {}B {}",
                                    payload.len(),
                                    hex::encode(&payload[..payload.len().min(64)]),
                                );
                            }
                            4 if capex == 2 => {
                                tracing::info!(
                                    "[epi] :{epi_port} <- CAPEX CONFIRM from peer (initial sync complete)"
                                );
                                capex = 3;
                            }
                            other => {
                                tracing::info!(
                                    "[epi] :{epi_port} unmatched msgType {other} | {}",
                                    hex::encode(&payload)
                                );
                            }
                        }
                    }
                }
                tracing::info!("[epi] :{epi_port} closed {peer} confirmed={confirmed}");
            });
            // Without this registration a `disconnect` aborts nothing and
            // the phone keeps the :46888 link half-open — PTC then refuses
            // new connects ("device Connected, Scan results are not
            // processed") while our panel already shows disconnected.
            if let Ok(mut m) = SESSION_KILLERS.lock() {
                let v = m.entry(event_host(&peer)).or_default();
                v.retain(|h| !h.is_finished());
                v.push(epi_session.abort_handle());
            }
            return;
        }
        let mut buf = vec![0u8; 8192];
        let mut ukey: Option<crate::ukey2::Ukey2Handshake> = None;
        let mut ss_echoed = false;
        let mut hbase: Option<u32> = None;
        let mut hello_sent = false;
        let mut hello_at: Option<std::time::Instant> = None;
        let mut sync_sent = false;
        let mut sync_pending = false;
        let mut ss_send: Option<Vec<u8>> = None;
        let mut ss_ctx: Option<crate::d2d::D2dConnectionContextV1> = None;
        let mut ss_iv: Option<Vec<u8>> = None;
        let mut dialed = false;
        let t0 = std::time::Instant::now();
        macro_rules! tclock {
            () => {
                t0.elapsed().as_millis()
            };
        }
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    tracing::info!(
                        "[tcp] {peer} {n}B t={} | {}",
                        tclock!(),
                        hex::encode(&buf[..n.min(48)])
                    );
                    record(&path, &format!("tcp {peer}"), &buf[..n]);
                    let frames = crate::scp::split_frames(&buf[..n]);
                    let frames: Vec<(usize, usize)> = if frames.is_empty() {
                        vec![(0, n)]
                    } else {
                        frames
                    };
                    for (fs, fe) in frames {
                        let sub = &buf[fs..fe];
                        // Post-ukey2 frames from the phone set the encrypted
                        // bit; unseal with both context keys x both IV
                        // candidates to identify the phone's cryptor combo.
                        if sub.len() > 13
                            && sub[1] & 0x08 != 0
                            && let Some(ctx) = ss_ctx.as_ref()
                        {
                            let sealed = &sub[12..];
                            let mut ivs: Vec<Vec<u8>> = Vec::new();
                            if let Some(iv) = ss_iv.as_deref() {
                                if iv.len() >= 12 {
                                    // Proven phone cryptor nonce: first 12
                                    // bytes of the ukey2 iv_spec.
                                    ivs.push(iv[..12].to_vec());
                                }
                                if iv.len() == 16 {
                                    ivs.push(iv.to_vec());
                                }
                                if iv.len() >= 16 {
                                    ivs.push(iv[..16].to_vec());
                                }
                            }
                            ivs.push(vec![0u8; 16]);
                            ivs.push({
                                let mut v = vec![0u8; 12];
                                for (i, x) in v.iter_mut().enumerate() {
                                    *x = i as u8;
                                }
                                v
                            });
                            let mut opened: Option<Vec<u8>> = None;
                            for (kn, k) in [("ek", ctx.encode_key()), ("dk", ctx.decode_key())] {
                                for (ivn, iv) in ivs.iter().enumerate() {
                                    if let Ok(pt) = crate::d2d::cryptor_open_iv(k, iv, sealed) {
                                        tracing::info!(
                                            "[cryptor] {peer} OPENED {}B payload GCM key={kn} iv#{ivn} pt={}B | {}",
                                            sealed.len(),
                                            pt.len(),
                                            hex::encode(&pt[..pt.len().min(48)])
                                        );
                                        if opened.is_none() {
                                            opened = Some(pt);
                                        }
                                    }
                                    let mut iv16 = [0u8; 16];
                                    iv16[..iv.len().min(16)]
                                        .copy_from_slice(&iv[..iv.len().min(16)]);
                                    if let Ok(pt) = crate::d2d::cryptor_open_phone(k, &iv16, sealed)
                                    {
                                        tracing::info!(
                                            "[cryptor] {peer} OPENED {}B payload CTR key={kn} iv#{ivn} pt={}B | {}",
                                            sealed.len(),
                                            pt.len(),
                                            hex::encode(&pt[..pt.len().min(48)])
                                        );
                                    }
                                }
                            }
                            // Interact channel handshake
                            // (`connect-protocols` scp_connection_manager):
                            // each side seals the literal `interact hello`
                            // after SYNC_SECURE; unknown payloads are
                            // rejected. Reply in kind (SCP_INTERACT=accept
                            // replies `accept` instead, for A/B).
                            if opened.as_deref() == Some(b"interact hello".as_slice()) {
                                let mode =
                                    std::env::var("SCP_INTERACT").unwrap_or_else(|_| "echo".into());
                                let bodies: Vec<&[u8]> = match InteractMode::from_str(&mode) {
                                    Ok(InteractMode::Accept) => vec![b"accept"],
                                    Ok(InteractMode::UpperAccept) => {
                                        vec![b"interact hello", b"ACCEPT"]
                                    }
                                    Ok(InteractMode::OnlyAccept) => vec![b"ACCEPT"],
                                    Ok(InteractMode::RejectLit) => {
                                        vec![b"interact hello", b"REJECT"]
                                    }
                                    Ok(InteractMode::HelloAccept) => {
                                        vec![b"interact hello", b"accept"]
                                    }
                                    Ok(InteractMode::Other(_)) | Err(_) => {
                                        vec![b"interact hello"]
                                    }
                                };
                                let key = ctx.decode_key();
                                let iv12: Vec<u8> = ss_iv
                                    .as_deref()
                                    .filter(|v| v.len() >= 12)
                                    .map(|v| v[..12].to_vec())
                                    .unwrap_or_else(|| (0..12u8).collect());
                                for body in bodies {
                                    // Phone cryptor uses the session-fixed
                                    // nonce iv_spec[..12] for all sealed
                                    // frames (observed on both directions).
                                    match crate::d2d::cryptor_seal_iv(key, &iv12, body) {
                                        Ok(ct) => {
                                            let mut fr = sub[..8].to_vec();
                                            // Business marker | isServer:
                                            // the phone's client role drops
                                            // s2c frames without 0x04.
                                            fr[1] = 0x3d;
                                            fr[2..4]
                                                .copy_from_slice(&(ct.len() as u16).to_be_bytes());
                                            fr.extend_from_slice(&sub[8..12]);
                                            fr.extend_from_slice(&ct);
                                            record(
                                                &path,
                                                &format!("sent {peer} interact-reply"),
                                                &fr,
                                            );
                                            let _ = sock.write_all(&fr).await;
                                            tracing::info!(
                                                "[interact] {peer} got hello, sent {:?} ({}B)",
                                                String::from_utf8_lossy(body),
                                                fr.len()
                                            );
                                        }
                                        Err(e) => {
                                            tracing::warn!("[interact] {peer} seal failed: {e}")
                                        }
                                    }
                                }
                            } else if let Some(pt) = opened.as_deref() {
                                // No blind drop: log any other sealed
                                // business plaintext.
                                tracing::info!(
                                    "[interact] {peer} payload {}B {:?}",
                                    pt.len(),
                                    String::from_utf8_lossy(&pt[..pt.len().min(64)])
                                );
                            }
                        }
                        if let Some(m) = crate::scp::decode_payload(&sub[8..]) {
                            let qs = crate::scp::q_from_payload(&sub[8..]).map(|q| q.sequence_no);
                            tracing::info!(
                                "[scp] {peer} inbound {} ({}B data) qseq={qs:?} fseq={}",
                                crate::scp::msg_name(m.msg_type.unwrap_or(0)),
                                m.data.len(),
                                u16::from_be_bytes([sub[6], sub[7]])
                            );
                            // We are the SCP SERVER on this socket (the phone
                            // dialed and sent HELLO/SYNC as client). Frames the
                            // phone sends carry isServer=0; respond in-sequence
                            // (l.java server branch): ukey2 3->send3->4->send4,
                            // then echo SYNC_SECURE's ksc/kscAlias.
                            if std::env::var("SCP_SERVER").is_ok() && sub[1] == 0x30 {
                                let mt = m.msg_type.unwrap_or(0);
                                match mt {
                                    1 => {
                                        if let Ok(sd) =
                                            <crate::scp::SyncData as prost::Message>::decode(
                                                m.data.as_slice(),
                                            )
                                        {
                                            tracing::info!(
                                                "[scp] {peer} peer SYNC: key_type={} link_type={:?} dev={} atm={}",
                                                sd.key_type,
                                                sd.link_type,
                                                sd.device_name,
                                                sd.active_trigger_mode
                                            );
                                            let nm = sd.device_name.clone();
                                            emit_device(
                                                "scp_sync",
                                                event_host(&peer),
                                                Some(nm),
                                                true,
                                            );
                                            if std::env::var("SCP_SEND_DEVICE_INFO").is_ok() {
                                                let sid = u16::from_be_bytes([sub[4], sub[5]]) >> 2;
                                                let f = session_info_frame(&dev_name, sid);
                                                record(&path, "scp-send-101", &f);
                                                let _ = sock.write_all(&f).await;
                                                tracing::info!(
                                                    "[scp] {peer} -> 101 deviceName={}",
                                                    dev_name
                                                );
                                            }
                                        }
                                    }
                                    3 | 4 => {
                                        // Phone CLIENT drives ukey2: it sends
                                        // msgType3 CLIENT_INIT, we answer msgType3
                                        // SERVER_INIT; it sends msgType4
                                        // CLIENT_FINISH (commitment =
                                        // SHA-512(envelope)), we ack msgType4 with
                                        // ZERO bytes (`l.java:108`
                                        // k(f, new byte[0])`).
                                        let h = ukey.get_or_insert_with(|| {
                                            crate::ukey2::Ukey2Handshake::new(
                                                crate::ukey2::Role::Responder,
                                            )
                                        });
                                        match h.parse(&m.data) {
                                            Ok(true) => {
                                                // Stop any armed SYNC re-send: the
                                                // peer has left receiveSync behind and
                                                // now expects UKEY2_FINISHED; a late
                                                // msgType-1 frame is a fatal 2510 there.
                                                sync_pending = false;
                                                let reply = if mt == 4 {
                                                    if std::env::var("SCP_NO_MT4").is_ok() {
                                                        None
                                                    } else {
                                                        Some(Vec::new())
                                                    }
                                                } else {
                                                    h.next_message()
                                                };
                                                if let Some(next) = reply {
                                                    let f = crate::scp::msg_frame(mt, next.clone());
                                                    tracing::info!(
                                                        "[scp] {peer} ukey2 reply mt{mt} data={}B",
                                                        next.len()
                                                    );
                                                    record(
                                                        &path,
                                                        &format!("sent {peer} ukey2 mt{mt}"),
                                                        &f,
                                                    );
                                                    let _ = sock.write_all(&f).await;
                                                    let _ = sock.flush().await;
                                                    if mt == 4
                                                        && std::env::var("SCP_SS_NOW").is_ok()
                                                    {
                                                        // Diagnostic: no re-sends so the
                                                        // peer's sync-secure waiter sees
                                                        // exactly one frame after FINISHED.
                                                    } else if mt == 4 {
                                                        for delay in [300u64, 900] {
                                                            tokio::time::sleep(
                                                                std::time::Duration::from_millis(
                                                                    delay,
                                                                ),
                                                            )
                                                            .await;
                                                            let _ = sock.write_all(&f).await;
                                                            let _ = sock.flush().await;
                                                        }
                                                    }
                                                }
                                                if h.is_complete() {
                                                    tracing::info!(
                                                        "[scp] {peer} ukey2 handshake complete"
                                                    );
                                                    // Their client waits (5 s) for our
                                                    // SYNC_SECURE after ukey2; it carries
                                                    // our per-peer bond (`issue_ksc`), not
                                                    // session key material.
                                                    if std::env::var("SCP_SS_SEND").is_ok()
                                                        && mt == 4
                                                        && ss_send.is_none()
                                                    {
                                                        let _ = h.auth_string();
                                                        if let Ok(ctx) = h.to_connection_context() {
                                                            if std::env::var("SCP_KS_DUMP").is_ok()
                                                            {
                                                                tracing::info!(
                                                                    "[ks] {peer} {} iv={}",
                                                                    h.ks_dump(),
                                                                    ss_iv
                                                                        .as_deref()
                                                                        .map(hex::encode)
                                                                        .unwrap_or_default(),
                                                                );
                                                            }
                                                            ss_ctx = Some(
                                                                crate::d2d::D2dConnectionContextV1::new(
                                                                    ctx.encode_key().to_vec(),
                                                                    ctx.decode_key().to_vec(),
                                                                ),
                                                            );
                                                            ss_iv = h.peer_iv().map(|v| v.to_vec());
                                                            let pdid = std::env::var("SCP_PDID")
                                                                .unwrap_or_else(|_| {
                                                                    "A1B2C3D4E5F6".into()
                                                                });
                                                            // Present our BOND for this
                                                            // peer, never a fresh key: the
                                                            // phone persists ksc only in a
                                                            // user-confirmed pairing and
                                                            // AUTH-keys on the stored row
                                                            // (KscRepositoryImpl.loadKsc,
                                                            // "SELECT * FROM ksc_info WHERE
                                                            // deviceId = ? AND alias = ?").
                                                            let peer_ip = peer.ip().to_string();
                                                            let (ksc, alias) =
                                                                issue_ksc(&peer_ip, &pdid);
                                                            ss_send = Some(ksc.clone());
                                                            let ss = crate::scp::SyncSecure {
                                                                device_id: Some(pdid.clone()),
                                                                ksc: Some(ksc.clone()),
                                                                ksc_alias: Some(alias),
                                                            };
                                                            let f = if std::env::var("SCP_SS_ENC")
                                                                .is_ok()
                                                            {
                                                                let wrap = {
                                                                    let sm = crate::scp::ScpMessage {
                                                                        msg_type: Some(2),
                                                                        data: <crate::scp::SyncSecure as prost::Message>::encode_to_vec(&ss),
                                                                    };
                                                                    <crate::scp::ScpMessage as prost::Message>::encode_to_vec(&sm)
                                                                };
                                                                let key: &[u8] =
                                                                    if std::env::var("SCP_SS_KEY")
                                                                        .as_deref()
                                                                        == Ok("ek")
                                                                    {
                                                                        ctx.encode_key()
                                                                    } else {
                                                                        ctx.decode_key()
                                                                    };
                                                                let mut iv = [0u8; 16];
                                                                if std::env::var("SCP_SS_IV")
                                                                    .as_deref()
                                                                    != Ok("zero")
                                                                    && let Some(pi) =
                                                                        ss_iv.as_deref()
                                                                {
                                                                    iv[..16].copy_from_slice(
                                                                        &pi[..16.min(pi.len())],
                                                                    );
                                                                }
                                                                let mut nonce = [0u8; 8];
                                                                if std::env::var(
                                                                    "SCP_SS_NONCE_ZERO",
                                                                )
                                                                .is_err()
                                                                {
                                                                    use rand::Rng;
                                                                    rand::rng()
                                                                        .fill_bytes(&mut nonce);
                                                                }
                                                                let sealed_iv: Option<Vec<u8>> = {
                                                                    let mut ivv: Vec<Vec<u8>> =
                                                                        Vec::new();
                                                                    if let Some(pi) =
                                                                        ss_iv.as_deref()
                                                                    {
                                                                        if pi.len() == 12 {
                                                                            ivv.push(pi.to_vec());
                                                                        }
                                                                        if pi.len() == 16 {
                                                                            ivv.push(
                                                                                pi[..12].to_vec(),
                                                                            );
                                                                        }
                                                                    }
                                                                    ivv.push(vec![
                                                                        0, 1, 2, 3, 4, 5, 6, 7, 8,
                                                                        9, 10, 11,
                                                                    ]);
                                                                    ivv.into_iter().find_map(|iv| {
                                                                        crate::d2d::cryptor_seal_iv(
                                                                            key, &iv, &wrap,
                                                                        )
                                                                        .ok()
                                                                    })
                                                                };
                                                                let ct = match sealed_iv {
                                                                    Some(ct) => ct,
                                                                    None => {
                                                                        tracing::info!(
                                                                            "[scp] {peer} SS seal failed"
                                                                        );
                                                                        crate::scp::msg_frame(
                                                                            2,
                                                                            <crate::scp::SyncSecure as prost::Message>::encode_to_vec(
                                                                                &ss,
                                                                            ),
                                                                        )
                                                                    }
                                                                };
                                                                let _ = nonce;
                                                                crate::scp::msg_frame_sealed(ct)
                                                            } else {
                                                                crate::scp::msg_frame(2, <crate::scp::SyncSecure as prost::Message>::encode_to_vec(&ss))
                                                            };
                                                            tracing::info!(
                                                                "[scp] {peer} SYNC_SECURE send (pdid {pdid}, ksc {}B, enc={}/{}/{})",
                                                                ss.ksc
                                                                    .as_ref()
                                                                    .map_or(0, |v| v.len()),
                                                                std::env::var("SCP_SS_ENC").is_ok(),
                                                                std::env::var("SCP_SS_KEY").unwrap_or_else(|_| "dk".into()),
                                                                std::env::var("SCP_SS_IV").unwrap_or_else(|_| "range".into()),
                                                            );
                                                            record(
                                                                &path,
                                                                &format!(
                                                                    "sent {peer} sync-secure-send"
                                                                ),
                                                                &f,
                                                            );
                                                            let _ = sock.write_all(&f).await;
                                                            let _ = sock.flush().await;
                                                        }
                                                    }
                                                }
                                            }
                                            Ok(false) => tracing::info!(
                                                "[scp] {peer} ukey2 mt{mt} ignored (state)"
                                            ),
                                            Err(e) => tracing::info!(
                                                "[scp] {peer} ukey2 parse mt{mt} failed: {e}"
                                            ),
                                        }
                                    }
                                    2 => {
                                        if !ss_echoed {
                                            ss_echoed = true;
                                            let pdid = std::env::var("SCP_PDID")
                                                .unwrap_or_else(|_| "A1B2C3D4E5F6".into());
                                            match crate::scp::sync_secure_echo(&m.data, &pdid) {
                                                Ok(f) => {
                                                    tracing::info!(
                                                        "[scp] {peer} SYNC_SECURE echo (pdid {pdid}, {}B data)",
                                                        m.data.len()
                                                    );
                                                    record(
                                                        &path,
                                                        &format!("sent {peer} sync-secure-echo"),
                                                        &f,
                                                    );
                                                    let _ = sock.write_all(&f).await;
                                                    let _ = sock.flush().await;
                                                }
                                                Err(e) => tracing::info!(
                                                    "[scp] {peer} SYNC_SECURE decode failed: {e} | {}",
                                                    hex::encode(&m.data)
                                                ),
                                            }
                                        }
                                    }
                                    other => tracing::info!(
                                        "[scp] {peer} unexpected inbound msgType {other:?} ({}B data) | {}",
                                        m.data.len(),
                                        hex::encode(&m.data[..m.data.len().min(32)])
                                    ),
                                }
                            }
                        }
                        // Server-role leg (the phone dialed): role model exact —
                        // send HELLO only after the peer's HELLO, SYNC only after
                        // the peer's SYNC. The peer's consumers attach
                        // asynchronously to a replay-0 channel, so preemptive
                        // bursts race: an early frame gets consumed by the wrong
                        // waiter (observed: its receiveSync aborted on our HELLO,
                        // `syn ack null`).
                        if std::env::var("CLIENTSCP").is_ok()
                            && sub.len() >= 2
                            && sub[0] == 0x40
                            && sub[1] == 0x30
                            && let Some(m) = crate::scp::decode_payload(&sub[8..])
                        {
                            let mt = m.msg_type.unwrap_or(0);
                            // Re-send armed by an earlier event lands here,
                            // one RTT after the original.
                            if sync_sent && sync_pending && std::env::var("SCP_SYNC_RESEND").is_ok()
                            {
                                sync_pending = false;
                                let hseq = hbase.unwrap_or_else(crate::scp::now_base);
                                let keytype: i32 = std::env::var("SCP_KEYTYPE")
                                    .ok()
                                    .and_then(|v| v.parse().ok())
                                    .unwrap_or(3);
                                let sync = crate::scp::sync_frame_ex(
                                    hseq + 1,
                                    "active_connection",
                                    "com.heytap.accessory",
                                    &dev_name,
                                    &scp_model(),
                                    true,
                                    keytype,
                                );
                                record(
                                    &path,
                                    &format!("sent {peer} sync-resend seq{}", hseq + 1),
                                    &sync,
                                );
                                let _ = sock.write_all(&sync).await;
                                let _ = sock.flush().await;
                                tracing::info!(
                                    "[tcp] {peer} scp sync seq{} (resend on mt{mt}) t={} | {}",
                                    hseq + 1,
                                    tclock!(),
                                    hex::encode(&sync)
                                );
                            }
                            if mt != 1 && !hello_sent {
                                hello_sent = true;
                                // Their `waiting4Hello`/`receiveHello` waiters
                                // match on ScpWrapData.msgType == 0. A HELLO
                                // emitted before those waiters attach lands in
                                // the shared replay-1 channel and is later eaten
                                // by the SYNC_SECURE waiter as msgType[0]
                                // (2564), so keep it back when probing.
                                if std::env::var("SCP_NO_HELLO").is_ok() {
                                    continue;
                                }
                                let base = crate::scp::q_from_payload(&sub[8..])
                                    .map(|q| q.sequence_no)
                                    .unwrap_or_else(crate::scp::now_base);
                                hbase = Some(base);
                                let delta: u32 = std::env::var("SCP_SEQ_DELTA")
                                    .ok()
                                    .and_then(|s| s.parse().ok())
                                    .unwrap_or(1);
                                let hseq = base + delta;
                                let hello = crate::scp::hello_frame_ex(
                                    hseq,
                                    "active_connection",
                                    "com.heytap.accessory",
                                    true,
                                );
                                record(&path, &format!("sent {peer} hello seq{hseq}"), &hello);
                                let _ = sock.write_all(&hello).await;
                                let _ = sock.flush().await;
                                hello_at = Some(std::time::Instant::now());
                                tracing::info!(
                                    "[tcp] {peer} scp hello seq{hseq} (reactive) t={} | {}",
                                    tclock!(),
                                    hex::encode(&hello)
                                );
                            } else if mt == 1 && std::env::var("SCP_NO_SYNC").is_err() {
                                // Peer's SYNC: answer immediately. Its
                                // `receiveSync` consumer attaches only after
                                // it transmits this SYNC, so the immediate
                                // copy can race the attach and be dropped on
                                // the replay-0 channel (`syn ack may be
                                // timeout` with no wrong-type log). Arm the
                                // one-shot re-send for the next inbound frame
                                // — protocol-triggered, not timed.
                                if !sync_sent {
                                    sync_sent = true;
                                    sync_pending = true;
                                    // Their reader handles ONE frame per read:
                                    // a sync coalesced behind our HELLO is
                                    // tail-dropped, so keep a wave gap.
                                    if let Some(t) = hello_at {
                                        let ms = t.elapsed().as_millis();
                                        if ms < 250 {
                                            tokio::time::sleep(std::time::Duration::from_millis(
                                                250 - ms as u64,
                                            ))
                                            .await;
                                        }
                                    }
                                    let hseq = hbase.unwrap_or_else(crate::scp::now_base);
                                    let keytype: i32 = std::env::var("SCP_KEYTYPE")
                                        .ok()
                                        .and_then(|v| v.parse().ok())
                                        .unwrap_or(3);
                                    let sync = crate::scp::sync_frame_ex(
                                        hseq + 1,
                                        "active_connection",
                                        "com.heytap.accessory",
                                        &dev_name,
                                        &scp_model(),
                                        true,
                                        keytype,
                                    );
                                    record(
                                        &path,
                                        &format!("sent {peer} sync seq{}", hseq + 1),
                                        &sync,
                                    );
                                    let _ = sock.write_all(&sync).await;
                                    let _ = sock.flush().await;
                                    tracing::info!(
                                        "[tcp] {peer} scp sync seq{} (reactive) t={} | {}",
                                        hseq + 1,
                                        tclock!(),
                                        hex::encode(&sync)
                                    );
                                }
                            }
                        }
                        // Frame: [40 30][len u16][type u16][seq u16][payload]; the
                        // len counts payload bytes after the 4-byte token prefix.
                        // Answer channel-open requests (type 0x0002) with an
                        // echo response so the 5 s timeout does not fire.
                        if sub.len() >= 10
                            && sub[0] == 0x40
                            && sub[1] == 0x30
                            && sub[4..6] == [0x00, 0x02]
                        {
                            let payload = &sub[8..];
                            let variant_str =
                                std::env::var("RESP").unwrap_or_else(|_| "echo".into());
                            let variant =
                                RespVariant::from_str(&variant_str).unwrap_or(RespVariant::Echo);
                            let is_active = payload.windows(17).any(|w| w == b"active_connection");
                            let mut body: Vec<u8> = Vec::new();
                            match variant {
                                // no reply at all: every reply body parses on the
                                // phone as msg_type-omitted = HELLO and lands on
                                // the ScpItem consumers (`receiveSync` aborts on
                                // `msgType[0]`); the phone never needed these acks
                                // — it proceeds past OPEN without them.
                                RespVariant::Off => {}
                                // token only + f3=1 (accept)
                                RespVariant::Accept => {
                                    body.extend_from_slice(&payload[..4]);
                                    body.extend_from_slice(&[0x18, 0x01]);
                                }
                                // token + empty f2 message
                                RespVariant::Empty2 => {
                                    body.extend_from_slice(&payload[..4]);
                                    body.extend_from_slice(&[0x12, 0x00]);
                                }
                                // token + f2{f1=1}
                                RespVariant::Ok2 => {
                                    body.extend_from_slice(&payload[..4]);
                                    body.extend_from_slice(&[0x12, 0x02, 0x08, 0x01]);
                                }
                                // token + f1=1 (success in field 1)
                                RespVariant::Ok1 => {
                                    body.extend_from_slice(&payload[..4]);
                                    body.extend_from_slice(&[0x18, 0x01]);
                                }
                                RespVariant::Echo
                                | RespVariant::Type3
                                | RespVariant::Type1
                                | RespVariant::Other(_) => body.extend_from_slice(payload),
                            }
                            if variant != RespVariant::Off {
                                let rtype: [u8; 2] = match variant {
                                    RespVariant::Type3 => [0x00, 0x03],
                                    RespVariant::Type1 => [0x00, 0x01],
                                    _ => [0x00, 0x00],
                                };
                                // body = token(4) || proto; header len excludes the token.
                                let len = (body.len().saturating_sub(4)) as u16;
                                let mut reply = Vec::with_capacity(8 + body.len());
                                // Responses carry the 0x34 response flag (their client
                                // routes 4034 frames into the pending open future).
                                reply.extend_from_slice(&[0x40, 0x34]);
                                reply.extend_from_slice(&len.to_be_bytes());
                                reply.extend_from_slice(&rtype);
                                reply.extend_from_slice(&sub[6..8]);
                                reply.extend_from_slice(&body);
                                tracing::info!(
                                    "[tcp] {peer} reply({variant}) {}B | {}",
                                    reply.len(),
                                    hex::encode(&reply[..reply.len().min(64)])
                                );
                                record(&path, &format!("sent {peer} reply({variant})"), &reply);
                                let _ = sock.write_all(&reply).await;
                                let _ = sock.flush().await;
                            }
                            // SCP client leg on the accepted channel: send HELLO
                            // now; SYNC goes out reactively after the phone's
                            // own HELLO (their waiting4Sync ignores pre-hello
                            // frames — see inbound decode branch).
                            if is_active && std::env::var("CLIENTSCP_REACTIVE_OFF").is_ok() {
                                // (legacy preemptive path, disabled)
                            }
                            // EstablishLink: the phone's AndroidMultiLanServer
                            // waits to accept our callback connection.
                            if is_active && !dialed {
                                dialed = true;
                                for p in std::env::var("SCP_DIAL_PORTS")
                                    .ok()
                                    .map(|s| {
                                        s.split(',')
                                            .filter_map(|x| x.trim().parse::<u16>().ok())
                                            .collect::<Vec<u16>>()
                                    })
                                    .unwrap_or_else(|| {
                                        vec![10153u16, 10162, 10151, 10152, 10150, 59399]
                                    })
                                {
                                    if p == 10152 && std::env::var("SCP_NO_OPENOUT").is_ok() {
                                        continue;
                                    }
                                    let addr = (peer.ip(), p);
                                    let capex_dial = std::env::var("EPI_CAPEX_DIAL")
                                        .ok()
                                        .and_then(|s| s.parse::<u16>().ok())
                                        == Some(p);
                                    match tokio::time::timeout(
                                        std::time::Duration::from_millis(800),
                                        tokio::net::TcpStream::connect(addr),
                                    )
                                    .await
                                    {
                                        Ok(Ok(mut stream)) => {
                                            tracing::info!(
                                                "[tcp] callback :{p} to {peer} connected (keep)"
                                            );
                                            if capex_dial {
                                                // Reserved-session/databus lane:
                                                // send the capex QUERY here
                                                // (transport session queue),
                                                // answer phone RESPONSE with CONFIRM.
                                                let mut q: Vec<u8> =
                                                    vec![0x01, 0x03, 0, 0, 0, 0, 6];
                                                for pr in [
                                                    "com.oplus.pantaconnect.globaldevice.discovery",
                                                    "uuid.icdf.service1",
                                                    "app:oplus.pantaconnect.app_service",
                                                    "vdc.service.sync",
                                                    "oaf.service.iphone.call",
                                                    "icdf.videocall.service",
                                                ] {
                                                    q.extend_from_slice(pr.as_bytes());
                                                    q.push(0x3b);
                                                }
                                                let qf = dt_frame(&q);
                                                let _ = stream.write_all(&qf).await;
                                                tracing::info!(
                                                    "[tcp] :{p} -> CAPEX QUERY dialed {}B",
                                                    qf.len()
                                                );
                                                record(&path, &format!("capexdial{p} q"), &qf);
                                                let (mut r0, mut w0) = stream.into_split();
                                                let path0 = path.clone();
                                                tokio::spawn(async move {
                                                    let mut b = [0u8; 4096];
                                                    let mut buf: Vec<u8> = Vec::new();
                                                    let mut conf_sent = false;
                                                    loop {
                                                        match r0.read(&mut b).await {
                                                            Ok(0) | Err(_) => break,
                                                            Ok(n) => {
                                                                tracing::info!(
                                                                    "[tcp] :{p} <- {n}B | {}",
                                                                    hex::encode(&b[..n.min(64)])
                                                                );
                                                                record(
                                                                    &path0,
                                                                    &format!("capexdial{p} rx"),
                                                                    &b[..n],
                                                                );
                                                                buf.extend_from_slice(&b[..n]);
                                                                loop {
                                                                    if buf.len() < 2 {
                                                                        break;
                                                                    }
                                                                    let (hl, pl) = if buf[0] == 0
                                                                        && buf[1] > 0
                                                                    {
                                                                        (2usize, buf[1] as usize)
                                                                    } else {
                                                                        break;
                                                                    };
                                                                    if buf.len() < hl + pl {
                                                                        break;
                                                                    }
                                                                    let pld =
                                                                        buf[hl..hl + pl].to_vec();
                                                                    buf.drain(..hl + pl);
                                                                    let mt = pld[0];
                                                                    tracing::info!(
                                                                        "[tcp] :{p} frame mt={mt} {}B {}",
                                                                        pld.len(),
                                                                        hex::encode(
                                                                            &pld[..pld
                                                                                .len()
                                                                                .min(48)]
                                                                        )
                                                                    );
                                                                    if mt == 2 && !conf_sent {
                                                                        let cf = dt_frame(
                                                                            &capex_confirm(0, 0),
                                                                        );
                                                                        let _ =
                                                                            w0.write_all(&cf).await;
                                                                        tracing::info!(
                                                                            "[tcp] :{p} -> CAPEX CONFIRM (status 0)"
                                                                        );
                                                                        record(
                                                                            &path0,
                                                                            &format!(
                                                                                "capexdial{p} cfm"
                                                                            ),
                                                                            &cf,
                                                                        );
                                                                        conf_sent = true;
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                });
                                            } else if p == 10153 {
                                                // CloudProbeConnection accept
                                                // waits <=2 s on this socket. Keep
                                                // it OPEN (their read blocks, no
                                                // EOF) but write NOTHING: an
                                                // empty-body `0x30` data frame
                                                // parses on the phone as
                                                // `ScpMessage{}` = HELLO with our
                                                // agentAddress and isServer=0 —
                                                // ScpAddressing routes it by
                                                // header, poisoning the
                                                // active_connection server item
                                                // (2546 `sync req is null`).
                                                let (mut r1, w1) = stream.into_split();
                                                tracing::info!(
                                                    "[tcp] probe keep-alive -> :{p} (silent)"
                                                );
                                                std::mem::forget(w1);
                                                let path3 = path.clone();
                                                tokio::spawn(async move {
                                                    let mut b = [0u8; 2048];
                                                    loop {
                                                        match r1.read(&mut b).await {
                                                            Ok(0) | Err(_) => break,
                                                            Ok(n) => {
                                                                tracing::info!(
                                                                    "[tcp] :{p} probe resp {n}B | {}",
                                                                    hex::encode(&b[..n.min(64)])
                                                                );
                                                                record(
                                                                    &path3,
                                                                    &format!("tcp {peer} probe"),
                                                                    &b[..n],
                                                                );
                                                                if let Some(m) =
                                                                    crate::scp::decode_payload(
                                                                        &b[8..n],
                                                                    )
                                                                {
                                                                    tracing::info!(
                                                                        "[scp] {peer} probe <- {}",
                                                                        crate::scp::msg_name(
                                                                            m.msg_type.unwrap_or(0)
                                                                        )
                                                                    );
                                                                }
                                                            }
                                                        }
                                                    }
                                                });
                                            } else if p == 10152 {
                                                // open-out: we are the cpbus client on
                                                // the phone's session server; request
                                                // our own agent channel then hold it.
                                                let (mut r, mut w) = stream.into_split();
                                                let path2 = path.clone();
                                                let id: u64 = 0x1_95ad_0001;
                                                let mut vid = Vec::new();
                                                let mut v = id;
                                                while v >= 0x80 {
                                                    vid.push((v as u8 & 0x7f) | 0x80);
                                                    v >>= 7;
                                                }
                                                vid.push(v as u8);
                                                let mut body: Vec<u8> =
                                                    vec![0x7b, 0x08, 0xad, 0x12, 0x12];
                                                let inner: Vec<u8> = {
                                                    let mut i = vec![0x08];
                                                    i.extend_from_slice(&vid);
                                                    i.extend_from_slice(&[0x12, 0x11]);
                                                    i.extend_from_slice(b"active_connection");
                                                    i.extend_from_slice(&[0x1a, 0x14]);
                                                    i.extend_from_slice(b"com.heytap.accessory");
                                                    i
                                                };
                                                body.push(inner.len() as u8);
                                                body.extend_from_slice(&inner);
                                                let len = (body.len() - 4) as u16;
                                                let mut frame = vec![0x40, 0x30];
                                                frame.extend_from_slice(&len.to_be_bytes());
                                                frame.extend_from_slice(&[0x00, 0x02]);
                                                frame.extend_from_slice(&[0x00, 0x00]);
                                                frame.extend_from_slice(&body);
                                                tracing::info!(
                                                    "[tcp] open-out -> :{p} {}B | {}",
                                                    frame.len(),
                                                    hex::encode(&frame)
                                                );
                                                record(&path2, "sent open-out open", &frame);
                                                let _ = w.write_all(&frame).await;
                                                let _ = w.flush().await;
                                                if let Ok(extra) = std::env::var("OPENOUT_SYNC") {
                                                    for part in extra.split(';') {
                                                        if let Ok(bytes) = hex::decode(part.trim())
                                                        {
                                                            tracing::info!(
                                                                "[tcp] open-out extra {}/{:x}B",
                                                                bytes.len(),
                                                                bytes.len()
                                                            );
                                                            record(
                                                                &path2,
                                                                "sent open-out extra",
                                                                &bytes,
                                                            );
                                                            let _ = w.write_all(&bytes).await;
                                                            let _ = w.flush().await;
                                                        }
                                                    }
                                                }
                                                if std::env::var("CLIENTSCP").is_ok() {
                                                    // Reactive hello+sync is sent from
                                                    // the reader once the ack arrives
                                                    // (echoing its q); no eager hello.
                                                }
                                                let dev_name2 = dev_name.clone();
                                                tokio::spawn(async move {
                                                    let mut b = [0u8; 2048];
                                                    let mut sync_sent2 = false;
                                                    loop {
                                                        match r.read(&mut b).await {
                                                            Ok(0) | Err(_) => break,
                                                            Ok(n) => {
                                                                tracing::info!(
                                                                    "[tcp] :{p} resp {n}B | {}",
                                                                    hex::encode(&b[..n.min(64)])
                                                                );
                                                                record(
                                                                    &path2,
                                                                    &format!("tcp {peer} open-out"),
                                                                    &b[..n],
                                                                );
                                                                if let Some(m) =
                                                                    crate::scp::decode_payload(
                                                                        &b[8..n],
                                                                    )
                                                                {
                                                                    let qs =
                                                                        crate::scp::q_from_payload(
                                                                            &b[8..n],
                                                                        )
                                                                        .map(|q| q.sequence_no);
                                                                    tracing::info!(
                                                                        "[scp] {peer} open-out <- {} qseq={qs:?} fseq={}",
                                                                        crate::scp::msg_name(
                                                                            m.msg_type.unwrap_or(0)
                                                                        ),
                                                                        u16::from_be_bytes([
                                                                            b[6], b[7]
                                                                        ])
                                                                    );
                                                                    // Their mutual-OPEN
                                                                    // handshake: answer
                                                                    // the type-0x0002 OPEN
                                                                    // with our ack (same
                                                                    // ok2 shape as the
                                                                    // inbound leg) or the
                                                                    // 5 s dispatcher
                                                                    // timeout fires.
                                                                    if n >= 6
                                                                        && b[4..6] == [0x00, 0x02]
                                                                        && std::env::var(
                                                                            "OPENOUT_ACK",
                                                                        )
                                                                        .is_ok()
                                                                    {
                                                                        let ack: [u8; 16] = [
                                                                            0x40, 0x34, 0x00, 0x04,
                                                                            0x00, 0x00, 0x00, 0x00,
                                                                            0x7b, 0x08, 0xad, 0x12,
                                                                            0x12, 0x02, 0x08, 0x01,
                                                                        ];
                                                                        record(
                                                                            &path2,
                                                                            "sent open-out open-ack",
                                                                            &ack,
                                                                        );
                                                                        let _ =
                                                                            w.write_all(&ack).await;
                                                                        let _ = w.flush().await;
                                                                        tracing::info!(
                                                                            "[scp] {peer} open-out open-ack sent"
                                                                        );
                                                                    }
                                                                    if m.msg_type != Some(1)
                                                                        && !sync_sent2
                                                                        && std::env::var(
                                                                            "SCP_OPENOUT_SCP",
                                                                        )
                                                                        .is_ok()
                                                                    {
                                                                        sync_sent2 = true;
                                                                        let base = crate::scp::q_from_payload(&b[8..n])
                                                                    .map(|q| q.sequence_no)
                                                                    .unwrap_or_else(crate::scp::now_base);
                                                                        // Their ScpServer flow is strictly
                                                                        // sequential — waiting4Hello, then
                                                                        // receiveSync — and a wrong-typed frame is
                                                                        // FATAL while receiveSync is attached. Our
                                                                        // OPEN (msgType omitted → 0) is consumed
                                                                        // as their hello (their HELLO response proves it), so the ONLY frame
                                                                        // to send now is SYNC, one wave later.
                                                                        let sync = crate::scp::sync_frame_ex(base + 1, "active_connection", "com.heytap.accessory", &dev_name2, &scp_model(), false, 3);
                                                                        record(
                                                                            &path2,
                                                                            &format!(
                                                                                "sent open-out sync seq{}",
                                                                                base + 1
                                                                            ),
                                                                            &sync,
                                                                        );
                                                                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                                                                        let _ = w
                                                                            .write_all(&sync)
                                                                            .await;
                                                                        let _ = w.flush().await;
                                                                        tracing::info!(
                                                                            "[scp] {peer} open-out reactive sync seq{base} sent"
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                });
                                            } else if p == 10162 || p == 10150 {
                                                // Candidate SCP listener slots: greet
                                                // with the same HELLO/SYNC set.
                                                if std::env::var("SCP_GREET").is_ok() {
                                                    let (hb, _sb) = crate::scp::hello_sync_bytes(
                                                        "active_connection",
                                                        "com.heytap.accessory",
                                                        &dev_name,
                                                        &scp_model(),
                                                    );
                                                    for ft in [1u16, 2, 0] {
                                                        let hello = crate::scp::frame_t(ft, 1, &hb);
                                                        record(
                                                            &path,
                                                            &format!("sent :{p} hello ft{ft}"),
                                                            &hello,
                                                        );
                                                        let _ = stream.write_all(&hello).await;
                                                    }
                                                    let (_h, sb) = crate::scp::hello_sync_bytes(
                                                        "active_connection",
                                                        "com.heytap.accessory",
                                                        &dev_name,
                                                        &scp_model(),
                                                    );
                                                    for ft in [1u16, 2, 0] {
                                                        let sync = crate::scp::frame_t(ft, 2, &sb);
                                                        record(
                                                            &path,
                                                            &format!("sent :{p} sync ft{ft}"),
                                                            &sync,
                                                        );
                                                        let _ = stream.write_all(&sync).await;
                                                    }
                                                    let _ = stream.flush().await;
                                                    tracing::info!("[tcp] :{p} scp greeting sent");
                                                }
                                                std::mem::forget(stream);
                                            } else if p == 59399 {
                                                // AndroidTcpProbeServer: the PC must
                                                // announce itself as a lanprovider
                                                // probe — >=1 byte within 1 s, and the
                                                // bytes are parsed as an SDP packet.
                                                let reg = reg59399.clone();
                                                let (mut r9, mut w9) = stream.into_split();
                                                record(&path, "sent probe59399 REGISTER", &reg);
                                                let _ = w9.write_all(&reg).await;
                                                let _ = w9.flush().await;
                                                tracing::info!(
                                                    "[tcp] probe59399 REGISTER -> {peer} {}B",
                                                    reg.len()
                                                );
                                                std::mem::forget(w9);
                                                let path9 = path.clone();
                                                tokio::spawn(async move {
                                                    let mut b = [0u8; 2048];
                                                    loop {
                                                        match r9.read(&mut b).await {
                                                            Ok(0) | Err(_) => break,
                                                            Ok(n) => {
                                                                tracing::info!(
                                                                    "[tcp] :{p} probe59399 resp {n}B | {}",
                                                                    hex::encode(&b[..n.min(64)])
                                                                );
                                                                record(
                                                                    &path9,
                                                                    &format!(
                                                                        "tcp {peer} probe59399"
                                                                    ),
                                                                    &b[..n],
                                                                );
                                                            }
                                                        }
                                                    }
                                                });
                                            } else {
                                                // Hold the connection; dropping it
                                                // would read as "Socket closed".
                                                std::mem::forget(stream);
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            tracing::info!("[tcp] callback :{p} to {peer} err {e}")
                                        }
                                        Err(_) => {
                                            tracing::info!("[tcp] callback :{p} to {peer} timeout")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    if let Ok(mut m) = SESSION_KILLERS.lock() {
        let v = m.entry(session_ip.clone()).or_default();
        v.retain(|h| !h.is_finished());
        v.push(task.abort_handle());
        tracing::info!(
            "[tcp] session pump registered for {session_ip} (n={})",
            v.len()
        );
    }
}

// SDP response context: config, sockets, and per-request SDP fields —
// grouping them would only rename the same bundle.
#[expect(clippy::too_many_arguments)]
async fn handle(
    cfg: &std::sync::Arc<SdpdConfig>,
    uni: &UdpSocket,
    link_b64: &Option<String>,
    seen: &mut HashMap<(String, String), Instant>,
    last_phone: &mut Option<SocketAddr>,
    plane: &str,
    from: SocketAddr,
    data: &[u8],
) {
    if from.ip().to_string().starts_with("127.") {
        return;
    }
    let line = first_line(data);
    tracing::info!("[{plane}] {from} {line}");
    record(
        &cfg.log_path,
        &format!("{plane} from {from} | {line}"),
        data,
    );
    *last_phone = Some(from);
    if let Ok(mut g) = PHONE_IP.lock() {
        *g = Some(from.ip().to_string());
    }
    let verb = line.split(' ').next().unwrap_or("").to_string();
    if verb != "QUERY" && !line.starts_with("SENSELESS ") {
        return;
    }
    let key = (from.ip().to_string(), verb.clone());
    if seen
        .get(&key)
        .is_some_and(|t| t.elapsed() < Duration::from_secs(5))
    {
        return;
    }
    seen.insert(key, Instant::now());
    for (variant, extra) in reply_variants(&verb) {
        let owned: Vec<(&str, &str)> = extra
            .iter()
            .map(|(k, v)| {
                if *k == "NSData" {
                    (*k, link_b64.as_deref().unwrap_or(*v))
                } else {
                    (*k, *v)
                }
            })
            .collect();
        let msg = render(variant.as_str(), cfg, &owned);
        tracing::info!("[{plane}] reply {variant:?} -> {from}");
        let _ = uni.send_to(msg.as_bytes(), from).await;
    }
}

/// bincode (varint encoding) unsigned integer.
fn bincode_varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// bincode (varint encoding) string: varint length + UTF-8 bytes.
fn bincode_str(s: &str, out: &mut Vec<u8>) {
    bincode_varint(s.len() as u64, out);
    out.extend_from_slice(s.as_bytes());
}

/// Identity MAC for link frames: `LINK_MAC`, else `eth0`, else synthetic.
fn link_mac_spec() -> String {
    std::env::var("LINK_MAC")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/sys/class/net/eth0/address")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "aa:bb:cc:dd:ee:ff".into())
}

/// Gateway string derived from the VIP's first three octets.
fn gateway_of(vip: &str) -> String {
    let octets: Vec<&str> = vip.split('.').collect();
    if octets.len() == 4 {
        format!("{}.{}.{}.1", octets[0], octets[1], octets[2])
    } else {
        vip.to_string()
    }
}

/// `LinkInfoPayload` for the LinkSwitchMgr `SERVICE-PUBLISH`
/// (phone-side parser: libcpkit `0x26528c` → `0x26392c`):
/// TLV `tag u16le 0x332F` + `version u8 0x32`, bincode varint length,
/// then bincode(varint) `LinkInfoPayloadData{compact_links,
/// v_gateway_ip_addr, need_all_response, known_peer_devices}`.
fn link_info_payload(mac: &str, ip: &str, gw: &str) -> Vec<u8> {
    let mut body = Vec::new();
    bincode_varint(1, &mut body); // compact_links: one entry
    bincode_varint(1, &mut body); // link_states_bitmap: WLAN_STA connected
    bincode_str(mac, &mut body); // link_mac_addr
    bincode_str(ip, &mut body); // link_ip_addr
    bincode_str(gw, &mut body); // v_gateway_ip_addr
    body.push(0); // need_all_response: false
    bincode_varint(0, &mut body); // known_peer_devices: []
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&[0x2f, 0x33, 0x32]); // tag 0x332F (LE) + version 0x32
    bincode_varint(body.len() as u64, &mut out);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // (ksc tests share the crate-wide ENV_TEST_LOCK: env mutation is process-global)

    #[expect(unsafe_code, reason = "std::env::set_var is unsafe in edition 2024")]
    fn ksc_env_isolate(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("lplus-ksc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        unsafe {
            std::env::set_var("LPLUS_STATE_DIR", &dir);
            std::env::remove_var("SCP_KSC");
        }
        dir
    }

    #[test]
    fn ksc_bond_is_minted_once_and_replayed_across_restarts() {
        let _guard = crate::state::ENV_TEST_LOCK.lock().expect("ksc test lock");
        let dir = ksc_env_isolate("mint");
        let (k1, a1) = issue_ksc("192.0.2.102", "A1B2C3D4E5F6");
        assert_eq!(k1.len(), 16);
        assert_eq!(a1.len(), 6);
        // "Restart" = fresh process view; the store file is re-read each call.
        let (k2, a2) = issue_ksc("192.0.2.102", "A1B2C3D4E5F6");
        assert_eq!(k1, k2, "resumption must replay the bonded ksc verbatim");
        assert_eq!(a1, a2, "alias must be stable too (loadKsc keys on it)");
        let stored = std::fs::read_to_string(crate::state::ksc_store_path()).expect("store");
        assert!(
            stored.contains(&hex::encode(&k1)),
            "bond not persisted: {stored}"
        );
        // A different peer gets its own key, not a reuse of the first.
        let (k3, _) = issue_ksc("192.0.2.103", "A1B2C3D4E5F6");
        assert_ne!(k1, k3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auth_mac_accepted_only_for_bonded_key_and_promoted_to_dev_id() {
        let _guard = crate::state::ENV_TEST_LOCK.lock().expect("ksc test lock");
        let dir = ksc_env_isolate("auth");
        let qc = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let ts = 45608u64;
        let bonded = [0xabu8; 16];
        let mac = ksc_s(&bonded, &qc, ts);
        let dev_hex = "bcc5b323465c";
        // No bond yet: nothing to verify against (phone would re-pair).
        assert!(ksc_candidates("192.0.2.102", dev_hex).is_empty());
        // Bond issued via sync-secure to the peer IP.
        let (_, alias) = issue_ksc("192.0.2.102", "A1B2C3D4E5F6");
        ksc_store_put("192.0.2.102", "A1B2C3D4E5F6", &bonded, &alias);
        let cands = ksc_candidates("192.0.2.102", dev_hex);
        assert_eq!(cands, vec![bonded.to_vec()]);
        assert!(cands.iter().any(|c| ksc_s(c, &qc, ts) == mac));
        // Success promotes the bond under the claimed device id, so the
        // next AUTH resolves even from a different socket/port.
        remember_ksc(dev_hex, dev_hex, &bonded);
        assert_eq!(ksc_candidates("192.0.2.9", dev_hex), vec![bonded.to_vec()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dbs_payload_json_accepts_our_frame_and_rejects_bad_msgtype() {
        let from = [1u8, 2, 3, 4, 5, 6];
        let to = [7u8, 8, 9, 10, 11, 12];
        let json = "{\"dbs_msg_type\":\"msg_topic_sync\",\"dbs_msg_id\":\"x\"}";
        let frame = crate::kms::dbs_data_frame(&from, &to, 7, 0x1001, json.as_bytes());
        let payload = &frame[4..];
        let v = dbs_payload_json(payload).expect("our own frame parses");
        assert_eq!(v["dbs_msg_type"], "msg_topic_sync");
        // The phone's DbsDataReceiver only parses dbr.a msgType 42/82.
        let mut bad = frame.clone();
        bad[4 + 3 + 26] = 7;
        assert!(dbs_payload_json(&bad[4..]).is_none());
    }

    #[test]
    fn topic_sync_json_carries_sub_list_and_type() {
        let j = crate::kms::dbs_topic_sync_json("aabb", "ccdd", &["Oplus_PcConnect"], 5);
        assert!(j.contains(r#""dbs_msg_type":"msg_topic_sync""#));
        assert!(j.contains(r#""sub":["Oplus_PcConnect"]"#));
        assert!(j.contains(r#""dbs_msg_from_device":"aabb""#));
    }

    /// The published blob must round-trip the phone parser's contract:
    /// TLV header `2f 33 32`, bincode varint payload length, then the
    /// six `LinkInfoPayloadData` fields in order.
    #[test]
    fn link_info_payload_round_trips_fields() {
        let mac = "02:00:00:00:00:01";
        let ip = "192.0.2.11";
        let gw = "192.0.2.1";
        let blob = link_info_payload(mac, ip, gw);
        assert_eq!(&blob[..3], &[0x2f, 0x33, 0x32]);

        let mut cur = &blob[3..];
        let read_varint = |cur: &mut &[u8]| -> u64 {
            let mut v = 0u64;
            let mut shift = 0;
            loop {
                let b = cur[0];
                *cur = &cur[1..];
                v |= ((b & 0x7f) as u64) << shift;
                if b & 0x80 == 0 {
                    return v;
                }
                shift += 7;
            }
        };
        let read_str = |cur: &mut &[u8]| -> String {
            let n = read_varint(cur) as usize;
            let s = String::from_utf8(cur[..n].to_vec()).unwrap();
            *cur = &cur[n..];
            s
        };

        let payload_len = read_varint(&mut cur) as usize;
        assert_eq!(payload_len, cur.len());
        assert_eq!(read_varint(&mut cur), 1); // compact_links count
        assert_eq!(read_varint(&mut cur), 1); // link_states_bitmap
        assert_eq!(read_str(&mut cur), mac);
        assert_eq!(read_str(&mut cur), ip);
        assert_eq!(read_str(&mut cur), gw);
        assert_eq!(cur[0], 0); // need_all_response
        cur = &cur[1..];
        assert_eq!(read_varint(&mut cur), 0); // known_peer_devices
        assert!(cur.is_empty());
    }

    #[test]
    fn gateway_of_derives_from_vip() {
        assert_eq!(gateway_of("192.0.2.11"), "192.0.2.1");
        assert_eq!(gateway_of("not-an-ip"), "not-an-ip");
    }

    #[test]
    fn render_has_all_validated_headers() {
        let cfg = SdpdConfig::default();
        let msg = render("ANNOUNCE * HTTP/1.1", &cfg, &[]);
        for key in [
            "NS:", "DSP:", "CSP:", "DMS:", "PDID:", "AD:", "DT:", "DN:", "MAN:",
        ] {
            assert!(msg.contains(key), "missing {key} in {msg}");
        }
        assert!(msg.ends_with("\r\n\r\n"));
        assert!(msg.contains("DT: 6"));
    }

    #[test]
    fn query_packet_first_line_parsed() {
        let wire = b"QUERY * HTTP/1.1\r\nMAN: \"sdp/1\"\r\nNS: scp.device\r\n\r\n";
        assert_eq!(first_line(wire), "QUERY * HTTP/1.1");
    }

    #[test]
    fn replies_cover_ack_and_200_shapes() {
        let v: Vec<String> = reply_variants("QUERY")
            .into_iter()
            .map(|(l, _)| l)
            .collect();
        assert!(v.iter().any(|l| l == "QUERY-ACK * HTTP/1.1"));
        assert!(v.iter().any(|l| l == "HTTP/1.1 200 OK"));
        let v: Vec<String> = reply_variants("SENSELESS")
            .into_iter()
            .map(|(l, _)| l)
            .collect();
        assert!(
            !v.iter()
                .any(|l| l.starts_with(proto::rtsp::RtspMethod::Announce.as_ref()))
        );
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;
    /// Live 2026-11-09 capture frame (KSC replaced by a synthetic constant;
    /// MACs re-derived from the pinned data): phone AUTH_REQUEST on our
    /// :46888 after the kscAlias fix. Pins the s() MAC construction.
    #[test]
    fn phone_auth_request_mac_vector() {
        let ksc = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        // Truncated to the bytes the MAC covers (hdr, code, ts, s-MAC);
        // the captured peer-id tail was scrubbed.
        let frame = hex::decode("1002b910f5b2b453bc2100000000000ceccf15d13d394c5cb12d").unwrap();
        let ts = u64::from_be_bytes(frame[10..18].try_into().unwrap());
        assert_eq!(ts, 847055);
        assert_eq!(
            ksc_s(&ksc, &frame[2..10], ts),
            <[u8; 8]>::try_from(&hex::decode("ddf9231a3bff24ec").unwrap()[..]).unwrap()
        );
    }
    /// Live confirm leg: client rc_2 = s(ksc, qs, ts_request) with the
    /// phone's own ts, and server Rs = t(ksc, qc, qs, ts_response) LE —
    /// both pinned from the 2026-11-09 :46888 session.
    #[test]
    fn phone_auth_confirm_and_response_vectors() {
        let ksc = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let qc = hex::decode("9623adac6690e35b").unwrap();
        let qs = hex::decode("43aa25bad6cdfac1").unwrap();
        assert_eq!(
            ksc_s(&ksc, &qs, 847273),
            <[u8; 8]>::try_from(&hex::decode("1ff18852275d64c5").unwrap()[..]).unwrap()
        );
        assert_eq!(
            ksc_t(&ksc, &qc, &qs, 1794216480975),
            <[u8; 8]>::try_from(&hex::decode("605c4a2a6e09a9b3").unwrap()[..]).unwrap()
        );
    }

    #[test]
    fn capex_query_and_confirm_wire() {
        // Pins the datatrans/service/f.y()-mirrored layouts:
        // QUERY = 01|queryType 03|checksum u32be|recordNum u8|ids+0x3B
        assert_eq!(
            capex_query(&["ab.cd", "e"]),
            vec![
                0x01, 0x03, 0, 0, 0, 0, 2, b'a', b'b', b'.', b'c', b'd', 0x3b, b'e', 0x3b
            ],
        );
        // CONFIRM = 04|accessoryId u16be|statusCode u8 (4B payload)
        assert_eq!(capex_confirm(0x8C0E, 0), vec![0x04, 0x8C, 0x0E, 0x00]);
    }

    #[test]
    fn capex_response_wire_shape() {
        let r = capex_response(&["e"]);
        assert_eq!(&r[0..2], &[0x02, 0x03]);
        assert_eq!(&r[6..8], &[0x00, 0x01]); // one package record
        assert_eq!(&r[8..], b"com.oplus.pantaconnect;A1B2C3D4E5F6000000000000000000FF;\x00\x01\x01\x00e;\x01\x00\x01\x00\x0a");
        // checksum = CRC32(pkg + pid + f "10" + role "1" + ver "1.0" + e,l,m "000" + sorted profiles)
        let expect = crc32(b"com.oplus.pantaconnecte1011.0000e");
        assert_eq!(&r[2..6], &expect.to_be_bytes());
    }

    #[test]
    fn crc32_matches_java_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn kms_bootstrap_frame_carries_databus_envelope() {
        let f = kms_bootstrap_frame(36863, "pw", "192.0.2.1", "A1B2C3D4E5F6", "0123456789AB")
            .expect("build");
        assert_eq!(&f[2..4], &[0x00, 0x20]); // ftype DATA, sid 8
        let json = String::from_utf8(f[7 + 52..].to_vec()).expect("utf8 tail");
        assert!(json.contains("\"key\":\"input_service\""));
        assert!(json.contains("msg_type\\\":61"));
        assert!(json.contains("kms_socket_port"));
        assert_eq!(&f[7..13], &hex::decode("A1B2C3D4E5F6").unwrap()[..]); // dbr from
    }

    #[test]
    fn session_info_frame_is_msgtype_then_raw_name() {
        // Phone side (session/a.java:878) reads msgType byte then takes the
        // remainder as deviceName; framing reuses the session header.
        let f = session_info_frame("NW", 2);
        assert_eq!(f, vec![0x00, 0x05, 0x00, 0x08, 101, b'N', b'W']);
    }

    #[test]
    fn sess_frame_encodes_capex_session_id() {
        // Session reader framing: len covers header+payload; header bits
        // (frameType << 9 | sessionId << 2 | fragmentation); sid 2 = capex.
        assert_eq!(
            sess_frame(&[0x01, 0x03], 2),
            vec![0x00, 0x04, 0x00, 0x08, 0x01, 0x03]
        );
        let q = capex_query(&["ab.cd"]);
        let f = sess_frame(&q, 2);
        assert_eq!(&f[0..2], &((q.len() + 2) as u16).to_be_bytes());
        assert_eq!(&f[2..4], &[0x00, 0x08]);
        assert_eq!(&f[4..], &q[..]);
    }

    #[test]
    fn sess_frame_databus_ack_matches_phone_peer_format() {
        // DataBus (sid 8) DATA [04][tid][ctr][ct+tag] is answered with the
        // plain ACK [0A][tid]; sid 8 must encode header 0x0020 (captured
        // 264B frames, sdp-rs.bin).
        assert_eq!(
            sess_frame(&[0x0a, 0x00, 0x01], 8),
            vec![0x00, 0x05, 0x00, 0x20, 0x0a, 0x00, 0x01]
        );
    }

    #[test]
    fn link_reply_mirror_substitutes_identity() {
        // Live phone probe frame (incl. [00][40] header), 2026-11-09 daemon log.
        let frame = hex::decode(concat!(
            "00400c30313233343536373839414201380201000b01fd010000000002",
            "0000000000000000000000000b01fc020200c00000000000000000000001fc110200c00000",
        ))
        .unwrap();
        let probe = &frame[2..];
        let r = link_reply_mirror(
            probe,
            b"A1B2C3D4E5F6",
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            &[192, 0, 2, 1],
            None,
            &[],
        )
        .unwrap();
        assert_eq!(r.len(), probe.len());
        assert_eq!(&r[1..13], b"A1B2C3D4E5F6");
        // MAC entry (0b 01 fd) now carries our MAC little-endian.
        let fdi = r.windows(3).rposition(|w| w == [0x0b, 0x01, 0xfd]).unwrap();
        assert_eq!(&r[fdi + 3..fdi + 9], &[0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa]);
        // IP entry (0b 01 fc) now carries 192.0.2.1 little-endian.
        let fci = r.windows(3).rposition(|w| w == [0x0b, 0x01, 0xfc]).unwrap();
        assert_eq!(&r[fci + 3..fci + 7], &[0x01, 0x02, 0x00, 0xc0]);
        // Trailing virtual-gateway entry (01 fc | 6B) republished as our IP:
        // otherwise the phone dials the active_connection lane to itself.
        let gwi = r.windows(2).rposition(|w| w == [0x01, 0xfc]).unwrap();
        assert!(gwi > fci);
        assert_eq!(&r[gwi + 2..gwi + 6], &[0x01, 0x02, 0x00, 0xc0]);
        assert_eq!(&r[gwi + 6..gwi + 8], &[0x00, 0x00]);
        // Phone's own PDID bytes are gone.
        assert!(!r.windows(12).any(|w| w == b"0123456789AB"));
        // Route poison: link_ip entry diverges from the v_gateway IP so the
        // phone's `192.0.2.1 via ... src vgate` route never shields our
        // real TCP lanes (see link_reply_mirror).
        let p = link_reply_mirror(
            probe,
            b"A1B2C3D4E5F6",
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            &[192, 0, 2, 1],
            Some(&[192, 0, 2, 16]),
            &[],
        )
        .unwrap();
        let pfci = p.windows(3).rposition(|w| w == [0x0b, 0x01, 0xfc]).unwrap();
        assert_eq!(&p[pfci + 3..pfci + 7], &[0x10, 0x02, 0x00, 0xc0]);
        let pgwi = p.windows(2).rposition(|w| w == [0x01, 0xfc]).unwrap();
        assert_eq!(&p[pgwi + 2..pgwi + 6], &[0x01, 0x02, 0x00, 0xc0]);
        // known_peer_devices trailer: [count][len id]* appended after the
        // 6-byte v_gateway entry (79B live frame shape from the phone).
        let k = link_reply_mirror(
            probe,
            b"A1B2C3D4E5F6",
            &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            &[192, 0, 2, 1],
            None,
            &[b"0123456789AB".to_vec(), b"A1B2C3D4E5F6".to_vec()],
        )
        .unwrap();
        assert_eq!(
            &k[probe.len()..probe.len() + 14],
            &[
                0x02u8, 0x0c, b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A',
                b'B'
            ][..]
        );
        assert!(k.ends_with(b"A1B2C3D4E5F6"));
        assert_eq!(k.len(), probe.len() + 1 + (1 + 12) * 2);
    }
}
