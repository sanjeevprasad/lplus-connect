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
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use strum::{Display, EnumString};
use tokio::net::UdpSocket;

use crate::config::{flag, hex_bytes, ipv4, num, ports, setting_str, str_of};
use crate::svc::{epi, scp_server};

/// Configuration for one responder instance.
#[derive(Clone)]
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

/// The machine's own name (cross-platform, via `whoami`). `whoami` needs
/// its `std` feature for the real `gethostname`; a literal `localhost`
/// (stub or misconfigured box) is useless as a beacon name, so it falls
/// through to the caller's default.
pub fn system_hostname() -> Option<String> {
    whoami::hostname()
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("localhost"))
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

pub(crate) fn ksc_stored(peer_key: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let r = ksc_store().remove(peer_key)?;
    let ksc = hex::decode(&r.ksc).ok()?;
    let alias = hex::decode(&r.alias).ok()?;
    (ksc.len() == 16 && alias.len() == 6).then_some((ksc, alias))
}

/// The store's only row, when exactly one peer is bonded. A phone's LAN IP
/// is DHCP-dynamic, so the key written at pairing can go stale; with a
/// single bond the AUTH exchange itself is the identity gate (a wrong peer
/// gets `KSC_ERROR`), and `remember_ksc` re-keys the row to the fresh IP on
/// success. Multi-bond stores deliberately return None — there the IP/
/// claimed-id keys must match.
pub(crate) fn single_bond() -> Option<KscRecord> {
    let mut rows = ksc_store().into_values();
    let r = rows.next()?;
    rows.next().is_none().then_some(r)
}

/// Whether the bond store covers an announcing peer, so a dial is worth
/// spending. The SDP `PDID` header is the phone's real identity — live
/// capture 2026-11-11 (PROTOCOL.md §4) shows it queries with its 6-byte
/// OnetId, equal to the bonded `device_id` row — so match it against the
/// rows' `device_id`; an exact IP-key row still counts (written at
/// pairing), and when the announcement carried no PDID the single-bond
/// fallback applies (AUTH then decides and re-keys). A PDID that matches no
/// row is a different phone — never dial it.
pub(crate) fn bond_covers(rows: &[(String, KscRecord)], ip: &str, pdid: Option<&str>) -> bool {
    if let Some(p) = pdid
        && rows
            .iter()
            .any(|(_, r)| !r.device_id.is_empty() && r.device_id.eq_ignore_ascii_case(p))
    {
        return true;
    }
    if rows.iter().any(|(k, _)| k == ip) {
        return true;
    }
    pdid.is_none() && rows.len() == 1
}

/// Store-reading wrapper for `svc::autolink`.
pub(crate) fn bond_announced(ip: &str, pdid: Option<&str>) -> bool {
    let rows: Vec<(String, KscRecord)> = ksc_store().into_iter().collect();
    bond_covers(&rows, ip, pdid)
}

/// The full stored bond row for `peer_key` (ksc + alias + the device id
/// the peer claims). The PC-dialed EPI lane needs the recorded device id:
/// the phone's DataBus broker only routes topic messages whose sender id
/// matches the peer identity its registry knows.
pub(crate) fn ksc_bond(peer_key: &str) -> Option<KscRecord> {
    let r = ksc_store().remove(peer_key)?;
    (hex::decode(&r.ksc).is_ok() && hex::decode(&r.alias).is_ok()).then_some(r)
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

/// Operator pin: `scpKsc` in `settings.json` forces the key for every
/// peer (pairing material restored from the panel settings).
/// The key pair to present to (and verify against) `peer_key`. Stored
/// bond wins so resumption always replays what the phone persisted; a
/// first pairing mints the random pair and persists it (vendor `b.java`
/// behavior). `SCP_KSC` pins over everything for restored bonds.
pub(crate) fn issue_ksc(pin: Option<&[u8]>, peer_key: &str, device_id: &str) -> (Vec<u8>, Vec<u8>) {
    if let Some(pair) = ksc_stored(peer_key) {
        return pair;
    }
    let ksc = pin.map(<[u8]>::to_vec).unwrap_or_else(|| ksc_rand(16));
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
pub(crate) fn ksc_candidates(pin: Option<&[u8]>, peer_key: &str, dev_key: &str) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for key in [peer_key, dev_key] {
        if let Some((ksc, _)) = ksc_stored(key)
            && !out.contains(&ksc)
        {
            out.push(ksc);
        }
    }
    // The settings-pinned bond must keep verifying until a successful
    // AUTH promotes it into a bond.
    if let Some(k) = pin {
        out.push(k.to_vec());
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

/// KMS bootstrap port span: `KMS_PORT` base (default 36863) plus
/// `KMS_PORT_ROT` candidates (default 4, clamped 1..16). `KMS_PORT_ROT=1`
/// reproduces the historical fixed-port behavior.
impl Sdp {
    /// Listener/rotation span; `max(1)` keeps a mis-set rot usable.
    pub(crate) fn kms_port_span(&self) -> u16 {
        self.gcfg.kms.port_rot.max(1)
    }
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
    {
        let mut rev = *mac6;
        rev.reverse();
        r[fdi + 3..fdi + 3 + 6].copy_from_slice(&rev);
    }
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
    {
        let mut rev = *route_ip;
        rev.reverse();
        r[fci + 3..fci + 3 + 4].copy_from_slice(&rev);
    }
    // The trailing `01 fc | gw6` entry is the peer virtual-gateway IP: the
    // phone stores it in peer_devices and dials the active_connection lane
    // to it (ConnectConfig.peerAddress). Left mirrored, the phone would
    // store its own vgate IP (192.0.2.17) and dial itself -> ksc row
    // lookup inverts (deviceId = phone PDID) and SecurityServerFsm dies with
    // KSC_ERROR/-2104. Publish our IP there instead.
    let fci2 = r.windows(2).rposition(|w| w == [0x01, 0xfc])?;
    if fci2 >= fci && fci2 + 2 + 4 <= r.len() {
        {
            let mut rev = *ip4;
            rev.reverse();
            r[fci2 + 2..fci2 + 2 + 4].copy_from_slice(&rev);
        }
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
pub(crate) fn sess_frame(payload: &[u8], session_id: u16) -> Vec<u8> {
    let hdr: u16 = session_id << 2;
    let l = (payload.len() + 2) as u16;
    let mut v = Vec::with_capacity(4 + payload.len());
    v.extend_from_slice(&l.to_be_bytes());
    v.extend_from_slice(&hdr.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// Capex frames ride the session lane unless `EPI_CAPEX_FRAME=bare`.
pub(crate) fn capex_frame(f: &crate::svc::epi::EpiConfig, payload: &[u8]) -> Vec<u8> {
    if f.capex_frame == "bare" {
        dt_frame(f, payload)
    } else {
        sess_frame(payload, 2)
    }
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
pub(crate) fn dt_frame(f: &crate::svc::epi::EpiConfig, payload: &[u8]) -> Vec<u8> {
    let l = payload.len() as u16;
    if f.framing == "raw3" {
        let mut v = vec![0x00, (l >> 8) as u8, (l & 0xff) as u8];
        v.extend_from_slice(payload);
        v
    } else if f.framing == "3b" {
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

/// Parse the dbr.a DbsMessage out of a DataBus sid-8 payload. Both prefix
/// forms are accepted: the legacy `[b0][tid u16be]` (body from 3, JSON from
/// 55) and the wire DATA form `[0x04][tid u16be][ctr u64be]` that both ends
/// now write (body from 11). Only broadcast msgTypes 42/82 carry a
/// DbsMessage — the phone's `DbsDataReceiver` (`bf/c.java` case 0) parses
/// nothing else.
fn dbs_payload_json(payload: &[u8]) -> Option<serde_json::Value> {
    // dbr.a (`g5/b.java s()`): 44 B fixed header, destination count (4 B
    // BE), count x 6 B ids, extra length (4 B BE), extra bytes, JSON.
    // prefix 11 skips `[04][tid][ctr8]`; prefix 3 keeps the ctr view the
    // phone's own sealed frames use, so dbr.a rides 8 bytes deeper.
    for (prefix, dbr) in [(3usize, 8usize), (11, 0)] {
        let body = payload.get(prefix + dbr..)?;
        if body.len() < 56 || !matches!(body[26], 42 | 82) {
            continue;
        }
        let count = u32::from_be_bytes(body[44..48].try_into().ok()?) as usize;
        if count > 255 {
            continue;
        }
        let extra_off = 48 + 6 * count;
        let extra_len =
            u32::from_be_bytes(body.get(extra_off..extra_off + 4)?.try_into().ok()?) as usize;
        if let Some(rest) = body.get(extra_off + 4 + extra_len..)
            && let Ok(v) = serde_json::from_slice(rest)
        {
            return Some(v);
        }
    }
    None
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

/// The SDP/UNI responder plus the SCP session server: owns the advertised
/// config, the presence broadcast, the last-seen phone peer, and a handle
/// on the EPI registry the session pump injects through.
pub struct Sdp {
    /// Wire/identity knobs for this daemon instance.
    pub cfg: SdpdConfig,
    /// Cached REGISTER probe reply handed to accepted sessions.
    probe_reg: Vec<u8>,
    /// Last LAN peer that probed the SDP planes (the phone). Used to
    /// resolve the `connect phone` shorthand in device actions.
    phone_ip: std::sync::Mutex<Option<String>>,
    /// Presence events for in-process consumers (the product embeds the
    /// daemon; external subscribers use the NDJSON bridge).
    device_tx: tokio::sync::broadcast::Sender<DeviceEvent>,
    /// Live EPI sink registry + command bus (session pumps inject here).
    pub epi: Arc<crate::svc::epi::Epi>,
    /// Index into the KMS bootstrap port span (`KMS_PORT`..+`KMS_PORT_ROT`);
    /// advanced per bootstrap session so the phone's same-port `start()`
    /// guard can never strand a stale ClientSocket (PROTOCOL §7.2).
    kms_rot: std::sync::atomic::AtomicU16,
    /// LAN peers that recently delivered sdp/1 traffic to us (phone QUERY /
    /// ANNOUNCE rounds every few seconds) → (last-seen, last SDP `PDID`).
    /// The address book for boot auto-link: a DHCP-renumbered phone
    /// re-announces itself, no IP list is persisted anywhere
    /// (`svc::autolink`).
    announced: std::sync::Mutex<HashMap<String, (Instant, Option<String>)>>,
    /// Global daemon configuration (nested sections, `Arc`-shared).
    pub gcfg: std::sync::Arc<crate::config::Config>,
    /// Pinned KSC (16 B) from config/settings for the PC-dialed lane.
    ksc_pin: Option<Vec<u8>>,
}

impl Sdp {
    pub fn new(cfg: SdpdConfig, epi: Arc<crate::svc::epi::Epi>) -> Arc<Self> {
        Self::with_config(cfg, epi, std::sync::Arc::new(crate::config::Config::load()))
    }

    /// Build with an explicit global config (tests / embedders).
    pub fn with_config(
        cfg: SdpdConfig,
        epi: Arc<crate::svc::epi::Epi>,
        gcfg: std::sync::Arc<crate::config::Config>,
    ) -> Arc<Self> {
        let mut cfg = cfg;
        if cfg.vip.trim().is_empty() {
            cfg.vip = default_vip();
            tracing::info!("[sdp] vip auto-resolved to {}", cfg.vip);
        }
        let (device_tx, _) = tokio::sync::broadcast::channel(64);
        let probe_reg = render("REGISTER * HTTP/1.1", &cfg, &[]).into_bytes();
        // Stored index is the last port handed to the phone; `begin_kms_session`
        // advances from it, so the first bootstrap never repeats that port
        // (a fresh daemon defaults to base, matching the pre-rotation history).
        let kms_rot = std::sync::atomic::AtomicU16::new(
            std::fs::read_to_string(crate::state::kms_rot_path())
                .ok()
                .and_then(|s| s.trim().parse::<u16>().ok())
                .unwrap_or(0),
        );
        let ksc_pin = gcfg.pairing.ksc_pin.clone();
        Arc::new(Self {
            cfg,
            gcfg,
            ksc_pin,
            probe_reg,
            phone_ip: std::sync::Mutex::default(),
            device_tx,
            epi,
            kms_rot,
            announced: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Subscribe to the presence event stream.
    pub fn subscribe_devices(&self) -> tokio::sync::broadcast::Receiver<DeviceEvent> {
        self.device_tx.subscribe()
    }

    pub(crate) fn set_phone_ip(&self, ip: &str) {
        if let Ok(mut g) = self.phone_ip.lock() {
            *g = Some(ip.to_string());
        }
    }

    /// Record sdp/1 traffic from `ip` (called for every inbound SDP/UNI
    /// datagram; the phone re-sends QUERY/ANNOUNCE rounds every few
    /// seconds, so freshness doubles as liveness). `pdid` is the SDP header
    /// identity when the datagram carried one.
    pub(crate) fn note_announced(&self, ip: &str, pdid: Option<String>) {
        if let Ok(mut m) = self.announced.lock() {
            let now = Instant::now();
            match m.get_mut(ip) {
                Some(e) => {
                    e.0 = now;
                    if pdid.is_some() {
                        e.1 = pdid;
                    }
                }
                None => {
                    m.insert(ip.to_string(), (now, pdid));
                }
            }
        }
    }

    /// Peers seen on the SDP planes within `max_age`, oldest first, with
    /// their last SDP `PDID` if ever observed.
    pub(crate) fn announced_peers(&self, max_age: Duration) -> Vec<(String, Option<String>)> {
        let mut v: Vec<(Instant, String, Option<String>)> = self
            .announced
            .lock()
            .ok()
            .map(|m| {
                m.iter()
                    .filter(|(_, (t, _))| t.elapsed() < max_age)
                    .map(|(ip, (t, p))| (*t, ip.clone(), p.clone()))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v.into_iter().map(|(_, ip, p)| (ip, p)).collect()
    }

    /// Resolve the `"phone"` shorthand device-action target to the last
    /// LAN peer seen on the SDP planes; anything else is already an address.
    pub(crate) fn resolve_phone_ip(&self, ip: &str) -> String {
        if ip != "phone" {
            return ip.to_string();
        }
        self.phone_ip
            .lock()
            .ok()
            .and_then(|g| g.clone())
            .unwrap_or_else(|| {
                tracing::warn!("[cmd] no phone seen yet on the SDP planes; using 127.0.0.1");
                "127.0.0.1".into()
            })
    }

    /// KMS bootstrap frame for the configured KMS port/password and VIP.
    pub(crate) fn kms_bootstrap_frame(&self, from_hex: &str, to_hex: &str) -> Result<Vec<u8>> {
        let (kms_port, pwd, vip) = self.kms_bootstrap_env();
        kms_bootstrap_frame(kms_port, &pwd, &vip, from_hex, to_hex)
    }

    /// msg-61 sealed under AppCipher ([`crate::svc::kms::dbs_seal`]) — the
    /// only sid-8 body form the phone's receiver decrypts and routes to
    /// `CastDbsReceiver` (PROTOCOL.md §7.11).
    pub(crate) fn kms_bootstrap_sealed_frame(
        &self,
        ksc: &[u8],
        qcqs: &[u8],
        ctr: u64,
        from_hex: &str,
        to_hex: &str,
        tid: u16,
    ) -> Result<Vec<u8>> {
        let (kms_port, pwd, vip) = self.kms_bootstrap_env();
        let (json, seq) = kms_bootstrap_json(kms_port, &pwd, &vip, from_hex, to_hex)?;
        let from6: [u8; 6] = hex::decode(from_hex)?.as_slice().try_into()?;
        let to6: [u8; 6] = hex::decode(to_hex)?.as_slice().try_into()?;
        crate::svc::kms::dbs_data_frame_sealed(
            &crate::svc::kms::DbsSealCtx { ksc, qcqs },
            ctr,
            &from6,
            &to6,
            seq,
            tid,
            json.as_bytes(),
        )
    }

    /// msg-61 sealed with the DbsMessage JSON as the raw GCM plaintext
    /// (no dbr.a 52 B header) — A/B against the header-bearing form.
    pub(crate) fn kms_bootstrap_sealed_json_only(
        &self,
        ksc: &[u8],
        qcqs: &[u8],
        ctr: u64,
        from_hex: &str,
        to_hex: &str,
        tid: u16,
    ) -> Result<Vec<u8>> {
        let (kms_port, pwd, vip) = self.kms_bootstrap_env();
        let (json, _seq) = kms_bootstrap_json(kms_port, &pwd, &vip, from_hex, to_hex)?;
        let ct = crate::svc::kms::dbs_seal(ksc, qcqs, ctr, json.as_bytes())?;
        let mut payload = vec![0x04u8, (tid >> 8) as u8, tid as u8];
        payload.extend_from_slice(&ctr.to_be_bytes());
        payload.extend_from_slice(&ct);
        Ok(crate::svc::kms::dbs_wrap(payload))
    }

    /// Arm a new KMS bootstrap session: advance the persisted port
    /// rotation so the msg-61 `kms_socket_port` differs from the previous
    /// one. The phone's `CastSocketInputHost.start()` returns without
    /// reconnecting when `mStarted` is stale-true and the port matches
    /// (live 2026-11-11: "already started with same port=36863, return"),
    /// so every fresh Connect must present a new port to force
    /// `stopInternal()` + redial. All span ports carry a `Kms` listener
    /// (`svc::run`).
    pub(crate) fn begin_kms_session(&self) {
        let span = self.kms_port_span();
        let next = (self.kms_rot.load(std::sync::atomic::Ordering::Relaxed) + 1) % span;
        self.kms_rot
            .store(next, std::sync::atomic::Ordering::Relaxed);
        let _ = std::fs::write(crate::state::kms_rot_path(), next.to_string());
    }

    fn kms_bootstrap_env(&self) -> (u16, String, String) {
        let kms_port = self.gcfg.kms.port_base
            + self.kms_rot.load(std::sync::atomic::Ordering::Relaxed) % self.kms_port_span();
        let pwd = self.gcfg.kms.pwd.clone();
        (kms_port, pwd, self.cfg.vip.clone())
    }

    pub(crate) fn emit_device(
        &self,
        kind: &'static str,
        ip: String,
        name: Option<String>,
        connected: bool,
    ) {
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        lplus_ipc::push_device_event(kind, &ip, name.as_deref(), connected);
        let _ = self.device_tx.send(DeviceEvent {
            kind,
            ip,
            name,
            connected,
            ts_ms,
        });
    }
}

/// CastMessage msg_type=61 DbsMessage JSON (PROTOCOL.md §7.2): the value
/// `msg_body` carries `kms_socket_port`/`local_ip`/`randomPwd`/`testData`,
/// which the phone's `InputServiceManager.execute(61, …)` consumes before
/// dialing our KMS. Returns `(json, seq)` so the caller can also seal it.
pub(crate) fn kms_bootstrap_json(
    kms_port: u16,
    pwd: &str,
    local_ip: &str,
    from_hex: &str,
    to_hex: &str,
) -> Result<(String, u64)> {
    let td = crate::svc::kms::make_test_data(pwd)?;
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
    let json = crate::svc::kms::dbs_message_json(
        "Oplus_Cast",
        from_hex,
        to_hex,
        "input_service",
        &cast,
        seq,
    );
    Ok((json, seq))
}

/// The msg-61 JSON wrapped in the proven plaintext DataBus frame (§7.2).
pub(crate) fn kms_bootstrap_frame(
    kms_port: u16,
    pwd: &str,
    local_ip: &str,
    from_hex: &str,
    to_hex: &str,
) -> Result<Vec<u8>> {
    let (json, seq) = kms_bootstrap_json(kms_port, pwd, local_ip, from_hex, to_hex)?;
    let from6: [u8; 6] = hex::decode(from_hex)?.as_slice().try_into()?;
    let to6: [u8; 6] = hex::decode(to_hex)?.as_slice().try_into()?;
    Ok(crate::svc::kms::dbs_data_frame(
        &from6,
        &to6,
        seq,
        1,
        json.as_bytes(),
    ))
}

/// "ip:port" Display value -> host part.
fn event_host(peer: &impl std::fmt::Display) -> String {
    let s = peer.to_string();
    s.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or(s)
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

impl Sdp {
    /// Run the responder until the process is killed.
    pub async fn run(self: &Arc<Self>) -> Result<()> {
        let gcfg = self.gcfg.clone();
        let cfg = self.cfg.clone();
        let mcast = UdpSocket::bind(("0.0.0.0", cfg.sdp_port))
            .await
            .with_context(|| format!("udp bind :{}", cfg.sdp_port))?;
        mcast
            .join_multicast_v4(cfg.group, Ipv4Addr::UNSPECIFIED)
            .with_context(|| format!("join multicast {}", cfg.group))?;
        let uni = UdpSocket::bind(("0.0.0.0", cfg.uni_port))
            .await
            .with_context(|| format!("udp bind :{}", cfg.uni_port))?;
        // The engine dials the announced port *and* port+1 (TcpManager connects
        // socketPort+1 after the SCP channel request), plus probes the SDP port
        // itself; listen on all of them and log every session.
        let mut scp_ports: Vec<u16> = Vec::new();
        for p in [
            cfg.csp,
            cfg.csp.wrapping_add(1),
            cfg.uni_port,
            cfg.uni_port.wrapping_add(1),
            cfg.sdp_port,
            cfg.sdp_port.wrapping_add(1),
        ] {
            if !scp_ports.contains(&p) {
                scp_ports.push(p);
            }
        }
        let log_path = cfg.log_path.clone();
        scp_server::bind_sessions(self, &scp_ports).await?;
        epi::Epi::bind_sessions(self, &[46888u16, 47888, 48888], true).await?;
        tracing::info!(
            "sdp up: :{} (mcast {}) :{} (uni) tcp{:?} epi[46888,47888,48888]",
            cfg.sdp_port,
            cfg.group,
            cfg.uni_port,
            scp_ports
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
        let link_pub_bytes: Option<Vec<u8>> = gcfg.link.pub_hex.clone().or_else(|| {
            Some(link_info_payload(
                &link_mac_spec(),
                &cfg.vip,
                &gateway_of(&cfg.vip),
            ))
        });
        let link_probe_ports: Vec<u16> = gcfg.link.ports.clone();
        if !link_probe_ports.is_empty() {
            // Reply template: mirror the phone's own 66B link-detection frame
            // (captured live): `[00 40][0c][PDID ascii 12][01 38 02 01 00]
            //  entry{0b 01 fd | mac6 LE | 0*8} entry{0b 01 fc | ip4 LE 0*2 0*6}
            //  entry{01 fc | gw-ish 6B}` with our identity substituted.
            let link_reply: Vec<u8> = link_pub_bytes.clone().unwrap_or_else(|| {
                let mac = link_mac_spec();
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
            let mirror_on = true;
            let mut pdid12 = [b'0'; 12];
            let pdid_s = format!("{:0<12}", cfg.pdid).to_uppercase();
            pdid12.copy_from_slice(&pdid_s.as_bytes()[..12]);
            let mac_spec = link_mac_spec();
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
            // Peer link_ip published for LinkSwitchMgr's route install; the
            // phone has no vgate return path for our LAN IP, so route-poison
            // with an unreachable TEST-NET address.
            let poison: Option<[u8; 4]> = gcfg.link.poison;
            let ack_mode = gcfg.link.ack.clone();
            let link_hex: Option<Vec<u8>> = gcfg.link.reply_hex.clone();
            let link_type: Option<u8> = None;
            let link_hex_file: Option<String> = gcfg.link.reply_hex_file.clone();
            // known_peer_devices ids for the mirror reply (comma-separated).
            let kpd: Vec<Vec<u8>> = gcfg.link.kpd.clone();
            for &p in &link_probe_ports {
                let log_path = log_path.clone();
                let reply_src = link_reply.clone();
                let ack_mode = ack_mode.clone();
                let kpd = kpd.clone();
                let link_hex = link_hex.clone();
                let link_hex_file = link_hex_file.clone();
                let (mirror_on, pdid12, mac6, ip4o, poison) =
                    (mirror_on, pdid12, mac6, ip4o, poison);
                tokio::spawn(async move {
                    let Ok(sock) = UdpSocket::bind(("0.0.0.0", p)).await else {
                        tracing::warn!("[link-det] bind :{p} failed");
                        return;
                    };
                    tracing::info!("[link-det] listening :{p}");
                    let mut buf = vec![0u8; 2048];
                    loop {
                        if let Ok((n, from)) = sock.recv_from(&mut buf).await {
                            if n == 0 || from.ip().is_loopback() {
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
        let linkns = gcfg.link.ns.clone();
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
                        handle(&cfg, self, &uni, &link_b64, &mut seen, &mut last_phone, "mcast", from, &mbuf[..n]).await;
                    }
                }
                r = uni.recv_from(&mut ubuf) => {
                    if let Ok((n, from)) = r {
                        handle(&cfg, self, &uni, &link_b64, &mut seen, &mut last_phone, "uni", from, &ubuf[..n]).await;
                    }
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

impl Sdp {
    pub(crate) fn spawn_session_logger(
        self: &Arc<Self>,
        mut sock: tokio::net::TcpStream,
        peer: SocketAddr,
        epi: bool,
        epi_port: u16,
    ) {
        tracing::info!("[tcp] connection from {peer}");
        let session_ip = peer.ip().to_string();
        let path = self.cfg.log_path.clone();
        let dev_name = self.cfg.name.clone();
        let reg59399 = self.probe_reg.clone();
        let epi_svc = self.epi.clone();
        let sdp = self.clone();
        let epic = self.gcfg.epi.clone();
        let scp = self.gcfg.scp.clone();
        let gcfg = self.gcfg.clone();
        let task = tokio::spawn({
            let sdp = sdp.clone();
            let epi_svc = epi_svc.clone();
            let epic = epic.clone();
            let scp = scp.clone();
            let gcfg = gcfg.clone();
            async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                if epi {
                    // EPI PD OFFER over the datatrans channel (jf/b.java writer,
                    // ProtocolVersion<=10 so the 39B account block is skipped):
                    // [0]msgType [1..3)proto u16be [3..39)PeerId 36B [39]SapModes
                    // [40]featureCount=0.
                    let mtype: u8 = epic.offer_type;
                    let proto: u16 = epic.offer_proto;
                    let peer_id: String = epic.peer_id.clone();
                    let mut peer_id = peer_id.clone();
                    if peer_id.len() < 36 {
                        while peer_id.len() < 36 {
                            peer_id.push('0');
                        }
                    }
                    peer_id.truncate(36);
                    let mut frame: Vec<u8> = if let Some(h) = epic.msg_override.as_deref() {
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
                        let out: Vec<u8> = if epic.framing == "raw3" {
                            // Live client-socket reader form (setCrcEnabled=false):
                            // 3-byte length field only, no crc fields.
                            let mut v = vec![0x00, (len >> 8) as u8, (len & 0xff) as u8];
                            v.append(&mut frame);
                            v
                        } else if epic.framing == "3b" {
                            let mut crc: u16 = 0;
                            for &b in &frame {
                                crc = CRC16_TABLE[((crc as u8) ^ b) as usize] ^ (crc >> 8);
                            }
                            let mut v =
                                vec![0x00, (len >> 8) as u8, (len & 0xff) as u8, 0x00, 0x00, 0x00];
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
                            Ok(()) => {
                                tracing::info!("[epi] :{epi_port} -> {peer} sent {}B", out.len())
                            }
                            Err(e) => tracing::info!("[epi] :{epi_port} write fail: {e}"),
                        }
                        record(&path, &format!("sent epi{epi_port} {peer}"), &out);
                    }
                    // PD server role on our channel port: EpiClientFsm (phone) waits
                    // for our OFFER, answers with msgType 2, we finalize with
                    // CONFIRM msgType 4 [4][proto u16be][status=1]. Accept both the
                    // connector 2B header [00][len][payload] and the legacy 3B form.
                    let peer_id2 = peer_id.clone();
                    let epi_session = tokio::spawn({
                        let epi_svc = epi_svc.clone();
                        let sdp = sdp.clone();
                        let epic = sdp.gcfg.epi.clone();
                        let cfgs = sdp.gcfg.clone();
                        async move {
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
                            // Command-frame injection sink: DISCONNECT / KMS bootstrap /
                            // RpcFrame bytes are written onto this live socket from the
                            // read loop's select, no re-handshake needed.
                            // Key: "{port} {peer}".
                            let inject_key = format!("{epi_port} {peer}");
                            // Rate-limited link-evidence refresh: devices.rs drops
                            // `is_connected` when a row goes quiet, so live traffic
                            // must re-assert presence (≤1/min, cheap broadcast).
                            let mut last_ev = tokio::time::Instant::now();
                            sdp.emit_device("epi", event_host(&peer), None, true);
                            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
                            epi_svc.register_sink(inject_key.clone(), tx).await;
                            let mut inject_rx = Some(rx);
                            // Expected rc_2 = s(ksc, qc, ts) for the pending AUTH_CONFIRM.
                            let mut expect_rc2: Option<[u8; 8]> = None;
                            // FrameType byte for our AUTH_RESPONSE; phone dispatches on
                            // {16,17,18,19,20}; server proof frame is 18 (0x12).
                            let resp_type: u8 = epic.auth_resp;
                            // Server-side confirm echo sent after rc_2 verifies; 0 = off.
                            let auth_ack: u8 = epic.auth_ack;
                            // Capability exchange (datatrans/service/f): after auth+PD the
                            // phone enters QUERYING and dies after 10 s (errorCode 258,
                            // "Capex waiting for query timed out") unless the server sends
                            // a capex QUERY; we then must answer its RESPONSE with a
                            // CONFIRM (statusCode 0) to reach AVAILABLE/ATTACHED.
                            let capex_on = epic.capex;
                            // Clipboard lane (opt-in CLIPBOARD=1): subscribe our side to
                            // `Oplus_PcConnect` via `msg_topic_sync` once the DataBus
                            // session is live, then apply published ClipboardBean text to
                            // the system clipboard.
                            let clipboard_on = cfgs.databus.clipboard;
                            let mut clip_subscribed = false;
                            let capex_profiles_owned = epic.capex_profiles.clone();
                            let capex_profiles: Vec<&str> =
                                capex_profiles_owned.iter().map(String::as_str).collect();
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
                                            let qf =
                                                capex_frame(&epic, &capex_query(&capex_profiles));
                                            let _ = sock.write_all(&qf).await;
                                            tracing::info!(
                                                "[epi] :{epi_port} -> CAPEX QUERY resend #{capex_attempts} ({} profiles)",
                                                capex_profiles.len(),
                                            );
                                            record(
                                                &path,
                                                &format!(
                                                    "epicapexq{epi_port} {peer}#{capex_attempts}"
                                                ),
                                                &qf,
                                            );
                                            continue;
                                        }
                                    }
                                } else {
                                    // Idle guard: a peer that vanishes without a FIN
                                    // must not pin the row's connected flag — silence
                                    // for `EPI_IDLE` is treated as a closed link.
                                    const EPI_IDLE: std::time::Duration =
                                        std::time::Duration::from_secs(90);
                                    match &mut inject_rx {
                                        Some(rx) => {
                                            tokio::select! {
                                                r = sock.read(&mut tmp) => r,
                                                b = rx.recv() => {
                                                    match b {
                                                        Some(bytes) => {
                                                            let _ = sock.write_all(&bytes).await;
                                                            record(&path, &format!("inject-sent {inject_key}"), &bytes);
                                                            tracing::info!(
                                                                "[inject] -> {inject_key} {}B {}",
                                                                bytes.len(),
                                                                hex::encode(&bytes[..bytes.len().min(64)])
                                                            );
                                                        }
                                                        // Registry dropped: stop selecting.
                                                        None => inject_rx = None,
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
                                        epi_svc.unregister_sink(&inject_key).await;
                                        sdp.emit_device("epi", event_host(&peer), None, false);
                                        break;
                                    }
                                    Ok(n) => {
                                        acc.extend_from_slice(&tmp[..n]);
                                        if last_ev.elapsed() >= std::time::Duration::from_secs(60) {
                                            last_ev = tokio::time::Instant::now();
                                            sdp.emit_device("epi", event_host(&peer), None, true);
                                        }
                                        tracing::info!(
                                            "[epi] :{epi_port} <- {peer} {n}B | {}",
                                            hex::encode(&tmp[..n.min(64)])
                                        );
                                        record(
                                            &path,
                                            &format!("epircv{epi_port} {peer}"),
                                            &tmp[..n],
                                        );
                                    }
                                }
                                loop {
                                    if acc.len() < 3 {
                                        break;
                                    }
                                    let (hlen, plen) = if acc.len() >= 4
                                        && acc[2] == 0x00
                                        && (acc[3] == 0x08 || acc[3] == 0x20)
                                        && u16::from_be_bytes([acc[0], acc[1]]) as usize >= 5
                                    {
                                        // Session lane (capex): [len u16BE][hdr 0x0008][payload];
                                        // 0x0020 = DataBus session (sid 8). Minimum 5 =
                                        // the 3-byte DataBus ACK frame (hdr 0x0020).
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
                                                && u16::from_be_bytes([acc[i], acc[i + 1]]) as usize
                                                    >= 6
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
                                                        v["dbs_msg_payload"]
                                                    ),
                                                    "msg_normal_topic_data" => {
                                                        let topic = v
                                                            .pointer(
                                                                "/dbs_msg_topic/dbs_topic_name",
                                                            )
                                                            .and_then(|x| x.as_str())
                                                            .unwrap_or("");
                                                        // The phone's DbsMessage.payload is
                                                        // a String field: the wire form is a
                                                        // quoted JSON string, but tolerate
                                                        // the bare-object shape too.
                                                        let payload = v
                                                            .get("dbs_msg_payload")
                                                            .and_then(|p| match p {
                                                                serde_json::Value::String(s) => {
                                                                    serde_json::from_str(s).ok()
                                                                }
                                                                _ => Some(p.clone()),
                                                            });
                                                        if topic == "Oplus_PcConnect"
                                                            && let Some(s) = payload
                                                                .as_ref()
                                                                .and_then(|p| p.pointer("/value"))
                                                                .and_then(|x| x.as_str())
                                                            && let Some(text) =
                                                                proto::odmf::clipboard_text(s)
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
                                                let json = crate::svc::kms::dbs_topic_sync_json(
                                                    &hex::encode(ours6),
                                                    &hex::encode(phone6),
                                                    &["Oplus_PcConnect"],
                                                    seq,
                                                );
                                                let f = crate::svc::kms::dbs_data_frame(
                                                    &ours6,
                                                    &phone6,
                                                    seq,
                                                    0x1001,
                                                    json.as_bytes(),
                                                );
                                                let _ = sock.write_all(&f).await;
                                                record(
                                                    &path,
                                                    &format!("clipsubscribe{epi_port} {peer}"),
                                                    &f,
                                                );
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
                                        record(
                                            &path,
                                            &format!("epidatabusack{epi_port} {peer}"),
                                            &ack,
                                        );
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
                                            let outa = if epic.framing == "raw3" {
                                                let l = an.len() as u16;
                                                let mut v =
                                                    vec![0x00, (l >> 8) as u8, (l & 0xff) as u8];
                                                v.append(&mut an);
                                                v
                                            } else if epic.framing == "3b" {
                                                let mut crc: u16 = 0;
                                                for &b in &an {
                                                    crc = CRC16_TABLE[((crc as u8) ^ b) as usize]
                                                        ^ (crc >> 8);
                                                }
                                                let l = an.len() as u16;
                                                let mut v = vec![
                                                    0x00,
                                                    (l >> 8) as u8,
                                                    (l & 0xff) as u8,
                                                    0,
                                                    0,
                                                    0,
                                                ];
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
                                            let ts = u64::from_be_bytes(
                                                payload[10..18].try_into().unwrap(),
                                            );
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
                                            let accepted = ksc_candidates(
                                                sdp.ksc_pin.as_deref(),
                                                &peer_ip,
                                                &hex::encode(dev),
                                            )
                                            .into_iter()
                                            .find(|c| ksc_s(c, qc, ts) == mac8);
                                            if let Some(k) = accepted {
                                                ksc = Some(k.clone());
                                                remember_ksc(&peer_ip, &hex::encode(dev), &k);
                                                remember_ksc(
                                                    &hex::encode(dev),
                                                    &hex::encode(dev),
                                                    &k,
                                                );
                                            }
                                            let Some(ksc) = ksc.clone() else {
                                                tracing::info!(
                                                    "[epi] :{epi_port} AUTH_REQUEST but no ksc; skipping response"
                                                );
                                                continue;
                                            };
                                            let mac_ok = ksc_s(&ksc, qc, ts) == mac8;
                                            tracing::info!(
                                                "[epi] :{epi_port} client mac check: {mac_ok}"
                                            );
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
                                            resp.extend_from_slice(&ts2.to_be_bytes());
                                            resp.extend_from_slice(&rs);
                                            let out = dt_frame(&epic, &resp);
                                            let _ = sock.write_all(&out).await;
                                            tracing::info!(
                                                "[epi] :{epi_port} -> AUTH_RESPONSE {resp_type:#04x} ver={ver} qs={} ts={ts2} rs={} (sessionKey {}+zeros)",
                                                hex::encode(qs),
                                                hex::encode(rs),
                                                hex::encode(rs),
                                            );
                                            record(
                                                &path,
                                                &format!("epiauthresp{epi_port} {peer}"),
                                                &out,
                                            );
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
                                                .map(|e| {
                                                    e == <[u8; 8]>::try_from(rc2).unwrap_or([0; 8])
                                                })
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
                                                let mut ack: Vec<u8> =
                                                    vec![auth_ack, payload[1], 0x00];
                                                ack.extend_from_slice(rc2);
                                                let out = dt_frame(&epic, &ack);
                                                let _ = sock.write_all(&out).await;
                                                tracing::info!(
                                                    "[epi] :{epi_port} -> AUTH ack {auth_ack:#04x} rc_2={}",
                                                    hex::encode(rc2)
                                                );
                                                record(
                                                    &path,
                                                    &format!("epiauthack{epi_port} {peer}"),
                                                    &out,
                                                );
                                            }
                                            if ok && probe_pending {
                                                // PD leg: deliver the deferred PROBE now
                                                // that the security lane is complete —
                                                // client answers it with CONFIRM(4).
                                                let mut cf = vec![3u8, 0, 10];
                                                cf.extend_from_slice(&probe_peer);
                                                let outc = dt_frame(&epic, &cf);
                                                let _ = sock.write_all(&outc).await;
                                                tracing::info!(
                                                    "[epi] :{epi_port} -> PROBE sent (post-auth)"
                                                );
                                                record(
                                                    &path,
                                                    &format!("epiprobe{epi_port} {peer}"),
                                                    &outc,
                                                );
                                                probe_pending = false;
                                                confirmed = true;
                                                if capex_on {
                                                    let qf = capex_frame(
                                                        &epic,
                                                        &capex_query(&capex_profiles),
                                                    );
                                                    let _ = sock.write_all(&qf).await;
                                                    tracing::info!(
                                                        "[epi] :{epi_port} -> CAPEX QUERY ({} profiles)",
                                                        capex_profiles.len(),
                                                    );
                                                    record(
                                                        &path,
                                                        &format!("epicapexq{epi_port} {peer}"),
                                                        &qf,
                                                    );
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
                                            record(
                                                &path,
                                                &format!("epicapexqin{epi_port} {peer}"),
                                                &payload,
                                            );
                                            let theirs: Vec<String> = if payload.len() > 7 {
                                                payload[7..]
                                                    .split(|b| *b == 0x3b)
                                                    .map(|s| {
                                                        String::from_utf8_lossy(s)
                                                            .trim()
                                                            .to_string()
                                                    })
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
                                            let rf = capex_frame(&epic, &capex_response(&mine));
                                            let _ = sock.write_all(&rf).await;
                                            tracing::info!(
                                                "[epi] :{epi_port} -> CAPEX RESPONSE ({} profiles, ck={})",
                                                mine.len(),
                                                hex::encode(&rf[6..10]),
                                            );
                                            record(
                                                &path,
                                                &format!("epicapexprspo{epi_port} {peer}"),
                                                &rf,
                                            );
                                            let cf = capex_frame(&epic, &capex_confirm(0, 0));
                                            let _ = sock.write_all(&cf).await;
                                            tracing::info!(
                                                "[epi] :{epi_port} -> CAPEX CONFIRM (post-response)"
                                            );
                                            record(
                                                &path,
                                                &format!("epicapexcfm2{epi_port} {peer}"),
                                                &cf,
                                            );
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
                                            record(
                                                &path,
                                                &format!("epicapexprsp{epi_port} {peer}"),
                                                &payload,
                                            );
                                            let cf = capex_frame(&epic, &capex_confirm(0, 0));
                                            let _ = sock.write_all(&cf).await;
                                            tracing::info!(
                                                "[epi] :{epi_port} -> CAPEX CONFIRM (status 0)"
                                            );
                                            record(
                                                &path,
                                                &format!("epicapexcfm{epi_port} {peer}"),
                                                &cf,
                                            );
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
                        }
                    });
                    // Without this registration a `disconnect` aborts nothing and
                    // the phone keeps the :46888 link half-open — PTC then refuses
                    // new connects ("device Connected, Scan results are not
                    // processed") while our panel already shows disconnected.
                    epi_svc.register_killer(&event_host(&peer), epi_session.abort_handle());
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
                let mut mt4_sent = false;
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
                    // One-shot SYNC re-send (phone's late receiveSync attach):
                    // only while the peer has not advanced past SYNC (no ukey2
                    // frame seen). A short window lets the peer's in-flight
                    // burst land first, so the re-send never races its
                    // receiveKeyAgreement (fatal 2510, live 2026-11-11).
                    let mut pre_read: Option<std::io::Result<usize>> = None;
                    if sync_sent && sync_pending && ukey.is_none() {
                        tokio::select! {
                            biased;
                            r = sock.read(&mut buf) => pre_read = Some(r),
                            _ = tokio::time::sleep(std::time::Duration::from_millis(80)) => {
                                sync_pending = false;
                                let hseq = hbase.unwrap_or_else(crate::scp::now_base);
                                let keytype: i32 = scp.keytype;
                                let sync = crate::scp::sync_frame_ex(
                                    hseq + 1,
                                    "active_connection",
                                    "com.heytap.accessory",
                                    &dev_name,
                                    &scp.model,
                                    true,
                                    keytype,
                                );
                                record(&path, &format!("sent {peer} sync-resend seq{}", hseq + 1), &sync);
                                let _ = sock.write_all(&sync).await;
                                let _ = sock.flush().await;
                                tracing::info!(
                                    "[tcp] {peer} scp sync seq{} (timed resend) t={} | {}",
                                    hseq + 1,
                                    tclock!(),
                                    hex::encode(&sync)
                                );
                                continue;
                            }
                        }
                    }
                    let rd = match pre_read {
                        Some(r) => r,
                        None => sock.read(&mut buf).await,
                    };
                    match rd {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            tracing::info!(
                                "[tcp] {peer} {n}B t={} | {}",
                                tclock!(),
                                hex::encode(&buf[..n.min(220)])
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
                                    for (kn, k) in
                                        [("ek", ctx.encode_key()), ("dk", ctx.decode_key())]
                                    {
                                        for (ivn, iv) in ivs.iter().enumerate() {
                                            if let Ok(pt) =
                                                crate::d2d::cryptor_open_iv(k, iv, sealed)
                                            {
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
                                            if let Ok(pt) =
                                                crate::d2d::cryptor_open_phone(k, &iv16, sealed)
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
                                        let mode = scp.interact.clone();
                                        let bodies: Vec<&[u8]> = match InteractMode::from_str(&mode)
                                        {
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
                                                    fr[2..4].copy_from_slice(
                                                        &(ct.len() as u16).to_be_bytes(),
                                                    );
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
                                                    tracing::warn!(
                                                        "[interact] {peer} seal failed: {e}"
                                                    )
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
                                    let qs = crate::scp::q_from_payload(&sub[8..])
                                        .map(|q| q.sequence_no);
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
                                    if scp.server && sub[1] == 0x30 {
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
                                                    sdp.emit_device(
                                                        "scp_sync",
                                                        event_host(&peer),
                                                        Some(nm),
                                                        true,
                                                    );
                                                }
                                            }
                                            3 | 4 => {
                                                // Phone CLIENT drives ukey2 (l.java
                                                // waitForShareSecret, client arm): it
                                                // sends msgType3 CLIENT_INIT, we answer
                                                // msgType3 SERVER_INIT; it sends
                                                // CLIENT_FINISH as a second msgType3
                                                // (`k(f2924e, b2)` — not msgType4), then
                                                // waits in g(f2925f) for our msgType4
                                                // UKEY2_FINISHED; it closes with an empty
                                                // msgType4 (`l.java:108` k(f, new
                                                // byte[0])`), which we ack empty as well.
                                                let h = ukey.get_or_insert_with(|| {
                                                    crate::ukey2::Ukey2Handshake::new(
                                                        crate::ukey2::Role::Responder,
                                                    )
                                                });
                                                let parsed = h.parse(&m.data);
                                                if matches!(parsed, Ok(true))
                                                    || (matches!(parsed, Ok(false))
                                                        && h.is_complete())
                                                {
                                                    // Stop any armed SYNC re-send: the
                                                    // peer has left receiveSync behind and
                                                    // now expects UKEY2_FINISHED; a late
                                                    // msgType-1 frame is a fatal 2510 there.
                                                    sync_pending = false;
                                                    let (out_mt, reply) = if h.is_complete() {
                                                        // CLIENT_FINISH parsed:
                                                        // answer the peer's
                                                        // g(UKEY2_FINISHED) with
                                                        // exactly one msgType4
                                                        // (vendor server sends
                                                        // k(f2925f, finish)); a
                                                        // later empty mt4 from
                                                        // the client gets none.
                                                        if mt4_sent {
                                                            (4, None)
                                                        } else {
                                                            mt4_sent = true;
                                                            (4, Some(Vec::new()))
                                                        }
                                                    } else {
                                                        (3, h.next_message())
                                                    };
                                                    if let Some(next) = reply {
                                                        let f = crate::scp::msg_frame(
                                                            out_mt,
                                                            next.clone(),
                                                        );
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
                                                        if mt == 4 && scp.ss_now {
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
                                                        if scp.ss_send
                                                            && ss_send.is_none()
                                                            && h.is_complete()
                                                        {
                                                            let _ = h.auth_string();
                                                            if let Ok(ctx) =
                                                                h.to_connection_context()
                                                            {
                                                                if scp.ks_dump {
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
                                                                ss_iv =
                                                                    h.peer_iv().map(|v| v.to_vec());
                                                                let pdid = scp.pdid.clone();
                                                                // Present our BOND for this
                                                                // peer, never a fresh key: the
                                                                // phone persists ksc only in a
                                                                // user-confirmed pairing and
                                                                // AUTH-keys on the stored row
                                                                // (KscRepositoryImpl.loadKsc,
                                                                // "SELECT * FROM ksc_info WHERE
                                                                // deviceId = ? AND alias = ?").
                                                                let peer_ip = peer.ip().to_string();
                                                                let (ksc, alias) = issue_ksc(
                                                                    sdp.ksc_pin.as_deref(),
                                                                    &peer_ip,
                                                                    &pdid,
                                                                );
                                                                ss_send = Some(ksc.clone());
                                                                let ss = crate::scp::SyncSecure {
                                                                    device_id: Some(pdid.clone()),
                                                                    ksc: Some(ksc.clone()),
                                                                    ksc_alias: Some(alias),
                                                                };
                                                                let f = if scp.ss_enc {
                                                                    let wrap = {
                                                                        let sm = crate::scp::ScpMessage {
                                                                        msg_type: Some(2),
                                                                        data: <crate::scp::SyncSecure as prost::Message>::encode_to_vec(&ss),
                                                                    };
                                                                        <crate::scp::ScpMessage as prost::Message>::encode_to_vec(&sm)
                                                                    };
                                                                    let key: &[u8] =
                                                                        if scp.ss_key == "ek" {
                                                                            ctx.encode_key()
                                                                        } else {
                                                                            ctx.decode_key()
                                                                        };
                                                                    let mut iv = [0u8; 16];
                                                                    if scp.ss_iv != "zero"
                                                                        && let Some(pi) =
                                                                            ss_iv.as_deref()
                                                                    {
                                                                        iv[..16].copy_from_slice(
                                                                            &pi[..16.min(pi.len())],
                                                                        );
                                                                    }
                                                                    let mut nonce = [0u8; 8];
                                                                    if !scp.ss_nonce_zero {
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
                                                                                ivv.push(
                                                                                    pi.to_vec(),
                                                                                );
                                                                            }
                                                                            if pi.len() == 16 {
                                                                                ivv.push(
                                                                                    pi[..12]
                                                                                        .to_vec(),
                                                                                );
                                                                            }
                                                                        }
                                                                        ivv.push(vec![
                                                                            0, 1, 2, 3, 4, 5, 6, 7,
                                                                            8, 9, 10, 11,
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
                                                                    scp.ss_enc,
                                                                    scp.ss_key.clone(),
                                                                    scp.ss_iv.clone(),
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
                                                } else {
                                                    match parsed {
                                                        Ok(false) => tracing::info!(
                                                            "[scp] {peer} ukey2 mt{mt} ignored (state)"
                                                        ),
                                                        Err(e) => tracing::info!(
                                                            "[scp] {peer} ukey2 parse mt{mt} failed: {e}"
                                                        ),
                                                        _ => {}
                                                    }
                                                }
                                            }
                                            2 => {
                                                if !ss_echoed {
                                                    ss_echoed = true;
                                                    let pdid = scp.pdid.clone();
                                                    match crate::scp::sync_secure_echo(
                                                        &m.data, &pdid,
                                                    ) {
                                                        Ok(f) => {
                                                            tracing::info!(
                                                                "[scp] {peer} SYNC_SECURE echo (pdid {pdid}, {}B data)",
                                                                m.data.len()
                                                            );
                                                            record(
                                                                &path,
                                                                &format!(
                                                                    "sent {peer} sync-secure-echo"
                                                                ),
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
                                                "[scp] {peer} unexpected inbound msgType {other:?} ({}B data) | {} | {:?}",
                                                m.data.len(),
                                                hex::encode(&m.data[..m.data.len().min(220)]),
                                                String::from_utf8_lossy(
                                                    &m.data[..m.data.len().min(220)]
                                                )
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
                                if scp.clientscp
                                    && sub.len() >= 2
                                    && sub[0] == 0x40
                                    && sub[1] == 0x30
                                    && let Some(m) = crate::scp::decode_payload(&sub[8..])
                                {
                                    let mt = m.msg_type.unwrap_or(0);
                                    // A peer frame past HELLO/SYNC proves its
                                    // receiveSync completed: drop the armed
                                    // one-shot re-send. A msgType-1 landing in
                                    // the phone's receiveKeyAgreement is a fatal
                                    // 2510 (`msgType not matched: SYNC vs
                                    // UKEY2_INIT`, live 2026-11-11 — the phone
                                    // sends SYNC and UKEY2_INIT in one burst).
                                    if sync_sent && sync_pending && mt > 1 {
                                        sync_pending = false;
                                        tracing::info!(
                                            "[tcp] {peer} sync-resend disarmed: peer advanced to mt{mt}"
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
                                        let base = crate::scp::q_from_payload(&sub[8..])
                                            .map(|q| q.sequence_no)
                                            .unwrap_or_else(crate::scp::now_base);
                                        hbase = Some(base);
                                        let hseq = base + 1;
                                        let hello = crate::scp::hello_frame_ex(
                                            hseq,
                                            "active_connection",
                                            "com.heytap.accessory",
                                            true,
                                        );
                                        record(
                                            &path,
                                            &format!("sent {peer} hello seq{hseq}"),
                                            &hello,
                                        );
                                        let _ = sock.write_all(&hello).await;
                                        let _ = sock.flush().await;
                                        hello_at = Some(std::time::Instant::now());
                                        tracing::info!(
                                            "[tcp] {peer} scp hello seq{hseq} (reactive) t={} | {}",
                                            tclock!(),
                                            hex::encode(&hello)
                                        );
                                        // The phone builds its paired-device
                                        // record's display name from the
                                        // peer's ScpSyncData it cached before
                                        // SYNC_SECURE (`a0.onSyncSecureReceived`
                                        // → `f7835h`); the SCP_SERVER lane
                                        // otherwise never answers with a SYNC
                                        // and the tile renders blank. HELLO
                                        // must precede it (waiting4Hello then
                                        // receiveSync), hence sending ours
                                        // immediately after with the wave gap.
                                        if !sync_sent {
                                            sync_sent = true;
                                            sync_pending = true;
                                            if let Some(t) = hello_at {
                                                let ms = t.elapsed().as_millis();
                                                if ms < 250 {
                                                    tokio::time::sleep(
                                                        std::time::Duration::from_millis(
                                                            250 - ms as u64,
                                                        ),
                                                    )
                                                    .await;
                                                }
                                            }
                                            let keytype: i32 = scp.keytype;
                                            let sync = crate::scp::sync_frame_ex(
                                                hseq + 1,
                                                "active_connection",
                                                "com.heytap.accessory",
                                                &dev_name,
                                                &scp.model,
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
                                                "[tcp] {peer} scp sync seq{} (after hello) t={} | {}",
                                                hseq + 1,
                                                tclock!(),
                                                hex::encode(&sync)
                                            );
                                        }
                                    } else if mt == 1 {
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
                                                    tokio::time::sleep(
                                                        std::time::Duration::from_millis(
                                                            250 - ms as u64,
                                                        ),
                                                    )
                                                    .await;
                                                }
                                            }
                                            let hseq = hbase.unwrap_or_else(crate::scp::now_base);
                                            let keytype: i32 = scp.keytype;
                                            let sync = crate::scp::sync_frame_ex(
                                                hseq + 1,
                                                "active_connection",
                                                "com.heytap.accessory",
                                                &dev_name,
                                                &scp.model,
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
                                    let variant_str = scp.resp.clone();
                                    let variant = RespVariant::from_str(&variant_str)
                                        .unwrap_or(RespVariant::Echo);
                                    let is_active =
                                        payload.windows(17).any(|w| w == b"active_connection");
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
                                        record(
                                            &path,
                                            &format!("sent {peer} reply({variant})"),
                                            &reply,
                                        );
                                        let _ = sock.write_all(&reply).await;
                                        let _ = sock.flush().await;
                                    }
                                    // SCP client leg on the accepted channel: send HELLO
                                    // now; SYNC goes out reactively after the phone's
                                    // own HELLO (their waiting4Sync ignores pre-hello
                                    // frames — see inbound decode branch).
                                    // EstablishLink: the phone's AndroidMultiLanServer
                                    // waits to accept our callback connection.
                                    if is_active && !dialed {
                                        dialed = true;
                                        for &p in &scp.dial_ports {
                                            if p == 10152 {
                                                continue;
                                            }
                                            let addr = (peer.ip(), p);
                                            let capex_dial = gcfg.epi.capex_dial == Some(p);
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
                                                        let qf = dt_frame(&epic, &q);
                                                        let _ = stream.write_all(&qf).await;
                                                        tracing::info!(
                                                            "[tcp] :{p} -> CAPEX QUERY dialed {}B",
                                                            qf.len()
                                                        );
                                                        record(
                                                            &path,
                                                            &format!("capexdial{p} q"),
                                                            &qf,
                                                        );
                                                        let (mut r0, mut w0) = stream.into_split();
                                                        let path0 = path.clone();
                                                        let epic_c = epic.clone();
                                                        tokio::spawn(async move {
                                                            let epic = epic_c;
                                                            let mut b = [0u8; 4096];
                                                            let mut buf: Vec<u8> = Vec::new();
                                                            let mut conf_sent = false;
                                                            loop {
                                                                match r0.read(&mut b).await {
                                                                    Ok(0) | Err(_) => break,
                                                                    Ok(n) => {
                                                                        tracing::info!(
                                                                            "[tcp] :{p} <- {n}B | {}",
                                                                            hex::encode(
                                                                                &b[..n.min(64)]
                                                                            )
                                                                        );
                                                                        record(
                                                                            &path0,
                                                                            &format!(
                                                                                "capexdial{p} rx"
                                                                            ),
                                                                            &b[..n],
                                                                        );
                                                                        buf.extend_from_slice(
                                                                            &b[..n],
                                                                        );
                                                                        loop {
                                                                            if buf.len() < 2 {
                                                                                break;
                                                                            }
                                                                            let (hl, pl) = if buf[0]
                                                                                == 0
                                                                                && buf[1] > 0
                                                                            {
                                                                                (
                                                                                    2usize,
                                                                                    buf[1] as usize,
                                                                                )
                                                                            } else {
                                                                                break;
                                                                            };
                                                                            if buf.len() < hl + pl {
                                                                                break;
                                                                            }
                                                                            let pld = buf
                                                                                [hl..hl + pl]
                                                                                .to_vec();
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
                                                                            if mt == 2 && !conf_sent
                                                                            {
                                                                                let cf = dt_frame(
                                                                                    &epic,
                                                                                    &capex_confirm(
                                                                                        0, 0,
                                                                                    ),
                                                                                );
                                                                                let _ = w0
                                                                                    .write_all(&cf)
                                                                                    .await;
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
                                                                            hex::encode(
                                                                                &b[..n.min(64)]
                                                                            )
                                                                        );
                                                                        record(
                                                                            &path3,
                                                                            &format!(
                                                                                "tcp {peer} probe"
                                                                            ),
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
                                                            i.extend_from_slice(
                                                                b"active_connection",
                                                            );
                                                            i.extend_from_slice(&[0x1a, 0x14]);
                                                            i.extend_from_slice(
                                                                b"com.heytap.accessory",
                                                            );
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
                                                        record(
                                                            &path2,
                                                            "sent open-out open",
                                                            &frame,
                                                        );
                                                        let _ = w.write_all(&frame).await;
                                                        let _ = w.flush().await;
                                                        if let Some(extra) =
                                                            scp.openout_sync.as_deref()
                                                        {
                                                            for part in extra.split(';') {
                                                                if let Ok(bytes) =
                                                                    hex::decode(part.trim())
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
                                                                    let _ =
                                                                        w.write_all(&bytes).await;
                                                                    let _ = w.flush().await;
                                                                }
                                                            }
                                                        }
                                                        if scp.clientscp {
                                                            // Reactive hello+sync is sent from
                                                            // the reader once the ack arrives
                                                            // (echoing its q); no eager hello.
                                                        }
                                                        let dev_name2 = dev_name.clone();
                                                        let scp_c = scp.clone();
                                                        tokio::spawn(async move {
                                                            let scp = scp_c;
                                                            let mut b = [0u8; 2048];
                                                            let mut sync_sent2 = false;
                                                            loop {
                                                                match r.read(&mut b).await {
                                                                    Ok(0) | Err(_) => break,
                                                                    Ok(n) => {
                                                                        tracing::info!(
                                                                            "[tcp] :{p} resp {n}B | {}",
                                                                            hex::encode(
                                                                                &b[..n.min(64)]
                                                                            )
                                                                        );
                                                                        record(
                                                                            &path2,
                                                                            &format!(
                                                                                "tcp {peer} open-out"
                                                                            ),
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
                                                                        && scp.openout_ack
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
                                                                        && scp.openout_scp
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
                                                                        let sync = crate::scp::sync_frame_ex(base + 1, "active_connection", "com.heytap.accessory", &dev_name2, &scp.model, false, 3);
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
                                                        if scp.greet {
                                                            let (hb, _sb) =
                                                                crate::scp::hello_sync_bytes(
                                                                    "active_connection",
                                                                    "com.heytap.accessory",
                                                                    &dev_name,
                                                                    &scp.model,
                                                                );
                                                            for ft in [1u16, 2, 0] {
                                                                let hello =
                                                                    crate::scp::frame_t(ft, 1, &hb);
                                                                record(
                                                                    &path,
                                                                    &format!(
                                                                        "sent :{p} hello ft{ft}"
                                                                    ),
                                                                    &hello,
                                                                );
                                                                let _ =
                                                                    stream.write_all(&hello).await;
                                                            }
                                                            let (_h, sb) =
                                                                crate::scp::hello_sync_bytes(
                                                                    "active_connection",
                                                                    "com.heytap.accessory",
                                                                    &dev_name,
                                                                    &scp.model,
                                                                );
                                                            for ft in [1u16, 2, 0] {
                                                                let sync =
                                                                    crate::scp::frame_t(ft, 2, &sb);
                                                                record(
                                                                    &path,
                                                                    &format!(
                                                                        "sent :{p} sync ft{ft}"
                                                                    ),
                                                                    &sync,
                                                                );
                                                                let _ =
                                                                    stream.write_all(&sync).await;
                                                            }
                                                            let _ = stream.flush().await;
                                                            tracing::info!(
                                                                "[tcp] :{p} scp greeting sent"
                                                            );
                                                        }
                                                        std::mem::forget(stream);
                                                    } else if p == 59399 {
                                                        // AndroidTcpProbeServer: the PC must
                                                        // announce itself as a lanprovider
                                                        // probe — >=1 byte within 1 s, and the
                                                        // bytes are parsed as an SDP packet.
                                                        let reg = reg59399.clone();
                                                        let (mut r9, mut w9) = stream.into_split();
                                                        record(
                                                            &path,
                                                            "sent probe59399 REGISTER",
                                                            &reg,
                                                        );
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
                                                                            hex::encode(
                                                                                &b[..n.min(64)]
                                                                            )
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
                                                    tracing::info!(
                                                        "[tcp] callback :{p} to {peer} err {e}"
                                                    )
                                                }
                                                Err(_) => {
                                                    tracing::info!(
                                                        "[tcp] callback :{p} to {peer} timeout"
                                                    )
                                                }
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
        epi_svc.register_killer(&session_ip, task.abort_handle());
    }
}

// SDP response context: config, sockets, and per-request SDP fields —
// grouping them would only rename the same bundle.
#[expect(clippy::too_many_arguments)]
async fn handle(
    cfg: &std::sync::Arc<SdpdConfig>,
    sdp: &Arc<Sdp>,
    uni: &UdpSocket,
    link_b64: &Option<String>,
    seen: &mut HashMap<(String, String), Instant>,
    last_phone: &mut Option<SocketAddr>,
    plane: &str,
    from: SocketAddr,
    data: &[u8],
) {
    if from.ip().is_loopback() {
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
    sdp.set_phone_ip(&from.ip().to_string());
    let pdid = String::from_utf8_lossy(data).lines().find_map(|l| {
        let l = l.trim();
        l.strip_prefix("PDID:").map(|v| v.trim().to_string())
    });
    // Our own broadcast QUERY/ANNOUNCE echoes back to us on the LAN; it
    // must not enter the auto-link address book (self-dial).
    let self_echo = pdid
        .as_deref()
        .is_some_and(|p| p.eq_ignore_ascii_case(cfg.pdid.trim()));
    if !self_echo {
        sdp.note_announced(&from.ip().to_string(), pdid);
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

/// Identity MAC for link frames: the first physical NIC's sysfs address,
/// else any non-loopback interface with a plausible MAC, else synthetic.
fn link_mac_spec() -> String {
    let valid = |mac: &str| {
        mac.len() == 17
            && mac.bytes().all(|b| b == b':' || b.is_ascii_hexdigit())
            && mac != "00:00:00:00:00:00"
    };
    let mac_of = |name: &str| -> Option<String> {
        std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|m| valid(m))
    };
    if let Ok(ifaces) = std::fs::read_dir("/sys/class/net") {
        let mut names: Vec<String> = ifaces
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| n != "lo")
            .collect();
        names.sort();
        // Physical NICs (have a `device` link) win over virtual ones.
        for pass in [true, false] {
            for name in &names {
                let physical =
                    std::fs::symlink_metadata(format!("/sys/class/net/{name}/device")).is_ok();
                if physical == pass
                    && let Some(mac) = mac_of(name)
                {
                    return mac;
                }
            }
        }
    }
    "aa:bb:cc:dd:ee:ff".into()
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

// ==== service configuration (env keys read once at startup) ====

/// SCP/pantaconnect session lane (`SCP_*`, `CLIENTSCP`, `RESP`).
#[derive(Debug, Clone)]
pub struct ScpConfig {
    /// `SCP_SERVER`: answer phone-initiated sessions as SCP server.
    pub server: bool,
    /// `CLIENTSCP`: client-scp responders on active_connection.
    pub clientscp: bool,
    /// `SCP_KEYTYPE`: ScpSyncData.keyType we present (1 = vendor PC).
    pub keytype: i32,
    /// `SCP_PDID`: our 12-hex protocol device id.
    pub pdid: String,
    /// `SCP_MODEL`: ScpSyncData.modelId, 3 bytes hex (a real PC model).
    pub model: String,
    /// `SCP_INTERACT`: interact-handshake flavour (`accept`|`echo`).
    pub interact: String,
    /// `RESP`: channel-open reply flavour (`off`|`accept`|`echo`|…).
    pub resp: String,
    /// `SCP_SS_SEND`: send SYNC_SECURE unsolicited on the dial lane.
    pub ss_send: bool,
    /// `SCP_SS_ENC`: seal SYNC_SECURE rather than plaintext.
    pub ss_enc: bool,
    /// `SCP_SS_KEY`: seal key selection (`dk`|`ek`).
    pub ss_key: String,
    /// `SCP_SS_IV`: IV policy label (`range`|`zero`).
    pub ss_iv: String,
    /// `SCP_SS_NOW`: skip post-FINISHED SYNC re-sends.
    pub ss_now: bool,
    /// `SCP_KS_DUMP`: log negotiated key material (local logs only).
    pub ks_dump: bool,
    /// `SCP_NO_OPENOUT`: suppress the :10152 open-out callback dial.
    pub no_openout: bool,
    /// `SCP_DIAL_PORTS`: EstablishLink callback ports we dial back.
    pub dial_ports: Vec<u16>,
    /// `SCP_SS_NONCE_ZERO`: force-zero the sync-secure GCM nonce.
    pub ss_nonce_zero: bool,
    /// `OPENOUT_SYNC` / `OPENOUT_ACK` / `SCP_OPENOUT_SCP` / `SCP_GREET`:
    /// open-out diagnostics experiments (env presence enables).
    pub openout_sync: Option<String>,
    pub openout_ack: bool,
    pub openout_scp: bool,
    pub greet: bool,
}

impl Default for ScpConfig {
    fn default() -> Self {
        Self {
            server: true,
            clientscp: true,
            keytype: 1,
            pdid: "A1B2C3D4E5F6".into(),
            model: "2B1488".into(),
            interact: "accept".into(),
            resp: "off".into(),
            ss_send: true,
            ss_enc: true,
            ss_key: "dk".into(),
            ss_iv: "range".into(),
            ss_now: true,
            ks_dump: true,
            no_openout: true,
            dial_ports: vec![10153, 10162, 10151, 10152, 10150, 59399],
            ss_nonce_zero: false,
            openout_sync: None,
            openout_ack: false,
            openout_scp: false,
            greet: false,
        }
    }
}

// ==== service configuration (env keys read once at startup) ====

/// Link-detection probe sockets / LinkSwitch replies (`LINK*`, `LINKNS`).
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// `LINK_PORTS`: probe sockets we answer.
    pub ports: Vec<u16>,
    /// `LINK_POISON_IP`: vgate route-poison address (off = none).
    pub poison: Option<[u8; 4]>,
    /// `LINK_REPLY_MIRROR`: answer probes with the mirrored frame.
    pub mirror: bool,
    /// `LINKNS`: LinkSwitchMgr namespace for publishes.
    pub ns: String,
    /// `LINK_ACK`: probe reply flavour (empty = mirror reply).
    pub ack: String,
    /// `LINKPUB`: raw hex override for the SERVICE-PUBLISH payload.
    pub pub_hex: Option<Vec<u8>>,
    /// `LINK_REPLY_HEX` / `LINK_REPLY_HEX_FILE`: hot reply overrides.
    pub reply_hex: Option<Vec<u8>>,
    pub reply_hex_file: Option<String>,
    /// `LINK_KPD` / settings.json `linkKpd`: known-peer-device ids.
    pub kpd: Vec<Vec<u8>>,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            ports: vec![54227, 57320, 63125, 59566],
            poison: Some([192, 0, 2, 16]),
            mirror: true,
            ns: "LinkSwitchMgr".into(),
            ack: String::new(),
            pub_hex: None,
            reply_hex: None,
            reply_hex_file: None,
            kpd: Vec::new(),
        }
    }
}

// ==== service configuration (env keys read once at startup) ====

/// Pairing material: env override first, then `settings.json`.
#[derive(Debug, Clone, Default)]
pub struct PairingConfig {
    /// `SCP_KSC` / settings.json `scpKsc`: 16B KSC pin.
    pub ksc_pin: Option<Vec<u8>>,
}

// -- ScpConfig --
impl ScpConfig {
    pub fn load() -> Self {
        let d = Self::default();
        Self {
            server: flag("SCP_SERVER", d.server),
            clientscp: flag("CLIENTSCP", d.clientscp),
            keytype: num("SCP_KEYTYPE", d.keytype),
            pdid: str_of("SCP_PDID", &d.pdid),
            model: str_of("SCP_MODEL", &d.model),
            interact: str_of("SCP_INTERACT", &d.interact),
            resp: str_of("RESP", &d.resp),
            ss_send: flag("SCP_SS_SEND", d.ss_send),
            ss_enc: flag("SCP_SS_ENC", d.ss_enc),
            ss_key: str_of("SCP_SS_KEY", &d.ss_key),
            ss_iv: str_of("SCP_SS_IV", &d.ss_iv),
            ss_now: flag("SCP_SS_NOW", d.ss_now),
            ks_dump: flag("SCP_KS_DUMP", d.ks_dump),
            no_openout: flag("SCP_NO_OPENOUT", d.no_openout),
            dial_ports: ports("SCP_DIAL_PORTS", &d.dial_ports),
            ss_nonce_zero: std::env::var("SCP_SS_NONCE_ZERO").is_ok(),
            openout_sync: std::env::var("OPENOUT_SYNC").ok().filter(|s| !s.is_empty()),
            openout_ack: std::env::var("OPENOUT_ACK").is_ok(),
            openout_scp: std::env::var("SCP_OPENOUT_SCP").is_ok(),
            greet: std::env::var("SCP_GREET").is_ok(),
        }
    }
}

// -- LinkConfig --
impl LinkConfig {
    pub fn load(settings: &serde_json::Value) -> Self {
        let d = Self::default();
        Self {
            ports: ports("LINK_PORTS", &d.ports),
            poison: match std::env::var("LINK_POISON_IP").ok() {
                Some(v) if v.eq_ignore_ascii_case("off") || v.trim().is_empty() => None,
                Some(v) => ipv4(v.trim()).or(d.poison),
                None => d.poison,
            },
            mirror: flag("LINK_REPLY_MIRROR", d.mirror),
            ns: str_of("LINKNS", &d.ns),
            ack: str_of("LINK_ACK", &d.ack),
            pub_hex: hex_bytes("LINKPUB"),
            reply_hex: hex_bytes("LINK_REPLY_HEX"),
            reply_hex_file: std::env::var("LINK_REPLY_HEX_FILE")
                .ok()
                .filter(|s| !s.is_empty()),
            kpd: std::env::var("LINK_KPD")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| setting_str(settings, "linkKpd"))
                .map(|s| {
                    s.split(',')
                        .map(|x| x.trim().as_bytes().to_vec())
                        .filter(|v| !v.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

// -- PairingConfig --
impl PairingConfig {
    pub fn load(settings: &serde_json::Value) -> Self {
        Self {
            ksc_pin: hex_bytes("SCP_KSC")
                .filter(|v| v.len() == 16)
                .or_else(|| {
                    setting_str(settings, "scpKsc")
                        .and_then(|s| hex::decode(s.replace(':', "")).ok())
                })
                .filter(|v| v.len() == 16),
        }
    }
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
        }
        dir
    }

    #[test]
    fn ksc_bond_is_minted_once_and_replayed_across_restarts() {
        let _guard = crate::state::ENV_TEST_LOCK.lock().expect("ksc test lock");
        let dir = ksc_env_isolate("mint");
        let (k1, a1) = issue_ksc(None, "192.0.2.102", "A1B2C3D4E5F6");
        assert_eq!(k1.len(), 16);
        assert_eq!(a1.len(), 6);
        // "Restart" = fresh process view; the store file is re-read each call.
        let (k2, a2) = issue_ksc(None, "192.0.2.102", "A1B2C3D4E5F6");
        assert_eq!(k1, k2, "resumption must replay the bonded ksc verbatim");
        assert_eq!(a1, a2, "alias must be stable too (loadKsc keys on it)");
        let stored = std::fs::read_to_string(crate::state::ksc_store_path()).expect("store");
        assert!(
            stored.contains(&hex::encode(&k1)),
            "bond not persisted: {stored}"
        );
        // A different peer gets its own key, not a reuse of the first.
        let (k3, _) = issue_ksc(None, "192.0.2.103", "A1B2C3D4E5F6");
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
        assert!(ksc_candidates(None, "192.0.2.102", dev_hex).is_empty());
        // Bond issued via sync-secure to the peer IP.
        let (_, alias) = issue_ksc(None, "192.0.2.102", "A1B2C3D4E5F6");
        ksc_store_put("192.0.2.102", "A1B2C3D4E5F6", &bonded, &alias);
        let cands = ksc_candidates(None, "192.0.2.102", dev_hex);
        assert_eq!(cands, vec![bonded.to_vec()]);
        assert!(cands.iter().any(|c| ksc_s(c, &qc, ts) == mac));
        // Success promotes the bond under the claimed device id, so the
        // next AUTH resolves even from a different socket/port.
        remember_ksc(dev_hex, dev_hex, &bonded);
        assert_eq!(
            ksc_candidates(None, "192.0.2.9", dev_hex),
            vec![bonded.to_vec()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dbs_payload_json_accepts_our_frame_and_rejects_bad_msgtype() {
        let from = [1u8, 2, 3, 4, 5, 6];
        let to = [7u8, 8, 9, 10, 11, 12];
        let json = "{\"dbs_msg_type\":\"msg_topic_sync\",\"dbs_msg_id\":\"x\"}";
        let frame = crate::svc::kms::dbs_data_frame(&from, &to, 7, 0x1001, json.as_bytes());
        let payload = &frame[4..];
        let v = dbs_payload_json(payload).expect("our own frame parses");
        assert_eq!(v["dbs_msg_type"], "msg_topic_sync");
        // The phone's DbsDataReceiver only parses dbr.a msgType 42/82.
        let mut bad = frame.clone();
        bad[4 + 3 + 26] = 7; // legacy prefix view
        bad[4 + 11 + 26] = 7; // DATA (0x04 + ctr) prefix view
        assert!(dbs_payload_json(&bad[4..]).is_none());
    }

    fn row(key: &str, device_id: &str) -> (String, KscRecord) {
        (
            key.to_string(),
            KscRecord {
                device_id: device_id.to_string(),
                alias: "aabbccddeeff".into(),
                ksc: "00112233445566778899aabbccddeeff".into(),
            },
        )
    }

    #[test]
    fn bond_gate_matches_announced_pdid_case_insensitively() {
        let rows = vec![row("192.0.2.102", "bcc5b323465c")];
        assert!(bond_covers(&rows, "192.0.2.5", Some("BCC5B323465C")));
        assert!(bond_covers(&rows, "192.0.2.102", None));
    }

    #[test]
    fn bond_gate_rejects_foreign_pdid_even_with_one_bond() {
        let rows = vec![row("192.0.2.102", "bcc5b323465c")];
        assert!(!bond_covers(&rows, "192.0.2.5", Some("DEADBEEFDEAD")));
    }

    #[test]
    fn bond_gate_falls_back_to_single_bond_without_pdid() {
        let one = vec![row("192.0.2.102", "bcc5b323465c")];
        assert!(bond_covers(&one, "192.0.2.9", None));
        let two = vec![
            row("192.0.2.102", "bcc5b323465c"),
            row("192.0.2.77", "aabbccddeeff"),
        ];
        assert!(!bond_covers(&two, "192.0.2.9", None));
    }

    #[test]
    fn kms_port_rotation_advances_within_span() {
        let sdp = Sdp::new(SdpdConfig::default(), crate::svc::epi::Epi::new());
        let base = sdp.gcfg.kms.port_base;
        let span = sdp.kms_port_span();
        let p0 = sdp.kms_bootstrap_env().0;
        assert!(p0 >= base && p0 < base + span, "port {p0} outside span");
        sdp.begin_kms_session();
        let p1 = sdp.kms_bootstrap_env().0;
        assert_ne!(p0, p1, "begin must change the port (stale same-port guard)");
        for _ in 0..span {
            sdp.begin_kms_session();
        }
        assert_eq!(sdp.kms_bootstrap_env().0, p1, "rotation must cycle");
    }

    #[test]
    fn topic_sync_json_carries_sub_list_and_type() {
        let j = crate::svc::kms::dbs_topic_sync_json("aabb", "ccdd", &["Oplus_PcConnect"], 5);
        assert!(j.contains(r#""dbs_msg_type":"msg_topic_sync""#));
        assert!(j.contains(r#""dbs_msg_from_device":"aabb""#));
        // `f.h` Gson-parses the payload as Map<String, Set<ONetTopic>>:
        // string-typed payload holding ONetTopic-shaped objects.
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let payload: serde_json::Value =
            serde_json::from_str(v["dbs_msg_payload"].as_str().unwrap()).unwrap();
        assert_eq!(payload["sub"][0]["dbs_topic_name"], "Oplus_PcConnect");
        assert_eq!(payload["sub"][0]["dbs_topic_tag"], 0);
        assert!(payload["pub"].as_array().unwrap().is_empty());
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
        assert_eq!(f[4], 0x04); // b0 DATA
        let json = String::from_utf8(f[4 + 11 + 58..].to_vec()).expect("utf8 tail");
        // payload is a quoted JSON string, so inner quotes arrive escaped.
        assert!(json.contains("\\\"key\\\":\\\"input_service\\\""));
        assert!(json.contains("msg_type"));
        assert!(json.contains("kms_socket_port"));
        assert_eq!(
            &f[4 + 11..4 + 17],
            &hex::decode("A1B2C3D4E5F6").unwrap()[..]
        ); // dbr from
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
