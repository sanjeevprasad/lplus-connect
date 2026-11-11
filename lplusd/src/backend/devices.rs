//! Daemon-backed device inventory: the single source for the contract's
//! `ListDevices` / `GetPairedDevices` responses.
//!
//! Presence is **typed, not scraped**: the in-process backend publishes
//! `DeviceEvent{kind,ip,name,connected,ts_ms}` on a tokio broadcast
//! (`crate::sdpd`, PROTOCOL.md §7) and this model consumes it directly via
//! `subscribe_devices()`. A reconnection subscriber on
//! `OPLUS_EVENTS_PORT=<p>[,<p>…]` additionally follows the NDJSON bridge of
//! an external daemon during development.
//!
//! Rows are deduped by ip: the name comes from `scp_sync` events (the
//! phone's model string), `connected` flips on `epi`/`kms` session events,
//! and rows with no events for >5 min are pruned. There is no stdout
//! frame-scanner, peers map or historical prescan any more — a device is
//! visible exactly while the backend reports events for it. Every event
//! mirrors to the log as `[presence] event …`.
//!
//! The row shape mirrors the vendor `devicesList` entry (RE reference for
//! the mydevice screen); consumers read it through the contract — the
//! renderer-era bus push lane was cut with the parked window.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use strum::EnumString;

use serde::Deserialize;

use crate::svc::sdp::DeviceEvent;

/// Rows with no event for this long are dropped.
const ROW_TTL_SECS: u64 = 5 * 60;
/// Rows without an event for this long drop the discovered flag.
const DISCOVERED_WINDOW_SECS: u64 = 120;
/// A row may only claim "connected" on fresh link evidence: `epi`/`kms`
/// session events and `scp_sync` refresh `last_session` (presence-only
/// events update `last_seen` alone, so accessory chatter can no longer
/// keep a dead session looking alive). Silence beyond this clears the flag.
/// Phones that vanish without a TCP FIN never deliver the close event, so
/// without this clients keep claiming Connected forever.
const CONN_STALE_SECS: u64 = 120;
const BRIDGE_RETRY: Duration = Duration::from_secs(2);

/// Host-local addresses: the backend may report its own side of sessions
/// (primary NIC, loopback) — never accessories.
fn local_ips() -> &'static std::collections::HashSet<String> {
    static LOCALS: LazyLock<std::collections::HashSet<String>> = LazyLock::new(|| {
        let mut set = std::collections::HashSet::new();
        set.insert(crate::svc::sdp::default_vip());
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0")
            && sock.connect(("8.8.8.8", 80)).is_ok()
            && let Ok(addr) = sock.local_addr()
        {
            set.insert(addr.ip().to_string());
        }
        set
    });
    &LOCALS
}

fn is_local(ip: &str) -> bool {
    ip.starts_with("127.") || local_ips().contains(ip)
}

/// One card row, shaped to what mydevice/`devicesList` consumers read —
/// the generated contract type (`lplus_ipc::pb::Device`, from
/// `protos/lplus.proto`), re-exported so in-crate callers keep saying
/// `crate::backend::devices::Device`.
pub use lplus_ipc::pb::Device;

/// NDJSON wire form of `crate::svc::sdp::DeviceEvent` for external-bridge
/// subscribers. (The backend type derives `Serialize` only; this mirror
/// parses the same JSON that `spawn_events_bridge` writes.)
#[derive(Deserialize)]
struct WireEvent {
    kind: String,
    ip: String,
    name: Option<String>,
    connected: bool,
    ts_ms: i64,
}

#[derive(Default)]
struct Inner {
    /// Visible rows keyed by ip (dedupe); minted only by backend events.
    rows: HashMap<String, Device>,
    /// Last persisted serialization of the paired rows (`paired-devices.json`).
    paired_saved: String,
    /// User-removed device ids (`generic_agent_settings_remove_device`,
    /// vendor `add_blacklist=1`): suppress stale adb transports from
    /// re-minting rows until a fresh scp_sync lifts the block.
    unpaired: HashSet<String>,
    /// Last persisted serialization of `unpaired` (`unpaired.json`).
    unpaired_saved: String,
}

/// Vendor `CONNECT_TYPE` bits (renderer `Ve.gy`): LAN discovery vs adb/USB.
pub const CONNECT_TYPE_LAN: u32 = 16;
pub const CONNECT_TYPE_USB: u32 = 128;

/// The product is Wi-Fi only. Legacy USB rows (from the removed adb
/// transport lane) stay hidden from every read surface unless
/// `LPLUS_USB=1`; their bonds stay in `paired.json` untouched.
pub fn usb_lane_on() -> bool {
    std::env::var("LPLUS_USB").is_ok_and(|v| v == "1")
}

/// Surface-level visibility for one row (pure for tests).
fn usb_hidden(row: &Device, usb_on: bool) -> bool {
    !usb_on && row.connect_type == CONNECT_TYPE_USB
}

/// Process-wide registry: the loopback server thread and the GPUI direct
/// dispatch share one model without plumbing State through both.
static REGISTRY: LazyLock<Mutex<Inner>> = LazyLock::new(Mutex::default);

fn inner() -> &'static Mutex<Inner> {
    &REGISTRY
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// --------------------------------------------------------------- pairing ---

/// Persistent pairing bond file (`paired.json` in the state dir; see
/// `state.rs`).
fn paired_path() -> std::path::PathBuf {
    crate::state::paired_path()
}

/// Registry key a persisted row belongs to; `None` for unusable rows.
fn row_key(row: &Device) -> Option<String> {
    if row.connect_type == CONNECT_TYPE_USB {
        row.usb_serial.as_deref().map(|s| format!("usb:{s}"))
    } else if row.ip.is_empty() {
        None
    } else {
        Some(row.ip.clone())
    }
}

/// Load persisted paired rows; any read/parse failure means "no bonds".
fn load_paired(path: &std::path::Path) -> Vec<Device> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match serde_json::from_str::<Vec<Device>>(&raw) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("[pair] paired bond file unusable ({}): {e}", path.display());
            Vec::new()
        }
    }
}

/// Persist paired rows when they differ from the last saved state.
fn save_paired(path: &std::path::Path, rows: &[&Device]) -> std::io::Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(&rows)?.as_bytes())
}

/// Write the paired set if its serialization changed since last save.
fn sync_paired(i: &mut Inner) {
    let mut rows: Vec<&Device> = i.rows.values().filter(|r| r.is_paired).collect();
    rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    let Ok(json) = serde_json::to_string_pretty(&rows) else {
        return;
    };
    if json == i.paired_saved || (rows.is_empty() && i.paired_saved.is_empty()) {
        return;
    }
    let path = paired_path();
    match save_paired(&path, &rows) {
        Ok(()) => i.paired_saved = json,
        Err(e) => tracing::warn!("[pair] persist failed ({}): {e}", path.display()),
    }
}

/// Rows carrying a persistent pairing bond — authority for
/// `generic_agent_get_paired_devices` (consumers read `entries[]` /
/// `pairedDevices`, e.g. gaPairBoundStatus).
pub fn paired_rows() -> Vec<Device> {
    let mut i = inner().lock().expect("devices lock poisoned");
    refresh_ephemeral(&mut i);
    sync_paired(&mut i);
    let mut rows: Vec<&Device> = i
        .rows
        .values()
        .filter(|r| r.is_paired && !usb_hidden(r, usb_lane_on()))
        .collect();
    rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    rows.into_iter().cloned().collect()
}

/// User-initiated device removal (`generic_agent_settings_remove_device`,
/// payload `{ device_id, removeStateDir }`): drops every row for the id and
/// blocks stale adb transports from re-minting it until a fresh scp_sync.
pub fn remove_device(device_id: &str) -> bool {
    if device_id.is_empty() {
        return false;
    }
    let mut i = inner().lock().expect("devices lock poisoned");
    let removed = forget(&mut i, device_id);
    sync_paired(&mut i);
    sync_unpaired(&mut i);
    removed
}

/// `remove_device` body, pure over `Inner`.
fn forget(i: &mut Inner, device_id: &str) -> bool {
    let dead: Vec<String> = i
        .rows
        .iter()
        .filter(|(_, r)| r.device_id == device_id || r.protcol_device_id == device_id)
        .map(|(k, _)| k.clone())
        .collect();
    let removed = !dead.is_empty();
    for key in dead {
        tracing::info!("[pair] device {device_id} removed ({key})");
        i.rows.remove(&key);
    }
    i.unpaired.insert(device_id.to_string());
    removed
}

/// Persisted user-removal block list (state dir).
fn unpaired_path() -> std::path::PathBuf {
    crate::state::unpaired_path()
}

fn load_unpaired(path: &std::path::Path) -> HashSet<String> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    match serde_json::from_str::<Vec<String>>(&raw) {
        Ok(v) => v.into_iter().collect(),
        Err(e) => {
            tracing::warn!("[pair] unpaired.json unusable ({}): {e}", path.display());
            HashSet::new()
        }
    }
}

fn sync_unpaired(i: &mut Inner) {
    sync_unpaired_at(i, &unpaired_path());
}

fn sync_unpaired_at(i: &mut Inner, path: &std::path::Path) {
    if i.unpaired.is_empty() && i.unpaired_saved.is_empty() {
        return;
    }
    let mut ids: Vec<&String> = i.unpaired.iter().collect();
    ids.sort();
    let Ok(json) = serde_json::to_string_pretty(&ids) else {
        return;
    };
    if json == i.unpaired_saved {
        return;
    }
    match std::fs::write(path, json.as_bytes()) {
        Ok(()) => i.unpaired_saved = json,
        Err(e) => tracing::warn!("[pair] unpaired persist failed ({}): {e}", path.display()),
    }
}

static INIT: std::sync::Once = std::sync::Once::new();

/// Subscribe to the in-process event broadcast and to any external daemon
/// bridges. Idempotent: every entry point calls it, the lanes start once.
pub fn init(sdp: &std::sync::Arc<crate::svc::sdp::Sdp>) {
    let sdp = sdp.clone();
    INIT.call_once(|| init_inner(sdp));
}

fn init_inner(sdp: std::sync::Arc<crate::svc::sdp::Sdp>) {
    {
        let persisted = load_paired(&paired_path());
        let blocked = load_unpaired(&unpaired_path());
        let mut i = inner().lock().expect("devices lock poisoned");
        for row in persisted {
            if let Some(key) = row_key(&row) {
                i.rows.entry(key).or_insert(row);
            }
        }
        i.unpaired = blocked;
        let mut ids: Vec<&String> = i.unpaired.iter().collect();
        ids.sort();
        i.unpaired_saved = serde_json::to_string_pretty(&ids).unwrap_or_default();
        let mut rows: Vec<&Device> = i.rows.values().filter(|r| r.is_paired).collect();
        rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        i.paired_saved = serde_json::to_string_pretty(&rows).unwrap_or_default();
    }
    let mut rx = sdp.subscribe_devices();
    // Own thread + tiny current-thread runtime: presence ingest must not
    // depend on a UI runtime being up.
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("presence ingest runtime");
        rt.block_on(async move {
            while let Ok(ev) = rx.recv().await {
                apply_event(&ev);
            }
        });
    });
    spawn_bridge_consumers();
}

/// Serializable visible rows (sorted, ephemeral flags refreshed, stale
/// rows pruned) as typed rows — the API surface.
pub fn visible_device_rows() -> Vec<Device> {
    let mut i = inner().lock().expect("devices lock poisoned");
    visible_rows(&mut i)
}

fn visible_rows(i: &mut Inner) -> Vec<Device> {
    visible_rows_gated(i, usb_lane_on())
}

fn visible_rows_gated(i: &mut Inner, usb_on: bool) -> Vec<Device> {
    refresh_ephemeral(i);
    let mut rows: Vec<&Device> = i.rows.values().filter(|r| !usb_hidden(r, usb_on)).collect();
    rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    rows.into_iter().cloned().collect()
}

// ------------------------------------------------------------------ events

/// Mirror one presence event to the log (also used by `--headless`).
pub fn log_presence(ev: &DeviceEvent) {
    log_event(ev.kind, &ev.ip, ev.name.as_deref(), ev.connected, ev.ts_ms);
}

fn log_event(kind: &str, ip: &str, name: Option<&str>, connected: bool, ts_ms: i64) {
    tracing::info!(
        "[presence] event kind={kind} ip={ip} connected={connected} name={:?} ts_ms={ts_ms}",
        name.unwrap_or("-")
    );
}

/// Apply one in-process `DeviceEvent` (also the bridge path after JSON
/// decode). Every event is mirrored to the log for live verification.
pub fn apply_event(ev: &DeviceEvent) {
    let mut i = inner().lock().expect("devices lock poisoned");
    log_event(ev.kind, &ev.ip, ev.name.as_deref(), ev.connected, ev.ts_ms);
    ingest_event(&mut i, ev.kind, &ev.ip, ev.name.as_deref(), ev.connected);
    sync_paired(&mut i);
    sync_unpaired(&mut i);
}

// ------------------------------------------------------------------ usb ----

/// Classified `DeviceEvent.kind` spellings the model reacts to; anything
/// else is unclassified accessory chatter (`None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString)]
#[strum(serialize_all = "snake_case")]
enum EventKind {
    Epi,
    Kms,
    ScpSync,
}

/// Fold one presence event into the row table (pure over `Inner`). Row
/// identity is the ip; names only ever come from `scp_sync`, `connected`
/// flips only on `epi`/`kms` session events. Unknown kinds refresh
/// presence of an existing row but never mint one — accessory chatter the
/// backend has not classified stays invisible.
fn ingest_event(i: &mut Inner, kind: &str, ip: &str, name: Option<&str>, connected: bool) {
    if ip.is_empty() || is_local(ip) {
        return;
    }
    let now = now_secs();
    let known = i.rows.contains_key(ip);
    let kind = EventKind::from_str(kind).ok();
    if !known && kind.is_none() {
        return;
    }
    let row = i.rows.entry(ip.to_string()).or_insert_with(|| Device {
        device_id: device_id_for(ip),
        device_name: format!("Phone {}", ip.rsplit('.').next().unwrap_or(ip)),
        ip: ip.to_string(),
        connect_type: CONNECT_TYPE_LAN,
        device_type: 8,
        is_same_account: false,
        status: "default".into(),
        time: now,
        usb_serial: None,
        is_discovered: true,
        is_connected: false,
        is_paired: false,
        protcol_device_id: device_id_for(ip),
        last_seen: now,
        last_session: 0,
    });
    row.last_seen = now;
    match kind {
        // epi/datatrans or KMS session traffic is the link state.
        Some(EventKind::Epi) | Some(EventKind::Kms) => {
            row.is_connected = connected;
            row.last_session = if connected { now } else { 0 };
        }
        // scp SYNC is a real accessory session and carries the model name.
        Some(EventKind::ScpSync) => {
            row.last_session = now;
            row.is_paired = true;
            if let Some(n) = name {
                set_name(i, ip, n);
            }
            // Fresh pairing evidence outranks a user removal.
            let id = i.rows.get(ip).map(|r| r.device_id.clone());
            if let Some(id) = id {
                i.unpaired.remove(&id);
            }
        }
        None => {}
    }
}

fn device_id_for(ip: &str) -> String {
    ip.replace('.', "-")
}

/// Prune rows idle beyond the TTL and recompute the discovered flag.
fn refresh_ephemeral(i: &mut Inner) {
    let now = now_secs();
    i.rows.retain(|key, row| {
        let keep = row.is_paired || now.saturating_sub(row.last_seen) <= ROW_TTL_SECS;
        if !keep {
            tracing::debug!(
                "[pair] ttl-prune {key} (paired={}, lastSeen={})",
                row.is_paired,
                row.last_seen
            );
        }
        keep
    });
    let stale_conn: Vec<String> = i
        .rows
        .iter()
        .filter(|(_, r)| r.is_connected && now.saturating_sub(r.last_session) > CONN_STALE_SECS)
        .map(|(k, _)| k.clone())
        .collect();
    for row in i.rows.values_mut() {
        row.is_discovered = now.saturating_sub(row.last_seen) <= DISCOVERED_WINDOW_SECS;
    }
    for key in &stale_conn {
        if let Some(row) = i.rows.get_mut(key) {
            row.is_connected = false;
            tracing::info!(
                "[pair] {} marked disconnected: no link evidence for {}s",
                row.device_id,
                CONN_STALE_SECS
            );
        }
    }
    if !stale_conn.is_empty() {}
}

/// Adopt an `scp_sync` name; keep an existing model name over weaker
/// fallbacks (`Phone <octet>` or non-model strings).
fn set_name(i: &mut Inner, ip: &str, name: &str) {
    let clean: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '(' | ')'))
        .collect();
    let clean = clean.trim().to_string();
    if clean.len() < 3 || clean.len() > 24 {
        return;
    }
    if let Some(row) = i.rows.get_mut(ip)
        && (row.device_name.starts_with("Phone ") || is_model_name(&clean))
    {
        row.device_name = clean;
    }
}

fn is_model_name(name: &str) -> bool {
    ["OnePlus", "ONEPLUS", "OPPO", "CPH", "RMX", "PD", "PJ"]
        .iter()
        .any(|t| name.contains(t))
}

// ----------------------------------------------------------------- bridges

/// Reconnecting NDJSON subscriber per `OPLUS_EVENTS_PORT` entry — dev aid
/// for following an external daemon's presence bridge. Each line is a
/// `DeviceEvent` JSON object (`WireEvent` mirror); lines that fail to parse
/// are dropped. The unified binary feeds this model from the in-process
/// broadcast, so its own bridge port is for external consumers, not us.
fn spawn_bridge_consumers() {
    let Ok(csv) = std::env::var("OPLUS_EVENTS_PORT") else {
        return;
    };
    for port in csv.split(',').filter_map(|s| s.trim().parse::<u16>().ok()) {
        thread::spawn(move || {
            let addr = ("127.0.0.1", port);
            loop {
                if let Ok(sock) = TcpStream::connect(addr) {
                    tracing::info!("[presence] bridge :{port} connected");
                    let mut reader = BufReader::new(sock);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        let Ok(n) = reader.read_line(&mut line) else {
                            break;
                        };
                        if n == 0 {
                            break;
                        }
                        if let Ok(ev) = serde_json::from_str::<WireEvent>(line.trim()) {
                            log_event(&ev.kind, &ev.ip, ev.name.as_deref(), ev.connected, ev.ts_ms);
                            let mut i = inner().lock().expect("devices lock poisoned");
                            ingest_event(
                                &mut i,
                                &ev.kind,
                                &ev.ip,
                                ev.name.as_deref(),
                                ev.connected,
                            );
                        }
                    }
                    tracing::info!("[presence] bridge :{port} lost; reconnecting");
                }
                thread::sleep(BRIDGE_RETRY);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(i: &mut Inner, kind: &str, ip: &str, name: Option<&str>, connected: bool) {
        ingest_event(i, kind, ip, name, connected);
    }

    fn usb_row(serial: &str, paired: bool) -> Device {
        Device {
            device_id: format!("usb-{serial}"),
            device_name: "Phone".into(),
            ip: String::new(),
            connect_type: CONNECT_TYPE_USB,
            device_type: 8,
            is_same_account: false,
            status: "default".into(),
            time: 0,
            usb_serial: Some(serial.into()),
            is_discovered: true,
            is_connected: true,
            is_paired: paired,
            protcol_device_id: format!("usb-{serial}"),
            last_seen: 0,
            last_session: 0,
        }
    }

    #[test]
    fn remove_device_drops_rows_and_lifts_on_bond() {
        let mut i = Inner::default();
        ev(&mut i, "epi", "192.0.2.9", Some("Phone"), true);
        assert!(i.rows.contains_key("192.0.2.9"));
        assert!(forget(&mut i, "192-0-2-9"));
        assert!(!i.rows.contains_key("192.0.2.9"));
        assert!(i.unpaired.contains("192-0-2-9"));
        assert!(!forget(&mut i, "never-seen"));
        // A fresh scp_sync bond lifts the removal record.
        ev(&mut i, "scp_sync", "192.0.2.8", Some("OnePlus 12R"), true);
        i.unpaired.insert("192-0-2-8".to_string());
        ev(&mut i, "scp_sync", "192.0.2.8", None, true);
        assert!(!i.unpaired.contains("192-0-2-8"));
        assert!(i.rows["192.0.2.8"].is_paired);
    }

    #[test]
    fn unpaired_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!("lplus-unpaired-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("unpaired.json");
        let mut i = Inner::default();
        forget(&mut i, "usb-GONE");
        sync_unpaired_at(&mut i, &path);
        let raw = std::fs::read_to_string(&path).expect("written");
        assert!(raw.contains("usb-GONE"));
        std::fs::write(&path, "not json").expect("corrupt");
        assert!(load_unpaired(&path).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scp_sync_marks_pairing_bond() {
        let mut i = Inner::default();
        ev(&mut i, "epi", "192.0.2.8", None, true);
        assert!(!i.rows["192.0.2.8"].is_paired);
        ev(&mut i, "scp_sync", "192.0.2.8", Some("OnePlus 12R"), true);
        assert!(i.rows["192.0.2.8"].is_paired);
    }

    #[test]
    fn paired_rows_survive_ttl_pruning() {
        let mut i = Inner::default();
        i.rows.insert("192.0.2.5".to_string(), {
            let mut r = usb_row("X", false);
            r.ip = "192.0.2.5".into();
            r.connect_type = CONNECT_TYPE_LAN;
            r.is_connected = false;
            r
        });
        i.rows.insert("usb:KEPT".to_string(), usb_row("KEPT", true));
        refresh_ephemeral(&mut i);
        assert!(!i.rows.contains_key("192.0.2.5"));
        assert!(i.rows.contains_key("usb:KEPT"));
    }

    #[test]
    fn paired_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!("lplus-paired-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("paired-devices.json");
        let mut i = Inner::default();
        // Transport presence alone must not persist as a bond; the bond is
        // the row carried in (or written to) `paired.json`.
        i.rows.insert(
            "usb:FAKESERIAL000001".to_string(),
            usb_row("FAKESERIAL000001", false),
        );
        i.rows
            .insert("usb:BONDED".to_string(), usb_row("BONDED", true));
        ev(&mut i, "epi", "192.0.2.2", None, false);
        let rows: Vec<&Device> = i.rows.values().filter(|r| r.is_paired).collect();
        assert_eq!(rows.len(), 1, "transport presence alone is not a bond");
        save_paired(&path, &rows).expect("save");
        let loaded = load_paired(&path);
        assert_eq!(loaded, rows.into_iter().cloned().collect::<Vec<_>>());
        assert_eq!(row_key(&loaded[0]).as_deref(), Some("usb:BONDED"));
        std::fs::write(&path, "not json").expect("corrupt");
        assert!(load_paired(&path).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scp_sync_mints_named_row_and_epi_flips_connected() {
        let mut i = Inner::default();
        // The phone: scp SYNC names it, epi session proves the link.
        ev(&mut i, "scp_sync", "192.0.2.2", Some("CPH2745"), true);
        ev(&mut i, "epi", "192.0.2.2", None, true);
        let rows = visible_rows(&mut i);
        assert_eq!(rows.len(), 1, "exactly the phone is visible: {rows:?}");
        let row = &rows[0];
        assert_eq!(row.device_id, "192-0-2-2");
        assert_eq!(row.protcol_device_id, "192-0-2-2");
        assert_eq!(row.device_name, "CPH2745");
        assert!(row.is_connected);
        assert!(row.is_discovered);

        // epi close flips connected off but keeps the row (presence TTL).
        ev(&mut i, "epi", "192.0.2.2", None, false);
        let rows = visible_rows(&mut i);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].is_connected);

        // KMS session traffic also drives the connected flag.
        ev(&mut i, "kms", "192.0.2.2", None, true);
        assert!(visible_rows(&mut i)[0].is_connected);
    }

    #[test]
    fn noisy_neighbour_stays_invisible() {
        let mut i = Inner::default();
        // The phone produces typed session events; the neighbour's SSDP /
        // probe chatter never reaches the event bus, and an unclassified
        // event for it must not mint a row either.
        ev(&mut i, "scp_sync", "192.0.2.2", Some("OnePlus 12"), true);
        ev(&mut i, "probe", "192.0.2.6", None, false);
        ev(&mut i, "announce", "192.0.2.6", None, false);
        let rows = visible_rows(&mut i);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, "192-0-2-2");
        assert!(!i.rows.contains_key("192.0.2.6"));
    }

    #[test]
    fn events_per_ip_collapse_to_one_row() {
        let mut i = Inner::default();
        ev(&mut i, "epi", "192.0.2.2", None, true);
        ev(&mut i, "scp_sync", "192.0.2.2", Some("CPH2745"), true);
        ev(&mut i, "kms", "192.0.2.2", None, true);
        assert_eq!(visible_rows(&mut i).len(), 1);
    }

    #[test]
    fn host_side_events_ignored() {
        // The backend's own side (VIP, loopback) is not an accessory.
        let mut i = Inner::default();
        // Same resolver the production LOCALS set uses, so the row lands
        // on the host side regardless of the machine this runs on.
        let vip = crate::svc::sdp::default_vip();
        ev(&mut i, "epi", &vip, None, true);
        ev(&mut i, "scp_sync", "127.0.0.1", Some("CPH2745"), true);
        assert!(visible_rows(&mut i).is_empty());
    }

    #[test]
    fn model_name_preferred_over_fallbacks() {
        let mut i = Inner::default();
        // epi mints the row with a Phone fallback…
        ev(&mut i, "epi", "192.0.2.2", None, true);
        assert_eq!(visible_rows(&mut i)[0].device_name, "Phone 2");
        // …scp_sync supplies the real model, and junk never overwrites it.
        ev(&mut i, "scp_sync", "192.0.2.2", Some("CPH2745"), true);
        ev(&mut i, "scp_sync", "192.0.2.2", Some("ok"), true);
        assert_eq!(visible_rows(&mut i)[0].device_name, "CPH2745");
    }

    #[test]
    fn stale_rows_pruned_after_ttl() {
        let mut i = Inner::default();
        ev(&mut i, "epi", "192.0.2.2", None, true);
        assert_eq!(visible_rows(&mut i).len(), 1);
        let stale = now_secs() - (ROW_TTL_SECS + 10);
        for row in i.rows.values_mut() {
            row.last_seen = stale;
        }
        assert!(visible_rows(&mut i).is_empty());
    }

    #[test]
    fn connected_flag_requires_fresh_link_evidence() {
        let mut i = Inner::default();
        ev(&mut i, "epi", "192.0.2.7", None, true);
        assert!(visible_rows(&mut i)[0].is_connected);
        // Silent beyond the window (phone vanished without a FIN): the
        // row stays inside the TTL but must stop claiming Connected.
        for row in i.rows.values_mut() {
            row.last_session = now_secs() - (CONN_STALE_SECS + 5);
        }
        let rows = visible_rows(&mut i);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].is_connected);
        // Fresh link evidence re-asserts it.
        ev(&mut i, "epi", "192.0.2.7", None, true);
        assert!(visible_rows(&mut i)[0].is_connected);
    }

    /// Presence events (unclassified accessory chatter) refresh `last_seen`
    /// but are not link evidence: a session that went silent must still be
    /// flipped to disconnected while the phone keeps probing.
    #[test]
    fn presence_events_do_not_keep_connected_alive() {
        let mut i = Inner::default();
        ev(&mut i, "epi", "192.0.2.8", None, true);
        assert!(visible_rows(&mut i)[0].is_connected);
        let dead = now_secs() - (CONN_STALE_SECS + 5);
        i.rows.get_mut("192.0.2.8").unwrap().last_session = dead;
        // ... and keep arriving, so `last_seen` stays fresh.
        ev(&mut i, "probe", "192.0.2.8", None, false);
        let rows = visible_rows(&mut i);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].is_connected, "presence must not pin the flag");
    }

    #[test]
    fn wifi_only_mode_hides_usb_rows_from_surfaces() {
        // The product surface is Wi-Fi only unless the diagnostic adb
        // lane is enabled; bonds stay in the registry (paired.json).
        assert!(usb_hidden(&usb_row("B", true), false));
        assert!(!usb_hidden(&usb_row("B", true), true));
        let mut i = Inner::default();
        i.rows
            .insert("usb:BONDED".to_string(), usb_row("BONDED", true));
        ev(&mut i, "epi", "192.0.2.8", None, true);
        let rows = visible_rows_gated(&mut i, false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, "192-0-2-8");
        assert!(
            i.rows.contains_key("usb:BONDED"),
            "bond must persist hidden"
        );
        // Lane on: the row shows again, untouched.
        let rows = visible_rows_gated(&mut i, true);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.iter().filter(|r| r.connect_type == 128).count(), 1);
    }
}
