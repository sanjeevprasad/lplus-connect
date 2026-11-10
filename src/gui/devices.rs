//! Daemon-backed device inventory feeding the vendored renderer's device
//! list.
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
//! Rows are exposed two ways: the `/__devices` route on the loopback server
//! (the row shape is the vendor `devicesList` electron-store entry that the
//! mydevice screen renders from) and `ipc_renderer_event` bus pushes
//! (`push_search_devices_in_deivce_list`) for clients that subscribe via
//! `ipc_event_init`.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use strum::EnumString;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::sdpd::DeviceEvent;

/// Event name the mydevice card listens on (spelling is the renderer's).
const PUSH_EVENT: &str = "push_search_devices_in_deivce_list";
const PUSH_INTERVAL_SECS: u64 = 1;
/// Rows with no event for this long are dropped.
const ROW_TTL_SECS: u64 = 5 * 60;
/// Rows without an event for this long drop the discovered flag.
const DISCOVERED_WINDOW_SECS: u64 = 120;
/// A row may only claim "connected" on fresh link evidence: epi/kms
/// traffic (keepalive-re-emitted at ≤60 s cadence while a session lives)
/// or adb polls refresh `last_seen`; silence beyond this clears the flag.
/// Phones that vanish without a TCP FIN never deliver the close event, so
/// without this the GUI keeps claiming Connected forever.
const CONN_STALE_SECS: u64 = 180;
const BRIDGE_RETRY: Duration = Duration::from_secs(2);

/// Host-local addresses: the backend may report its own side of sessions
/// (`--vip`, primary NIC, loopback) — never accessories.
fn local_ips() -> &'static std::collections::HashSet<String> {
    static LOCALS: LazyLock<std::collections::HashSet<String>> = LazyLock::new(|| {
        let mut set = std::collections::HashSet::new();
        set.insert(std::env::var("LPLUS_VIP").unwrap_or_else(|_| crate::sdpd::default_vip()));
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

/// One card row, shaped to what mydevice/`devicesList` consumers read.
#[derive(Clone, Default, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceRow {
    pub device_id: String,
    pub device_name: String,
    pub ip: String,
    pub connect_type: u8,
    pub device_type: u8,
    pub is_same_account: bool,
    pub status: String,
    pub time: u64,
    pub usb_serial: Option<String>,
    pub is_discovered: bool,
    pub is_connected: bool,
    /// Persistent pairing bond (scp_sync session or a bond carried in
    /// `paired.json`; adb authorization alone is transport presence, not
    /// a bond). Paired rows survive TTL pruning and show offline.
    pub is_paired: bool,
    /// Spelling as consumed by mydevice.handleDiscoveryDevice.
    #[serde(rename = "protcol_device_id")]
    pub protcol_device_id: String,
    #[serde(rename = "lastSeen")]
    pub last_seen: u64,
    #[serde(rename = "lastSession")]
    pub last_session: u64,
}

/// NDJSON wire form of `crate::sdpd::DeviceEvent` for external-bridge
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
    rows: HashMap<String, DeviceRow>,
    /// Last persisted serialization of the paired rows (`paired-devices.json`).
    paired_saved: String,
    /// User-removed device ids (`generic_agent_settings_remove_device`,
    /// vendor `add_blacklist=1`): suppress stale adb transports from
    /// re-minting rows until a fresh scp_sync lifts the block.
    unpaired: HashSet<String>,
    /// Last persisted serialization of `unpaired` (`unpaired.json`).
    unpaired_saved: String,
    /// Bus events the renderer subscribed to (`ipc_event_init`).
    subscribed: HashSet<String>,
    dirty: bool,
    last_push: u64,
}

/// Vendor `CONNECT_TYPE` bits (renderer `Ve.gy`): LAN discovery vs adb/USB.
pub const CONNECT_TYPE_LAN: u8 = 16;
pub const CONNECT_TYPE_USB: u8 = 128;

/// The product is Wi-Fi only: adb/USB transport rows are a diagnostic
/// lane. Unless `LPLUS_USB=1` the poller never starts and every read
/// surface hides these rows (their bonds stay in `paired.json` so
/// re-enabling restores them untouched).
pub fn usb_lane_on() -> bool {
    std::env::var("LPLUS_USB").is_ok_and(|v| v == "1")
}

/// Surface-level visibility for one row (pure for tests).
fn usb_hidden(row: &DeviceRow, usb_on: bool) -> bool {
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
fn row_key(row: &DeviceRow) -> Option<String> {
    if row.connect_type == CONNECT_TYPE_USB {
        row.usb_serial.as_deref().map(|s| format!("usb:{s}"))
    } else if row.ip.is_empty() {
        None
    } else {
        Some(row.ip.clone())
    }
}

/// Load persisted paired rows; any read/parse failure means "no bonds".
fn load_paired(path: &std::path::Path) -> Vec<DeviceRow> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    match serde_json::from_str::<Vec<DeviceRow>>(&raw) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("[pair] paired bond file unusable ({}): {e}", path.display());
            Vec::new()
        }
    }
}

/// Persist paired rows when they differ from the last saved state.
fn save_paired(path: &std::path::Path, rows: &[&DeviceRow]) -> std::io::Result<()> {
    std::fs::write(path, serde_json::to_string_pretty(&rows)?.as_bytes())
}

/// Write the paired set if its serialization changed since last save.
fn sync_paired(i: &mut Inner) {
    let mut rows: Vec<&DeviceRow> = i.rows.values().filter(|r| r.is_paired).collect();
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
pub fn paired_rows() -> Vec<DeviceRow> {
    let mut i = inner().lock().expect("devices lock poisoned");
    refresh_ephemeral(&mut i);
    sync_paired(&mut i);
    let mut rows: Vec<&DeviceRow> = i
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
pub fn init() {
    INIT.call_once(init_inner);
}

fn init_inner() {
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
        let mut rows: Vec<&DeviceRow> = i.rows.values().filter(|r| r.is_paired).collect();
        rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        i.paired_saved = serde_json::to_string_pretty(&rows).unwrap_or_default();
    }
    let mut rx = crate::sdpd::subscribe_devices();
    // Own thread + tiny current-thread runtime: presence ingest must not
    // depend on the GUI runtime being up.
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
    spawn_usb_lane();
}

/// Poller hook: rate-limit pushes onto the GUI bus (consumed by the SSE
/// stream and the window alike). Event ingest is push-driven
/// (broadcast + bridge threads), so nothing else to pump. Pushes fire while
/// the renderer subscribed to the row-push event (via `ipc_event_init`) or
/// any bus consumer (SSE client, window push) could still receive them.
pub fn tick() {
    let mut i = inner().lock().expect("devices lock poisoned");
    if !i.dirty || !(i.subscribed.contains(PUSH_EVENT) || crate::gui::bus_has_listeners()) {
        return;
    }
    let now = now_secs();
    if now.saturating_sub(i.last_push) < PUSH_INTERVAL_SECS {
        return;
    }
    i.last_push = now;
    i.dirty = false;
    let mut rows: Vec<DeviceRow> = i.rows.values().cloned().collect();
    rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    drop(i);
    for row in rows {
        let frame = BusEventFrame {
            event: PUSH_EVENT,
            data: &row,
        };
        crate::gui::bus_publish(
            RENDERER_EVENT_CHANNEL,
            serde_json::to_value(&frame).unwrap_or_default(),
        );
    }
}

/// One bus row push: `{event, data}` with `data` as a JSON object (never
/// a stringified blob — consumers iterate it).
#[derive(Serialize)]
struct BusEventFrame<'a> {
    event: &'static str,
    data: &'a DeviceRow,
}

const RENDERER_EVENT_CHANNEL: &str = "ipc_renderer_event";

/// Record a bus-event subscription from `ipc_event_init`.
pub fn note_subscription(name: &str) {
    inner()
        .lock()
        .expect("devices lock poisoned")
        .subscribed
        .insert(name.to_string());
}

/// True when the renderer subscribed to `name` via `ipc_event_init`
/// (test hook: proves the bus path registered the subscription).
#[cfg(test)]
pub fn is_subscribed(name: &str) -> bool {
    inner()
        .lock()
        .expect("devices lock poisoned")
        .subscribed
        .contains(name)
}

/// Rows for `ipc_invoke`/bus routes and `/__devices`.
pub fn rows_json() -> Value {
    let mut i = inner().lock().expect("devices lock poisoned");
    serde_json::to_value(visible_rows(&mut i)).unwrap_or_else(|_| Value::Array(Vec::new()))
}

/// Serializable visible rows (sorted, ephemeral flags refreshed, stale
/// rows pruned) as typed rows — the API surface; `rows_json` is its
/// serialization boundary.
pub fn visible_device_rows() -> Vec<DeviceRow> {
    let mut i = inner().lock().expect("devices lock poisoned");
    visible_rows(&mut i)
}

fn visible_rows(i: &mut Inner) -> Vec<DeviceRow> {
    visible_rows_gated(i, usb_lane_on())
}

fn visible_rows_gated(i: &mut Inner, usb_on: bool) -> Vec<DeviceRow> {
    refresh_ephemeral(i);
    let mut rows: Vec<&DeviceRow> = i.rows.values().filter(|r| !usb_hidden(r, usb_on)).collect();
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

/// One authorized `adb devices` transport.
#[derive(Debug, PartialEq)]
pub struct AdbDevice {
    pub serial: String,
    pub model: Option<String>,
}

/// Parse `adb devices -l` output, keeping only authorized transports
/// (`device`); headers, `unauthorized`, and `offline` lines are dropped.
pub fn parse_adb_devices(out: &str) -> Vec<AdbDevice> {
    let mut devs = Vec::new();
    for line in out.lines().skip(1) {
        let line = line.trim_end_matches('\r');
        let mut toks = line.split_whitespace();
        let (Some(serial), Some(state)) = (toks.next(), toks.next()) else {
            continue;
        };
        if state != "device" || serial.is_empty() {
            continue;
        }
        let model = line
            .split_whitespace()
            .find_map(|t| t.strip_prefix("model:"))
            .map(|m| m.replace('_', " "));
        devs.push(AdbDevice {
            serial: serial.to_string(),
            model,
        });
    }
    devs
}

/// Fold the live adb transport set into the row table (pure over `Inner`).
/// USB rows are keyed `usb:<serial>` and always report connected while the
/// transport is up; vanished transports prune their rows.
fn ingest_adb(i: &mut Inner, devs: &[AdbDevice]) {
    let now = now_secs();
    let mut live: Vec<String> = Vec::with_capacity(devs.len());
    for d in devs {
        let device_id = format!("usb-{}", d.serial);
        if i.unpaired.contains(&device_id) {
            continue;
        }
        let key = format!("usb:{}", d.serial);
        live.push(key.clone());
        let row = i.rows.entry(key).or_insert_with(|| {
            tracing::info!("[usb] adb transport {} is connected", d.serial);
            DeviceRow {
                device_id: device_id.clone(),
                device_name: d.model.clone().unwrap_or_else(|| "Phone".to_string()),
                ip: String::new(),
                connect_type: CONNECT_TYPE_USB,
                device_type: 8,
                is_same_account: false,
                status: "default".into(),
                time: now,
                usb_serial: Some(d.serial.clone()),
                is_discovered: true,
                is_connected: true,
                // Transport presence alone is not a pairing bond; real
                // pairing evidence (scp_sync / persisted bond) flips this.
                is_paired: false,
                protcol_device_id: format!("usb-{}", d.serial),
                last_seen: now,
                last_session: now,
            }
        });
        row.last_seen = now;
        row.is_connected = true;
        if let Some(m) = &d.model {
            row.device_name = m.clone();
        }
    }
    let dead: Vec<String> = i
        .rows
        .keys()
        .filter(|k| k.starts_with("usb:") && !live.contains(k))
        .cloned()
        .collect();
    for key in dead {
        if i.rows.get(&key).is_some_and(|r| r.is_paired) {
            // Persistent bond: keep the row, report it offline.
            if let Some(row) = i.rows.get_mut(&key) {
                row.is_connected = false;
            }
        } else {
            i.rows.remove(&key);
            tracing::info!("[usb] adb transport gone");
        }
    }
}

/// Poll `adb devices -l` and fold results into the registry. Own thread +
/// runtime like presence ingest; missing/failing adb is silent (rows from
/// the last good poll prune away once adb answers empty).
fn spawn_usb_lane() {
    if !usb_lane_on() {
        return;
    }
    thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("usb lane runtime");
        rt.block_on(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let cmd = tokio::process::Command::new("adb")
                    .args(["devices", "-l"])
                    .output();
                let Ok(Ok(out)) =
                    tokio::time::timeout(std::time::Duration::from_secs(3), cmd).await
                else {
                    continue;
                };
                let text = String::from_utf8_lossy(&out.stdout).into_owned();
                let devs = parse_adb_devices(&text);
                let mut i = inner().lock().expect("devices lock poisoned");
                ingest_adb(&mut i, &devs);
                sync_paired(&mut i);
            }
        });
    });
}

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
    let row = i.rows.entry(ip.to_string()).or_insert_with(|| DeviceRow {
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
    i.dirty = true;
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
        .filter(|(_, r)| r.is_connected && now.saturating_sub(r.last_seen) > CONN_STALE_SECS)
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
    if !stale_conn.is_empty() {
        i.dirty = true;
    }
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
        i.dirty = true;
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

    #[test]
    fn parse_adb_devices_keeps_only_authorized() {
        let out = "List of devices attached\n\
                   FAKESERIAL000001         device product:FAKE110 model:TESTMODEL device:OP00F3L1 transport_id:1\n\
                   DEADBEEF                 unauthorized\n\
                   OFFLINE1                 offline\n";
        let devs = parse_adb_devices(out);
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].serial, "FAKESERIAL000001");
        assert_eq!(devs[0].model.as_deref(), Some("TESTMODEL"));
        assert_eq!(parse_adb_devices("List of devices attached\n"), Vec::new());
    }

    #[test]
    fn ingest_adb_upserts_and_prunes_usb_rows() {
        let mut i = Inner::default();
        let dev = AdbDevice {
            serial: "FAKESERIAL000001".into(),
            model: Some("OnePlus 15".into()),
        };
        ingest_adb(&mut i, &[dev]);
        let row = i.rows.get("usb:FAKESERIAL000001").expect("usb row minted");
        assert!(row.is_connected);
        assert!(!row.is_paired, "authorized adb alone is not a pairing bond");
        assert_eq!(row.connect_type, CONNECT_TYPE_USB);
        assert_eq!(row.usb_serial.as_deref(), Some("FAKESERIAL000001"));
        assert_eq!(row.device_name, "OnePlus 15");
        // Presence rows keep their LAN identity untouched.
        ev(&mut i, "epi", "192.0.2.2", None, false);
        assert_eq!(
            i.rows.get("192.0.2.2").map(|r| r.connect_type),
            Some(CONNECT_TYPE_LAN)
        );
        // Transport gone → presence-only usb rows prune; a paired row
        // (persisted bond) survives reporting offline; LAN rows untouched.
        i.rows.insert("usb:KEPT".to_string(), usb_row("KEPT", true));
        ingest_adb(&mut i, &[]);
        assert!(i.rows.contains_key("192.0.2.2"));
        assert!(!i.rows.contains_key("usb:FAKESERIAL000001"));
        let kept = i.rows.get("usb:KEPT").expect("paired row kept offline");
        assert!(!kept.is_connected);
        assert!(kept.is_paired);
        // Unpaired usb rows (never authorized) prune when the transport vanishes.
        i.rows
            .insert("usb:GONE".to_string(), usb_row("GONE", false));
        ingest_adb(&mut i, &[]);
        assert!(!i.rows.contains_key("usb:GONE"));
    }

    fn usb_row(serial: &str, paired: bool) -> DeviceRow {
        DeviceRow {
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
    fn remove_device_drops_rows_and_blocks_adb_resurfacing() {
        let mut i = Inner::default();
        let dev = AdbDevice {
            serial: "FAKESERIAL000001".into(),
            model: None,
        };
        ingest_adb(&mut i, &[dev]);
        assert!(i.rows.contains_key("usb:FAKESERIAL000001"));
        assert!(forget(&mut i, "usb-FAKESERIAL000001"));
        assert!(!i.rows.contains_key("usb:FAKESERIAL000001"));
        // Transport still up: the block keeps it from re-minting.
        ingest_adb(
            &mut i,
            &[AdbDevice {
                serial: "FAKESERIAL000001".into(),
                model: None,
            }],
        );
        assert!(!i.rows.contains_key("usb:FAKESERIAL000001"));
        assert!(!forget(&mut i, "never-seen"));
        // A fresh scp_sync bond lifts the block.
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
        // adb authorization alone must not persist as a bond; the bond is
        // the row carried in (or written to) `paired.json`.
        ingest_adb(
            &mut i,
            &[AdbDevice {
                serial: "FAKESERIAL000001".into(),
                model: Some("CPH2745".into()),
            }],
        );
        i.rows
            .insert("usb:BONDED".to_string(), usb_row("BONDED", true));
        ev(&mut i, "epi", "192.0.2.2", None, false);
        let rows: Vec<&DeviceRow> = i.rows.values().filter(|r| r.is_paired).collect();
        assert_eq!(rows.len(), 1, "adb presence alone is not a bond");
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
        let vip = crate::sdpd::default_vip();
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
            row.last_seen = now_secs() - (CONN_STALE_SECS + 5);
        }
        let rows = visible_rows(&mut i);
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].is_connected);
        // Fresh link evidence re-asserts it.
        ev(&mut i, "epi", "192.0.2.7", None, true);
        assert!(visible_rows(&mut i)[0].is_connected);
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

    #[test]
    fn bus_row_push_carries_object_not_stringified_json() {
        let mut rx = crate::gui::bus_subscribe();
        apply_event(&DeviceEvent {
            kind: "epi",
            ip: "192.0.2.4".into(),
            name: None,
            connected: true,
            ts_ms: 0,
        });
        tick();
        let mut found = None;
        for _ in 0..64 {
            match rx.try_recv() {
                Ok(frame) => {
                    if frame["payload"]["event"] == PUSH_EVENT {
                        found = Some(frame["payload"]["data"].clone());
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let data = found.expect("row push published on the GUI bus");
        assert!(
            data.is_object(),
            "pushed row must be a JSON object, got {data}"
        );
        assert_eq!(data["deviceId"], "192-0-2-4");
    }
}
