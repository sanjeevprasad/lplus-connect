//! Mock "main process" for the GPUI port.
//!
//! The vendor renderer talked to Electron main through `IpcService`/
//! `ipcManager` channels; the backend answers the same channel
//! names in `src/gui/ipc.rs`. To keep this UI decoupled from the backend
//! (per project direction), the UI talks to this in-process
//! mock with the identical contract: served channels answer `{ok:true,…}`,
//! anything else answers `{ok:false, __unhandled:"<channel>"}` and is
//! recorded in an audit ring exposed as `ipc_registry` — same ring idea as
//! the real backend. Swapping this for a real transport is a drop-in.

use std::collections::VecDeque;

use base64::{Engine as _, engine::general_purpose};
use serde_json::{Value, json};
use strum::{Display, EnumIter, EnumString};

/// Every IPC channel the ported UI invokes. `Display`/`FromStr` (strum)
/// carry the vendor wire names — the same ones the Electron renderer sends
/// and `linux-client/src/gui/ipc.rs` answers — so call sites are typed and
/// the mock's dispatch is compile-time exhaustive. Served channels answer
/// `{ok:true,…}`; the pending ones record into the audit ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumString, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum Channel {
    // vendor names deviate from snake_case of the variant:
    #[strum(serialize = "get_current_connected_device_info_list")]
    ConnectedDeviceInfoList,
    #[strum(serialize = "get_and_update_deviceinfo")]
    UpdateDeviceInfo,
    DeviceFoundList,
    ConnectDevice,
    DisconnectDevice,
    OdmfStart,
    OdmfStop,
    CastPush,
    GetGeneralConfig,
    SettingsGetHostName,
    SettingsSetHostName,
    LplusStatus,
    ReplExec,
    UploadDownloadList,
    IpcRegistry,
    // Dialog QR pairing payload: backend not wired yet, mock serves the
    // demo contract so the connect dialog can render a real code.
    GetPairingQrCode,
    // Pending backend channels: invoked by the stub views, audited.
    CrossFileList,
    AiSearchExecute,
    AiSearchDetail,
    RemoteControlConnect,
    RemoteControlAuth,
    HistoricalConnections,
    NoteList,
    // Assistant (generic agent) channels: served by the real backend
    // (`route_invoke` in linux-client/src/gui/ipc.rs); the mock answers the
    // same contracts with local bonds.
    GenericAgentEnsureRunning,
    GenericAgentGetPairedDevices,
    GenericAgentGetLocalDeviceId,
    GenericAgentGetCloudBind,
    GenericAgentSettingsRemoveDevice,
}

impl Channel {
    /// Whether the mock answers this channel instead of auditing it.
    pub fn is_served(self) -> bool {
        !matches!(
            self,
            Self::CrossFileList
                | Self::AiSearchExecute
                | Self::AiSearchDetail
                | Self::RemoteControlConnect
                | Self::RemoteControlAuth
                | Self::HistoricalConnections
                | Self::NoteList
        )
    }
}

const AUDIT_CAP: usize = 256;

/// QR deep link the phone's exported, autoVerify `QrCodeScanActivity`
/// accepts (PROTOCOL.md §3): `heycast://synergy/start?param=<b64
/// HeySynergy JSON>`. Override with `LPLUS_PAIRING_URL_BASE` for staging.
fn pairing_url_base() -> String {
    std::env::var("LPLUS_PAIRING_URL_BASE")
        .unwrap_or_else(|_| "heycast://synergy/start".to_string())
}

/// V1 `Synergy` bean subset fillable locally (field names and casing follow
/// the bean so the phone's GSON binds them); keys the mock cannot know stay
/// empty and the phone's pre-dial gate chain fills the rest. `Type` "4" is
/// `ConnectType::WLAN` (§5.3).
fn pairing_qr_param(host: &str) -> String {
    let bean = json!({ "HeySynergy": {
        "Mac": "",
        "BluetoothMac": "",
        "Ssid": "",
        "Pwd": "",
        "Name": host,
        "ServerIp": std::env::var("LPLUS_VIP").unwrap_or_default(),
        "ServerPort": std::env::var("LPLUS_CSP").unwrap_or_else(|_| "10152".to_string()),
        "Type": "4",
        "DeviceType": "SYNERGY_PC",
        "DeviceId": std::env::var("LPLUS_PC_DEVICE_ID").unwrap_or_default(),
        "DeviceKsc": "",
        "DeviceKscAlias": "",
        "ModelId": "",
        "AdvFreq": "",
        "ver": 1,
    }});
    general_purpose::STANDARD.encode(bean.to_string())
}

#[derive(Debug, Default)]
pub struct MockMain {
    audit: VecDeque<String>,
    host_name: String,
    connected_ids: Vec<String>,
    unpaired_ids: Vec<String>,
}

impl MockMain {
    pub fn new() -> Self {
        Self {
            audit: VecDeque::new(),
            host_name: "L+ PC".into(),
            connected_ids: Vec::new(),
            unpaired_ids: Vec::new(),
        }
    }

    /// The channel dispatch contract shared with the real backend.
    pub fn invoke(&mut self, channel: Channel, args: Value) -> Value {
        match channel {
            Channel::ConnectedDeviceInfoList | Channel::UpdateDeviceInfo => {
                let devices: Vec<Value> = self
                    .connected_ids
                    .iter()
                    .filter_map(|id| Self::device_json(id.as_str()))
                    .collect();
                json!({ "ok": true, "devices": devices })
            }
            Channel::DeviceFoundList => json!({
                "ok": true,
                "devices": [Self::mock_device("mock-phone-1", "OnePlus 12", false),
                             Self::mock_device("mock-pad-1", "OnePlus Pad 2", false)]
            }),
            Channel::ConnectDevice => {
                let Some(id) = args.get("deviceId").and_then(Value::as_str) else {
                    return json!({ "ok": false, "error": "deviceId required" });
                };
                if !id.starts_with("mock-") {
                    return json!({ "ok": false, "error": format!("unknown device {id}") });
                }
                if !self.connected_ids.contains(&id.to_string()) {
                    self.connected_ids.push(id.to_string());
                }
                json!({ "ok": true, "code_success": true })
            }
            Channel::DisconnectDevice => {
                if let Some(id) = args.get("deviceId").and_then(Value::as_str) {
                    self.connected_ids.retain(|c| c != id);
                }
                json!({ "ok": true })
            }
            Channel::OdmfStart => {
                json!({ "ok": true, "listen": "0.0.0.0:7536", "rtp_port": "7537" })
            }
            Channel::OdmfStop => json!({ "ok": true }),
            Channel::CastPush => {
                json!({ "ok": true, "key": args.get("key").cloned().unwrap_or(Value::Null) })
            }
            Channel::GetGeneralConfig => json!({
                "ok": true,
                "config": { "language": "en", "launchAtLogin": false, "autoUpdate": true }
            }),
            Channel::SettingsGetHostName => json!({ "ok": true, "hostName": self.host_name }),
            Channel::SettingsSetHostName => match args.get("hostName").and_then(Value::as_str) {
                Some(name) if !name.trim().is_empty() => {
                    self.host_name = name.trim().to_string();
                    json!({ "ok": true })
                }
                _ => json!({ "ok": false, "error": "hostName required" }),
            },
            Channel::LplusStatus => json!({
                "ok": true,
                "backend_up": true,
                "kms_listening": true,
                "odmf": { "enabled": true, "listen": "0.0.0.0:7536" }
            }),
            Channel::ReplExec => {
                json!({ "ok": true, "out": format!("(mock) {:#}", args.get("line").cloned().unwrap_or(Value::Null)) })
            }
            Channel::UploadDownloadList => json!({ "ok": true, "items": [] }),
            Channel::GetPairingQrCode => json!({
                "ok": true,
                "code": format!("{}?param={}", pairing_url_base(), pairing_qr_param(&self.host_name)),
            }),
            Channel::IpcRegistry => Value::Array(self.audit.iter().map(|e| json!(e)).collect()),
            Channel::GenericAgentEnsureRunning => json!({ "ok": true, "status": "idle" }),
            Channel::GenericAgentGetPairedDevices => {
                let rows = vec![
                    Self::mock_device("mock-phone-1", "OnePlus 12", false),
                    Self::mock_device("mock-pad-1", "OnePlus Pad 2", false),
                ]
                .into_iter()
                .filter(|r| {
                    !self
                        .unpaired_ids
                        .iter()
                        .any(|u| Some(u.as_str()) == r["deviceId"].as_str())
                })
                .collect::<Vec<_>>();
                let entries: Vec<Value> = rows
                    .iter()
                    .map(|r| {
                        json!({
                            "deviceId": r["deviceId"],
                            "displayName": r["deviceName"],
                        })
                    })
                    .collect();
                json!({
                    "ok": true,
                    "entries": entries,
                    "devices": rows.clone(),
                    "pairedDevices": rows,
                })
            }
            Channel::GenericAgentGetLocalDeviceId => json!("mock-pc-001"),
            Channel::GenericAgentGetCloudBind => {
                json!({ "ok": true, "bound": false, "record": null })
            }
            Channel::GenericAgentSettingsRemoveDevice => {
                let id = args.get("device_id").and_then(Value::as_str).unwrap_or("");
                let served = matches!(id, "mock-phone-1" | "mock-pad-1")
                    && !self.unpaired_ids.iter().any(|u| u == id);
                if served {
                    self.unpaired_ids.push(id.to_string());
                }
                json!({ "ok": served, "deviceId": id })
            }
            // Pending channels keep the vendor contract: typed unhandled + audit.
            pending => {
                debug_assert!(!pending.is_served());
                self.unhandled(pending)
            }
        }
    }

    /// Vendor-shaped unhandled reply for a pending channel.
    fn unhandled(&mut self, channel: Channel) -> Value {
        let name = channel.to_string();
        self.record_unhandled(&name);
        json!({ "ok": false, "__unhandled": name })
    }

    /// Raw-name entry point for channels outside the typed set; keeps the
    /// vendor contract (typed unhandled + audit) for dynamic names.
    pub fn invoke_raw(&mut self, name: &str, args: Value) -> Value {
        match name.parse::<Channel>() {
            Ok(channel) => self.invoke(channel, args),
            Err(_) => {
                self.record_unhandled(name);
                json!({ "ok": false, "__unhandled": name })
            }
        }
    }

    fn record_unhandled(&mut self, channel: &str) {
        let entry = format!("unhandled-invoke:{channel}");
        if self.audit.len() == AUDIT_CAP {
            self.audit.pop_front();
        }
        self.audit.push_back(entry);
    }

    pub fn audit(&self) -> Vec<String> {
        self.audit.iter().cloned().collect()
    }

    fn mock_device(id: &str, name: &str, connected: bool) -> Value {
        json!({
            "deviceId": id,
            "deviceName": name,
            "ip": "192.0.2.3",
            "isConnected": connected,
            "isDiscovered": true,
            "connectType": 2,   // P2P per vendor CONNECT_TYPE
            "deviceType": if id.contains("pad") { 10 } else { 8 }, // PAD:10 PHONE:8
            "lastSeen": 0,
            "lastSession": 0,
            "battery": 78,
        })
    }

    fn device_json(id: &str) -> Option<Value> {
        let name = match id {
            "mock-phone-1" => "OnePlus 12",
            "mock-pad-1" => "OnePlus Pad 2",
            _ => return None,
        };
        Some(Self::mock_device(id, name, true))
    }
}

// ---------------------------------------------------------------- transport --

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// Loopback `POST /__ipc` client for the linux-client GUI server
/// (`src/gui/server.rs` + `src/gui/ipc.rs` in the backend crate). Hand-rolled
/// HTTP/1.1 (`Connection: close`, read to EOF) on purpose: a local pipe does
/// not justify an http dependency, and the reply is the same `{ok,…}` JSON
/// the mock answers with.
#[derive(Debug, Clone, Copy)]
pub struct HttpBackend {
    pub addr: SocketAddr,
}

impl HttpBackend {
    fn post(&self, channel: &str, args: &Value) -> std::io::Result<Value> {
        let direct = self.post_raw(json!({ "cmd": channel, "args": args }))?;
        if direct.get("__unhandled").is_some() {
            // Vendor renderer channels live under the backend's `ipc_invoke`
            // registry; a direct miss has no side effects, so one retry is
            // safe (managed cmds like odmf_start answer directly, once).
            let via = self.post_raw(json!({
                "cmd": "ipc_invoke",
                "args": { "channel": channel, "payload": args }
            }))?;
            if via.get("__unhandled").is_none() {
                return Ok(via);
            }
        }
        Ok(direct)
    }

    fn post_raw(&self, body_json: Value) -> std::io::Result<Value> {
        let body = body_json.to_string();
        let req = format!(
            "POST /__ipc HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.addr,
            body.len()
        );
        let mut s = TcpStream::connect_timeout(&self.addr, Duration::from_millis(400))
            .map_err(|e| std::io::Error::other(format!("connect {}: {e}", self.addr)))?;
        s.set_write_timeout(Some(Duration::from_millis(750)))?;
        s.set_read_timeout(Some(Duration::from_millis(1500)))?;
        s.write_all(req.as_bytes())?;
        s.flush()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf)?;
        let head = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| std::io::Error::other("no http head"))?;
        if !buf[..head].starts_with(b"HTTP/1.1 200") {
            return Err(std::io::Error::other("http status not 200"));
        }
        serde_json::from_slice(&buf[head + 4..])
            .map_err(|e| std::io::Error::other(format!("bad json: {e}")))
    }
}

/// Loopback address a running `lplus` daemon listens on.
const DEFAULT_BACKEND_ADDR: &str = "127.0.0.1:1421";

/// Backend a live `Ipc` dispatches into before falling back to the mock.
#[derive(Debug)]
enum Transport {
    Http(HttpBackend),
    /// Same-process daemon (merged binary): call `gui::ipc::dispatch`
    /// directly — shared state, same `{cmd,args}` → `{ok,…}` contract,
    /// same `ipc_invoke` escalation for vendor renderer channels.
    Direct,
}

impl Transport {
    fn post(&self, channel: &str, args: &Value) -> std::io::Result<Value> {
        match self {
            Self::Http(b) => b.post(channel, args),
            Self::Direct => {
                let direct = crate::gui::ipc::dispatch(channel, args.clone());
                if direct.get("__unhandled").is_some() {
                    let via = crate::gui::ipc::dispatch(
                        "ipc_invoke",
                        json!({ "channel": channel, "payload": args }),
                    );
                    if via.get("__unhandled").is_none() {
                        return Ok(via);
                    }
                }
                Ok(direct)
            }
        }
    }

    fn addr(&self) -> SocketAddr {
        match self {
            Self::Http(b) => b.addr,
            Self::Direct => DEFAULT_BACKEND_ADDR.parse().unwrap_or_else(|_| "127.0.0.1:0".parse().expect("static")),
        }
    }
}

/// Resolution of `LPLUS_BACKEND`; `None` = mock only. With `default_backend`
/// an unset value means the local daemon (launch semantics); without it,
/// mock (test semantics).
fn ipc_spec(spec: &str, default_backend: bool) -> Option<SocketAddr> {
    if spec.is_empty() {
        return if default_backend {
            DEFAULT_BACKEND_ADDR.parse().ok()
        } else {
            None
        };
    }
    let lowered = spec.to_lowercase();
    if lowered == "off" || lowered == "0" || lowered == "mock" {
        return None;
    }
    if lowered == "1" || lowered == "auto" {
        return DEFAULT_BACKEND_ADDR.parse().ok();
    }
    spec.parse().ok()
}

/// Dispatcher behind `AppState::ipc`: prefers the real linux-client backend
/// and keeps the mock as per-channel filler (anything the backend answers
/// `__unhandled`, or everything once the backend is judged down). Same
/// `{ok,…}` contract either way, so the views never learn which side served.
#[derive(Debug)]
pub struct Ipc {
    mock: MockMain,
    backend: Option<Transport>,
    backend_down: bool,
    audit: VecDeque<String>,
    last_served: &'static str,
}

impl Default for Ipc {
    fn default() -> Self {
        Self::mock_only()
    }
}

impl Ipc {
    pub fn mock_only() -> Self {
        Self {
            mock: MockMain::new(),
            backend: None,
            backend_down: false,
            audit: VecDeque::new(),
            last_served: "mock",
        }
    }

    pub fn http(addr: SocketAddr) -> Self {
        Self {
            mock: MockMain::new(),
            backend: Some(Transport::Http(HttpBackend { addr })),
            backend_down: false,
            audit: VecDeque::new(),
            last_served: "mock",
        }
    }

    /// Merged-binary transport: dispatch straight into the in-process
    /// daemon (shared registry, no sockets).
    pub fn direct() -> Self {
        Self {
            mock: MockMain::new(),
            backend: Some(Transport::Direct),
            backend_down: false,
            audit: VecDeque::new(),
            last_served: "mock",
        }
    }

    /// `LPLUS_BACKEND`: `off`/`0`/`mock` → mock only; `1`/`auto` →
    /// `127.0.0.1:1421`; `host:port` → that address. Unset means mock only
    /// here (test default); real launches use [`Ipc::from_launch`], which
    /// defaults to the local daemon instead.
    pub fn from_env() -> Self {
        Self::from_spec(false)
    }

    /// Transport for real app launches: unset means "use the local daemon"
    /// so a running `lplus` is attached by default and already-connected /
    /// paired devices render at startup.
    pub fn from_launch() -> Self {
        Self::from_spec(true)
    }

    fn from_spec(default_backend: bool) -> Self {
        let spec = std::env::var("LPLUS_BACKEND").unwrap_or_default();
        match ipc_spec(spec.trim(), default_backend) {
            Some(addr) => Self::http(addr),
            None => Self::mock_only(),
        }
    }

    pub fn invoke(&mut self, channel: Channel, args: Value) -> Value {
        self.dispatch(&channel.to_string(), args)
    }

    /// Dynamic names (e.g. `settings_open_<section>`): typed channels route
    /// through `invoke`; anything else keeps the audit contract.
    pub fn invoke_raw(&mut self, name: &str, args: Value) -> Value {
        match name.parse::<Channel>() {
            Ok(channel) => self.invoke(channel, args),
            Err(_) => self.dispatch(name, args),
        }
    }

    fn dispatch(&mut self, channel: &str, args: Value) -> Value {
        if let Some(backend) = self.backend.as_ref()
            && !self.backend_down
        {
            match backend.post(channel, &args) {
                Ok(v) => {
                    if v.get("__unhandled").is_some() {
                        self.record(&format!("backend-unhandled:{channel}"));
                    } else {
                        self.record(&format!("backend-invoke:{channel}"));
                        self.last_served = "backend";
                        return v;
                    }
                }
                Err(e) => {
                    self.backend_down = true;
                    self.record(&format!("backend-down:{e}"));
                }
            }
        }
        self.last_served = "mock";
        self.mock.invoke_raw(channel, args)
    }

    /// Which side answered the last `invoke` — "backend" or "mock".
    pub fn last_served(&self) -> &'static str {
        self.last_served
    }

    /// `Some` while the real backend is configured and healthy.
    pub fn backend_addr(&self) -> Option<SocketAddr> {
        if self.backend_down {
            None
        } else {
            self.backend.as_ref().map(|b| b.addr())
        }
    }

    fn record(&mut self, entry: &str) {
        if self.audit.len() == AUDIT_CAP {
            self.audit.pop_front();
        }
        self.audit.push_back(entry.to_string());
    }

    /// Ipc-level backend events followed by the mock's own audit ring.
    pub fn audit(&self) -> Vec<String> {
        let mut out: Vec<String> = self.audit.iter().cloned().collect();
        out.extend(self.mock.audit());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn served_channel_answers_ok() {
        let mut m = MockMain::new();
        let v = m.invoke(Channel::LplusStatus, Value::Null);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["backend_up"], json!(true));
    }

    #[test]
    fn unknown_channel_is_typed_unhandled_and_audited() {
        let mut m = MockMain::new();
        let v = m.invoke_raw("get_phone_screen_data", Value::Null);
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["__unhandled"], json!("get_phone_screen_data"));
        let ring = m.invoke(Channel::IpcRegistry, Value::Null);
        assert!(
            ring.as_array()
                .unwrap()
                .iter()
                .any(|e| e.as_str() == Some("unhandled-invoke:get_phone_screen_data"))
        );
    }

    #[test]
    fn connect_then_list_shows_device_connected() {
        let mut m = MockMain::new();
        let ok = m.invoke(
            Channel::ConnectDevice,
            json!({ "deviceId": "mock-phone-1" }),
        );
        assert_eq!(ok["ok"], json!(true));
        let list = m.invoke(Channel::ConnectedDeviceInfoList, Value::Null);
        let devices = list["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0]["deviceName"], json!("OnePlus 12"));
        assert_eq!(devices[0]["isConnected"], json!(true));
    }

    #[test]
    fn connect_requires_known_device() {
        let mut m = MockMain::new();
        let bad = m.invoke(Channel::ConnectDevice, json!({ "deviceId": "ghost" }));
        assert_eq!(bad["ok"], json!(false));
        let missing = m.invoke(Channel::ConnectDevice, json!({}));
        assert_eq!(missing["ok"], json!(false));
    }

    #[test]
    fn disconnect_clears_list() {
        let mut m = MockMain::new();
        m.invoke(Channel::ConnectDevice, json!({ "deviceId": "mock-pad-1" }));
        m.invoke(
            Channel::DisconnectDevice,
            json!({ "deviceId": "mock-pad-1" }),
        );
        let list = m.invoke(Channel::ConnectedDeviceInfoList, Value::Null);
        assert!(list["devices"].as_array().unwrap().is_empty());
    }

    #[test]
    fn host_name_round_trips_with_validation() {
        let mut m = MockMain::new();
        assert_eq!(
            m.invoke(Channel::SettingsSetHostName, json!({ "hostName": "  " }))["ok"],
            json!(false)
        );
        assert_eq!(
            m.invoke(
                Channel::SettingsSetHostName,
                json!({ "hostName": "desk-box" })
            )["ok"],
            json!(true)
        );
        assert_eq!(
            m.invoke(Channel::SettingsGetHostName, Value::Null)["hostName"],
            json!("desk-box")
        );
    }

    #[test]
    fn found_list_carries_vendor_device_shape() {
        let mut m = MockMain::new();
        let v = m.invoke(Channel::DeviceFoundList, Value::Null);
        let devices = v["devices"].as_array().unwrap();
        assert_eq!(devices.len(), 2);
        // vendor DEVICE_TYPE: PHONE=8, PAD=10; CONNECT_TYPE P2P=2
        assert_eq!(devices[0]["deviceType"], json!(8));
        assert_eq!(devices[1]["deviceType"], json!(10));
        assert_eq!(devices[0]["connectType"], json!(2));
    }

    #[test]
    fn every_variant_matches_the_mock_behavior() {
        // Drift guard: is_served() and the invoke dispatch can no longer
        // disagree silently — this test is the single checkpoint.
        for channel in <Channel as strum::IntoEnumIterator>::iter() {
            let mut m = MockMain::new();
            let v = m.invoke(channel, Value::Null);
            if channel.is_served() {
                // Served channels must never fall through to the audit
                // path; arg-dependent ok:false (e.g. connect without id)
                // stays a behavior concern, covered by the tests above.
                assert!(v.get("__unhandled").is_none(), "{channel} must not audit");
            } else {
                assert_eq!(v["ok"], json!(false), "{channel} pending");
                assert_eq!(v["__unhandled"], json!(channel.to_string()));
            }
        }
    }

    #[test]
    fn wire_names_round_trip() {
        for channel in <Channel as strum::IntoEnumIterator>::iter() {
            let name = channel.to_string();
            assert_eq!(
                name.parse::<Channel>().ok(),
                Some(channel),
                "{name} must parse back"
            );
            assert!(
                name.is_ascii() && !name.chars().any(char::is_uppercase),
                "{name} wire-shaped"
            );
        }
        assert_eq!(
            Channel::ConnectedDeviceInfoList.to_string(),
            "get_current_connected_device_info_list"
        );
        assert_eq!(Channel::IpcRegistry.to_string(), "ipc_registry");
    }

    #[test]
    fn audit_ring_is_bounded_and_fifo() {
        let mut m = MockMain::new();
        for i in 0..(AUDIT_CAP + 10) {
            m.invoke_raw(&format!("ch_{i}"), Value::Null);
        }
        let ring = m.audit();
        assert_eq!(ring.len(), AUDIT_CAP);
        assert_eq!(ring.first().unwrap(), "unhandled-invoke:ch_10");
    }
}

#[cfg(test)]
pub(crate) mod http_tests {
    use super::{Channel, HttpBackend, Ipc, SocketAddr, ipc_spec};
    use serde_json::{Value, json};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    #[test]
    fn launch_defaults_to_backend_while_tests_default_to_mock() {
        let def: Option<SocketAddr> = "127.0.0.1:1421".parse().ok();
        assert_eq!(ipc_spec("", false), None);
        assert_eq!(ipc_spec("", true), def);
        for off in ["off", "OFF", "0", "mock"] {
            assert_eq!(ipc_spec(off, true), None, "{off} must force mock");
        }
        assert_eq!(ipc_spec("1", false), def);
        assert_eq!(ipc_spec("auto", false), def);
        assert_eq!(
            ipc_spec("127.0.0.1:9999", false),
            "127.0.0.1:9999".parse().ok()
        );
        assert_eq!(ipc_spec("garbage", true), None);
    }

    /// Loopback stub of the backend `POST /__ipc` seam: answers canned
    /// replies per registry key, mirrors `dispatch_device`'s `ip` keying,
    /// and reports every other channel `__unhandled` — exactly the
    /// behaviour mix the hybrid dispatcher must survive.
    pub(crate) fn stub_backend(replies: Vec<(&'static str, Value)>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            loop {
                let Ok((mut stream, _)) = l.accept() else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let mut len = 0usize;
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.strip_prefix("Content-Length: ") {
                        len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; len];
                let _ = reader.read_exact(&mut body);
                let parsed = serde_json::from_slice::<Value>(&body).ok();
                let cmd = parsed
                    .as_ref()
                    .and_then(|v| v.get("cmd").and_then(Value::as_str).map(str::to_string))
                    .unwrap_or_default();
                // Mirror the backend's two registries: top-level managed cmds
                // and the `ipc_invoke` vendor-channel registry.
                let key = if cmd == "ipc_invoke" {
                    let inner = parsed
                        .as_ref()
                        .and_then(|v| v.get("args")?.get("channel")?.as_str().map(str::to_string))
                        .unwrap_or_default();
                    format!("via:{inner}")
                } else {
                    cmd
                };
                // Mirror the backend's `dispatch_device` exactly: vendor
                // Connect/Disconnect key on payload.ip and ack as queued.
                let reply = match key.as_str() {
                    "via:connect_device" | "via:disconnect_device" => {
                        let ip = parsed
                            .as_ref()
                            .and_then(|v| {
                                v.get("args")?
                                    .get("payload")?
                                    .get("ip")?
                                    .as_str()
                                    .map(str::to_string)
                            })
                            .unwrap_or_default();
                        json!({
                            "ok": !ip.is_empty(),
                            "ip": ip,
                            "error": if ip.is_empty() { json!("missing ip") } else { Value::Null },
                        })
                    }
                    _ => replies
                        .iter()
                        .find(|(c, _)| *c == key)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_else(|| json!({ "ok": false, "__unhandled": key })),
                };
                let payload = serde_json::to_vec(&reply).unwrap();
                let mut out = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                Connection: close\r\n\r\n"
                    .to_vec();
                out.extend(payload);
                let _ = stream.write_all(&out);
            }
        });
        addr
    }

    #[test]
    fn backend_serves_channels_it_handles() {
        let addr = stub_backend(vec![(
            "lplus_status",
            json!({ "ok": true, "backend_up": true, "real": true }),
        )]);
        let mut ipc = Ipc::http(addr);
        let v = ipc.invoke(Channel::LplusStatus, Value::Null);
        assert_eq!(v["real"], json!(true), "must come from the backend");
        assert!(
            ipc.audit()
                .iter()
                .any(|e| e == "backend-invoke:lplus_status")
        );
        assert!(ipc.backend_addr().is_some());
    }

    #[test]
    fn connect_device_keys_on_ip_like_the_backend_contract() {
        let addr = stub_backend(vec![]);
        let mut ipc = Ipc::http(addr);
        // Vendor Connect/Disconnect are handled by the backend, so the
        // "missing ip" failure must surface from the backend, not be
        // papered over by the mock.
        let bad = ipc.invoke(Channel::ConnectDevice, json!({ "deviceId": "p1" }));
        assert_eq!(bad["ok"], json!(false), "{bad}");
        assert_eq!(bad["error"], json!("missing ip"));
        assert_eq!(ipc.last_served(), "backend");
        let queued = ipc.invoke(
            Channel::ConnectDevice,
            json!({ "deviceId": "p1", "ip": "192.0.2.10" }),
        );
        assert_eq!(queued["ok"], json!(true));
        assert_eq!(queued["ip"], json!("192.0.2.10"));
    }

    #[test]
    fn vendor_channel_escalates_via_ipc_invoke() {
        let addr = stub_backend(vec![(
            "via:device_found_list",
            json!({ "ok": true, "devices": [{ "deviceName": "RealPhone" }] }),
        )]);
        let mut ipc = Ipc::http(addr);
        let v = ipc.invoke(Channel::DeviceFoundList, Value::Null);
        assert_eq!(v["devices"][0]["deviceName"], json!("RealPhone"));
        assert!(
            ipc.audit()
                .iter()
                .any(|e| e == "backend-invoke:device_found_list")
        );
    }

    #[test]
    fn unhandled_on_backend_falls_back_to_mock() {
        let addr = stub_backend(vec![]);
        let mut ipc = Ipc::http(addr);
        let v = ipc.invoke(Channel::DeviceFoundList, Value::Null);
        assert_eq!(v["devices"].as_array().unwrap().len(), 2, "mock filler");
        assert!(
            ipc.audit()
                .iter()
                .any(|e| e == "backend-unhandled:device_found_list")
        );
    }

    #[test]
    fn dead_backend_degrades_to_mock_once() {
        // Bound then drop: connect() now refuses.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let mut ipc = Ipc::http(addr);
        let v = ipc.invoke(Channel::LplusStatus, Value::Null);
        assert_eq!(v["ok"], json!(true), "mock answers after the failure");
        assert!(ipc.audit().iter().any(|e| e.starts_with("backend-down:")));
        assert!(ipc.backend_addr().is_none(), "marked down, stops retrying");
    }

    #[test]
    fn http_post_roundtrips_json() {
        let addr = stub_backend(vec![("probe", json!({ "ok": true, "n": 7 }))]);
        let b = HttpBackend { addr };
        let v = b.post("probe", &json!({ "x": 1 })).unwrap();
        assert_eq!(v["n"], json!(7));
    }
}
