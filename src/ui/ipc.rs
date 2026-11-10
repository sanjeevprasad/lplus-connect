//! IPC seam for the GPUI port.
//!
//! The vendor renderer talked to Electron main through `IpcService`/
//! `ipcManager` channels; the backend answers the same channel
//! names in `src/gui/ipc.rs`. `Ipc` dispatches into that backend; with no
//! backend every channel keeps the vendor contract — `{ok:false,
//! __unhandled:"<channel>"}` — and is recorded in an audit ring exposed as
//! `ipc_registry` (same ring idea as the real backend). Test builds also
//! compile a stateful mock main (`MockMain`) that answers the served
//! channels with the identical `{ok:true,…}` contract, so the UI suite runs
//! without a phone or daemon.

use std::collections::VecDeque;
use std::str::FromStr;

#[cfg(test)]
use base64::{Engine as _, engine::general_purpose};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use strum::{Display, EnumIter, EnumString};

use crate::gui::api::{self, ConnectAck, DeviceRow};
use crate::ui::stores::connection::Device;

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
#[cfg(test)]
fn pairing_url_base() -> String {
    std::env::var("LPLUS_PAIRING_URL_BASE")
        .unwrap_or_else(|_| "heycast://synergy/start".to_string())
}

/// V1 `Synergy` bean subset fillable locally (field names and casing follow
/// the bean so the phone's GSON binds them); keys the mock cannot know stay
/// empty and the phone's pre-dial gate chain fills the rest. `Type` "4" is
/// `ConnectType::WLAN` (§5.3).
#[cfg(test)]
#[derive(Serialize)]
struct Synergy {
    #[serde(rename = "Mac")]
    mac: String,
    #[serde(rename = "BluetoothMac")]
    bluetooth_mac: String,
    #[serde(rename = "Ssid")]
    ssid: String,
    #[serde(rename = "Pwd")]
    pwd: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "ServerIp")]
    server_ip: String,
    #[serde(rename = "ServerPort")]
    server_port: String,
    #[serde(rename = "Type")]
    conn_type: String,
    #[serde(rename = "DeviceType")]
    device_type: String,
    #[serde(rename = "DeviceId")]
    device_id: String,
    #[serde(rename = "DeviceKsc")]
    device_ksc: String,
    #[serde(rename = "DeviceKscAlias")]
    device_ksc_alias: String,
    #[serde(rename = "ModelId")]
    model_id: String,
    #[serde(rename = "AdvFreq")]
    adv_freq: String,
    ver: u8,
}

#[cfg(test)]
fn pairing_qr_param(host: &str) -> String {
    let bean = Synergy {
        mac: String::new(),
        bluetooth_mac: String::new(),
        ssid: String::new(),
        pwd: String::new(),
        name: host.to_string(),
        server_ip: std::env::var("LPLUS_VIP").unwrap_or_default(),
        server_port: std::env::var("LPLUS_CSP").unwrap_or_else(|_| "10152".to_string()),
        conn_type: "4".into(),
        device_type: "SYNERGY_PC".into(),
        device_id: std::env::var("LPLUS_PC_DEVICE_ID").unwrap_or_default(),
        device_ksc: String::new(),
        device_ksc_alias: String::new(),
        model_id: String::new(),
        adv_freq: String::new(),
        ver: 1,
    };
    // Vendor GSON binds the wrapper `{"HeySynergy": <bean>}` with the
    // declared field spellings.
    #[derive(Serialize)]
    struct HeySynergy<'a> {
        #[serde(rename = "HeySynergy")]
        bean: &'a Synergy,
    }
    let wrapper = HeySynergy { bean: &bean };
    general_purpose::STANDARD.encode(serde_json::to_string(&wrapper).expect("synergy bean"))
}

/// Stateful fake vendor "main" — **test builds only**. Serves the two canned
/// demo devices over the shared channel contract so the GPUI suite (and
/// test-build launches with `LPLUS_BACKEND=off`) exercise the UI without a
/// phone or daemon. Shipped builds never compile this: dispatch goes to the
/// backend, or keeps the vendor unhandled contract.
#[cfg(test)]
#[derive(Debug, Default)]
pub struct MockMain {
    audit: VecDeque<String>,
    host_name: String,
    connected_ids: Vec<String>,
    unpaired_ids: Vec<String>,
}

#[cfg(test)]
fn mock_wire<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("mock response serializes")
}

/// Mock device row: the `DeviceRow` contract plus the demo `battery` the
/// cards render (the daemon's real rows carry no battery yet).
#[cfg(test)]
#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct MockDeviceRow {
    device_id: String,
    device_name: String,
    ip: String,
    is_connected: bool,
    is_discovered: bool,
    connect_type: u8,
    device_type: u8,
    last_seen: u64,
    last_session: u64,
    battery: u8,
}

#[cfg(test)]
#[derive(Serialize)]
struct MockDevices {
    ok: bool,
    devices: Vec<MockDeviceRow>,
}

#[cfg(test)]
#[derive(Serialize)]
struct MockPaired {
    ok: bool,
    entries: Vec<api::PairEntry>,
    devices: Vec<MockDeviceRow>,
    #[serde(rename = "pairedDevices")]
    paired_devices: Vec<MockDeviceRow>,
}

#[cfg(test)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MockHostName {
    ok: bool,
    host_name: String,
}

#[cfg(test)]
#[derive(Serialize)]
struct MockRepl {
    ok: bool,
    out: String,
}

#[cfg(test)]
#[derive(Serialize)]
struct MockCastPush {
    ok: bool,
    key: Value,
}

/// `get_general_config` demo answer shape (mock-only panel config probe).
#[cfg(test)]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MockGeneralConfigBody {
    language: String,
    launch_at_login: bool,
    auto_update: bool,
}

#[cfg(test)]
#[derive(Serialize)]
struct MockGeneralConfig {
    ok: bool,
    config: MockGeneralConfigBody,
}

#[cfg(test)]
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
                let devices: Vec<MockDeviceRow> = self
                    .connected_ids
                    .iter()
                    .filter_map(|id| Self::device_row(id.as_str()))
                    .collect();
                mock_wire(&MockDevices { ok: true, devices })
            }
            Channel::DeviceFoundList => mock_wire(&MockDevices {
                ok: true,
                devices: vec![
                    Self::mock_row("mock-phone-1", "OnePlus 12", false),
                    Self::mock_row("mock-pad-1", "OnePlus Pad 2", false),
                ],
            }),
            Channel::ConnectDevice => {
                let parsed: api::ConnectArgs = serde_json::from_value(args).unwrap_or_default();
                let id = parsed.device_id;
                if id.is_empty() {
                    return mock_wire(&ConnectAck {
                        ok: false,
                        ip: None,
                        error: Some("deviceId required".into()),
                        code_success: None,
                    });
                }
                if !id.starts_with("mock-") {
                    return mock_wire(&ConnectAck {
                        ok: false,
                        ip: None,
                        error: Some(format!("unknown device {id}")),
                        code_success: None,
                    });
                }
                if !self.connected_ids.contains(&id) {
                    self.connected_ids.push(id);
                }
                mock_wire(&ConnectAck {
                    ok: true,
                    ip: None,
                    error: None,
                    code_success: Some(true),
                })
            }
            Channel::DisconnectDevice => {
                let parsed: api::ConnectArgs = serde_json::from_value(args).unwrap_or_default();
                self.connected_ids.retain(|c| *c != parsed.device_id);
                mock_wire(&api::OkFlag::ok())
            }
            Channel::OdmfStart => mock_wire(&api::OdmfStartResp {
                ok: true,
                id: None,
                pushes: None,
                queued: None,
                listen: Some("0.0.0.0:7536".into()),
                rtp_port: Some("7537".into()),
                error: None,
            }),
            Channel::OdmfStop => mock_wire(&api::OkFlag::ok()),
            Channel::CastPush => mock_wire(&MockCastPush {
                ok: true,
                key: args.get("key").cloned().unwrap_or(Value::Null),
            }),
            Channel::GetGeneralConfig => mock_wire(&MockGeneralConfig {
                ok: true,
                config: MockGeneralConfigBody {
                    language: "en".into(),
                    launch_at_login: false,
                    auto_update: true,
                },
            }),
            Channel::SettingsGetHostName => mock_wire(&MockHostName {
                ok: true,
                host_name: self.host_name.clone(),
            }),
            Channel::SettingsSetHostName => {
                let parsed: api::SetHostNameArgs = serde_json::from_value(args).unwrap_or_default();
                let name = parsed.host_name.trim().to_string();
                if name.is_empty() {
                    mock_wire(&api::OkFlag::err("hostName required"))
                } else {
                    self.host_name = name;
                    mock_wire(&api::OkFlag::ok())
                }
            }
            Channel::LplusStatus => mock_wire(&api::LplusStatus {
                ok: true,
                backend_up: true,
                repl_port: crate::gui::cast::DEFAULT_REPL_PORT,
                repl_enabled: true,
                kms_listening: true,
                odmf: api::OdmfInfo {
                    enabled: true,
                    listen: "0.0.0.0:7536".into(),
                    rtp_port: "7537".into(),
                    out_dir: String::new(),
                    session_bin: api::FileInfo {
                        exists: false,
                        size: 0,
                        mtime_secs: None,
                    },
                    video: api::FileInfo {
                        exists: false,
                        size: 0,
                        mtime_secs: None,
                    },
                },
                rtsp: api::RtspInfo {
                    enabled: false,
                    target: String::new(),
                },
            }),
            Channel::ReplExec => {
                let parsed: api::ReplArgs = serde_json::from_value(args).unwrap_or_default();
                mock_wire(&MockRepl {
                    ok: true,
                    out: format!("(mock) {:?}", parsed.line),
                })
            }
            Channel::UploadDownloadList => mock_wire(&api::UploadDownloadList {
                ok: Some(true),
                items: Some(Vec::new()),
            }),
            Channel::GetPairingQrCode => mock_wire(&api::QrCode {
                ok: Some(true),
                code: Some(format!(
                    "{}?param={}",
                    pairing_url_base(),
                    pairing_qr_param(&self.host_name)
                )),
            }),
            Channel::IpcRegistry => mock_wire(&self.audit),
            Channel::GenericAgentEnsureRunning => mock_wire(&api::EnsureRunning {
                ok: true,
                status: "idle".into(),
            }),
            Channel::GenericAgentGetPairedDevices => {
                let rows: Vec<MockDeviceRow> = vec![
                    Self::mock_row("mock-phone-1", "OnePlus 12", false),
                    Self::mock_row("mock-pad-1", "OnePlus Pad 2", false),
                ]
                .into_iter()
                .filter(|r| !self.unpaired_ids.contains(&r.device_id))
                .collect();
                let entries = rows
                    .iter()
                    .map(|r| api::PairEntry {
                        device_id: r.device_id.clone(),
                        display_name: r.device_name.clone(),
                    })
                    .collect();
                mock_wire(&MockPaired {
                    ok: true,
                    entries,
                    devices: rows.clone(),
                    paired_devices: rows,
                })
            }
            Channel::GenericAgentGetLocalDeviceId => Value::String("mock-pc-001".into()),
            Channel::GenericAgentGetCloudBind => mock_wire(&api::CloudBind {
                ok: true,
                bound: false,
                record: None,
            }),
            Channel::GenericAgentSettingsRemoveDevice => {
                let parsed: api::RemoveDeviceArgs =
                    serde_json::from_value(args).unwrap_or_default();
                let id = parsed.device_id;
                let served = matches!(id.as_str(), "mock-phone-1" | "mock-pad-1")
                    && !self.unpaired_ids.contains(&id);
                if served {
                    self.unpaired_ids.push(id.clone());
                }
                mock_wire(&api::RemoveDeviceResp {
                    ok: served,
                    device_id: id,
                })
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
        mock_wire(&api::Unhandled::new(name))
    }

    /// Raw-name entry point for channels outside the typed set; keeps the
    /// vendor contract (typed unhandled + audit) for dynamic names.
    pub fn invoke_raw(&mut self, name: &str, args: Value) -> Value {
        match name.parse::<Channel>() {
            Ok(channel) => self.invoke(channel, args),
            Err(_) => {
                self.record_unhandled(name);
                mock_wire(&api::Unhandled::new(name))
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

    fn mock_row(id: &str, name: &str, connected: bool) -> MockDeviceRow {
        MockDeviceRow {
            device_id: id.to_string(),
            device_name: name.to_string(),
            ip: "192.0.2.3".into(),
            is_connected: connected,
            is_discovered: true,
            // P2P per vendor CONNECT_TYPE
            connect_type: 2,
            // vendor DEVICE_TYPE: PAD:10 PHONE:8
            device_type: if id.contains("pad") { 10 } else { 8 },
            last_seen: 0,
            last_session: 0,
            battery: 78,
        }
    }

    fn device_row(id: &str) -> Option<MockDeviceRow> {
        let name = match id {
            "mock-phone-1" => "OnePlus 12",
            "mock-pad-1" => "OnePlus Pad 2",
            _ => return None,
        };
        Some(Self::mock_row(id, name, true))
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

/// `POST /__ipc` request envelope (`{cmd,args}`), typed both directions
/// of the client edge.
#[derive(Serialize)]
struct IpcEnvelope<'a, A: Serialize + ?Sized> {
    cmd: &'a str,
    args: &'a A,
}

impl HttpBackend {
    fn post(&self, channel: &str, args: &Value) -> std::io::Result<Value> {
        let direct = self.post_raw(&IpcEnvelope { cmd: channel, args })?;
        if direct.get("__unhandled").is_some() {
            // Vendor renderer channels live under the backend's `ipc_invoke`
            // registry; a direct miss has no side effects, so one retry is
            // safe (managed cmds like odmf_start answer directly, once).
            let via = self.post_raw(&IpcEnvelope {
                cmd: "ipc_invoke",
                args: &api::IpcInvokeArgs {
                    channel: channel.to_string(),
                    payload: args.clone(),
                },
            })?;
            if via.get("__unhandled").is_none() {
                return Ok(via);
            }
        }
        Ok(direct)
    }

    fn post_raw<T: Serialize>(&self, body_json: &T) -> std::io::Result<Value> {
        let body = serde_json::to_string(body_json)
            .map_err(|e| std::io::Error::other(format!("bad request: {e}")))?;
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
                        serde_json::to_value(api::IpcInvokeArgs {
                            channel: channel.to_string(),
                            payload: args.clone(),
                        })
                        .expect("typed invoke args"),
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
            Self::Direct => DEFAULT_BACKEND_ADDR
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:0".parse().expect("static")),
        }
    }
}

/// `LPLUS_BACKEND` spellings that mean "no backend" (case-insensitive).
#[derive(Debug, Clone, Copy, EnumString)]
enum OffToken {
    #[strum(serialize = "off", serialize = "0", serialize = "mock")]
    Off,
}

/// Resolution of `LPLUS_BACKEND`; `None` = no backend. With `default_backend`
/// an unset value means the local daemon (launch semantics); without it, no
/// backend (test semantics: mock filler).
fn ipc_spec(spec: &str, default_backend: bool) -> Option<SocketAddr> {
    if spec.is_empty() {
        return if default_backend {
            DEFAULT_BACKEND_ADDR.parse().ok()
        } else {
            None
        };
    }
    let lowered = spec.to_lowercase();
    if OffToken::from_str(&lowered).is_ok() {
        return None;
    }
    if lowered == "1" || lowered == "auto" {
        return DEFAULT_BACKEND_ADDR.parse().ok();
    }
    spec.parse().ok()
}

/// Dispatcher behind `AppState::ipc`: prefers the real linux-client backend;
/// test builds additionally keep the mock as per-channel filler (anything
/// the backend answers `__unhandled`, or everything once the backend is
/// judged down). Shipped builds have no filler: with no backend every
/// channel keeps the vendor unhandled contract. Same `{ok,…}` shape either
/// way, so the views never learn which side served.
#[derive(Debug)]
pub struct Ipc {
    #[cfg(test)]
    mock: MockMain,
    backend: Option<Transport>,
    backend_down: bool,
    audit: VecDeque<String>,
    last_served: &'static str,
}

impl Ipc {
    fn with_backend(backend: Option<Transport>, last_served: &'static str) -> Self {
        Self {
            #[cfg(test)]
            mock: MockMain::new(),
            backend,
            backend_down: false,
            audit: VecDeque::new(),
            last_served,
        }
    }

    /// No transport and no mock filler: every dispatch is audited and
    /// answered `__unhandled`. `LPLUS_BACKEND=off` in shipped builds.
    fn detached() -> Self {
        Self::with_backend(None, "none")
    }

    /// Test-only fallback when no backend is configured (test semantics).
    #[cfg(test)]
    pub fn mock_only() -> Self {
        Self::with_backend(None, "mock")
    }

    #[cfg(test)]
    fn fallback() -> Self {
        Self::mock_only()
    }

    #[cfg(not(test))]
    fn fallback() -> Self {
        Self::detached()
    }

    pub fn http(addr: SocketAddr) -> Self {
        Self::with_backend(Some(Transport::Http(HttpBackend { addr })), "backend")
    }

    /// Merged-binary transport: dispatch straight into the in-process
    /// daemon (shared registry, no sockets).
    pub fn direct() -> Self {
        Self::with_backend(Some(Transport::Direct), "backend")
    }

    /// `LPLUS_BACKEND`: `off`/`0`/`mock` → no backend; `1`/`auto` →
    /// `127.0.0.1:1421`; `host:port` → that address. Unset means no backend
    /// here (test semantics: mock filler); real launches use
    /// [`Ipc::from_launch`], which defaults to the local daemon instead.
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
            None => Self::fallback(),
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
        #[cfg(test)]
        {
            self.last_served = "mock";
            self.mock.invoke_raw(channel, args)
        }
        #[cfg(not(test))]
        {
            // Shipped builds have no filler: keep the vendor unhandled
            // contract and audit it for the audit page / probe.
            self.last_served = "none";
            self.record(&format!("unhandled-invoke:{channel}"));
            serde_json::to_value(api::Unhandled::new(channel)).expect("unhandled is serializable")
        }
    }

    /// Which side answered the last `invoke` — "backend" or "mock".
    pub fn last_served(&self) -> &'static str {
        self.last_served
    }

    fn using_direct(&self) -> bool {
        matches!(self.backend.as_ref(), Some(Transport::Direct)) && !self.backend_down
    }

    /// Typed-args invoke: arguments are serde structs, never hand-built
    /// JSON; the reply stays `Value` (edge) for `invoke_typed` to parse.
    fn invoke_ser<S: Serialize>(&mut self, channel: Channel, args: &S) -> Value {
        let payload = serde_json::to_value(args).expect("typed args serialize");
        self.invoke(channel, payload)
    }

    /// Typed reply parse; `None` when the answer is not this channel's
    /// typed shape (unhandled marker, garbage).
    fn invoke_typed<T: DeserializeOwned>(
        &mut self,
        channel: Channel,
        args: &impl Serialize,
    ) -> Option<T> {
        let v = self.invoke_ser(channel, args);
        serde_json::from_value(v).ok()
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

    /// Ipc-level backend events followed by the mock's own audit ring
    /// (test builds only).
    pub fn audit(&self) -> Vec<String> {
        let base = self.audit.iter().cloned();
        #[cfg(test)]
        let base = base.chain(self.mock.audit());
        base.collect()
    }
}

/// Device-list wire shapes: the real backend answers some channels with a
/// bare vendor array, the mock wraps in `{ok, devices}` — one untagged
/// type accepts both.
#[derive(Deserialize)]
#[serde(untagged)]
enum DevicesWire {
    Bare(Vec<Device>),
    Wrapped { devices: Vec<Device> },
}

/// Host name answers: the daemon replies a bare string, the mock
/// `{ok, hostName}`.
#[derive(Deserialize)]
#[serde(untagged)]
enum HostNameWire {
    Bare(String),
    Wrapped {
        #[serde(rename = "hostName")]
        host_name: String,
    },
}

/// Remove ack: `{ok, deviceId}` from a served lane, or the unhandled
/// marker (which the UI treats as "already gone" = success).
#[derive(Deserialize)]
struct RemoveOutcome {
    #[serde(default)]
    ok: Option<bool>,
    #[serde(rename = "__unhandled", default)]
    unhandled: Option<String>,
}

fn rows_to_devices(rows: Vec<DeviceRow>) -> Vec<Device> {
    rows.into_iter()
        .map(|r| Device {
            device_id: r.device_id,
            device_name: r.device_name,
            ip: r.ip,
            is_connected: r.is_connected,
            is_discovered: r.is_discovered,
            is_paired: r.is_paired,
            connect_type: r.connect_type,
            device_type: r.device_type,
            // Daemon rows carry no battery reading yet.
            battery: None,
        })
        .collect()
}

/// The service surface `AppState` calls. Implementing it as a trait keeps
/// the mock/daemon contract compile-checked: any second impl (test fakes)
/// must cover every method.
pub trait ConnectApi {
    fn connected_devices(&mut self) -> Option<Vec<Device>>;
    fn paired_devices(&mut self) -> Option<Vec<Device>>;
    fn found_devices(&mut self) -> Option<Vec<Device>>;
    fn ensure_running(&mut self) -> Option<api::EnsureRunning>;
    fn local_device_id(&mut self) -> Option<String>;
    fn cloud_bound(&mut self) -> Option<bool>;
    fn qr_code(&mut self) -> Option<String>;
    /// `true` when unbound (or the lane is unhandled — already gone).
    fn remove_device(&mut self, device_id: &str) -> bool;
    fn connect(&mut self, device_id: &str, ip: &str) -> ConnectAck;
    fn disconnect(&mut self, device_id: &str, ip: &str) -> ConnectAck;
    /// Started sink address (`listen`) when ok.
    fn odmf_start(&mut self) -> Option<String>;
    fn odmf_stop(&mut self);
    fn crossfile(&mut self, category: &str) -> Option<Vec<api::CrossFile>>;
    fn run_ai_search(&mut self, query: &str);
    fn upload_items(&mut self) -> Option<Vec<api::UploadItem>>;
    fn host_name(&mut self) -> Option<String>;
    fn set_host_name(&mut self, name: &str) -> bool;
    fn last_served(&self) -> &'static str;
}

impl ConnectApi for Ipc {
    fn connected_devices(&mut self) -> Option<Vec<Device>> {
        if self.using_direct() {
            return Some(rows_to_devices(api::connected_devices()));
        }
        self.invoke_typed::<DevicesWire>(Channel::ConnectedDeviceInfoList, &api::NoArgs {})
            .map(|w| match w {
                DevicesWire::Bare(d) | DevicesWire::Wrapped { devices: d } => d,
            })
    }

    fn paired_devices(&mut self) -> Option<Vec<Device>> {
        if self.using_direct() {
            return Some(rows_to_devices(api::paired_devices().devices));
        }
        self.invoke_typed::<DevicesWire>(Channel::GenericAgentGetPairedDevices, &api::NoArgs {})
            .map(|w| match w {
                DevicesWire::Bare(d) | DevicesWire::Wrapped { devices: d } => d,
            })
    }

    fn found_devices(&mut self) -> Option<Vec<Device>> {
        if self.using_direct() {
            return Some(rows_to_devices(api::device_found_list().devices));
        }
        self.invoke_typed::<DevicesWire>(Channel::DeviceFoundList, &api::NoArgs {})
            .map(|w| match w {
                DevicesWire::Bare(d) | DevicesWire::Wrapped { devices: d } => d,
            })
    }

    fn ensure_running(&mut self) -> Option<api::EnsureRunning> {
        if self.using_direct() {
            return Some(api::ensure_running());
        }
        self.invoke_typed(Channel::GenericAgentEnsureRunning, &api::NoArgs {})
    }

    fn local_device_id(&mut self) -> Option<String> {
        if self.using_direct() {
            return Some(api::local_device_id());
        }
        self.invoke_typed(Channel::GenericAgentGetLocalDeviceId, &api::NoArgs {})
    }

    fn cloud_bound(&mut self) -> Option<bool> {
        if self.using_direct() {
            return Some(api::cloud_bind().bound);
        }
        self.invoke_typed::<api::CloudBind>(Channel::GenericAgentGetCloudBind, &api::NoArgs {})
            .map(|b| b.bound)
    }

    fn qr_code(&mut self) -> Option<String> {
        self.invoke_typed::<api::QrCode>(Channel::GetPairingQrCode, &api::NoArgs {})?
            .code
    }

    fn remove_device(&mut self, device_id: &str) -> bool {
        let args = api::RemoveDeviceArgs {
            device_id: device_id.to_string(),
            remove_state_dir: true,
        };
        if self.using_direct() {
            return api::remove_device(&args).ok;
        }
        match self.invoke_typed::<RemoveOutcome>(Channel::GenericAgentSettingsRemoveDevice, &args) {
            Some(o) => o.unhandled.is_some() || o.ok == Some(true),
            None => true,
        }
    }

    fn connect(&mut self, device_id: &str, ip: &str) -> ConnectAck {
        if self.using_direct() {
            let a = api::device_action(true, ip);
            return ConnectAck {
                ok: a.ok,
                ip: (!a.ip.is_empty()).then_some(a.ip),
                error: a.error,
                code_success: None,
            };
        }
        let args = api::ConnectArgs {
            device_id: device_id.to_string(),
            ip: ip.to_string(),
        };
        self.invoke_typed(Channel::ConnectDevice, &args)
            .unwrap_or(ConnectAck {
                ok: false,
                ip: None,
                error: Some("phone unreachable".into()),
                code_success: None,
            })
    }

    fn disconnect(&mut self, device_id: &str, ip: &str) -> ConnectAck {
        if self.using_direct() {
            let a = api::device_action(false, ip);
            return ConnectAck {
                ok: a.ok,
                ip: (!a.ip.is_empty()).then_some(a.ip),
                error: a.error,
                code_success: None,
            };
        }
        let args = api::ConnectArgs {
            device_id: device_id.to_string(),
            ip: ip.to_string(),
        };
        self.invoke_typed(Channel::DisconnectDevice, &args)
            .unwrap_or(ConnectAck {
                ok: false,
                ip: None,
                error: Some("phone unreachable".into()),
                code_success: None,
            })
    }

    fn odmf_start(&mut self) -> Option<String> {
        if self.using_direct() {
            let r = crate::gui::cast::odmf_start();
            return r.ok.then_some(r.listen).flatten();
        }
        let r = self.invoke_typed::<api::OdmfStartResp>(Channel::OdmfStart, &api::NoArgs {})?;
        r.ok.then_some(r.listen).flatten()
    }

    fn odmf_stop(&mut self) {
        self.invoke_ser(Channel::OdmfStop, &api::NoArgs {});
    }

    fn crossfile(&mut self, category: &str) -> Option<Vec<api::CrossFile>> {
        let args = api::CrossFileArgs {
            category: category.to_string(),
        };
        let resp = self.invoke_typed::<api::CrossFileListResp>(Channel::CrossFileList, &args)?;
        (resp.ok == Some(true)).then(|| resp.files.unwrap_or_default())
    }

    fn run_ai_search(&mut self, query: &str) {
        let args = api::AiSearchArgs {
            query: query.to_string(),
        };
        self.invoke_ser(Channel::AiSearchExecute, &args);
    }

    fn upload_items(&mut self) -> Option<Vec<api::UploadItem>> {
        self.invoke_typed::<api::UploadDownloadList>(Channel::UploadDownloadList, &api::NoArgs {})
            .and_then(|l| l.items)
    }

    fn host_name(&mut self) -> Option<String> {
        if self.using_direct() {
            return Some(api::host_name().host_name);
        }
        self.invoke_typed::<HostNameWire>(Channel::SettingsGetHostName, &api::NoArgs {})
            .map(|w| match w {
                HostNameWire::Bare(s) => s,
                HostNameWire::Wrapped { host_name } => host_name,
            })
    }

    fn set_host_name(&mut self, name: &str) -> bool {
        if self.using_direct() {
            return api::set_host_name(name).is_ok();
        }
        // One typed arg type; the daemon reads `name`, the mock `hostName`
        // — the alias on `SetHostNameArgs` binds both.
        let args = api::SetHostNameArgs {
            host_name: name.to_string(),
        };
        self.invoke_typed::<api::OkFlag>(Channel::SettingsSetHostName, &args)
            .is_some_and(|r| r.ok)
    }

    fn last_served(&self) -> &'static str {
        self.last_served
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
    fn typed_host_name_accepts_daemon_and_mock_shapes() {
        use crate::ui::ipc::http_tests::stub_backend;
        let addr = stub_backend(vec![("settings_get_host_name", json!("desk-1"))]);
        let mut ipc = Ipc::http(addr);
        assert_eq!(ipc.host_name().as_deref(), Some("desk-1"));

        let mut mock = Ipc::mock_only();
        assert_eq!(mock.host_name().as_deref(), Some("L+ PC"));
    }

    #[test]
    fn typed_set_host_name_requires_ok_and_falls_back() {
        use crate::ui::ipc::http_tests::stub_backend;
        let addr = stub_backend(vec![("settings_set_host_name", json!({ "ok": true }))]);
        let mut ipc = Ipc::http(addr);
        assert!(ipc.set_host_name("desk-2"));
        assert_eq!(ipc.last_served(), "backend");

        let addr = stub_backend(vec![("settings_set_host_name", json!({ "ok": false }))]);
        let mut ipc = Ipc::http(addr);
        assert!(
            !ipc.set_host_name("desk-2"),
            "ok=false must be a typed false"
        );

        // No stubbed reply: the mock answers the same typed call.
        let addr = stub_backend(vec![]);
        let mut ipc = Ipc::http(addr);
        assert!(ipc.set_host_name("desk-2"));
        assert_eq!(ipc.last_served(), "mock");
    }

    #[test]
    fn connect_api_service_surface_through_mock() {
        let mut ipc = Ipc::mock_only();
        let found = ipc.found_devices().expect("found list typed");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].device_name, "OnePlus 12");
        assert_eq!(found[0].device_type, 8);
        assert_eq!(found[0].battery, Some(78));

        let ack = ipc.connect("mock-phone-1", "");
        assert!(ack.ok && ack.code_success == Some(true) && ack.ip.is_none());
        assert!(ipc.connected_devices().is_some_and(|d| d.len() == 1));
        let bad = ipc.connect("nope", "");
        assert!(!bad.ok && bad.error.as_deref() == Some("unknown device nope"));

        assert!(ipc.remove_device("mock-pad-1"));
        assert!(ipc.paired_devices().is_some_and(|p| p.len() == 1));
        assert_eq!(ipc.local_device_id().as_deref(), Some("mock-pc-001"));
        assert_eq!(ipc.cloud_bound(), Some(false));
        assert!(ipc.ensure_running().is_some_and(|r| r.status == "idle"));
        assert!(ipc.qr_code().is_some_and(|c| c.starts_with("heycast://")));
        assert!(ipc.odmf_start().is_some_and(|l| l == "0.0.0.0:7536"));
        ipc.odmf_stop();
        assert!(ipc.upload_items().is_some_and(|i| i.is_empty()));
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
    use super::{Channel, ConnectApi, HttpBackend, Ipc, SocketAddr, ipc_spec};
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
    fn devices_wire_accepts_bare_and_wrapped_replies() {
        // Real backend: bare vendor array, partial rows.
        let addr = stub_backend(vec![(
            "get_current_connected_device_info_list",
            json!([{ "deviceId": "p1", "deviceName": "OnePlus 15", "isConnected": true }]),
        )]);
        let mut ipc = Ipc::http(addr);
        let d = ipc.connected_devices().expect("bare vendor array parses");
        assert_eq!(d[0].device_name, "OnePlus 15");
        assert!(d[0].is_connected);
        // Mock-shaped wrapper over the same channel.
        let addr = stub_backend(vec![(
            "generic_agent_get_paired_devices",
            json!({ "ok": true, "devices": [{ "deviceId": "m1" }] }),
        )]);
        let mut ipc = Ipc::http(addr);
        assert_eq!(ipc.paired_devices().map(|d| d.len()), Some(1));
    }

    #[test]
    fn crossfile_unhandled_answer_is_typed_none() {
        // Neither lane serves cross_file_list: the typed parse refuses the
        // unhandled shape (ok=false), so the caller keeps its fallback.
        let addr = stub_backend(vec![]);
        let mut ipc = Ipc::http(addr);
        assert!(ipc.crossfile("image").is_none());
    }

    #[test]
    fn http_post_roundtrips_json() {
        let addr = stub_backend(vec![("probe", json!({ "ok": true, "n": 7 }))]);
        let b = HttpBackend { addr };
        let v = b.post("probe", &json!({ "x": 1 })).unwrap();
        assert_eq!(v["n"], json!(7));
    }
}
