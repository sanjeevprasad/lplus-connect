//! Typed daemon API — the single source of truth for every channel shape
//! the in-process consumers (GPUI window) and the `/__ipc` router speak.
//!
//! Rules of the surface:
//! * Arg/response shapes live here as serde structs (`Serialize` for
//!   callers, `Deserialize` for handlers); the vendor `{ok,…}` wire shapes
//! * Handlers in `ipc.rs`/`cast.rs` build these types; `Value` survives
//!   only at the two edges — `POST /__ipc` (untrusted external debug
//!   clients) and the HTTP transport in `ui/ipc.rs` — plus test fixtures.
//! * Strictness is declarative: typed fields + `#[serde(default)]` where
//!   the vendor tolerates absence + `alias` for dual vendor key spellings.
//!   Unknown keys are ignored (vendored renderers ship extras); the wire
//!   tests in `ipc.rs`/`ui/ipc.rs` pin the shapes.

use serde::{Deserialize, Serialize};

pub use crate::gui::devices::DeviceRow;

// ------------------------------------------------------------------ args --

/// `settings_set_host_name` — vendor sends `name` (daemon) or `hostName`
/// (panel/mock); both spellings bind to one typed field.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetHostNameArgs {
    #[serde(alias = "name", default)]
    pub host_name: String,
}

/// Connect/Disconnect/KMS args: `{ip}` object or a bare IP string (both
/// are live vendor shapes).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IpPayload {
    Plain(String),
    Fields {
        #[serde(rename = "ip", default)]
        ip: String,
    },
}

impl Default for IpPayload {
    fn default() -> Self {
        Self::Plain(String::new())
    }
}

impl IpPayload {
    pub fn ip(&self) -> &str {
        match self {
            Self::Plain(s) => s,
            Self::Fields { ip } => ip,
        }
    }
}

/// Renderer Connect/Dispatch payload (mock keys on `deviceId`, the daemon
/// lanes key on `ip`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectArgs {
    #[serde(rename = "deviceId", default)]
    pub device_id: String,
    #[serde(default)]
    pub ip: String,
}

/// `generic_agent_settings_remove_device` — vendor UNBIND payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemoveDeviceArgs {
    #[serde(rename = "device_id", alias = "deviceId", default)]
    pub device_id: String,
    #[serde(rename = "removeStateDir", default)]
    pub remove_state_dir: bool,
}

/// `cast_push {key, value}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CastPushArgs {
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub value: String,
}

/// `repl_exec {line}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplArgs {
    #[serde(default)]
    pub line: String,
}

/// `ipc_invoke {channel, payload}` envelope; `payload` stays `Value` —
/// it is re-typed by the per-channel handler.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpcInvokeArgs {
    #[serde(default)]
    pub channel: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// `ipc_send {channel}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SendArgs {
    #[serde(default)]
    pub channel: String,
}

/// `console_log {batch:[{level,text}]}`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConsoleLogArgs {
    #[serde(default)]
    pub batch: Option<Vec<ConsoleLine>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConsoleLine {
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
}

/// `open_external {url}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpenExternalArgs {
    #[serde(default)]
    pub url: String,
}

/// `crossfile_list {category}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossFileArgs {
    #[serde(default)]
    pub category: String,
}

/// `ai_search_execute {query}`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiSearchArgs {
    #[serde(default)]
    pub query: String,
}

/// Payload for channels that take nothing (`null` on the wire).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct NoArgs {}

// ------------------------------------------------------------- responses --

/// `{ok:false, __unhandled:"<name>", error:"unhandled:<name>"}` — the
/// vendor unhandled contract (boot must never hang on a missing handler).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unhandled {
    pub ok: bool,
    #[serde(rename = "__unhandled")]
    pub unhandled: String,
    pub error: String,
}

impl Unhandled {
    pub fn new(channel: impl Into<String>) -> Self {
        let unhandled = channel.into();
        let error = format!("unhandled:{unhandled}");
        Self {
            ok: false,
            unhandled,
            error,
        }
    }
}

/// `{ok:true}` ack (bus confirms, stop lanes, host-name sets).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkFlag {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl OkFlag {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }
    pub fn err(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
        }
    }
}

/// `generic_agent_get_paired_devices`: persistent pairing bonds; consumers
/// read `entries[]` / `pairedDevices` (gaPairBoundStatus.js).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedDevices {
    pub ok: bool,
    pub entries: Vec<PairEntry>,
    pub devices: Vec<DeviceRow>,
    #[serde(rename = "pairedDevices")]
    pub paired_devices: Vec<DeviceRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairEntry {
    pub device_id: String,
    pub display_name: String,
}

/// `device_found_list` (DiscoveredDevices contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFoundList {
    pub ok: bool,
    pub devices: Vec<DeviceRow>,
}

/// `generic_agent_get_cloud_bind`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudBind {
    pub ok: bool,
    pub bound: bool,
    /// Bind record when bound; always `null` while unbound.
    pub record: Option<CloudRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudRecord {}

/// `generic_agent_ensure_running`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnsureRunning {
    pub ok: bool,
    pub status: String,
}

/// `generic_agent_settings_remove_device` reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveDeviceResp {
    pub ok: bool,
    pub device_id: String,
}

/// `connect_device`/`disconnect_device`/`kms_bootstrap` acks: `error` is
/// omitted when the command queued.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAction {
    pub ok: bool,
    #[serde(default)]
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

/// Renderer Connect/Disconnect ack union: the mock answers
/// `{ok:true, code_success}`, the backend queues `{ok, ip[, error]}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectAck {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code_success: Option<bool>,
}

/// `settings_set_host_name` reply (`name` on success, `error` on refusal).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetHostNameResp {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `lplus_sidecar_status` (`logTailing` is the historical name for the
/// presence lane).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SidecarStatus {
    pub running: bool,
    pub log_tailing: String,
}

/// `repl_exec` reply: `out` on success, `error` on refusal/unreachability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplExec {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub out: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `cast_push` reply: injected frame report plus the live sink roster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastPushResp {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repl_out: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `odmf_start` reply: the two-push trigger report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdmfStartResp {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pushes: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued: Option<Vec<bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtp_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `lplus_status` snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LplusStatus {
    pub ok: bool,
    pub backend_up: bool,
    pub repl_port: u16,
    pub repl_enabled: bool,
    pub kms_listening: bool,
    pub odmf: OdmfInfo,
    pub rtsp: RtspInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OdmfInfo {
    pub enabled: bool,
    pub listen: String,
    pub rtp_port: String,
    pub out_dir: String,
    pub session_bin: FileInfo,
    pub video: FileInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtspInfo {
    pub enabled: bool,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub exists: bool,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtime_secs: Option<u64>,
}

/// `crossfile_list` reply (backend lane pending; mock/daemon typed shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFileListResp {
    #[serde(default)]
    pub ok: Option<bool>,
    #[serde(default)]
    pub files: Option<Vec<CrossFile>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossFile {
    pub name: String,
    pub size: u64,
}

/// `upload_download_list` reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadDownloadList {
    #[serde(default)]
    pub ok: Option<bool>,
    #[serde(default)]
    pub items: Option<Vec<UploadItem>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadItem {
    pub id: String,
    pub name: String,
    pub size: u64,
    #[serde(default)]
    pub direction: Option<String>,
}

/// `get_pairing_qr_code` reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrCode {
    #[serde(default)]
    pub ok: Option<bool>,
    #[serde(default)]
    pub code: Option<String>,
}

/// `open_getFeatureEnable` bus reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureEnable {
    pub ok: bool,
    pub enable: bool,
}

/// `settings.json` (state dir) — the persisted panel settings blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsFile {
    pub host_name: String,
}

// ------------------------------------------------------------ functions --

/// Current advertised PC host name (`settings_get_host_name`).
pub fn host_name() -> HostName {
    HostName {
        host_name: crate::gui::ipc::host_name(),
    }
}

/// Host name as stored by the daemon (`{hostName}` settings blob).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostName {
    /// Advertiser name shown to phones.
    pub host_name: String,
}

/// Validate and store the host name (the daemon persists best-effort).
pub fn set_host_name(name: &str) -> Result<(), EmptyHostName> {
    let clean = name.trim().to_string();
    if clean.is_empty() {
        return Err(EmptyHostName);
    }
    crate::gui::ipc::set_host_name(&clean);
    Ok(())
}

/// A rejected `set_host_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyHostName;

impl std::fmt::Display for EmptyHostName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("host name must not be empty")
    }
}

impl std::error::Error for EmptyHostName {}

/// `settings_set_host_name` channel lane: trim + reject blank, then
/// persist; reply keeps the vendor `{ok, name}` / `{ok:false, error}` shape.
pub fn set_host_name_channel(args: &SetHostNameArgs) -> SetHostNameResp {
    let name = args.host_name.trim().to_string();
    if name.is_empty() {
        return SetHostNameResp {
            ok: false,
            name: None,
            error: Some("missing name".into()),
        };
    }
    crate::gui::ipc::set_host_name(&name);
    SetHostNameResp {
        ok: true,
        name: Some(name),
        error: None,
    }
}

/// Persistent pairing bonds from the row table (scp_sync / authorized adb).
pub fn paired_devices() -> PairedDevices {
    let rows = crate::gui::devices::paired_rows();
    let entries = rows
        .iter()
        .map(|r| PairEntry {
            device_id: r.device_id.clone(),
            display_name: r.device_name.clone(),
        })
        .collect();
    PairedDevices {
        ok: true,
        entries,
        devices: rows.clone(),
        paired_devices: rows,
    }
}

/// The `DeviceEvent`-fed visible row table (device wall / bus sync).
pub fn visible_rows() -> Vec<DeviceRow> {
    crate::gui::devices::visible_device_rows()
}

/// The currently-connected subset (`get_current_connected_device_info_list`).
pub fn connected_devices() -> Vec<DeviceRow> {
    visible_rows()
        .into_iter()
        .filter(|r| r.is_connected)
        .collect()
}

/// Device wall (`device_found_list`).
pub fn device_found_list() -> DeviceFoundList {
    DeviceFoundList {
        ok: true,
        devices: visible_rows(),
    }
}

/// This PC's agent id (`generic_agent_get_local_device_id`).
pub fn local_device_id() -> String {
    std::env::var("LPLUS_PC_DEVICE_ID").unwrap_or_else(|_| "LPLUSLINUXPC1".to_string())
}

/// Cloud bind state (`generic_agent_get_cloud_bind`): no cloud lane yet.
pub fn cloud_bind() -> CloudBind {
    CloudBind {
        ok: true,
        bound: false,
        record: None,
    }
}

/// `generic_agent_ensure_running`: the daemon is in-process, always idle-ok.
pub fn ensure_running() -> EnsureRunning {
    EnsureRunning {
        ok: true,
        status: "idle".into(),
    }
}

/// UNBIND (settings page / card delete): drops the row set for the id and
/// blocks stale adb transports from re-minting it (see `devices.rs`).
pub fn remove_device(args: &RemoveDeviceArgs) -> RemoveDeviceResp {
    RemoveDeviceResp {
        ok: crate::gui::devices::remove_device(&args.device_id),
        device_id: args.device_id.clone(),
    }
}

/// `lplus_sidecar_status`: presence-lane probe.
pub fn sidecar_status() -> SidecarStatus {
    SidecarStatus {
        running: crate::gui::backend_up(),
        log_tailing: "in-process backend".into(),
    }
}

/// Connect/Disconnect button lane: queue a `sdpd::Command` for the
/// in-process backend (adb-side steering + EPI sink push run there).
pub fn device_action(connect: bool, ip: &str) -> DeviceAction {
    use crate::sdpd::{Command, send_command};
    if ip.is_empty() {
        return DeviceAction {
            ok: false,
            ip: ip.to_string(),
            error: Some("missing ip".into()),
        };
    }
    let kind = if connect {
        "connect_device"
    } else {
        "disconnect_device"
    };
    let cmd = if connect {
        Command::Connect { ip: ip.to_string() }
    } else {
        Command::Disconnect { ip: ip.to_string() }
    };
    let queued = send_command(cmd);
    tracing::info!("[ipc] {kind} {ip} queued={queued}");
    DeviceAction {
        ok: queued,
        ip: ip.to_string(),
        error: if queued {
            None
        } else {
            Some("backend command channel closed".into())
        },
    }
}

/// KMS input-link lane: push the CastMessage msg-61 bootstrap on the live
/// :46888 session (`Command::KmsBootstrap`).
pub fn kms_bootstrap(ip: &str) -> DeviceAction {
    use crate::sdpd::{Command, send_command};
    if ip.is_empty() {
        return DeviceAction {
            ok: false,
            ip: ip.to_string(),
            error: Some("missing ip".into()),
        };
    }
    let queued = send_command(Command::KmsBootstrap { ip: ip.to_string() });
    tracing::info!("[ipc] kms_bootstrap {ip} queued={queued}");
    DeviceAction {
        ok: queued,
        ip: ip.to_string(),
        error: if queued {
            None
        } else {
            Some("backend command channel closed".into())
        },
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn host_name_round_trips_typed_and_rejects_blank() {
        let _guard = crate::gui::ipc::HOST_TEST_LOCK
            .lock()
            .expect("host test lock");
        let previous = crate::gui::ipc::host_name();
        super::set_host_name("  boxed  ").expect("non-blank accepted");
        assert_eq!(super::host_name().host_name, "boxed");
        assert!(
            super::set_host_name("   ").is_err(),
            "blank must be rejected"
        );
        assert_eq!(
            super::host_name().host_name,
            "boxed",
            "rejected set is a no-op"
        );
        crate::gui::ipc::set_host_name(&previous);
    }

    /// Wire contract: dual vendor key spellings bind to one typed field.
    #[test]
    fn set_host_name_args_accepts_both_vendor_keys() {
        let a: super::SetHostNameArgs = serde_json::from_str(r#"{"hostName":"desk-1"}"#).unwrap();
        assert_eq!(a.host_name, "desk-1");
        let b: super::SetHostNameArgs = serde_json::from_str(r#"{"name":"desk-2"}"#).unwrap();
        assert_eq!(b.host_name, "desk-2");
        let c: super::SetHostNameArgs = serde_json::from_str("{}").unwrap();
        assert!(c.host_name.is_empty());
    }

    #[test]
    fn ip_payload_accepts_object_and_bare_string() {
        let a: super::IpPayload = serde_json::from_str(r#"{"ip":"192.0.2.2"}"#).unwrap();
        assert_eq!(a.ip(), "192.0.2.2");
        let b: super::IpPayload = serde_json::from_str(r#""192.0.2.3""#).unwrap();
        assert_eq!(b.ip(), "192.0.2.3");
        let c: super::IpPayload = serde_json::from_str("null").unwrap_or_default();
        assert_eq!(c.ip(), "");
    }
}
