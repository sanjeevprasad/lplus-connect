//! Rust implementation of the vendored O+ Connect renderer's IPC contract:
//! the single dispatch behind `POST /__ipc` on the loopback server
//! (`server.rs`) — the GPUI window calls it directly, attach and probe
//! clients through HTTP.
//!
//! The renderer talked to "Electron main" over two surfaces, both served
//! here:
//!
//! * `ipcRenderer.invoke(channel, payload)`  → `ipc_invoke` — one-shot
//!   request/response keyed by the channel strings the renderer bundles
//!   (`src/common/ipcmanager/IpcChannel.js`, recovered from the `.js.map`
//!   files shipped in `vendor/renderer`).
//! * `ipcRenderer.send('ipc_main_event', {name, data, callbackId})` — the
//!   app-internal bus (`src/common/ipcmanager/IpcRender.js`) → `ipc_bus`,
//!   which answers as a `GET /__events` SSE frame with
//!   `{callbackId, code, data}` exactly like the Electron bus helper did —
//!   via the GUI bus.
//!
//! Every channel not in the registry answers with a typed
//! `{ok:false, __unhandled:"<channel>"}` and is recorded in the audit ring
//! (`ipc_registry`) instead of throwing — boot must never hang on a missing
//! main-process handler. Window probes (bounds/focus) are host-side
//! concerns and are not part of this registry.

use std::collections::VecDeque;
use std::io::{Read, Write as _};
use std::path::Path;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;
use strum::{Display, EnumString};

use serde::Serialize;
use serde_json::Value;

/// Bus reply channel the renderer's IpcRender listens on.
const RENDERER_EVENT: &str = "ipc_renderer_event";

const AUDIT_CAP: usize = 400;
const APP_VERSION: &str = "17.100.10";
/// Cap for one panel REPL round-trip (`repl_exec`): read until EOF or this
/// deadline, whichever comes first.
const REPL_TIMEOUT: Duration = Duration::from_millis(1500);

// ------------------------------------------------------------------ audit
/// Ring buffer of channels the renderer hit that we do not serve yet.
/// Process-global so `dispatch` stays a free function.
static AUDIT: LazyLock<Mutex<VecDeque<String>>> = LazyLock::new(Mutex::default);

fn audit() -> &'static Mutex<VecDeque<String>> {
    &AUDIT
}

fn audit_record(kind: &str, channel: &str) {
    let mut ring = audit().lock().expect("ipc audit lock poisoned");
    let entry = format!("{kind}:{channel}");
    if ring.back().map(String::as_str) != Some(entry.as_str()) {
        if ring.len() == AUDIT_CAP {
            ring.pop_front();
        }
        ring.push_back(entry);
    }
    tracing::info!("[ipc] {kind} {channel}");
}

fn audit_snapshot() -> Vec<String> {
    audit()
        .lock()
        .expect("ipc audit lock poisoned")
        .iter()
        .cloned()
        .collect()
}

/// The single serialization boundary: handlers speak `api` types, the
/// `/__ipc` edge speaks `Value`. Own structs, so serialization is
/// infallible by construction.
fn wire<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("api response is serializable")
}

// --------------------------------------------------------------- host name
/// Advertised PC host name (`settings_get_host_name` / the panel's
/// `settings_set_host_name`). Persisted best-effort to
/// `settings.json` in the state dir and loaded on first use; persistence
/// is skipped under `cfg(test)` so tests never touch the user file.
static HOST_NAME: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(load_host_name()));

/// Serializes tests that read/write the shared `HOST_NAME` static.
#[cfg(test)]
pub(crate) static HOST_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(Mutex::default);

/// Panel settings file: `settings.json` in the per-user state dir
/// (`state.rs`); migrated once from the legacy capture-dir
/// `panel-settings.json`.
#[cfg(not(test))]
pub(crate) fn settings_path() -> std::path::PathBuf {
    crate::state::panel_settings_path()
}

fn load_host_name() -> String {
    #[cfg(not(test))]
    {
        let pinned = std::fs::read_to_string(settings_path())
            .ok()
            .and_then(|raw| parse_host_name(&raw));
        pinned
            .or_else(crate::sdpd::system_hostname)
            .unwrap_or_else(|| "L+ PC".into())
    }
    #[cfg(test)]
    {
        "linux-panel".to_string()
    }
}

/// Pull `hostName` out of a settings JSON blob; `None` when absent/blank.
fn parse_host_name(raw: &str) -> Option<String> {
    let blob: crate::gui::api::SettingsFile = serde_json::from_str(raw).ok()?;
    let name = blob.host_name.trim().to_string();
    (!name.is_empty()).then_some(name)
}

pub(crate) fn host_name() -> String {
    HOST_NAME.lock().expect("host name lock poisoned").clone()
}

pub(crate) fn set_host_name(name: &str) {
    *HOST_NAME.lock().expect("host name lock poisoned") = name.to_string();
    #[cfg(not(test))]
    if let Err(e) = persist_host_name(&settings_path(), name) {
        tracing::warn!(
            "[ipc] host name persist failed ({}): {e}",
            settings_path().display()
        );
    }
    tracing::info!("[ipc] host name set: {name}");
}

/// Write `{"hostName": name}` to `path` (best-effort; parent created).
fn persist_host_name(path: &Path, name: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let blob = crate::gui::api::SettingsFile {
        host_name: name.to_string(),
    };
    std::fs::write(path, serde_json::to_string(&blob).expect("settings blob"))
}

// ------------------------------------------------------------------- repl
/// Panel REPL lane (`repl_exec`): run one line through the backend line
/// REPL on 127.0.0.1:`LPLUS_REPL_PORT` (default 47991). Empty lines are
/// refused before touching the socket.
pub(crate) fn repl_exec_line(line: &str) -> crate::gui::api::ReplExec {
    if line.trim().is_empty() {
        return crate::gui::api::ReplExec {
            ok: false,
            out: None,
            error: Some("empty line".into()),
        };
    }
    repl_exec_port(line, crate::gui::cast::repl_port())
}

/// `repl_exec` against an explicit port (one-shot listener in tests).
fn repl_exec_port(line: &str, port: u16) -> crate::gui::api::ReplExec {
    use crate::gui::api::ReplExec;
    let fail = |error: String| ReplExec {
        ok: false,
        out: None,
        error: Some(error),
    };
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = match std::net::TcpStream::connect_timeout(&addr, REPL_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[ipc] repl_exec connect {addr} failed: {e}");
            return fail(format!("repl connect {addr}: {e}"));
        }
    };
    let _ = stream.set_write_timeout(Some(REPL_TIMEOUT));
    let _ = stream.set_read_timeout(Some(REPL_TIMEOUT));
    if writeln!(stream, "{line}").is_err() {
        return fail("repl write failed".into());
    }
    // Half-close so the REPL's line loop sees EOF and hangs up: the reply
    // arrives without waiting out the read timeout.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break, // EOF or the 1500 ms deadline
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let out: Vec<String> = text.lines().map(str::to_string).collect();
    tracing::info!("[ipc] repl_exec {line:?} -> {} line(s)", out.len());
    ReplExec {
        ok: true,
        out: Some(out),
        error: None,
    }
}

// -------------------------------------------------------------- dispatch
/// Shape used by the renderer bus (`IpcRender.send`) for request payloads.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BusPayload {
    #[serde(default)]
    callback_id: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    data: BusData,
    #[serde(default)]
    sync: bool,
}

/// Bus `data`: the subscription lanes send a bare event name or
/// `{name}`; anything else is opaque to the registry.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(untagged)]
enum BusData {
    Text(String),
    Named {
        name: String,
    },
    // Opaque payloads are acknowledged but never inspected; the registry
    // only consumes the two subscription shapes.
    #[expect(dead_code, reason = "opaque bus payloads stay unread")]
    Catch(Vec<serde_json::Value>),
}

impl Default for BusData {
    fn default() -> Self {
        Self::Catch(Vec::new())
    }
}

fn unhandled(channel: &str) -> Value {
    wire(&crate::gui::api::Unhandled::new(channel))
}

/// Wire names for renderer `cmd` values and `ipc_invoke` channels. The
/// dispatch/registry tables key on the payload-less discriminant
/// (`WireCmdKind`): a name typo is a compile error at the variant site,
/// and the strum `snake_case` serialization pins each variant to its
/// exact wire spelling. Every cmd carries its strict argument type;
/// [`WireCmd::from_wire`] is the single parse point at the edge. Unknown
/// wire strings never enter the enum — the edge handles them as typed
/// unhandled and audits the original spelling.
#[derive(Debug, strum::EnumDiscriminants)]
#[strum_discriminants(
    name(WireCmdKind),
    derive(Display, EnumString),
    strum(serialize_all = "snake_case")
)]
enum WireCmd {
    // Transport/protocol commands (plain `cmd` posts).
    IpcInvoke(crate::gui::api::IpcInvokeArgs),
    IpcBus(BusPayload),
    IpcSend(crate::gui::api::SendArgs),
    ConsoleLog(crate::gui::api::ConsoleLogArgs),
    OpenExternal(crate::gui::api::OpenExternalArgs),
    IpcRegistry,
    ReplExec(crate::gui::api::ReplArgs),
    CastPush(crate::gui::api::CastPushArgs),
    OdmfStart,
    KmsBootstrap(crate::gui::api::IpPayload),
    LplusStatus,
    SettingsSetHostName(crate::gui::api::SetHostNameArgs),
    ConnectDevice(crate::gui::api::IpPayload),
    DisconnectDevice(crate::gui::api::IpPayload),
    // Vendor inventory/probe channels (`ipc_invoke` and plain spellings);
    // args are typed per handler in `route_invoke`.
    GenericAgentGetPairedDevices,
    GenericAgentSettingsRemoveDevice,
    GenericAgentGetLocalDeviceId,
    GenericAgentGetCloudBind,
    GenericAgentEnsureRunning,
    GetCurrentConnectedDeviceInfoList,
    PublicGetSystemTheme,
    SettingsGetPcConnectRunning,
    LplusSidecarStatus,
    SettingsGetHostName,
    GetHttpServerPort,
    IsHttpServerRunning,
    DeviceFoundList,
}

impl WireCmd {
    /// The single edge parse: resolve the cmd spelling, then bind the
    /// argument object to the variant's strict type (garbage degrades to
    /// `default()` — the handler refuses it as it always did).
    fn from_wire(cmd: &str, args: &Value) -> Option<Self> {
        use WireCmdKind as K;
        let kind = K::from_str(cmd).ok()?;
        Some(match kind {
            K::IpcInvoke => Self::IpcInvoke(args_of(args)),
            // The bus accepts the payload directly or wrapped as
            // `{payload: …}` (the shape `/__ipc` clients forward).
            K::IpcBus => {
                let body = args.get("payload").cloned().unwrap_or_else(|| args.clone());
                Self::IpcBus(args_of(&body))
            }
            K::IpcSend => Self::IpcSend(args_of(args)),
            K::ConsoleLog => Self::ConsoleLog(args_of(args)),
            K::OpenExternal => Self::OpenExternal(args_of(args)),
            K::IpcRegistry => Self::IpcRegistry,
            K::ReplExec => Self::ReplExec(args_of(args)),
            K::CastPush => Self::CastPush(args_of(args)),
            K::OdmfStart => Self::OdmfStart,
            K::KmsBootstrap => Self::KmsBootstrap(args_of(args)),
            K::LplusStatus => Self::LplusStatus,
            K::SettingsSetHostName => Self::SettingsSetHostName(args_of(args)),
            K::ConnectDevice => Self::ConnectDevice(args_of(args)),
            K::DisconnectDevice => Self::DisconnectDevice(args_of(args)),
            K::GenericAgentGetPairedDevices => Self::GenericAgentGetPairedDevices,
            K::GenericAgentSettingsRemoveDevice => Self::GenericAgentSettingsRemoveDevice,
            K::GenericAgentGetLocalDeviceId => Self::GenericAgentGetLocalDeviceId,
            K::GenericAgentGetCloudBind => Self::GenericAgentGetCloudBind,
            K::GenericAgentEnsureRunning => Self::GenericAgentEnsureRunning,
            K::GetCurrentConnectedDeviceInfoList => Self::GetCurrentConnectedDeviceInfoList,
            K::PublicGetSystemTheme => Self::PublicGetSystemTheme,
            K::SettingsGetPcConnectRunning => Self::SettingsGetPcConnectRunning,
            K::LplusSidecarStatus => Self::LplusSidecarStatus,
            K::SettingsGetHostName => Self::SettingsGetHostName,
            K::GetHttpServerPort => Self::GetHttpServerPort,
            K::IsHttpServerRunning => Self::IsHttpServerRunning,
            K::DeviceFoundList => Self::DeviceFoundList,
        })
    }
}

/// Tolerant arg parse: a missing/garbage argument object degrades to the
/// type's `default()` — handlers refuse it the way they used to (missing
/// ip/key/line), never a panic at the edge.
fn args_of<T: serde::de::DeserializeOwned + Default>(payload: &Value) -> T {
    serde_json::from_value(payload.clone()).unwrap_or_default()
}

/// Registry for `ipcRenderer.invoke` channels. Returns `None` when no
/// handler exists; callers then record + return [`unhandled`].
fn route_invoke(channel: WireCmdKind, payload: &Value) -> Option<Value> {
    use crate::gui::api;
    use WireCmdKind as W;
    match channel {
        // ---- daemon / device inventory ---------------------------------
        // PAIRED_DEVICES: persistent pairing bonds from the row table
        // (scp_sync / authorized adb); consumers expect { ok, entries[] }
        // and read pairedDevices??paired_devices??instances (see
        // render/genericAgent/binding/gaPairBoundStatus.js).
        W::GenericAgentGetPairedDevices => Some(wire(&api::paired_devices())),
        // UNBIND (settings page / card delete): vendor payload
        // `{ device_id, removeStateDir }`; consumers toast on !ok.
        W::GenericAgentSettingsRemoveDevice => Some(wire(&api::remove_device(&args_of::<
            api::RemoveDeviceArgs,
        >(payload)))),
        // GET_LOCAL_DEVICE_ID: consumers String(localId || '') — plain id string.
        W::GenericAgentGetLocalDeviceId => Some(Value::String(api::local_device_id())),
        // GET_CLOUD_BIND: consumers expect { ok, bound, record? }.
        W::GenericAgentGetCloudBind => Some(wire(&api::cloud_bind())),
        W::GenericAgentEnsureRunning => Some(wire(&api::ensure_running())),
        // GET_CURRENT_CONNECTED_DEVICE_INFO_LIST: consumers iterate an array.
        W::GetCurrentConnectedDeviceInfoList => Some(wire(&api::connected_devices())),
        W::PublicGetSystemTheme => Some(Value::String("light".into())),
        W::SettingsGetPcConnectRunning => Some(Value::Bool(false)),

        // ---- window probes (viewport / focus) are host-side concerns;
        //      clients get them from the OS, not this registry. ----------

        // ---- lplus-specific probes (safe defaults) ------------------------
        W::LplusSidecarStatus => Some(wire(&api::sidecar_status())),
        W::SettingsGetHostName => Some(Value::String(host_name())),
        W::GetHttpServerPort => Some(Value::Null),
        W::IsHttpServerRunning => Some(Value::Bool(false)),

        // ---- device actions (renderer Connect/Disconnect) ------------------
        // Forwarded to the backend command channel (crate::sdpd::Command);
        // payload carries {ip} or a bare IP string.
        W::ConnectDevice | W::DisconnectDevice => {
            let connect = matches!(channel, W::ConnectDevice);
            let payload = args_of::<api::IpPayload>(payload);
            Some(wire(&api::device_action(connect, payload.ip())))
        }
        // Device-wall channel (DiscoveredDevices contract): same rows as
        // the bus, wrapped so `ok`-checking consumers work.
        W::DeviceFoundList => Some(wire(&api::device_found_list())),
        // Transport commands are not invoke channels; callers audit them.
        _ => None,
    }
}

/// Registry for the app-internal bus (`ipcManager.emit(name, {…success})`).
fn route_bus(name: &str) -> Option<Value> {
    use crate::gui::api;
    match name {
        // App.vue stores the returned value as `isComputerVersion`.
        "ComputerVersion" => Some(Value::String(APP_VERSION.into())),
        // IpcRender event subscriptions: acknowledge, nothing to fan out yet.
        "ipc_event_init" | "ipc_event_destory" => Some(wire(&api::OkFlag::ok())),
        // Mini window device info sync — empty list keeps views in the
        // "no devices found" state without throwing.
        "get_and_update_deviceinfo" => Some(wire(&api::visible_rows())),
        // mydevice connect-button broadcasts; answered so the UI does not
        // sit on an unhandled bus call.
        "open_getFeatureEnable" => Some(wire(&api::FeatureEnable {
            ok: true,
            enable: true,
        })),
        // Main window identity (single-window port: always the main window).
        "isMainWin" => Some(Value::Bool(true)),
        // Config probe on the boot path: empty object keeps clients on the
        // defaults branch.
        "get_general_config" => Some(Value::Object(serde_json::Map::new())),
        _ => None,
    }
}

/// The single IPC entry point, shared by the GPUI direct transport and
/// `POST /__ipc` on the loopback server. `args` is the command's argument
/// object (`{channel, payload}` for `ipc_invoke`, the bus payload for
/// `ipc_bus`, …). This is the only `Value` edge for the daemon: every
/// handler below parses typed `api` args and answers typed responses via
/// [`wire`]. Unknown commands answer with the typed unhandled marker.
pub fn dispatch(cmd: &str, args: Value) -> Value {
    use crate::gui::api;
    let Some(wire_cmd) = WireCmd::from_wire(cmd, &args) else {
        // Unknown top-level cmd: typed unhandled, original spelling kept.
        audit_record("unknown-cmd", cmd);
        return unhandled(cmd);
    };
    match wire_cmd {
        WireCmd::IpcInvoke(parsed) => {
            match WireCmdKind::from_str(&parsed.channel)
                .ok()
                .and_then(|channel| route_invoke(channel, &parsed.payload))
            {
                Some(v) => v,
                None => {
                    audit_record("unhandled-invoke", &parsed.channel);
                    unhandled(&parsed.channel)
                }
            }
        }
        WireCmd::IpcBus(parsed) => {
            if parsed.name == "ipc_event_init" {
                // IpcRender registers the webview-side event name here; device
                // pushes are only fanned out to subscribers (see devices.rs).
                match &parsed.data {
                    BusData::Text(ev) => crate::gui::devices::note_subscription(ev),
                    BusData::Named { name } => crate::gui::devices::note_subscription(name),
                    BusData::Catch(_) => {}
                }
            }
            let data = match route_bus(&parsed.name) {
                Some(v) => v,
                None => {
                    audit_record("unhandled-bus", &parsed.name);
                    // code_success + ok:false: the renderer bus treats code_error as
                    // an exception path and floods console; success envelope with an
                    // unhandled marker keeps call sites on their benign branch.
                    unhandled(&parsed.name)
                }
            };
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct BusReply<'a> {
                callback_id: &'a Option<String>,
                code: &'static str,
                data: Value,
                sync: bool,
            }
            let reply = wire(&BusReply {
                callback_id: &parsed.callback_id,
                code: "code_success",
                data,
                sync: parsed.sync,
            });
            crate::gui::bus_publish(RENDERER_EVENT, reply);
            wire(&api::OkFlag::ok())
        }
        // Fire-and-forget `ipcRenderer.send` on any non-bus channel: recorded.
        WireCmd::IpcSend(parsed) => {
            audit_record("send", &parsed.channel);
            wire(&api::OkFlag::ok())
        }
        // Console bridge: remote clients mirror batched logs onto the host
        // log so boot diagnostics are capturable without devtools.
        WireCmd::ConsoleLog(parsed) => {
            for line in parsed.batch.unwrap_or_default() {
                let level = line.level.as_deref().unwrap_or("log");
                let text = line.text.as_deref().unwrap_or("");
                tracing::info!("[renderer:{level}] {text}");
            }
            wire(&api::OkFlag::ok())
        }
        // `shell.openExternal` bridge: URLs are validated and logged, never
        // launched from the server side.
        WireCmd::OpenExternal(parsed) => {
            let url = parsed.url;
            if !(url.starts_with("http://")
                || url.starts_with("https://")
                || url.starts_with("mailto:"))
            {
                tracing::warn!("[ipc] open_external refused non-web url: {url}");
                return wire(&api::OkFlag::err("non-web url refused"));
            }
            tracing::info!("[ipc] open_external (browser-side) {url}");
            wire(&api::OkFlag::ok())
        }
        // Debug helper: channels hit but not served yet (feeds GUI.md §3).
        WireCmd::IpcRegistry => wire(&audit_snapshot()),

        // ---- panel product channels (contract) -----------------------------
        WireCmd::ReplExec(parsed) => wire(&repl_exec_line(&parsed.line)),
        WireCmd::CastPush(parsed) => wire(&crate::gui::cast::cast_push(&parsed.key, &parsed.value)),
        WireCmd::OdmfStart => wire(&crate::gui::cast::odmf_start()),
        WireCmd::KmsBootstrap(parsed) => wire(&api::kms_bootstrap(parsed.ip())),
        WireCmd::LplusStatus => wire(&crate::gui::cast::status()),
        WireCmd::SettingsSetHostName(parsed) => wire(&api::set_host_name_channel(&parsed)),
        // Renderer (or direct) Connect/Disconnect entry points.
        WireCmd::ConnectDevice(parsed) => wire(&api::device_action(true, parsed.ip())),
        WireCmd::DisconnectDevice(parsed) => wire(&api::device_action(false, parsed.ip())),
        // Vendor inventory/probe channels posted in their plain form:
        // answer from the registry or audit.
        _ => {
            let kind = WireCmdKind::from_str(cmd).expect("from_wire only yields known kinds");
            if let Some(v) = route_invoke(kind, &args) {
                return v;
            }
            let name = kind.to_string();
            audit_record("unknown-cmd", &name);
            unhandled(&name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use serde_json::json;

    #[test]
    fn dispatch_known_channel_answers_host_name() {
        let _guard = HOST_TEST_LOCK.lock().expect("host test lock");
        let v = dispatch(
            "ipc_invoke",
            json!({ "channel": "settings_get_host_name", "payload": null }),
        );
        assert_eq!(v, json!("linux-panel"));
    }

    #[test]
    fn dispatch_unhandled_channel_is_typed() {
        let v = dispatch(
            "ipc_invoke",
            json!({ "channel": "no_such_channel_xyz", "payload": null }),
        );
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["__unhandled"], json!("no_such_channel_xyz"));
        // …and it landed in the audit ring.
        let ring = dispatch("ipc_registry", Value::Null);
        assert!(
            ring.as_array()
                .expect("audit is an array")
                .iter()
                .any(|e| e.as_str() == Some("unhandled-invoke:no_such_channel_xyz")),
            "audit ring missing entry: {ring}"
        );
    }

    #[test]
    fn dispatch_unknown_cmd_is_typed() {
        let v = dispatch("no_such_cmd", json!({}));
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["__unhandled"], json!("no_such_cmd"));
    }

    #[test]
    fn dispatch_bus_answers_and_records_subscription() {
        let v = dispatch(
            "ipc_bus",
            json!({ "name": "ComputerVersion", "data": null }),
        );
        assert_eq!(v["ok"], json!(true));
        // Payload-wrapped form (what `/__ipc` clients forward) also parses.
        let v = dispatch(
            "ipc_bus",
            json!({ "payload": { "name": "ipc_event_init", "data": "some_event", "callbackId": "c1" } }),
        );
        assert_eq!(v["ok"], json!(true));
        assert!(
            crate::gui::devices::is_subscribed("some_event"),
            "ipc_event_init must register a subscription"
        );
    }

    #[test]
    fn dispatch_connect_without_ip_fails_cleanly() {
        let v = dispatch("connect_device", json!({}));
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"], json!("missing ip"));
    }

    // ---- panel product channels ------------------------------------------

    /// One-shot fake REPL: answers the first connection's line with fixed
    /// output, then hangs up (exercises the read-until-EOF path).
    fn fake_repl(reply: &'static str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake repl");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            if let Ok((sock, _)) = listener.accept() {
                use std::io::{BufRead, BufReader, Write};
                let mut rd = BufReader::new(sock);
                let mut line = String::new();
                let _ = rd.read_line(&mut line); // the request line
                let mut sock = rd.into_inner();
                let _ = sock.write_all(reply.as_bytes());
                // socket drop → EOF for the client
            }
        });
        port
    }

    /// A port with nothing listening (bind + release).
    fn dead_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
        l.local_addr().expect("probe addr").port()
    }

    #[test]
    fn repl_exec_roundtrips_against_fake_repl() {
        let port = fake_repl("peers 1\n  46888 192.0.2.2:52000\n");
        let v = repl_exec_port("list", port);
        assert!(v.ok, "{v:?}");
        let out = v.out.clone().expect("out vector");
        assert_eq!(out.len(), 2, "{v:?}");
        assert_eq!(out[0], "peers 1");
        assert!(out[1].contains("46888"));
    }

    #[test]
    fn repl_exec_refuses_empty_line() {
        let v = dispatch("repl_exec", json!({ "line": "   " }));
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"], json!("empty line"));
        let v = dispatch("repl_exec", json!({}));
        assert_eq!(v["ok"], json!(false));
    }

    #[test]
    fn repl_exec_reports_unreachable_backend() {
        // Nothing is listening on the dead port: typed failure, no hang.
        let v = repl_exec_port("list", dead_port());
        assert!(!v.ok);
        assert!(v.error.unwrap().contains("repl connect"));
    }

    #[test]
    fn dispatch_device_found_list_wraps_rows() {
        let v = dispatch(
            "ipc_invoke",
            json!({ "channel": "device_found_list", "payload": null }),
        );
        assert_eq!(v["ok"], json!(true), "{v}");
        assert!(v["devices"].is_array(), "{v}");
        // Not in the registry → typed unhandled (no silent null).
        let miss = dispatch(
            "ipc_invoke",
            json!({ "channel": "no_such_vendor_channel", "payload": null }),
        );
        assert_eq!(miss["__unhandled"], json!("no_such_vendor_channel"));
    }

    #[test]
    fn dispatch_cast_push_builds_frame_and_reports_sinks() {
        // send_command finds no subscriber in a bare test process; the
        // channel still succeeds (fire-and-forget), reporting the frame.
        let v = dispatch(
            "cast_push",
            json!({ "key": "cast_ability_sync", "value": "{\"pc_support_odmf\":false}" }),
        );
        assert_eq!(v["ok"], json!(true), "{v}");
        assert!(v["frame_bytes"].as_u64().unwrap() > 52, "{v}");
        assert!(v["repl_out"].is_array(), "{v}");
    }

    #[test]
    fn dispatch_cast_push_requires_key() {
        let v = dispatch("cast_push", json!({ "key": "", "value": "{}" }));
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"], json!("missing key"));
    }

    #[test]
    fn dispatch_odmf_start_missing_pub_key_is_typed() {
        // ODMF_PUB_FILE defaults to /tmp/odmf_pub.b64; force a missing
        // file through the same env the channel reads would race other
        // tests, so assert the channel's own default-path shape instead:
        // either a successful start (file present) or the typed error.
        let v = dispatch("odmf_start", json!({}));
        if v["ok"] == json!(false) {
            assert!(
                v["error"]
                    .as_str()
                    .unwrap()
                    .starts_with("missing ODMF public key ("),
                "{v}"
            );
        } else {
            assert_eq!(v["pushes"], json!(2), "{v}");
            assert!(v["id"].is_string(), "{v}");
            // b64 of lplus-pc-<n>
            let id = v["id"].as_str().unwrap();
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(id)
                .expect("id is standard b64");
            assert!(String::from_utf8_lossy(&decoded).starts_with("lplus-pc-"));
        }
    }

    #[test]
    fn dispatch_kms_bootstrap_requires_ip_and_replies() {
        let v = dispatch("kms_bootstrap", json!({}));
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"], json!("missing ip"));
        let v = dispatch("kms_bootstrap", json!({ "ip": "192.0.2.2" }));
        assert_eq!(v["ok"], json!(false)); // no backend subscriber in tests
        assert_eq!(v["ip"], json!("192.0.2.2"));
        assert!(v["error"].is_string());
    }

    #[test]
    fn dispatch_lplus_status_has_full_shape() {
        let v = dispatch("lplus_status", json!({}));
        assert_eq!(v["ok"], json!(true));
        assert!(v["backend_up"].is_boolean());
        assert!(v["repl_port"].is_number());
        assert!(v["repl_enabled"].is_boolean());
        assert!(v["kms_listening"].is_boolean());
        assert!(v["odmf"]["enabled"].is_boolean());
        assert!(v["odmf"]["session_bin"]["exists"].is_boolean());
        assert!(v["rtsp"]["enabled"].is_boolean());
    }

    #[test]
    fn settings_host_name_persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!("lplus-settings-{}", std::process::id()));
        let path = dir.join("panel-settings.json");
        persist_host_name(&path, "panel-alpha").expect("persist");
        let raw = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(parse_host_name(&raw).as_deref(), Some("panel-alpha"));
        assert_eq!(parse_host_name("{}"), None);
        assert_eq!(parse_host_name(r#"{"hostName":"  "}"#), None);
        assert_eq!(parse_host_name("not json"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dispatch_settings_set_then_get_host_name() {
        let _guard = HOST_TEST_LOCK.lock().expect("host test lock");
        let v = dispatch("settings_set_host_name", json!({ "name": "  " }));
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"], json!("missing name"));
        // Set through the channel, read back through the renderer invoke
        // (single-threaded so the shared static is deterministic here).
        let v = dispatch(
            "settings_set_host_name",
            json!({ "name": "roundtrip-host" }),
        );
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["name"], json!("roundtrip-host"));
        let got = dispatch(
            "ipc_invoke",
            json!({ "channel": "settings_get_host_name", "payload": null }),
        );
        assert_eq!(got, json!("roundtrip-host"));
        // Restore the default for other tests in this binary.
        dispatch("settings_set_host_name", json!({ "name": "linux-panel" }));
    }
}
