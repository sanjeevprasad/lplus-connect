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
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

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

fn audit_snapshot() -> Vec<Value> {
    audit()
        .lock()
        .expect("ipc audit lock poisoned")
        .iter()
        .map(|e| json!(e))
        .collect()
}

// --------------------------------------------------------------- host name
/// Advertised PC host name (`settings_get_host_name` / the panel's
/// `settings_set_host_name`). Persisted best-effort to
/// `settings.json` in the state dir and loaded on first use; persistence
/// is skipped under `cfg(test)` so tests never touch the user file.
static HOST_NAME: LazyLock<Mutex<String>> = LazyLock::new(|| Mutex::new(load_host_name()));

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
    let name = serde_json::from_str::<Value>(raw)
        .ok()?
        .get("hostName")?
        .as_str()?
        .trim()
        .to_string();
    (!name.is_empty()).then_some(name)
}

fn host_name() -> String {
    HOST_NAME.lock().expect("host name lock poisoned").clone()
}

fn set_host_name(name: &str) {
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
    std::fs::write(path, json!({ "hostName": name }).to_string())
}

// ------------------------------------------------------------------- repl
/// Panel REPL lane (`repl_exec`): run one line through the backend line
/// REPL on 127.0.0.1:`LPLUS_REPL_PORT` (default 47991). Empty lines are
/// refused before touching the socket.
pub(crate) fn repl_exec_line(line: &str) -> Value {
    if line.trim().is_empty() {
        return json!({ "ok": false, "error": "empty line" });
    }
    repl_exec_port(line, crate::gui::cast::repl_port())
}

/// `repl_exec` against an explicit port (one-shot listener in tests).
fn repl_exec_port(line: &str, port: u16) -> Value {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = match std::net::TcpStream::connect_timeout(&addr, REPL_TIMEOUT) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[ipc] repl_exec connect {addr} failed: {e}");
            return json!({ "ok": false, "error": format!("repl connect {addr}: {e}") });
        }
    };
    let _ = stream.set_write_timeout(Some(REPL_TIMEOUT));
    let _ = stream.set_read_timeout(Some(REPL_TIMEOUT));
    if writeln!(stream, "{line}").is_err() {
        return json!({ "ok": false, "error": "repl write failed" });
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
    let out: Vec<&str> = text.lines().collect();
    tracing::info!("[ipc] repl_exec {line:?} -> {} line(s)", out.len());
    json!({ "ok": true, "out": out })
}

// -------------------------------------------------------------- dispatch
/// Shape used by the renderer bus (`IpcRender.send`) for request payloads.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BusPayload {
    #[serde(default)]
    callback_id: Option<String>,
    name: String,
    #[serde(default)]
    data: Value,
    #[serde(default)]
    sync: bool,
}

fn unhandled(channel: &str) -> Value {
    json!({ "ok": false, "__unhandled": channel, "error": format!("unhandled:{channel}") })
}

/// Registry for `ipcRenderer.invoke` channels. Returns `None` when no
/// handler exists; callers then record + return [`unhandled`].
fn route_invoke(channel: &str, payload: &Value) -> Option<Value> {
    match channel {
        // ---- daemon / device inventory ---------------------------------
        // PAIRED_DEVICES: persistent pairing bonds from the row table
        // (scp_sync / authorized adb); consumers expect { ok, entries[] }
        // and read pairedDevices??paired_devices??instances (see
        // render/genericAgent/binding/gaPairBoundStatus.js).
        "generic_agent_get_paired_devices" => {
            let rows = crate::gui::devices::paired_rows();
            let entries: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "deviceId": r.get("deviceId").and_then(Value::as_str).unwrap_or(""),
                        "displayName": r.get("deviceName").and_then(Value::as_str).unwrap_or(""),
                    })
                })
                .collect();
            Some(json!({ "ok": true, "entries": entries, "devices": rows, "pairedDevices": rows }))
        }
        // UNBIND (settings page / card delete): vendor payload
        // `{ device_id, removeStateDir }`; consumers toast on !ok.
        "generic_agent_settings_remove_device" => {
            let id = payload
                .get("device_id")
                .and_then(Value::as_str)
                .unwrap_or("");
            let found = crate::gui::devices::remove_device(id);
            Some(json!({ "ok": found, "deviceId": id }))
        }
        // GET_LOCAL_DEVICE_ID: consumers String(localId || '') — plain id string.
        "generic_agent_get_local_device_id" => Some(pc_device_id()),
        // GET_CLOUD_BIND: consumers expect { ok, bound, record? }.
        "generic_agent_get_cloud_bind" => {
            Some(json!({ "ok": true, "bound": false, "record": null }))
        }
        "generic_agent_ensure_running" => Some(json!({ "ok": true, "status": "idle" })),
        // GET_CURRENT_CONNECTED_DEVICE_INFO_LIST: consumers iterate an array.
        "get_current_connected_device_info_list" => Some(device_list()),
        "public_get_system_theme" => Some(json!("light")),
        "settings_get_pc_connect_running" => Some(json!(false)),

        // ---- window probes (viewport / focus) are host-side concerns;
        //      clients get them from the OS, not this registry. ----------

        // ---- lplus-specific probes (safe defaults) ------------------------
        "lplus_sidecar_status" => Some(crate::gui::devices::sidecar_status()),
        "settings_get_host_name" => Some(json!(host_name())),
        "get_http_server_port" => Some(json!(null)),
        "is_http_server_running" => Some(json!(false)),

        // ---- device actions (renderer Connect/Disconnect) ------------------
        // Forwarded to the backend command channel (crate::sdpd::Command);
        // payload carries {ip}.
        "connect_device" | "disconnect_device" => {
            let ip = payload
                .get("ip")
                .and_then(Value::as_str)
                .or_else(|| payload.as_str())
                .unwrap_or("")
                .to_string();
            Some(dispatch_device(channel, ip))
        }
        // Device-wall channel (DiscoveredDevices contract): same rows as
        // the bus, wrapped so `ok`-checking consumers work.
        "device_found_list" => Some(json!({ "ok": true, "devices": all_rows() })),
        _ => {
            let _ = payload;
            None
        }
    }
}

/// Registry for the app-internal bus (`ipcManager.emit(name, {…success})`).
fn route_bus(name: &str, data: &Value) -> Option<Value> {
    match name {
        // App.vue stores the returned value as `isComputerVersion`.
        "ComputerVersion" => Some(json!(APP_VERSION)),
        // IpcRender event subscriptions: acknowledge, nothing to fan out yet.
        "ipc_event_init" => Some(json!({ "ok": true })),
        "ipc_event_destory" => Some(json!({ "ok": true })),
        // Mini window device info sync — empty list keeps views in the
        // "no devices found" state without throwing.
        "get_and_update_deviceinfo" => Some(Value::Array(all_rows())),
        // mydevice connect-button broadcasts; answered so the UI does not
        // sit on an unhandled bus call.
        "open_getFeatureEnable" => Some(json!({ "ok": true, "enable": true })),
        // Main window identity (single-window port: always the main window).
        "isMainWin" => Some(json!(true)),
        // Config probe on the boot path: empty object keeps clients on the
        // defaults branch.
        "get_general_config" => Some(json!({})),
        _ => {
            let _ = data;
            None
        }
    }
}

fn pc_device_id() -> Value {
    std::env::var("LPLUS_PC_DEVICE_ID")
        .unwrap_or_else(|_| "LPLUSLINUXPC1".to_string())
        .into()
}

/// Connected devices for the boot path, from the `DeviceEvent`-fed model
/// in `devices.rs`.
fn device_list() -> Value {
    // Consumers iterate the currently-connected subset.
    Value::Array(
        all_rows()
            .into_iter()
            .filter(|r| {
                r.get("isConnected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .collect(),
    )
}

fn all_rows() -> Vec<Value> {
    crate::gui::devices::rows_json()
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// Connect/Disconnect button lane: queue a `sdpd::Command` for the
/// in-process backend (adb-side steering + EPI sink push run there).
fn dispatch_device(kind: &str, ip: String) -> Value {
    use crate::sdpd::{Command, send_command};
    if ip.is_empty() {
        return json!({ "ok": false, "error": "missing ip" });
    }
    let cmd = match kind {
        "connect_device" => Command::Connect { ip: ip.clone() },
        _ => Command::Disconnect { ip: ip.clone() },
    };
    let queued = send_command(cmd);
    tracing::info!("[ipc] {kind} {ip} queued={queued}");
    json!({
        "ok": queued,
        "ip": ip,
        "error": if queued { Value::Null } else { json!("backend command channel closed") },
    })
}

/// KMS input-link lane: ask the backend to push the CastMessage msg-61
/// bootstrap on the live :46888 session (`Command::KmsBootstrap`).
fn dispatch_kms(ip: String) -> Value {
    use crate::sdpd::{Command, send_command};
    if ip.is_empty() {
        return json!({ "ok": false, "error": "missing ip" });
    }
    let queued = send_command(Command::KmsBootstrap { ip: ip.clone() });
    tracing::info!("[ipc] kms_bootstrap {ip} queued={queued}");
    json!({
        "ok": queued,
        "ip": ip,
        "error": if queued { Value::Null } else { json!("backend command channel closed") },
    })
}

/// The single IPC entry point, shared by the GPUI direct transport and
/// `POST /__ipc` on the loopback server. `args` is the command's argument
/// object (`{channel, payload}` for `ipc_invoke`, the bus payload for
/// `ipc_bus`, …). Unknown commands answer with the typed unhandled marker.
pub fn dispatch(cmd: &str, args: Value) -> Value {
    match cmd {
        "ipc_invoke" => {
            let channel = args.get("channel").and_then(Value::as_str).unwrap_or("");
            let payload = args.get("payload").cloned().unwrap_or(Value::Null);
            match route_invoke(channel, &payload) {
                Some(v) => v,
                None => {
                    audit_record("unhandled-invoke", channel);
                    unhandled(channel)
                }
            }
        }
        "ipc_bus" => {
            // Accept the payload directly or wrapped as `{payload: …}` (the
            // shape `/__ipc` clients forward).
            let body = args.get("payload").cloned().unwrap_or_else(|| args.clone());
            let parsed: BusPayload = match serde_json::from_value(body) {
                Ok(p) => p,
                Err(e) => {
                    tracing::info!("[ipc] malformed ipc_main_event payload: {e}");
                    return json!({ "ok": false, "error": format!("malformed bus payload: {e}") });
                }
            };
            if parsed.name == "ipc_event_init" {
                // IpcRender registers the webview-side event name here; device
                // pushes are only fanned out to subscribers (see devices.rs).
                if let Some(ev) = parsed.data.as_str() {
                    crate::gui::devices::note_subscription(ev);
                } else if let Some(ev) = parsed.data.get("name").and_then(Value::as_str) {
                    crate::gui::devices::note_subscription(ev);
                }
            }
            let data = match route_bus(&parsed.name, &parsed.data) {
                Some(v) => v,
                None => {
                    audit_record("unhandled-bus", &parsed.name);
                    // code_success + ok:false: the renderer bus treats code_error as
                    // an exception path and floods console; success envelope with an
                    // unhandled marker keeps call sites on their benign branch.
                    json!({ "ok": false, "__unhandled": parsed.name, "error": format!("unhandled:{}", parsed.name) })
                }
            };
            let reply = json!({
                "callbackId": parsed.callback_id,
                "code": "code_success",
                "data": data,
                "sync": parsed.sync,
            });
            crate::gui::bus_publish(RENDERER_EVENT, reply);
            json!({ "ok": true })
        }
        // Fire-and-forget `ipcRenderer.send` on any non-bus channel: recorded.
        "ipc_send" => {
            let channel = args.get("channel").and_then(Value::as_str).unwrap_or("");
            audit_record("send", channel);
            json!({ "ok": true })
        }
        // Console bridge: remote clients mirror batched logs onto the host
        // log so boot diagnostics are capturable without devtools.
        "console_log" => {
            if let Some(lines) = args.get("batch").and_then(Value::as_array) {
                for line in lines {
                    let level = line.get("level").and_then(Value::as_str).unwrap_or("log");
                    let text = line.get("text").and_then(Value::as_str).unwrap_or("");
                    tracing::info!("[renderer:{level}] {text}");
                }
            }
            json!({ "ok": true })
        }
        // `shell.openExternal` bridge: URLs are validated and logged, never
        // launched from the server side.
        "open_external" => {
            let url = args.get("url").and_then(Value::as_str).unwrap_or("");
            if !(url.starts_with("http://")
                || url.starts_with("https://")
                || url.starts_with("mailto:"))
            {
                tracing::warn!("[ipc] open_external refused non-web url: {url}");
                return json!({ "ok": false, "error": "non-web url refused" });
            }
            tracing::info!("[ipc] open_external (browser-side) {url}");
            json!({ "ok": true })
        }
        // Debug helper: channels hit but not served yet (feeds GUI.md §3).
        "ipc_registry" => Value::Array(audit_snapshot()),

        // ---- panel product channels (contract) -----------------------------
        "repl_exec" => {
            let line = args.get("line").and_then(Value::as_str).unwrap_or("");
            repl_exec_line(line)
        }
        "cast_push" => {
            let key = args.get("key").and_then(Value::as_str).unwrap_or("");
            let value = args.get("value").and_then(Value::as_str).unwrap_or("");
            crate::gui::cast::cast_push(key, value)
        }
        "odmf_start" => crate::gui::cast::odmf_start(),
        "kms_bootstrap" => dispatch_kms(device_ip(&args)),
        "lplus_status" => crate::gui::cast::status_json(),
        "settings_set_host_name" => {
            let name = args
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string();
            if name.is_empty() {
                return json!({ "ok": false, "error": "missing name" });
            }
            set_host_name(&name);
            json!({ "ok": true, "name": name })
        }
        // Renderer (or direct) Connect/Disconnect entry points.
        "connect_device" => dispatch_device("connect_device", device_ip(&args)),
        "disconnect_device" => dispatch_device("disconnect_device", device_ip(&args)),
        other => {
            audit_record("unknown-cmd", other);
            unhandled(other)
        }
    }
}

fn device_ip(args: &Value) -> String {
    args.get("ip")
        .and_then(Value::as_str)
        .or_else(|| args.as_str())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Serializes the tests that read/write the shared `HOST_NAME` static.
    static HOST_TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(Mutex::default);

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
        assert_eq!(v["ok"], json!(true), "{v}");
        let out = v["out"].as_array().expect("out array");
        assert_eq!(out.len(), 2, "{v}");
        assert_eq!(out[0], json!("peers 1"));
        assert!(out[1].as_str().unwrap().contains("46888"));
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
        assert_eq!(v["ok"], json!(false));
        assert!(v["error"].as_str().unwrap().contains("repl connect"));
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
