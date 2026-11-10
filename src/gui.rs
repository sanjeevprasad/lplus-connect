//! GUI of the unified `lplus` binary: the desktop UI is the GPUI window
//! (`src/ui/`), which dispatches into the backend in-process. The same
//! surface is exposed over a loopback HTTP server (`server.rs`) for attach
//! mode and probing: `POST /__ipc` (JSON `{cmd,args}` → `ipc::dispatch`),
//! `GET /__events` (SSE) plus `/__log`, `/__devices` and `/__capture/*`.
//! Every webview-era push (bus replies, device rows) travels on the
//! process-global `GUI_BUS` below and reaches subscribers through SSE.
//!
//! Backend and UI are fully decoupled: the daemon runs in-process
//! (`crate::sdpd::run` on its own tokio runtime), and the device model
//! (`devices.rs`) is fed purely by the backend's `DeviceEvent` broadcast.
//!
//! See `../GUI.md` for the vendored-renderer port and the full IPC channel
//! registry.

pub mod api;
pub mod cast;
pub mod devices;
pub(crate) mod ipc;
mod server;

use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::sdpd::SdpdConfig;

const POLL_INTERVAL: Duration = Duration::from_millis(300);

/// In-process backend liveness (surfaced by `lplus_sidecar_status`).
static BACKEND_UP: AtomicBool = AtomicBool::new(false);

pub fn backend_up() -> bool {
    BACKEND_UP.load(Ordering::Relaxed)
}

// ------------------------------------------------------------------ bus
/// UI-bound traffic as `{channel, payload}` envelopes. Producers:
/// `ipc::dispatch` bus replies (`channel = "ipc_renderer_event"`) and
/// `devices::tick` row pushes. Consumer: the SSE stream (`GET /__events`).
static GUI_BUS: LazyLock<broadcast::Sender<Value>> = LazyLock::new(|| broadcast::channel(256).0);

/// Publish one UI-bound frame on the GUI bus.
pub(crate) fn bus_publish(channel: &str, payload: Value) {
    let _ = GUI_BUS.send(json!({ "channel": channel, "payload": payload }));
}

/// True while any UI consumer (SSE client) is attached — lets
/// `devices::tick` stay silent when nobody could receive a push.
pub(crate) fn bus_has_listeners() -> bool {
    GUI_BUS.receiver_count() > 0
}

/// Attach a new bus consumer (SSE handler).
pub(crate) fn bus_subscribe() -> broadcast::Receiver<Value> {
    GUI_BUS.subscribe()
}

/// Spawn the backend on its own tokio runtime. `main` has already run
/// `preflight_or_die`, so a bind failure here means the ports were taken
/// after the check: fail loudly, never defer.
fn start_backend(cfg: SdpdConfig) {
    BACKEND_UP.store(true, Ordering::Relaxed);
    thread::Builder::new()
        .name("backend".into())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("backend tokio runtime");
            if rt.block_on(crate::sdpd::run(cfg)).is_err() {
                BACKEND_UP.store(false, Ordering::Relaxed);
                std::process::exit(1);
            }
        })
        .expect("spawn backend thread");
}

/// Background pump: rate-limited device bus pushes even when no command is
/// in flight.
fn spawn_poller(stop: Arc<AtomicBool>) {
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            thread::sleep(POLL_INTERVAL);
            devices::tick();
        }
    });
}

/// Bring up every daemon-side piece: device registry (presence + adb lanes),
/// the loopback server, the backend lanes and the push poller. Non-blocking;
/// everything runs on its own threads. Returns the loopback port.
pub fn start(cfg: SdpdConfig) -> Result<u16, String> {
    devices::init();
    let port = server::spawn()?;
    start_backend(cfg);
    spawn_poller(Arc::new(AtomicBool::new(false)));
    Ok(port)
}

/// `lplus panel` product entry: backend + HTTP seam only (no window) —
/// attach clients and scripts drive everything through `/__ipc` and
/// `/__events`. Blocks until the process is killed.
pub fn serve(cfg: SdpdConfig) -> Result<(), String> {
    let port = start(cfg)?;
    let url = format!("http://127.0.0.1:{port}/");
    tracing::info!("[gui] serving {url} (seam at /__ipc + /__events)");
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
