//! Backend orchestration of the unified `lplus` binary. The machine-facing
//! surface is the loopback gRPC contract server (`crate::contract`):
//! `service Lplusd` from `ipc/protos/lplus.proto` over tonic on
//! `127.0.0.1:1421`, strictly typed. The GPUI window (`ui/`) revives onto
//! that contract with the generated client, not another in-process seam;
//! the webview-era GUI bus push lane was cut with it.
//!
//! The daemon runs in-process (`crate::sdpd::run` on its own tokio
//! runtime), and the device model (`devices.rs`) is fed purely by the
//! backend's `DeviceEvent` broadcast.
//!
//! See `../GUI.md` for the vendored-renderer port and the contract.

pub mod api;
pub mod cast;
pub mod devices;
pub(crate) mod ipc;

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::sdpd::SdpdConfig;

/// In-process backend liveness (surfaced by `lplus_sidecar_status`).
static BACKEND_UP: AtomicBool = AtomicBool::new(false);

pub fn backend_up() -> bool {
    BACKEND_UP.load(Ordering::Relaxed)
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

/// Bring up every daemon-side piece: device registry (presence + adb
/// lanes), the loopback contract server and the backend lanes.
/// Non-blocking; everything runs on its own threads. Returns the loopback
/// port.
pub fn start(cfg: SdpdConfig) -> Result<u16, String> {
    devices::init();
    let port = crate::contract::spawn()?;
    start_backend(cfg);
    Ok(port)
}

/// `lplus panel` product entry: backend + contract server only (no
/// window) — attach clients and scripts drive everything through the
/// gRPC contract. Blocks until the process is killed.
pub fn serve(cfg: SdpdConfig) -> Result<(), String> {
    let port = start(cfg)?;
    tracing::info!(
        "[gui] serving contract server 127.0.0.1:{port} (grpc: lplus.backend.v1.Lplusd)"
    );
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
