//! Backend orchestration of the unified `lplus` binary: the daemon
//! threads (`crate::svc::run_all` on its own tokio runtime, with the device
//! model in `devices` fed purely by the `DeviceEvent` broadcast) plus the
//! loopback gRPC contract server (`crate::contract`): `service Lplusd`
//! from `ipc/protos/lplus.proto` over tonic on `127.0.0.1:1421`,
//! strictly typed. Everything machine-facing — including future UIs —
//! drives that contract with the generated client, never an in-process
//! seam. See `../GUI.md` for the contract reference.

pub mod api;
pub mod cast;
pub mod devices;
pub(crate) mod ipc;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

use crate::svc::{Services, sdp::SdpdConfig};

/// Spawn the services on their own tokio runtime. `main` has already run
/// `preflight_or_die`, so a bind failure here means the ports were taken
/// after the check: fail loudly, never defer.
fn start_backend(services: Arc<Services>) {
    services.up.store(true, Ordering::Relaxed);
    thread::Builder::new()
        .name("backend".into())
        .spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("backend tokio runtime");
            if let Err(e) = rt.block_on(services.run()) {
                tracing::error!("[backend] services stopped: {e:#}");
                services.up.store(false, Ordering::Relaxed);
                std::process::exit(1);
            }
        })
        .expect("spawn backend thread");
}

/// Bring up every daemon-side piece: the service graph (SDP/SCP/EPI/KMS/
/// WFD/events lanes), the device registry (presence + adb lanes) fed by
/// the SDP service's `DeviceEvent` broadcast, and the loopback contract
/// server. Non-blocking; everything runs on its own threads. Returns the
/// contract port.
pub fn start(cfg: SdpdConfig) -> Result<u16, String> {
    let services = Services::new(cfg);
    devices::init(&services.sdp);
    let port = crate::svc::contract::spawn(services.clone())?;
    start_backend(services.clone());
    // Presence mirror to stdout; on its own tiny runtime so lanes stay
    // independent.
    let sdp = services.sdp.clone();
    thread::Builder::new()
        .name("presence-log".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("presence log runtime");
            rt.block_on(async move {
                let mut rx = sdp.subscribe_devices();
                while let Ok(ev) = rx.recv().await {
                    devices::log_event(ev.kind, &ev.ip, ev.name.as_deref(), ev.connected, ev.ts_ms);
                }
            });
        })
        .map_err(|e| format!("spawn presence logger: {e}"))?;
    Ok(port)
}

/// Product entry: backend + contract server. Attach clients and scripts
/// drive everything through the gRPC contract. Blocks until killed.
pub fn serve(cfg: SdpdConfig) -> Result<(), String> {
    let port = start(cfg)?;
    tracing::info!(
        "[backend] serving contract server 127.0.0.1:{port} (grpc: lplus.backend.v1.Lplusd)"
    );
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
