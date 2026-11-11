//! The independent service lanes of `lplus`: every phone-facing listener
//! (SDP/UNI responder + SCP session server, EPI datatrans, KMS, WFD sink,
//! events bridge) and the machine-facing gRPC contract server. Each lane
//! is a self-contained `Arc`-owned struct; shared registries (live EPI
//! sinks, the command bus, presence) hang off the owning service, and
//! [`Services`] wires them together.
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub mod contract;
pub mod epi;
pub mod events;
pub mod kms;
pub mod scp_server;
pub mod sdp;
pub mod wfd;

pub use epi::Epi;
pub use sdp::{Sdp, SdpdConfig};

/// The daemon's service graph: one instance, shared by every lane and by
/// the contract server.
pub struct Services {
    pub sdp: Arc<Sdp>,
    pub epi: Arc<Epi>,
    /// In-process backend liveness (surfaced by `lplus_sidecar_status`).
    pub up: AtomicBool,
}

impl Services {
    pub fn new(cfg: SdpdConfig) -> Arc<Self> {
        let epi = Epi::new();
        let sdp = Sdp::new(cfg, epi.clone());
        Arc::new(Self {
            sdp,
            epi,
            up: AtomicBool::new(false),
        })
    }

    /// Start every lane except the contract server (which binds on its
    /// own runtime in [`crate::backend`]) and park in the SDP responder
    /// loop. Call from a tokio runtime context.
    pub async fn run(self: &Arc<Self>) -> anyhow::Result<()> {
        events::EventsBridge::new(self.sdp.clone()).spawn();
        let log_path = self.sdp.cfg().log_path.clone();
        let kms_port = std::env::var("KMS_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(36863u16);
        let kms_pwd = std::env::var("KMS_PWD").unwrap_or_else(|_| "lplus-kms-pw".into());
        if std::env::var("KMS").is_ok() {
            kms::Kms::new(kms_port, kms_pwd, log_path.clone(), self.sdp.clone()).spawn();
        }
        if std::env::var("ODMF_SINK").is_ok() {
            let listen: std::net::SocketAddr = std::env::var("ODMF_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:7236".into())
                .parse()
                .unwrap_or(([0, 0, 0, 0], 7236).into());
            let out = std::env::var("ODMF_OUT").unwrap_or_else(|_| "../capture".into());
            let respond = std::env::var("ODMF_RESPOND")
                .map(|v| v != "0")
                .unwrap_or(true);
            wfd::Wfd::new(listen, out, respond).spawn();
        }
        Epi::spawn_runner(self);
        self.sdp.run().await
    }
}
