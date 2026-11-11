//! The independent service lanes of `lplus`: every phone-facing listener
//! (SDP/UNI responder + SCP session server, EPI datatrans, KMS, WFD sink,
//! events bridge) and the machine-facing gRPC contract server. Each lane
//! is a self-contained `Arc`-owned struct; shared registries (live EPI
//! sinks, the command bus, presence) hang off the owning service, and
//! [`Services`] wires them together.
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub mod autolink;
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
        let log_path = self.sdp.cfg.log_path.clone();
        let kms_pwd = self.sdp.gcfg.kms.pwd.clone();
        if self.sdp.gcfg.kms.enabled {
            // One listener per bootstrap-port candidate: the bootstrap
            // rotates `kms_socket_port` per session (Sdp::begin_kms_session)
            // to defeat the phone's stale same-port start() guard, so all
            // span ports must be listening.
            let base = self.sdp.gcfg.kms.port_base;
            for i in 0..self.sdp.kms_port_span() {
                kms::Kms::new(
                    base + i,
                    kms_pwd.clone(),
                    log_path.clone(),
                    self.sdp.clone(),
                )
                .spawn();
            }
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
        if self.sdp.gcfg.autolink.enabled {
            autolink::spawn(self.sdp.clone(), self.epi.clone());
        }
        self.sdp.run().await
    }
}
