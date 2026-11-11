//! The independent service lanes of `lplus`: every phone-facing listener
//! (SDP/UNI responder, SCP session server, EPI datatrans, KMS, WFD sink,
//! events bridge) and the machine-facing gRPC contract server. Each lane
//! owns its bind and accept loop; protocol engines live with their lane.
pub mod contract;
pub mod epi;
pub mod events;
pub mod kms;
pub mod scp_server;
pub mod sdp;
pub mod wfd;

pub use sdp::SdpdConfig;

/// Start every lane except the contract server (which binds on its own
/// runtime in [`crate::backend`]) and park in the SDP responder loop.
/// Call from a tokio runtime context.
pub async fn run_all(cfg: SdpdConfig) -> anyhow::Result<()> {
    events::spawn();
    let kms_port = std::env::var("KMS_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(36863u16);
    let kms_pwd = std::env::var("KMS_PWD").unwrap_or_else(|_| "lplus-kms-pw".into());
    epi::spawn_command_runner(cfg.name.clone(), kms_pwd.clone(), cfg.vip.clone(), kms_port);
    let log_path = cfg.log_path.clone();
    if std::env::var("KMS").is_ok() {
        kms::spawn_server(kms_port, kms_pwd, log_path.clone());
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
        wfd::spawn(listen, out, respond);
    }
    sdp::run(cfg).await
}
