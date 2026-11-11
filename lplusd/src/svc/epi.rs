//! EPI session lane: the phone's datatrans servers (`:46888/47888/48888`),
//! the live-sink registry the contract's frame injection writes through,
//! and the command bus every machine-side trigger (connect, disconnect,
//! KMS bootstrap, RPC candidate push, raw inject) flows over.
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use tokio::sync::Mutex;

use crate::config::{csv, flag, hex_num, num, str_of};
use crate::svc::Services;
use crate::svc::sdp::Sdp;

/// Control plane: gRPC contract clients drive the phone through the
/// backend (LAN SCP dial, EPI sink push) instead of touching the transport
/// themselves.
#[derive(Debug, Clone)]
pub enum Command {
    /// Drive the phone's PC-panel row for our advertised name (AppFunction).
    Connect {
        ip: String,
    },
    Disconnect {
        ip: String,
    },
    /// Push the CastMessage msg_type=61 DataBus bootstrap on the live
    /// :46888 session so the phone dials our KMS server.
    KmsBootstrap {
        ip: String,
    },
    /// Inject the RpcFrame candidate set (compat-scp + cpbus.networking
    /// connect/acceptConnection) onto every live :46888 session.
    RpcConnect {
        ip: String,
    },
    /// Inject raw bytes onto every EPI sink whose key contains the
    /// substring (the DataBus cast lane pushes its DbsMessage frames this
    /// way; the gRPC boundary hex-decodes at the edge).
    SendFrame {
        key_substr: String,
        bytes: Vec<u8>,
    },
}

/// Live EPI sessions: injection handles and the pump-task abort handles a
/// contract `Disconnect` needs to close our side of the vendor session
/// (FIN/RST), not just push a DISCONNECT frame the phone may ignore.
pub struct Epi {
    /// Key: `"{port} {peer}"`; consumers unregister on socket death.
    sinks: Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
    killers: std::sync::Mutex<HashMap<String, Vec<tokio::task::AbortHandle>>>,
    cmd_tx: tokio::sync::broadcast::Sender<Command>,
}

impl Epi {
    pub fn new() -> Arc<Self> {
        let (cmd_tx, _) = tokio::sync::broadcast::channel(32);
        Arc::new(Self {
            sinks: Mutex::default(),
            killers: std::sync::Mutex::default(),
            cmd_tx,
        })
    }

    pub fn send(&self, cmd: Command) -> bool {
        self.cmd_tx.send(cmd).is_ok()
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Command> {
        self.cmd_tx.subscribe()
    }

    pub async fn sink_keys(&self) -> Vec<String> {
        self.sinks.lock().await.keys().cloned().collect()
    }

    /// Non-blocking snapshot for the synchronous dispatch table.
    pub fn try_sink_keys(&self) -> Vec<String> {
        self.sinks
            .try_lock()
            .map(|s| s.keys().cloned().collect())
            .unwrap_or_default()
    }

    pub async fn push_matching(&self, substr: &str, bytes: &[u8]) -> usize {
        let mut sent = 0usize;
        for (k, tx) in self.sinks.lock().await.iter() {
            if k.contains(substr) && tx.send(bytes.to_vec()).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    pub async fn register_sink(
        &self,
        key: String,
        tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) {
        self.sinks.lock().await.insert(key, tx);
    }

    pub async fn unregister_sink(&self, key: &str) {
        self.sinks.lock().await.remove(key);
    }

    /// Drop every injection handle whose key mentions `ip` (disconnect:
    /// lanes observing the closed channel end themselves).
    pub async fn drop_for(&self, ip: &str) -> usize {
        let mut sinks = self.sinks.lock().await;
        let before = sinks.len();
        sinks.retain(|k, _| !k.contains(ip));
        before - sinks.len()
    }

    pub fn register_killer(&self, ip: &str, handle: tokio::task::AbortHandle) {
        if let Ok(mut m) = self.killers.lock() {
            let v = m.entry(ip.to_string()).or_default();
            v.retain(|h| !h.is_finished());
            v.push(handle);
            tracing::info!("[tcp] session pump registered for {ip} (n={})", v.len());
        }
    }

    pub fn abort_sessions(&self, ip: &str) -> usize {
        let killers = self
            .killers
            .lock()
            .map(|m| m.get(ip).cloned().unwrap_or_default())
            .unwrap_or_default();
        let mut closed = 0usize;
        for h in killers {
            if !h.is_finished() {
                h.abort();
                closed += 1;
            }
        }
        closed
    }

    /// Bind the EPI session ports and hand every accepted socket to the
    /// shared session pump (protocol handling is gated by `EPI=1`; without
    /// it sessions are recorded only).
    pub(crate) async fn bind_sessions(
        sdp: &Arc<Sdp>,
        ports: &[u16],
        epi_mode: bool,
    ) -> anyhow::Result<()> {
        for &p in ports {
            let listener = tokio::net::TcpListener::bind(("0.0.0.0", p))
                .await
                .with_context(|| format!("tcp bind :{p}"))?;
            let sdp = sdp.clone();
            tokio::spawn(async move {
                loop {
                    if let Ok((sock, peer)) = listener.accept().await {
                        tracing::info!("[epi] accept :{p} <- {peer}");
                        sdp.clone().spawn_session_logger(sock, peer, epi_mode, p);
                    }
                }
            });
        }
        Ok(())
    }

    /// Consume the command bus: the machine-side triggers execute against
    /// the live sessions (sinks, killers) and the SDP plane (phone
    /// resolution, presence emission).
    pub(crate) fn spawn_runner(services: &Arc<Services>) {
        let services = services.clone();
        tokio::spawn(async move {
            let sdp = services.sdp.clone();
            let epi = services.epi.clone();
            let mut rx = epi.subscribe();
            while let Ok(cmd) = rx.recv().await {
                match cmd {
                    Command::Connect { ip } => {
                        let ip = sdp.resolve_phone_ip(&ip);
                        crate::scpc::spawn_dial(ip.clone(), sdp.cfg.name.clone(), sdp.gcfg.clone());
                        // Paired-idle case: the phone's :46888 acceptor is
                        // armed while paired, so dial it ourselves and run
                        // the client PD/AUTH/capex legs; on success the pump
                        // pushes the bootstrap + RpcFrames on its own session
                        // and stays live as an injection sink.
                        let sdp_dial = sdp.clone();
                        let ip_dial = ip.clone();
                        tokio::spawn(async move {
                            match crate::scpc::dial_epi(&sdp_dial, &ip_dial).await {
                                Ok(()) => tracing::info!("[epic] {ip_dial} pc-dial session ended"),
                                Err(e) => {
                                    tracing::warn!("[epic] {ip_dial} pc-dial FAILED: {e:#}")
                                }
                            }
                        });
                        // Session lane (proven): KMS bootstrap DataBus push is
                        // the trigger the phone's engine acts on (it dialed our
                        // :10152 with a completed handshake after this frame,
                        // PROTOCOL §7.2), and the RpcFrame candidate set rides
                        // the same live :46888 session (§7.10). Both no-op with
                        // no live session; the direct dial above covers that.
                        let _ = epi.send(Command::KmsBootstrap { ip: ip.clone() });
                        let _ = epi.send(Command::RpcConnect { ip });
                    }
                    Command::Disconnect { ip } => {
                        let ip = sdp.resolve_phone_ip(&ip);
                        // Vendor disconnect = cpbus DISCONNECT (msgType 65535)
                        // on the live session lanes; no live lane → no-op.
                        let frame = crate::scp::msg_frame(65535, Vec::new());
                        let sent = epi.push_matching(&ip, &frame).await;
                        epi.drop_for(&ip).await;
                        // Close our side of every live session with this peer
                        // so the phone sees the link actually go down (a
                        // DISCONNECT frame alone leaves the vendor UI at
                        // "Connected").
                        let closed = epi.abort_sessions(&ip);
                        sdp.emit_device("epi", ip.clone(), None, false);
                        tracing::info!(
                            "[cmd] disconnect {ip}: DISCONNECT pushed to {sent} sink(s), {closed} session(s) closed"
                        );
                    }
                    Command::RpcConnect { ip } => {
                        let ip = sdp.resolve_phone_ip(&ip);
                        let epi = epi.clone();
                        tokio::spawn({
                            let sdp = sdp.clone();
                            async move {
                                let phone_dev = crate::svc::sdp::ksc_bond(&ip)
                                    .map(|r| r.device_id)
                                    .unwrap_or_default();
                                for (label, wire) in
                                    crate::scpc::rpc_frames(&ip, &phone_dev, &sdp.gcfg)
                                {
                                    let sent = epi.push_matching("46888", &wire).await;
                                    tracing::info!("[cmd] rpc {label}: pushed to {sent} sink(s)");
                                    if sent == 0 {
                                        break;
                                    }
                                    tokio::time::sleep(std::time::Duration::from_millis(1200))
                                        .await;
                                }
                            }
                        });
                    }
                    Command::KmsBootstrap { ip } => {
                        let from = "A1B2C3D4E5F6";
                        // Destination must be the phone's bonded device id
                        // (dbr.a `to`/dest list gate, PROTOCOL §7.11); the
                        // vendor constant only as fallback.
                        let to = sdp
                            .gcfg
                            .link
                            .kpd
                            .first()
                            .map(|v| String::from_utf8_lossy(v).to_string())
                            .or_else(|| crate::svc::sdp::ksc_bond(&ip).map(|r| r.device_id))
                            .unwrap_or_else(|| "0123456789AB".into());
                        // Fresh port for this bootstrap (stale same-port
                        // guard, see Sdp::begin_kms_session).
                        sdp.begin_kms_session();
                        match sdp.kms_bootstrap_frame(from, &to) {
                            Ok(frame) => {
                                let sent = epi.push_matching("46888", &frame).await;
                                if sent == 0 {
                                    tracing::info!(
                                        "[cmd] kms bootstrap {ip}: no live :46888 sink (frame {}B dropped)",
                                        frame.len()
                                    );
                                } else {
                                    crate::svc::sdp::record(
                                        sdp.gcfg.dev.record_path.as_deref().unwrap_or_default(),
                                        "cmd-kms-bootstrap",
                                        &frame,
                                    );
                                    tracing::info!(
                                        "[cmd] kms bootstrap {ip}: pushed {}B to {sent} sink(s)",
                                        frame.len()
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("[cmd] kms bootstrap {ip} build FAILED: {e:#}")
                            }
                        }
                    }
                    Command::SendFrame { key_substr, bytes } => {
                        let sent = epi.push_matching(&key_substr, &bytes).await;
                        tracing::info!(
                            "[cmd] send {key_substr:?}: {sent} sink(s) {}B",
                            bytes.len()
                        );
                    }
                }
            }
        });
    }
}

// ==== service configuration (env keys read once at startup) ====

/// DataBus/EPI server + PC-dialed client lanes (`EPI*`).
#[derive(Debug, Clone)]
pub struct EpiConfig {
    /// `EPI`: bind the datatrans/EPI server lanes.
    pub enabled: bool,
    /// `EPI_DIAL_PORT`: the PC-dialed EPI client port on the phone.
    pub dial_port: u16,
    /// `EPI_FRAMING`: `connector`|`raw3`|`3b`.
    pub framing: String,
    /// `EPI_CAPEX`: run the capability-exchange leg (default on).
    pub capex: bool,
    /// `EPI_CAPEX_FRAME`: `sess` (session-wrapped) or `bare`.
    pub capex_frame: String,
    /// `EPI_CAPEX_PROFILES`: accessory profiles we register.
    pub capex_profiles: Vec<String>,
    /// `EPI_AUTH_RESP`: AUTH_RESPONSE FrameType byte (hex).
    pub auth_resp: u8,
    /// `EPI_AUTH_ACK`: confirm echo after rc_2 verifies (hex, 0 = off).
    pub auth_ack: u8,
    /// `EPI_TYPE` / `EPI_PROTO`: PD-offer msgType / protocol version.
    pub offer_type: u8,
    pub offer_proto: u16,
    /// `EPI_PEERID`: 36B peer id presented in the PD offer.
    pub peer_id: String,
    /// `EPI_MSG`: raw hex override for the whole PD offer frame.
    pub msg_override: Option<String>,
    /// `EPI_CAPEX_DIAL`: also run capex right after dialing this port.
    pub capex_dial: Option<u16>,
}

impl Default for EpiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dial_port: 46888,
            framing: "connector".into(),
            capex: true,
            capex_frame: "sess".into(),
            capex_profiles: [
                "com.oplus.pantaconnect.globaldevice.discovery",
                "uuid.icdf.service1",
                "app:oplus.pantaconnect.app_service",
                "vdc.service.sync",
                "oaf.service.iphone.call",
                "icdf.videocall.service",
            ]
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
            auth_resp: 0x11,
            auth_ack: 0x12,
            offer_type: 1,
            offer_proto: 10,
            peer_id: "A1B2C3D4E5F6".repeat(3),
            msg_override: None,
            capex_dial: None,
        }
    }
}

// -- EpiConfig --
impl EpiConfig {
    pub fn load() -> Self {
        let d = Self::default();
        Self {
            enabled: flag("EPI", d.enabled),
            dial_port: num("EPI_DIAL_PORT", d.dial_port),
            framing: str_of("EPI_FRAMING", &d.framing),
            capex: flag("EPI_CAPEX", d.capex),
            capex_frame: str_of("EPI_CAPEX_FRAME", &d.capex_frame),
            capex_profiles: csv("EPI_CAPEX_PROFILES").unwrap_or(d.capex_profiles),
            auth_resp: hex_num("EPI_AUTH_RESP", d.auth_resp),
            auth_ack: hex_num("EPI_AUTH_ACK", d.auth_ack),
            offer_type: num("EPI_TYPE", d.offer_type),
            offer_proto: num("EPI_PROTO", d.offer_proto),
            peer_id: str_of("EPI_PEERID", &d.peer_id),
            msg_override: std::env::var("EPI_MSG").ok().filter(|s| !s.is_empty()),
            capex_dial: std::env::var("EPI_CAPEX_DIAL")
                .ok()
                .and_then(|s| s.trim().parse().ok()),
        }
    }
}
