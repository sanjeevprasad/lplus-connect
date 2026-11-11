//! EPI session lane: the phone's datatrans servers (`:46888/47888/48888`),
//! the live-sink registry the contract's frame injection writes through,
//! and the command bus every machine-side trigger (connect, disconnect,
//! KMS bootstrap, RPC candidate push, raw inject) flows over.
use std::collections::HashMap;

use anyhow::Context;

use crate::svc::sdp::{emit_device, kms_bootstrap_frame, record, resolve_phone_ip};

/// Live TCP sink registry: every accepted EPI session registers an
/// injection handle so command frames (DISCONNECT, KMS bootstrap,
/// RpcFrame) can be written onto the open socket without a re-handshake.
/// Key: `"{epi_port} {peer}"`; consumers unregister on socket death.
pub(crate) static EPI_SINKS: std::sync::LazyLock<
    tokio::sync::Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<Vec<u8>>>>,
> = std::sync::LazyLock::new(tokio::sync::Mutex::default);

/// Abort handles for the live session pump tasks, per peer IP: a contract
/// `Disconnect` must close our side of the vendor session (FIN/RST), not
/// just push a DISCONNECT frame the phone may ignore.
pub(crate) static SESSION_KILLERS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, Vec<tokio::task::AbortHandle>>>,
> = std::sync::LazyLock::new(std::sync::Mutex::default);

/// Control plane: gRPC contract clients drive
/// the phone through the backend (LAN SCP dial, EPI sink push) instead of
/// touching the transport themselves.
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
    /// Inject raw hex onto every EPI sink whose key contains the substring
    /// (the DataBus cast lane pushes its DbsMessage frames this way).
    SendFrame {
        key_substr: String,
        hex: String,
    },
}

static CMD_TX: std::sync::LazyLock<tokio::sync::broadcast::Sender<Command>> =
    std::sync::LazyLock::new(|| tokio::sync::broadcast::channel(32).0);

pub fn send_command(cmd: Command) -> bool {
    CMD_TX.send(cmd).is_ok()
}

pub fn subscribe_commands() -> tokio::sync::broadcast::Receiver<Command> {
    CMD_TX.subscribe()
}

pub(crate) fn spawn_command_runner(
    dev_name: String,
    kms_pwd: String,
    local_ip: String,
    kms_port: u16,
) {
    tokio::spawn(async move {
        let mut rx = subscribe_commands();
        while let Ok(cmd) = rx.recv().await {
            match cmd {
                Command::Connect { ip } => {
                    let ip = resolve_phone_ip(&ip);
                    crate::scpc::spawn_dial(ip.clone(), dev_name.clone());
                    // Session lane (proven): KMS bootstrap DataBus push is
                    // the trigger the phone's engine acts on (it dialed our
                    // :10152 with a completed handshake after this frame,
                    // PROTOCOL §7.2), and the RpcFrame candidate set rides
                    // the same live :46888 session (§7.10). Both no-op with
                    // no live session; the direct dial above covers that.
                    let _ = send_command(Command::KmsBootstrap { ip: ip.clone() });
                    let _ = send_command(Command::RpcConnect { ip });
                }
                Command::Disconnect { ip } => {
                    let ip = resolve_phone_ip(&ip);
                    // Vendor disconnect = cpbus DISCONNECT (msgType 65535)
                    // on the live session lanes; no live lane → no-op.
                    let frame = crate::scp::msg_frame(65535, Vec::new());
                    let mut sent = 0usize;
                    {
                        let mut sinks = EPI_SINKS.lock().await;
                        for (k, tx) in sinks.iter() {
                            if k.contains(&ip) && tx.send(frame.clone()).is_ok() {
                                sent += 1;
                            }
                        }
                        // Drop our injection handles for this peer; lanes
                        // that observe the closed channel end themselves.
                        sinks.retain(|k, _| !k.contains(&ip));
                    }
                    // Close our side of every live session with this peer so
                    // the phone sees the link actually go down (a DISCONNECT
                    // frame alone leaves the vendor UI at "Connected").
                    let killers = SESSION_KILLERS
                        .lock()
                        .map(|m| m.get(&ip).cloned().unwrap_or_default())
                        .unwrap_or_default();
                    let mut closed = 0usize;
                    for h in killers {
                        if !h.is_finished() {
                            h.abort();
                            closed += 1;
                        }
                    }
                    emit_device("epi", ip.clone(), None, false);
                    tracing::info!(
                        "[cmd] disconnect {ip}: DISCONNECT pushed to {sent} sink(s), {closed} session(s) closed"
                    );
                }
                Command::RpcConnect { ip } => {
                    let ip = resolve_phone_ip(&ip);
                    tokio::spawn(async move {
                        for (label, wire) in crate::scpc::rpc_frames(&ip) {
                            let mut sent = 0usize;
                            for (k, tx) in EPI_SINKS.lock().await.iter() {
                                if k.contains("46888") && tx.send(wire.clone()).is_ok() {
                                    sent += 1;
                                }
                            }
                            tracing::info!("[cmd] rpc {label}: pushed to {sent} sink(s)");
                            if sent == 0 {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
                        }
                    });
                }
                Command::KmsBootstrap { ip } => {
                    let from =
                        std::env::var("LINK_DET_PEER").unwrap_or_else(|_| "A1B2C3D4E5F6".into());
                    let to = std::env::var("LINK_KPD")
                        .ok()
                        .and_then(|s| s.split(',').next().map(str::to_string))
                        .unwrap_or_else(|| "0123456789AB".into());
                    match kms_bootstrap_frame(kms_port, &kms_pwd, &local_ip, &from, &to) {
                        Ok(frame) => {
                            let mut sent = 0usize;
                            for (k, tx) in EPI_SINKS.lock().await.iter() {
                                if k.contains("46888") && tx.send(frame.clone()).is_ok() {
                                    sent += 1;
                                }
                            }
                            if sent == 0 {
                                tracing::info!(
                                    "[cmd] kms bootstrap {ip}: no live :46888 sink (frame {}B dropped)",
                                    frame.len()
                                );
                            } else {
                                record(
                                    &std::env::var("LPLUS_LOG").unwrap_or_default(),
                                    "cmd-kms-bootstrap",
                                    &frame,
                                );
                                tracing::info!(
                                    "[cmd] kms bootstrap {ip}: pushed {}B to {sent} sink(s)",
                                    frame.len()
                                );
                            }
                        }
                        Err(e) => tracing::warn!("[cmd] kms bootstrap {ip} build FAILED: {e:#}"),
                    }
                }
                Command::SendFrame { key_substr, hex } => match hex::decode(hex.trim()) {
                    Ok(bytes) => {
                        let mut sent = 0usize;
                        for (k, tx) in EPI_SINKS.lock().await.iter() {
                            if k.contains(&key_substr) && tx.send(bytes.clone()).is_ok() {
                                sent += 1;
                            }
                        }
                        tracing::info!(
                            "[cmd] send {key_substr:?}: {sent} sink(s) {}B",
                            bytes.len()
                        );
                    }
                    Err(e) => tracing::info!("[cmd] send {key_substr:?} bad hex: {e}"),
                },
            }
        }
    });
}

/// Bind the EPI session ports and hand every accepted socket to the
/// shared session pump (protocol handling is gated by `EPI=1`; without it
/// sessions are recorded only).
pub(crate) async fn bind_sessions(
    ports: &[u16],
    log_path: String,
    dev_name: String,
    probe_reg: std::sync::Arc<Vec<u8>>,
) -> anyhow::Result<()> {
    let epi = std::env::var("EPI").is_ok();
    for &p in ports {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", p))
            .await
            .with_context(|| format!("tcp bind :{p}"))?;
        let log_path = log_path.clone();
        let dev_name = dev_name.clone();
        let probe_reg = (*probe_reg).clone();
        tokio::spawn(async move {
            loop {
                if let Ok((sock, peer)) = listener.accept().await {
                    tracing::info!("[epi] accept :{p} <- {peer}");
                    crate::svc::sdp::spawn_session_logger(
                        sock,
                        peer,
                        log_path.clone(),
                        dev_name.clone(),
                        probe_reg.clone(),
                        epi,
                        p,
                    );
                }
            }
        });
    }
    Ok(())
}
