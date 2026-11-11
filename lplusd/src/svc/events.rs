//! Events bridge: NDJSON presence feed on `LPLUS_EVENTS_PORT` for
//! loopback subscribers (a sidecar need not link the daemon).
use std::sync::Arc;

use crate::svc::sdp::Sdp;

/// NDJSON bridge for `LPLUS_EVENTS_PORT`: one DeviceEvent JSON per line to
/// every loopback subscriber. Lets a sidecar (not just in-proc) consume.
pub struct EventsBridge {
    sdp: Arc<Sdp>,
}

impl EventsBridge {
    pub fn new(sdp: Arc<Sdp>) -> Self {
        Self { sdp }
    }

    pub fn spawn(&self) {
        let sdp = self.sdp.clone();
        let Ok(ps) = std::env::var("LPLUS_EVENTS_PORT") else {
            return;
        };
        let Ok(port) = ps.parse::<u16>() else {
            tracing::info!("[events] bad LPLUS_EVENTS_PORT={ps}");
            return;
        };
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let Ok(l) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await else {
                tracing::warn!("[events] bind :{port} failed");
                return;
            };
            tracing::info!("[events] NDJSON bridge :{port}");
            loop {
                let Ok((mut sock, _)) = l.accept().await else {
                    continue;
                };
                let mut rx = sdp.subscribe_devices();
                tokio::spawn(async move {
                    while let Ok(ev) = rx.recv().await {
                        let Ok(line) = serde_json::to_string(&ev) else {
                            continue;
                        };
                        if sock
                            .write_all(format!("{line}\n").as_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            }
        });
    }
}
