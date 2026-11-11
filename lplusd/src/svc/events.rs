//! Events bridge: NDJSON presence feed on `LPLUS_EVENTS_PORT` for
//! loopback subscribers (a sidecar need not link the daemon).
use std::sync::Arc;

use crate::config::num;
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
        // NDJSON bridge on by default; `LPLUS_EVENTS_PORT=0` disables.
        let port = self.sdp.gcfg.events.port;
        if port == 0 {
            return;
        }
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
                        let Ok(mut line) = serde_json::to_string(&ev) else {
                            continue;
                        };
                        line.push('\n');
                        if sock.write_all(line.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }
}

// ==== service configuration (env keys read once at startup) ====

/// Presence subscribers (NDJSON bridge).
#[derive(Debug, Clone)]
pub struct EventsConfig {
    /// `LPLUS_EVENTS_PORT`: NDJSON bridge (0 disables).
    pub port: u16,
    /// `OPLUS_EVENTS_PORT`: csv of extra subscriber ports (dev aid).
    pub oplus_subscribers: Option<String>,
}

impl Default for EventsConfig {
    fn default() -> Self {
        Self {
            port: 14752,
            oplus_subscribers: None,
        }
    }
}

// -- EventsConfig --
impl EventsConfig {
    pub fn load() -> Self {
        let d = Self::default();
        Self {
            port: num("LPLUS_EVENTS_PORT", d.port),
            oplus_subscribers: std::env::var("OPLUS_EVENTS_PORT")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        }
    }
}
