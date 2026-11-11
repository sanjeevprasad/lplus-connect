//! SCP session server: TCP listeners for the advertised session planes
//! (CSP and its probe siblings). The wire protocol lives with the SDP
//! service, [`Sdp::spawn_session_logger`].
use std::sync::Arc;

use anyhow::Context;

use crate::svc::sdp::Sdp;

pub(crate) async fn bind_sessions(sdp: &Arc<Sdp>, ports: &[u16]) -> anyhow::Result<()> {
    for &p in ports {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", p))
            .await
            .with_context(|| format!("tcp bind :{p}"))?;
        let sdp = sdp.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((sock, peer)) = listener.accept().await {
                    tracing::info!("[tcp] accept :{p} <- {peer}");
                    sdp.clone().spawn_session_logger(sock, peer, false, p);
                }
            }
        });
    }
    Ok(())
}
