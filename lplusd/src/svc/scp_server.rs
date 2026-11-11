//! SCP session server: TCP listeners for the advertised session planes
//! (CSP and its probe siblings). The wire protocol lives in
//! [`crate::svc::sdp::spawn_session_logger`].
use anyhow::Context;

pub(crate) async fn bind_sessions(
    ports: &[u16],
    log_path: String,
    dev_name: String,
    probe_reg: std::sync::Arc<Vec<u8>>,
) -> anyhow::Result<()> {
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
                    tracing::info!("[tcp] accept :{p} <- {peer}");
                    crate::svc::sdp::spawn_session_logger(
                        sock,
                        peer,
                        log_path.clone(),
                        dev_name.clone(),
                        probe_reg.clone(),
                        false,
                        p,
                    );
                }
            }
        });
    }
    Ok(())
}
