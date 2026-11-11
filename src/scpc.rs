//! PC-originated connect lane: dial the phone's LAN SCP server and run the
//! client side of the handshake (mirror of the :10152 responder pump in
//! `sdpd.rs`, roles flipped).
//!
//! Vendor parity: the O+ Connect PC client initiates connect over the LAN —
//! no adb, no AppFunction. The phone's Java LAN SCP server listens on TCP
//! 10152 (idle; the native 10153 only opens via the engine's
//! `acceptConnection` RPC). We are the SCP client here: `isServer=0` frames
//! (`0x30`) route to the phone's SERVER-side ScpItem, which sits in
//! `waiting4Hello` until our HELLO arrives.
//!
//! Sequence (PROTOCOL.md §5.4/§6.6):
//! HELLO(`ftype2`, `msgType=0`, `q`) → SYNC(`msgType=1`, keyType BOTH) →
//! peer HELLO/SYNC → UKEY2 INIT/FINISHED (`msgType` 3/4, raw `Ukey2Message`
//! in `data`, unencrypted) → SYNC_SECURE (`msgType=2`, `d0{deviceId,ksc,
//! kscAlias}`; the phone echoes our ksc byte-exact) → interact gate.

use anyhow::{Result, anyhow};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::scp;
use crate::ukey2::{Role, Ukey2Handshake};

const CHANNEL: &str = "active_connection";
const NAMESPACE: &str = "com.heytap.accessory";
const DEADLINE: Duration = Duration::from_secs(30);

/// `scp::msg_frame` with the CLIENT header role (`0x30`): on a socket we
/// dialed, the phone's SERVER item only consumes `isServer=0` frames.
fn dial_flags() -> u8 {
    std::env::var("SCP_DIAL_FLAGS")
        .ok()
        .and_then(|s| u8::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0x30)
}

fn cframe(mt: u32, data: Vec<u8>) -> Vec<u8> {
    let sm = scp::ScpMessage {
        msg_type: Some(mt),
        data,
    };
    let mut v = scp::TOKEN.to_vec();
    v.extend_from_slice(&<scp::ScpMessage as prost::Message>::encode_to_vec(&sm));
    let mut fr = scp::frame_t(2, 0, &v);
    fr[1] = dial_flags();
    fr
}

fn our_pdid() -> String {
    std::env::var("SCP_PDID").unwrap_or_else(|_| "A1B2C3D4E5F6".into())
}

/// Fire-and-forget dial used by the Connect command: logs the outcome.
pub fn spawn_dial(ip: String, dev_name: String) {
    tokio::spawn(async move {
        match tokio::time::timeout(DEADLINE, dial_connect(&ip, &dev_name)).await {
            Ok(Ok(summary)) => {
                tracing::info!("[scpc] {ip} connect OK — {summary}");
            }
            Ok(Err(e)) => {
                tracing::warn!("[scpc] {ip} connect FAILED: {e:#}");
            }
            Err(_) => {
                tracing::warn!("[scpc] {ip} connect FAILED: {DEADLINE:?} deadline");
            }
        }
    });
}

/// Dial `ip:10152` (override: `SCP_DIAL_PORT`) and drive the client
/// handshake to a verified session. Every peer frame is logged as
/// `[scpc]` so a failure is diagnosable from the log alone.
pub async fn dial_connect(ip: &str, dev_name: &str) -> Result<String> {
    let port: u16 = std::env::var("SCP_DIAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10152);
    let model = std::env::var("SCP_MODEL").unwrap_or_else(|_| "LPlusConnectPC".into());
    let addr = (ip.to_string(), port);
    let mut sock = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow!("tcp connect {addr:?} timeout"))?
        .map_err(|e| anyhow!("tcp connect {addr:?}: {e}"))?;
    sock.set_nodelay(true)?;
    tracing::info!("[scpc] dialed {ip}:{port} as SCP client");

    let pdid = our_pdid();
    // Present the same bond every time (vendor resumption parity).
    let (ksc, ss_alias) = crate::sdpd::issue_ksc(ip, &pdid);
    let seq: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() | 1)
        .unwrap_or(0x2a);

    let mut out = scp::hello_frame_ex(seq, CHANNEL, NAMESPACE, false);
    out[1] = dial_flags();
    let late_sync = std::env::var("SCP_DIAL_SYNC_LATE").is_ok();
    let no_init = std::env::var("SCP_DIAL_NO_INIT").is_ok();
    let key_type: i32 = std::env::var("SCP_DIAL_KEYTYPE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    if !late_sync {
        let mut sy = scp::sync_frame_ex(seq, CHANNEL, NAMESPACE, dev_name, &model, false, key_type);
        sy[1] = dial_flags();
        out.extend_from_slice(&sy);
    }
    sock.write_all(&out).await?;
    sock.flush().await?;
    tracing::info!(
        "[scpc] -> HELLO{} (seq {seq}, keyType {key_type})",
        if late_sync { "" } else { "+SYNC" }
    );

    let mut ctl = Ctl {
        hs: Ukey2Handshake::new(Role::Initiator),
        sent_ukey2: 0,
        ss_sent: false,
        ss_ok: false,
        interact: false,
        sync_pending: late_sync,
        peer_hello: false,
    };
    // The connecting side starts UKEY2: CLIENT_INIT goes out unprompted
    // (both engines otherwise sit waiting for the peer's msgType 3).
    // `SCP_DIAL_NO_INIT=1` defers it to the peer's INIT — A/B for whether
    // an unprompted INIT poisons the phone server's `receiveSync` slot.
    if !late_sync
        && !no_init
        && let Some(init) = ctl.hs.next_message()
    {
        ctl.sent_ukey2 = 1;
        let f = cframe(3, init);
        sock.write_all(&f).await?;
        sock.flush().await?;
        tracing::info!("[scpc] -> ukey2 mt3 (initiator opens)");
    }
    let mut buf = vec![0u8; 64 * 1024];
    let mut acc: Vec<u8> = Vec::new();

    loop {
        if ctl.ss_ok && ctl.interact {
            break;
        }
        // Frames coalesce on the wire; buffer and extract complete ones.
        while let Some((s, e)) = scp::split_frames(&acc).first().copied() {
            let frame = acc[s..e].to_vec();
            acc.drain(..e);
            handle_frame(&frame, &mut ctl, &mut sock, ksc.as_slice()).await?;
        }
        // Late-SYNC mode: follow the peer's HELLO with our SYNC (and then
        // the initiator's UKEY2_INIT unless deferred).
        if ctl.sync_pending && ctl.peer_hello {
            ctl.sync_pending = false;
            let mut f =
                scp::sync_frame_ex(seq, CHANNEL, NAMESPACE, dev_name, &model, false, key_type);
            f[1] = dial_flags();
            sock.write_all(&f).await?;
            sock.flush().await?;
            tracing::info!("[scpc] -> SYNC (late, keyType {key_type})");
            if !no_init && let Some(init) = ctl.hs.next_message() {
                ctl.sent_ukey2 = 1;
                let f = cframe(3, init);
                sock.write_all(&f).await?;
                sock.flush().await?;
                tracing::info!("[scpc] -> ukey2 mt3 (after late SYNC)");
            }
        }
        if ctl.ss_ok && ctl.interact {
            break;
        }
        // After ukey2 completes, proactively send SYNC_SECURE (the phone's
        // server only asks when it is the client; as its peer we present
        // proof unsolicited, mirroring the proven server-lane order).
        if ctl.hs.is_complete() && !ctl.ss_sent {
            let ss = scp::SyncSecure {
                device_id: Some(pdid.clone()),
                ksc: Some(ksc.clone()),
                ksc_alias: Some(ss_alias.clone()),
            };
            let f = cframe(2, <scp::SyncSecure as prost::Message>::encode_to_vec(&ss));
            sock.write_all(&f).await?;
            sock.flush().await?;
            ctl.ss_sent = true;
            tracing::info!("[scpc] -> SYNC_SECURE (pdid {pdid}, ksc {}B)", ksc.len());
        }
        let n = tokio::time::timeout(Duration::from_secs(5), sock.read(&mut buf))
            .await
            .map_err(|_| {
                anyhow!(
                    "idle 5 s (ukey2={} ss_sent={} ss_ok={} interact={})",
                    ctl.sent_ukey2,
                    ctl.ss_sent,
                    ctl.ss_ok,
                    ctl.interact
                )
            })?
            .map_err(|e| anyhow!("read: {e}"))?;
        if n == 0 {
            anyhow::bail!(
                "peer closed (ukey2={} ss_sent={} ss_ok={} interact={})",
                ctl.sent_ukey2,
                ctl.ss_sent,
                ctl.ss_ok,
                ctl.interact
            );
        }
        acc.extend_from_slice(&buf[..n]);
    }
    let _ = &ctl;
    Ok("ksc echo verified, interact accepted".to_string())
}

/// Session stage flags for the client handshake pump.
struct Ctl {
    hs: Ukey2Handshake,
    sent_ukey2: u8,
    ss_sent: bool,
    ss_ok: bool,
    interact: bool,
    /// Late-SYNC mode: queued until the peer's HELLO is seen.
    sync_pending: bool,
    peer_hello: bool,
}

async fn handle_frame(sub: &[u8], ctl: &mut Ctl, sock: &mut TcpStream, ksc: &[u8]) -> Result<()> {
    let Some(m) = scp::decode_payload(&sub[8..]) else {
        tracing::info!(
            "[scpc] <- non-scp frame {}B flags={:#04x} {:?}",
            sub.len(),
            sub.get(1).copied().unwrap_or(0),
            String::from_utf8_lossy(&sub[12..sub.len().min(44)])
        );
        // Business TEXT frames (interact replies) may not decode as
        // ScpMessage; treat a plaintext "accept" marker as success.
        let txt = String::from_utf8_lossy(&sub[8..]).to_string();
        if txt.contains("accept") || txt.contains("interact") {
            tracing::info!("[scpc] interact traffic: {:?}", &txt[..txt.len().min(48)]);
            ctl.interact = true;
        }
        return Ok(());
    };
    let mt = m.msg_type.unwrap_or(0);
    tracing::info!(
        "[scpc] <- {} ({}B data) flags={:#04x}",
        scp::msg_name(mt),
        m.data.len(),
        sub.get(1).copied().unwrap_or(0)
    );
    match mt {
        0 => ctl.peer_hello = true,
        1 => {
            if let Ok(sd) = <scp::SyncData as prost::Message>::decode(m.data.as_slice()) {
                tracing::info!(
                    "[scpc] peer SYNC: keyType={} device={} model={}",
                    sd.key_type,
                    sd.device_name,
                    sd.model_id
                );
            }
        }
        3 | 4 => {
            ctl.hs
                .parse(&m.data)
                .map_err(|e| anyhow!("ukey2 parse mt{mt}: {e}"))?;
            while let Some(msg) = ctl.hs.next_message() {
                // Initiator emits INIT (3) first, then FINISHED (4).
                let out_mt = if ctl.sent_ukey2 == 0 { 3 } else { 4 };
                ctl.sent_ukey2 += 1;
                let f = cframe(out_mt, msg);
                sock.write_all(&f).await?;
                sock.flush().await?;
                tracing::info!("[scpc] -> ukey2 mt{out_mt}");
            }
            if ctl.hs.is_complete() {
                tracing::info!("[scpc] ukey2 handshake complete");
            }
        }
        2 => {
            // SYNC_SECURE from the phone; after our own send, this is the
            // echo we authenticate against our stored ksc.
            match <scp::SyncSecure as prost::Message>::decode(m.data.as_slice()) {
                Ok(ss) => {
                    let peer_ksc = ss.ksc.unwrap_or_default();
                    if ctl.ss_sent && peer_ksc == ksc {
                        ctl.ss_ok = true;
                        tracing::info!("[scpc] SYNC_SECURE echo matches stored ksc");
                        // Interact gate: the connecting side presents the
                        // hello; reply text marks acceptance.
                        let mut hello = scp::frame_t(2, 0, &{
                            let mut v = scp::TOKEN.to_vec();
                            v.extend_from_slice(b"interact hello");
                            v
                        });
                        hello[1] = 0x31; // client role | TEXT payload
                        sock.write_all(&hello).await?;
                        sock.flush().await?;
                        tracing::info!("[scpc] -> interact hello");
                    } else {
                        tracing::info!(
                            "[scpc] peer SYNC_SECURE ({}B ksc, ours sent={})",
                            peer_ksc.len(),
                            ctl.ss_sent
                        );
                    }
                }
                Err(e) => tracing::info!("[scpc] SYNC_SECURE decode failed: {e}"),
            }
        }
        _ => {}
    }
    Ok(())
}

/// PC-originated connect trigger on the EPI plane: dial the phone's
/// :46888 datatrans server, answer its CAPEX exchange as the connecting
/// peer, and hold long enough for the engine to start the SCP dial back to
/// our :10152 (where the proven server pump completes the session).
pub async fn epi_trigger(ip: &str) -> Result<String> {
    let port: u16 = std::env::var("EPI_DIAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(46888);
    let mut sock = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((ip.to_string(), port)),
    )
    .await
    .map_err(|_| anyhow!("tcp connect {ip}:{port} timeout"))?
    .map_err(|e| anyhow!("tcp connect {ip}:{port}: {e}"))?;
    sock.set_nodelay(true)?;
    tracing::info!("[epic] dialed {ip}:{port} (EPI client)");

    let profiles_owned: Vec<String> = std::env::var("EPI_CAPEX_PROFILES")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_else(|| {
            [
                "com.oplus.pantaconnect.globaldevice.discovery",
                "uuid.icdf.service1",
                "app:oplus.pantaconnect.app_service",
                "vdc.service.sync",
                "oaf.service.iphone.call",
                "icdf.videocall.service",
            ]
            .iter()
            .map(|p| p.to_string())
            .collect()
        });
    let profiles: Vec<&str> = profiles_owned.iter().map(String::as_str).collect();

    let mut buf = vec![0u8; 64 * 1024];
    let mut acc: Vec<u8> = Vec::new();
    let mut capex: u8 = 0;
    let mut queried = false;
    // datatrans/security client lane (mirror of the proven server lane in
    // sdpd.rs): PD OFFER → CONFIRM → AUTH_REQUEST → AUTH_CONFIRM. The
    // phone's EpiServerFsm closes the socket on CAPEX from an
    // unauthenticated peer (measured: RST after our QUERY).
    let mut auth_stage: u8 = 0;
    let ksc = crate::sdpd::issue_ksc(ip, &our_pdid()).0;
    let pdid = our_pdid();
    let dev6: Vec<u8> =
        hex::decode(&pdid).unwrap_or_else(|_| pdid.as_bytes()[..6.min(pdid.len())].to_vec());
    let ts_req: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1);
    let qc: Vec<u8> = {
        let mut v = vec![0u8; 8];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut v);
        v
    };
    if std::env::var("EPI_AUTH_CLIENT").as_deref() != Ok("0") {
        let mut peer_id = std::env::var("EPI_PEERID").unwrap_or_else(|_| "A1B2C3D4E5F6".repeat(3));
        while peer_id.len() < 36 {
            peer_id.push('0');
        }
        peer_id.truncate(36);
        let mut offer: Vec<u8> = vec![0x01, 0x00, 0x0a];
        offer.extend_from_slice(peer_id.as_bytes());
        offer.push(0x00);
        offer.push(0x00);
        let of = epi_hdr_frame(64 << 2, &offer);
        sock.write_all(&of).await?;
        sock.flush().await?;
        auth_stage = 1;
        tracing::info!("[epic] -> PD OFFER (client) {}B", of.len());
    }
    let mut deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut rpc_done = false;
    loop {
        if capex == 2 && rpc_done {
            // Exchange done; give the engine a beat to dial our :10152.
            tokio::time::sleep(Duration::from_secs(3)).await;
            return Ok("CAPEX RESPONSE+CONFIRM exchanged".to_string());
        }
        let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now()) else {
            anyhow::bail!("EPI trigger deadline (capex stage {capex})");
        };
        let n = tokio::time::timeout(remaining.min(Duration::from_secs(5)), sock.read(&mut buf))
            .await
            .map_err(|_| anyhow!("idle waiting for EPI frames (capex stage {capex})"))?
            .map_err(|e| anyhow!("read: {e}"))?;
        if n == 0 {
            anyhow::bail!("phone closed EPI socket (capex stage {capex})");
        }
        acc.extend_from_slice(&buf[..n]);
        loop {
            if acc.len() < 4 {
                break;
            }
            let len = u16::from_be_bytes([acc[0], acc[1]]) as usize;
            if len < 2 || acc.len() < len + 2 {
                break;
            }
            let frame = acc[..len + 2].to_vec();
            acc.drain(..len + 2);
            let payload = &frame[4..];
            let mt = payload.first().copied().unwrap_or(0);
            let hdr = u16::from_be_bytes([frame[2], frame[3]]);
            tracing::info!(
                "[epic] <- {}B hdr=0x{hdr:04x} sid={}/ft={} mt={mt:02x} {}",
                frame.len(),
                hdr >> 9,
                (hdr >> 2) & 0x7f,
                hex::encode(&payload[..payload.len().min(24)])
            );
            // PD PROBE (msgType 10, `jf/b.java` plane): answer with a PD
            // RESPONSE (msgType 2) carrying our 36B peer id — the phone's
            // EpiServerFsm gates CAPEX on PD completion.
            if mt == 0x0a && std::env::var("EPI_PD_RESP").as_deref() != Ok("0") {
                let peer_id =
                    std::env::var("EPI_PEERID").unwrap_or_else(|_| "A1B2C3D4E5F6".repeat(3));
                let mut peer_id = peer_id;
                while peer_id.len() < 36 {
                    peer_id.push('0');
                }
                peer_id.truncate(36);
                let mut pd: Vec<u8> = vec![0x02, 0x00, 0x0a];
                pd.extend_from_slice(peer_id.as_bytes());
                pd.push(0x00);
                pd.push(0x00);
                let pf = epi_hdr_frame(0x0000, &pd); // sid 0 (PD lane)
                sock.write_all(&pf).await?;
                sock.flush().await?;
                tracing::info!(
                    "[epic] -> PD RESPONSE (sid 0, peerId {peer_id}) {}B",
                    pf.len()
                );
                if auth_stage == 1 {
                    let confirm = epi_hdr_frame(64 << 2, &[0x04, 0x00, 0x0a, 0x01]);
                    sock.write_all(&confirm).await?;
                    let mut req: Vec<u8> = vec![0x10, 0x01];
                    req.extend_from_slice(&qc);
                    req.extend_from_slice(&ts_req.to_be_bytes());
                    let mac = crate::sdpd::ksc_s(&ksc, &qc, ts_req);
                    req.extend_from_slice(&mac);
                    req.extend_from_slice(&dev6);
                    req.extend_from_slice(&dev6); // alias = dev (mirror server lane)
                    let af = epi_hdr_frame(64 << 2, &req);
                    sock.write_all(&af).await?;
                    sock.flush().await?;
                    auth_stage = 2;
                    tracing::info!(
                        "[epic] -> PD CONFIRM + AUTH_REQUEST qc={} mac={} ts={ts_req} {}B",
                        hex::encode(&qc),
                        hex::encode(mac),
                        af.len()
                    );
                }
            }
            // Server AUTH_RESPONSE [t|ver|0|qs8|ts8|rs8]: answer with
            // AUTH_CONFIRM 0x12 carrying rc_2 = s(ksc, qs, ts_ours).
            if auth_stage == 2 && (0x11..=0x13).contains(&mt) && payload.len() >= 11 {
                let qs = &payload[3..11];
                let rc2 = crate::sdpd::ksc_s(&ksc, qs, ts_req);
                let mut conf: Vec<u8> = vec![0x12, payload[1], 0x00];
                conf.extend_from_slice(&rc2);
                let cf = epi_hdr_frame(64 << 2, &conf);
                sock.write_all(&cf).await?;
                sock.flush().await?;
                auth_stage = 3;
                tracing::info!(
                    "[epic] -> AUTH_CONFIRM rc_2={} (channel authenticated)",
                    hex::encode(rc2)
                );
            }
            match mt {
                1 if capex < 2 => {
                    let echo = if std::env::var("EPI_ECHO_SID").as_deref() != Ok("0") {
                        (hdr >> 2) & 0x7f
                    } else {
                        2
                    };
                    let rf = epi_hdr_frame(echo << 2, &crate::sdpd::capex_response(&profiles));
                    sock.write_all(&rf).await?;
                    let cf = epi_hdr_frame(echo << 2, &crate::sdpd::capex_confirm(0, 0));
                    sock.write_all(&cf).await?;
                    sock.flush().await?;
                    capex = 2;
                    tracing::info!(
                        "[epic] -> CAPEX RESPONSE ({} profiles) + CONFIRM sid={}",
                        profiles.len(),
                        echo
                    );
                }
                2 if capex == 0 => {
                    let echo = if std::env::var("EPI_ECHO_SID").as_deref() != Ok("0") {
                        (hdr >> 2) & 0x7f
                    } else {
                        2
                    };
                    let cf = epi_hdr_frame(echo << 2, &crate::sdpd::capex_confirm(0, 0));
                    sock.write_all(&cf).await?;
                    sock.flush().await?;
                    capex = 2;
                    tracing::info!("[epic] -> CAPEX CONFIRM (after peer RESPONSE) sid={echo}");
                }
                _ => {}
            }
        }
        // Nothing ever sent QUERY and nothing else arrives: seed with our
        // own QUERY once so the phone's server enters the exchange.
        if capex == 0 && acc.is_empty() && !queried {
            queried = true;
            let sidq: u16 = std::env::var("EPI_QUERY_SID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(64);
            let qf = epi_hdr_frame(sidq << 2, &crate::sdpd::capex_query(&profiles));
            sock.write_all(&qf).await?;
            sock.flush().await?;
            tracing::info!(
                "[epic] -> CAPEX QUERY ({} profiles) sid={sidq}",
                profiles.len()
            );
        }
        if capex == 2 && !rpc_done {
            rpc_done = true;
            if std::env::var("EPI_RPC").as_deref().unwrap_or("1") != "0" {
                deadline = tokio::time::Instant::now() + Duration::from_secs(15);
                rpc_phase(&mut sock, ip).await;
            }
        }
        // The phone's :46888 server ignores our QUERY on PC-originated
        // sockets (measured); don't block the RPC brute-force on CAPEX.
        if !rpc_done && capex < 2 && queried && acc.is_empty() {
            tokio::time::sleep(Duration::from_secs(3)).await;
            if capex < 2 {
                rpc_done = true;
                if std::env::var("EPI_RPC").as_deref().unwrap_or("1") != "0" {
                    deadline = tokio::time::Instant::now() + Duration::from_secs(25);
                    rpc_phase(&mut sock, ip).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PC-originated connect RPC (requestCompatScpConnect) over the EPI :46888
// lane. The phone's `interconnect-framework` RpcServer dispatches
// `service_name`/`method_name` prost `RpcFrame`s (recovered from
// `libinterconnect_ipc_client.so`: pool string
// `RpcFrame:frame_type,request_id,service_name,method_name,payload,status,...`)
// that ride the NDSF DataBus session (sid 8, EPI header `0x0020`) on the
// same :46888 socket as CAPEX. The server handler parses
// `CompatScpConnectParam.parseFrom(payload)` and replies `SealedResult`
// (`/tmp/cpbusjx` processor `n`). Layouts A-D vary the DataBus body
// prefix + sealing around the RpcFrame body; the phone's own DATA frames
// use `[0x04][tid][ctr8][ct+tag]` (see `sdpd.rs` sid-8 parser).
// ---------------------------------------------------------------------------

fn epi_hdr_frame(hdr: u16, body: &[u8]) -> Vec<u8> {
    crate::rpc::session_frame(hdr, body)
}

/// Candidate set for a connect attempt: compat-scp group under the
/// `EPI_RPC_SERVICES`/`EPI_RPC_CANDS` knobs plus the vendor-LAN
/// `connect`/`acceptConnection` pair. Typed calls come from `crate::rpc`
/// (native prost client); this only enumerates the A/B envelope space.
pub fn rpc_frames(ip: &str) -> Vec<(String, Vec<u8>)> {
    let cands: Vec<(i32, u8)> = std::env::var("EPI_RPC_CANDS")
        .unwrap_or_else(|_| "1:1,2:1,0:1,1:2,1:3,1:4".into())
        .split(',')
        .filter_map(|c| {
            let (f, l) = c.split_once(':')?;
            Some((f.parse().ok()?, l.parse().ok()?))
        })
        .collect();
    let port: u16 = std::env::var("SCP_DIAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10152);
    let to = std::env::var("LINK_KPD")
        .ok()
        .and_then(|s| s.split(',').next().map(str::to_string))
        .unwrap_or_else(|| "0123456789AB".into());
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut tid = 0x21u16;
    // Evidence-first ordering: `cpbus.networking` is the LAN-callable pair
    // (dex-registered handlers); the compat group is binder-only and rides
    // as the compatibility probe behind it.
    let mut net_calls = vec![
        crate::rpc::networking_connect(&to, &format!("{ip}:{port}"), 3),
        crate::rpc::networking_accept_connection(10153, 1),
    ];
    for call in &mut net_calls {
        for (ft, layout) in [(1i32, 1u8), (1, 2)] {
            call.frame_type = ft;
            call.request_id = u64::from(tid);
            out.push((
                format!("net {} ft={ft} lay={layout} tid={tid:04x}", call.method),
                call.encode(layout),
            ));
            tid += 1;
        }
    }
    for service in std::env::var("EPI_RPC_SERVICES")
        .unwrap_or_else(|_| "connection|agent|".into())
        .split('|')
        .map(str::to_string)
        .collect::<Vec<_>>()
    {
        for (ft, layout) in &cands {
            let mut call = crate::rpc::compat_scp_connect(&pc_local_ip(ip), port, 6);
            call.service = service.clone();
            call.frame_type = *ft;
            call.request_id = u64::from(tid);
            out.push((
                format!(
                    "rpc {service}/{} ft={ft} lay={layout} tid={tid:04x}",
                    call.method
                ),
                call.encode(*layout),
            ));
            tid += 1;
        }
    }
    out
}

fn pc_local_ip(peer: &str) -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect(format!("{peer}:9"))?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

/// Send the candidate set on a fresh socket with pacing + reply drains.
/// The phone's :46888 server ignores frames pre-pairing (measured); this
/// remains the A/B harness for envelope variants.
async fn rpc_phase(sock: &mut TcpStream, ip: &str) {
    // Proven dial trigger (2026-11-09 live): unencrypted DataBus sid-8
    // DbsMessage Oplus_Cast/input_service msg_type=61. Replay on this
    // socket too — the phone's EPI server may act without CAPEX closing.
    let from = std::env::var("LINK_DET_PEER").unwrap_or_else(|_| "A1B2C3D4E5F6".into());
    let to = std::env::var("LINK_KPD")
        .ok()
        .and_then(|s| s.split(',').next().map(str::to_string))
        .unwrap_or_else(|| "0123456789AB".into());
    if let Ok(f) =
        crate::sdpd::kms_bootstrap_frame(36863, "lplus-kms-pw", &pc_local_ip(ip), &from, &to)
    {
        tracing::info!(
            "[epic] -> KMS bootstrap DataBus {}B (proven trigger)",
            f.len()
        );
        let _ = sock.write_all(&f).await;
        let _ = sock.flush().await;
        drain_reply(sock).await;
    }
    for (label, wire) in rpc_frames(ip) {
        tracing::info!(
            "[epic] -> {label} {}B {}",
            wire.len(),
            hex::encode(&wire[..wire.len().min(28)])
        );
        if sock.write_all(&wire).await.is_err() {
            tracing::warn!("[epic] RPC write failed at {label}");
            return;
        }
        let _ = sock.flush().await;
        tokio::time::sleep(Duration::from_millis(1200)).await;
        drain_reply(sock).await;
    }
    tracing::info!("[epic] RPC phase exhausted (watch for :10152 dial)");
}

async fn drain_reply(sock: &mut TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    for _ in 0..8 {
        let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(600), sock.read(&mut buf)).await
        else {
            return;
        };
        if n == 0 {
            return;
        }
        let mut acc = buf[..n].to_vec();
        while acc.len() >= 4 {
            let len = u16::from_be_bytes([acc[0], acc[1]]) as usize;
            if len < 2 || acc.len() < len + 2 {
                break;
            }
            let frame = acc[..len + 2].to_vec();
            acc.drain(..len + 2);
            let body = &frame[4..];
            tracing::info!(
                "[epic] <- reply {}B b0={:02x} {}",
                frame.len(),
                body.first().copied().unwrap_or(0),
                hex::encode(&body[..body.len().min(40)])
            );
            if let Some(reply) = crate::rpc::parse_reply(body) {
                match reply {
                    crate::rpc::Reply::Connect(cr) => tracing::info!(
                        "[epic] <- ConnectResponse result={} err={:?} handle={}",
                        cr.result,
                        cr.error,
                        cr.connection_handle
                    ),
                    crate::rpc::Reply::Sealed(sr) => tracing::info!(
                        "[epic] <- SealedResult code={:?} err={} msg={:?} data={}B",
                        sr.result_code(),
                        sr.error_code,
                        sr.message,
                        sr.data.len()
                    ),
                    crate::rpc::Reply::Frame(rf) => tracing::info!(
                        "[epic] <- RpcFrame ft={} svc={:?} m={:?} rid={} payload={}B",
                        rf.frame_type,
                        rf.service_name,
                        rf.method_name,
                        rf.request_id,
                        rf.payload.len()
                    ),
                }
            }
        }
    }
}
