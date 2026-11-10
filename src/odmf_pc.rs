//! PC-side WebRTC receiver for the ODMF cast media plane.
//!
//! Ground truth (odmf.jar): once the phone's ODMF signaling client is
//! paired (`onPairSuccess` → flush queue), the media plane is a
//! libwebrtc-style SDP exchange on the same signaling lane —
//! `{"type":"offer","sdp":…}` / `{"type":"answer","sdp":…}` /
//! `{"type":"candidate","label":0,"id":"0","candidate":"candidate:…"}`
//! (odmfr/odmfb.java `sendOfferSdp`/`sendAnswerSdp`/`odmfa(IceCandidate)`
//! and the `type` dispatch). The PC role creates the OFFER
//! (`PeerConnectionClient` "PC Create OFFER", odmfq/odmfb.java); the phone
//! answers and pushes RTP. We play that PC role with `str0m` (pure-Rust
//! ICE/DTLS/SRTP), sealing frames exactly like the phone seals under the
//! media key adopted from our `AuthSuccess`
//! ([`crate::wfd_sink::encrypt_frame`]).
//!
//! Topology: sink sessions own the TCP signaling sockets; this task owns
//! one UDP socket (the advertised RTP port) for ICE/DTLS/SRTP and drives
//! offer/answer/candidate through two channels.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Once, OnceLock};

use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::ChannelId;
use str0m::format::{Codec, FormatParams};
use str0m::media::{Direction, Frequency, KeyframeRequestKind, MediaKind, Mid};
use str0m::net::{DatagramRecv, Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::broadcast;

/// Events the sink forwards into the WebRTC task.
#[derive(Debug, Clone)]
pub enum PcEvent {
    /// The phone sealed a `PairRequest` on the socket tagged `tag`
    /// (`"ip:port"`); the offer goes there.
    Paired(String),
    /// `{"type":"answer","sdp":…}` from the phone.
    Answer { sdp: String },
    /// Trickle `{"type":"candidate",…}` from the phone.
    Candidate { candidate: String },
}

/// Signaling downlink: `(target socket tag, json payload)`; every sink
/// session receives it and writes the sealed frame if its tag matches.
static SIG: OnceLock<broadcast::Sender<(String, String)>> = OnceLock::new();
/// Uplink to the WebRTC task; created together with the task (Once).
static PC_CTL: OnceLock<UnboundedSender<PcEvent>> = OnceLock::new();
static TASK_STARTED: Once = Once::new();

fn sig_channel() -> &'static broadcast::Sender<(String, String)> {
    SIG.get_or_init(|| broadcast::channel(64).0)
}

/// Subscribe the current session to the signaling downlink.
pub fn sig_subscribe() -> broadcast::Receiver<(String, String)> {
    sig_channel().subscribe()
}

/// Tell the WebRTC task the phone paired on `tag` (after our PairSuccess).
pub fn paired(tag: &str) {
    ensure_task();
    if let Some(tx) = PC_CTL.get() {
        let _ = tx.send(PcEvent::Paired(tag.to_string()));
    }
}

/// Forward a plaintext ODMF frame (plain JSON or opened from an encrypted
/// frame); only the SDP/candidate types are consumed.
pub fn handle_inbound(json: &str) {
    if let Some(tx) = PC_CTL.get() {
        dispatch(tx, json);
    }
}

/// Testable inbound dispatch.
fn dispatch(tx: &UnboundedSender<PcEvent>, json: &str) {
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(json) else {
        return;
    };
    // The signaling lane nests SDP/candidate JSON inside
    // {"cmd":"send","msg":"<inner json string>"} (odmfr/odmfb.java case
    // CMD_SEND → odmfc(msg)); unwrap before type dispatch.
    if let Some(s) = v.get("msg").and_then(|m| m.as_str())
        && let Ok(inner) = serde_json::from_str::<serde_json::Value>(s)
    {
        v = inner;
    }
    match v.get("type").and_then(|t| t.as_str()) {
        Some("answer") => {
            if let Some(sdp) = v.get("sdp").and_then(|s| s.as_str()) {
                tracing::info!("[webrtc] rx answer ({}B sdp)", sdp.len());
                let _ = tx.send(PcEvent::Answer {
                    sdp: sdp.to_string(),
                });
            }
        }
        Some("candidate") => {
            if let Some(c) = v.get("candidate").and_then(|s| s.as_str()) {
                tracing::info!("[webrtc] rx candidate | {c}");
                let _ = tx.send(PcEvent::Candidate {
                    candidate: c.to_string(),
                });
            }
        }
        _ => {}
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn ensure_task() {
    TASK_STARTED.call_once(|| {
        let (tx, rx) = unbounded_channel::<PcEvent>();
        let _ = PC_CTL.set(tx);
        let rtp_port: u16 = env_or("ODMF_RTP_PORT", "15550").parse().unwrap_or(15550);
        let pc_ip: IpAddr = env_or("LPLUS_PC_IP", &crate::sdpd::default_vip())
            .parse()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let out_path = env_or("ODMF_VIDEO_OUT", "../capture/video_odmf.h265");
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                h.spawn(run(rx, pc_ip, rtp_port, out_path));
            }
            Err(_) => {
                std::thread::Builder::new()
                    .name("odmf-pc".into())
                    .spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("odmf-pc runtime");
                        rt.block_on(run(rx, pc_ip, rtp_port, out_path));
                    })
                    .expect("odmf-pc thread");
            }
        }
    });
}

/// H.265-only recvonly receiver config (heycast encoder contract on
/// SM8850; libwebrtc-style AVPF transport, DTLS-SRTP via ICE-lite so the
/// phone's full agent drives the connectivity checks).
fn rtc_build() -> Rtc {
    static PROVIDER: Once = Once::new();
    PROVIDER.call_once(|| {
        str0m_rust_crypto::default_provider().install_process_default();
    });
    let mut cfg = Rtc::builder()
        .set_rtp_mode(true)
        .set_ice_lite(true)
        .enable_h264(false)
        .enable_vp8(false)
        .enable_vp9(false);
    cfg.codec_config().clear();
    cfg.codec_config().add_config(
        96.into(),
        None,
        Codec::H265,
        Frequency::NINETY_KHZ,
        None,
        FormatParams::default(),
    );
    cfg.build(std::time::Instant::now())
}

async fn run(mut rx: UnboundedReceiver<PcEvent>, pc_ip: IpAddr, rtp_port: u16, out_path: String) {
    let bind: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), rtp_port);
    let udp = match tokio::net::UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[webrtc] udp bind {bind} failed: {e} — media plane disabled");
            return;
        }
    };
    let udp = Arc::new(udp);
    tracing::info!("[webrtc] pc-role receiver ready on {bind} (candidate {pc_ip}:{rtp_port})");

    let mut rtc = rtc_build();
    let Ok(cand) = Candidate::host(SocketAddr::new(pc_ip, rtp_port), "udp") else {
        tracing::warn!("[webrtc] bad host candidate {pc_ip}:{rtp_port}");
        return;
    };
    rtc.add_local_candidate(cand);

    // Offer lifecycle: None = not offered; Some = (json payload, pending)
    // awaiting an answer. Heycast binds its OdmfManager to only ONE of the
    // two paired signaling sockets, so the offer fans out to every paired
    // tag and re-sends every 8 s until the answer lands.
    let mut pending: Option<(String, SdpPendingOffer)> = None;
    let mut paired_tags: Vec<String> = Vec::new();
    let mut answered = false;
    let mut last_offer = tokio::time::Instant::now() - tokio::time::Duration::from_secs(9);
    let mut next_timeout = tokio::time::Instant::now();
    let mut pli = tokio::time::interval(tokio::time::Duration::from_millis(2000));
    pli.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut mid: Option<Mid> = None;
    let mut chan: Option<ChannelId> = None;
    let mut consult_sent = false;
    let mut consult_ack = false;
    let mut consult_tx: u32 = 0;
    let mut rebuilds: u32 = 0;
    let mut connected_at: Option<tokio::time::Instant> = None;
    let mut depkt = crate::wfd_sink::H265Depacketizer::default();
    let mut out: Option<std::fs::File> = None;
    let mut rtp_count: u64 = 0;
    let mut buf = vec![0u8; 2048];
    // Safety net: the phone's MEDIA_CONNECTED handler that requests the
    // consult is flaky across renegotiation rounds; re-send the consult
    // until the phone echoes it, and renegotiate if RTP never starts.
    let mut guard = tokio::time::interval(tokio::time::Duration::from_secs(3));
    guard.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    drain(
        &mut rtc,
        &mut DrainCtx {
            udp: &udp,
            next_timeout: &mut next_timeout,
            depkt: &mut depkt,
            out: &mut out,
            rtp_count: &mut rtp_count,
            out_path: &out_path,
            chan: &mut chan,
            consult_sent: &mut consult_sent,
            consult_ack: &mut consult_ack,
            consult_tx: &mut consult_tx,
            connected_at: &mut connected_at,
        },
    )
    .await;
    macro_rules! rebuild_pc {
        () => {{
            rtc = rtc_build();
            if let Ok(c) = Candidate::host(SocketAddr::new(pc_ip, rtp_port), "udp") {
                rtc.add_local_candidate(c);
            }
            pending = None;
            answered = false;
            mid = None;
            chan = None;
            consult_sent = false;
            consult_ack = false;
            consult_tx = 0;
            connected_at = None;
            out = None;
            depkt = crate::wfd_sink::H265Depacketizer::default();
            last_offer = tokio::time::Instant::now() - tokio::time::Duration::from_secs(9);
        }};
    }
    loop {
        tokio::select! {
            biased;
            ev = rx.recv() => {
                match ev {
                    None => return,
                    Some(PcEvent::Paired(tag)) => {
                        if !paired_tags.contains(&tag) {
                            paired_tags.push(tag.clone());
                            if answered {
                                // A fresh pairing round (mirror re-trigger):
                                // tear down the answered peer connection and
                                // negotiate a new one from scratch.
                                tracing::info!("[webrtc] new pairing round — rebuilding peer connection");
                                rebuilds = 0;
                                paired_tags.clear();
                                paired_tags.push(tag.clone());
                                rebuild_pc!();
                            }
                        }
                        if !answered {
                            offer_or_resend(
                                &mut rtc,
                                &mut pending,
                                &mut mid,
                                &mut chan,
                                &paired_tags,
                                &mut last_offer,
                            );
                        }
                    }
                    Some(PcEvent::Answer { sdp }) => {
                        let Some((_, p)) = pending.take() else { continue };
                        match SdpAnswer::from_sdp_string(&sdp)
                            .map_err(|e| format!("parse: {e}"))
                            .and_then(|a| rtc.sdp_api().accept_answer(p, a).map_err(|e| e.to_string()))
                        {
                            Ok(()) => {
                                answered = true;
                                tracing::info!("[webrtc] answer accepted — ICE/DTLS starting")
                            }
                            Err(e) => tracing::warn!("[webrtc] accept_answer: {e}"),
                        }
                    }
                    Some(PcEvent::Candidate { candidate }) => {
                        match Candidate::from_sdp_string(&candidate) {
                            Ok(c) => rtc.add_remote_candidate(c),
                            Err(e) => tracing::warn!("[webrtc] parse candidate {candidate}: {e}"),
                        }
                    }
                }
            }
            _ = pli.tick() => {
                if rtc.is_connected()
                    && let Some(m) = mid
                    && let Some(s) = rtc.direct_api().stream_rx_by_mid(m, None)
                {
                    s.request_keyframe(KeyframeRequestKind::Pli);
                } else if !paired_tags.is_empty() && !answered {
                    offer_or_resend(
                        &mut rtc,
                        &mut pending,
                        &mut mid,
                        &mut chan,
                        &paired_tags,
                        &mut last_offer,
                    );
                }
            }
            _ = guard.tick() => {
                if rtc.is_connected() && consult_gate_open(connected_at) {
                    if !consult_ack && consult_tx < 16 {
                        let n = send_consult(&mut rtc, &chan, chan);
                        if n > 0 {
                            consult_sent = true;
                            consult_tx += n;
                        }
                    }
                    // The phone's peer connection sometimes never leaves
                    // CONNECTING on the first offer (its data listener is
                    // bound to onConnectionChange(CONNECTED), so no consult
                    // processing ever starts). A fresh offer reliably
                    // completes it; renegotiate a few times at most.
                    if let Some(t) = connected_at
                        && rtp_count == 0
                        && !consult_ack
                        && consult_tx > 0
                        && rebuilds < 5
                        && t.elapsed() > tokio::time::Duration::from_secs(8)
                    {
                        rebuilds += 1;
                        tracing::info!(
                            "[webrtc] no consult ack/RTP {:?} after connect — renegotiating ({rebuilds}/5)",
                            t.elapsed()
                        );
                        rebuild_pc!();
                    }
                }
            }
            _ = tokio::time::sleep_until(next_timeout) => {
                let _ = rtc.handle_input(Input::Timeout(std::time::Instant::now()));
            }
            r = udp.recv_from(&mut buf) => {
                if let Ok((n, src)) = r {
                    // str0m matches STUN against the *advertised* candidate
                    // address; a wildcard bind's local_addr (0.0.0.0) reads
                    // as an unknown interface and silently drops checks.
                    let dst = SocketAddr::new(pc_ip, rtp_port);
                    if let Ok(contents) = DatagramRecv::try_from(&buf[..n]) {
                        let input = Input::Receive(
                            std::time::Instant::now(),
                            Receive {
                                proto: Protocol::Udp,
                                source: src,
                                destination: dst,
                                contents,
                            },
                        );
                        if let Err(e) = rtc.handle_input(input) {
                            tracing::debug!("[webrtc] handle_input: {e}");
                        }
                    }
                }
            }
        }
        drain(
            &mut rtc,
            &mut DrainCtx {
                udp: &udp,
                next_timeout: &mut next_timeout,
                depkt: &mut depkt,
                out: &mut out,
                rtp_count: &mut rtp_count,
                out_path: &out_path,
                chan: &mut chan,
                consult_sent: &mut consult_sent,
                consult_ack: &mut consult_ack,
                consult_tx: &mut consult_tx,
                connected_at: &mut connected_at,
            },
        )
        .await;
    }
}

/// Mutable per-session state threaded through the str0m output drain.
struct DrainCtx<'a> {
    udp: &'a Arc<tokio::net::UdpSocket>,
    next_timeout: &'a mut tokio::time::Instant,
    depkt: &'a mut crate::wfd_sink::H265Depacketizer,
    out: &'a mut Option<std::fs::File>,
    rtp_count: &'a mut u64,
    out_path: &'a str,
    chan: &'a mut Option<ChannelId>,
    consult_sent: &'a mut bool,
    consult_ack: &'a mut bool,
    consult_tx: &'a mut u32,
    connected_at: &'a mut Option<tokio::time::Instant>,
}

/// Drain str0m outputs to completion (sans-I/O contract: one input at a
/// time, then drain until the next Timeout).
async fn drain(rtc: &mut Rtc, c: &mut DrainCtx<'_>) {
    let DrainCtx {
        udp,
        next_timeout,
        depkt,
        out,
        rtp_count,
        out_path,
        chan,
        consult_sent,
        consult_ack,
        consult_tx,
        connected_at,
    } = c;
    loop {
        match rtc.poll_output() {
            Ok(Output::Timeout(t)) => {
                **next_timeout = tokio::time::Instant::from_std(t);
                return;
            }
            Ok(Output::Transmit(x)) => {
                let _ = udp.send_to(&x.contents, x.destination).await;
            }
            Ok(Output::Event(ev)) => match ev {
                Event::RtpPacket(p) => {
                    **rtp_count += 1;
                    if **rtp_count == 1 {
                        tracing::info!(
                            "[webrtc] first RTP {}B pt {}",
                            p.payload.len(),
                            p.header.payload_type
                        );
                    } else if rtp_count.is_multiple_of(500) {
                        tracing::info!("[webrtc] {rtp_count} RTP packets");
                    }
                    for au in depkt.push(&p.payload) {
                        if out.is_none() {
                            **out = Some(open_out(out_path));
                        }
                        if let Some(f) = out.as_mut()
                            && let Err(e) = std::io::Write::write_all(f, &au)
                        {
                            tracing::warn!("[webrtc] h265 write: {e}");
                        }
                    }
                }
                Event::Connected => {
                    **connected_at = Some(tokio::time::Instant::now());
                    tracing::info!("[webrtc] CONNECTED — ICE+DTLS up, awaiting RTP");
                }
                Event::IceConnectionStateChange(s) => {
                    tracing::info!("[webrtc] ice state {s:?}");
                }
                Event::ChannelOpen(id, label) => {
                    tracing::info!("[webrtc] channel open id={id:?} label={label}");
                    if !**consult_ack && consult_gate_open(**connected_at) {
                        let n = send_consult(rtc, chan, Some(id));
                        if n > 0 {
                            **consult_sent = true;
                            **consult_tx += n;
                        }
                    }
                }
                Event::ChannelData(d) => {
                    let txt = String::from_utf8_lossy(&d.data).to_string();
                    tracing::info!("[webrtc] channel rx: {txt}");
                    let command = serde_json::from_str::<serde_json::Value>(&txt)
                        .ok()
                        .and_then(|v| {
                            v.get("COMMAND")
                                .and_then(|c| c.as_str())
                                .map(|c| c.to_string())
                        });
                    if command
                        .as_deref()
                        .and_then(|c| c.parse::<crate::rtsp::RtspMethod>().ok())
                        == Some(crate::rtsp::RtspMethod::SetParameter)
                    {
                        // Phone echo (q2/i.java p(b)): consult was accepted.
                        **consult_ack = true;
                    }
                    if (command.as_deref() == Some("interaction") || !**consult_sent)
                        && consult_gate_open(**connected_at)
                    {
                        let n = send_consult(rtc, chan, Some(d.id));
                        if n > 0 {
                            **consult_sent = true;
                            **consult_tx += n;
                        }
                    }
                }
                _ => {}
            },
            Err(e) => {
                tracing::warn!("[webrtc] poll_output: {e}");
                return;
            }
        }
    }
}

/// Seconds to hold the consult back after WebRTC connect (env
/// `ODMF_CONSULT_DELAY_SECS`, default 0 = immediate). The phone's
/// MediaProjection token is killed as soon as capture starts while its
/// `PROJECT_MEDIA` app-op is denied; delaying the consult lets the user
/// confirm the "Share entire screen" dialog first, which flips the app-op
/// to allow and the later capture then survives.
fn consult_delay() -> std::time::Duration {
    static D: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *D.get_or_init(|| {
        let secs = std::env::var("ODMF_CONSULT_DELAY_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        std::time::Duration::from_secs(secs)
    })
}

fn consult_gate_open(connected_at: Option<tokio::time::Instant>) -> bool {
    let d = consult_delay();
    d.is_zero() || connected_at.is_some_and(|t| t.elapsed() >= d)
}

/// Send the sink consult `SET_PARAMETER` (q2/r.java `r.a` schema) on every
/// negotiated channel (ours and the peer's); the phone gates screen capture
/// until it lands. Returns the number of channels the write succeeded on.
fn send_consult(rtc: &mut Rtc, chan: &Option<ChannelId>, extra: Option<ChannelId>) -> u32 {
    let (w, h, fps) = (
        env_or("ODMF_SINK_W", "1272").parse().unwrap_or(1272),
        env_or("ODMF_SINK_H", "2772").parse().unwrap_or(2772),
        env_or("ODMF_SINK_FPS", "30").parse().unwrap_or(30),
    );
    let reply = serde_json::json!({
        "COMMAND": crate::rtsp::RtspMethod::SetParameter.to_string(),
        "width": w,
        "height": h,
        "fps": fps,
        "foldRotatesWithContent": false,
        "rotatesWithContent": false
    })
    .to_string();
    let mut targets = Vec::new();
    if let Some(own) = *chan {
        targets.push(own);
    }
    if let Some(x) = extra
        && !targets.contains(&x)
    {
        targets.push(x);
    }
    let mut sent = 0;
    for cid in targets {
        if let Some(mut ch) = rtc.channel(cid) {
            match ch.write(false, reply.as_bytes()) {
                Ok(n) => {
                    sent += 1;
                    tracing::info!("[webrtc] tx consult SET_PARAMETER {n}B on {cid:?} (w{w} h{h} fps{fps})");
                }
                Err(e) => tracing::warn!("[webrtc] channel {cid:?} write: {e}"),
            }
            if std::env::var("ODMF_UIBC_TEST").is_ok() {
                // Probe: category-129 UIBC event. The phone's data listener
                // logs "onUibcMessage bytes" on the same dispatch path the
                // consult travels; its absence pins the stall to the phone
                // handler thread, not the channel.
                let probe: [u8; 5] = [129, 1, 0, 0, 0];
                match ch.write(true, &probe) {
                    Ok(n) => tracing::info!("[webrtc] tx uibc probe {n}B on {cid:?}"),
                    Err(e) => tracing::warn!("[webrtc] uibc probe {cid:?}: {e}"),
                }
            }
        }
    }
    sent
}

fn open_out(path: &str) -> std::fs::File {
    if let Some(p) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(p);
    }
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => {
            tracing::info!("[webrtc] writing H.265 access units to {path}");
            f
        }
        Err(e) => {
            tracing::warn!("[webrtc] open {path}: {e}");
            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open("/tmp/video_odmf.h265")
                .expect("fallback h265")
        }
    }
}

fn offer_or_resend(
    rtc: &mut Rtc,
    pending: &mut Option<(String, SdpPendingOffer)>,
    mid: &mut Option<Mid>,
    chan: &mut Option<ChannelId>,
    tags: &[String],
    last: &mut tokio::time::Instant,
) {
    if tags.is_empty() {
        return;
    }
    let stale = last.elapsed() >= tokio::time::Duration::from_secs(8);
    match pending {
        Some((payload, _)) => {
            if stale {
                tracing::info!("[webrtc] resend offer → {} tags", tags.len());
                for tag in tags {
                    let _ = sig_channel().send((tag.clone(), payload.clone()));
                }
                *last = tokio::time::Instant::now();
            }
        }
        None => {
            if !stale {
                return;
            }
            let mut api = rtc.sdp_api();
            let m = api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
            // SCTP data channel: heycast's PCRemoteDataHandler runs the
            // media consult over it ({"COMMAND":"interaction"} →
            // {"COMMAND":"SET_PARAMETER",width,height,fps,...}, q2/i.java).
            let cid = api.add_channel("lplus-consult".to_string());
            match api.apply() {
                Some((offer, p)) => {
                    let sdp = offer.to_string();
                    tracing::info!(
                        "[webrtc] tx offer → {} tags ({}B sdp)",
                        tags.len(),
                        sdp.len()
                    );
                    // Signaling wire contract (odmfs/odmfa.java odmfb(String)):
                    // the client only dispatches SDP/candidate JSON nested in
                    // {"cmd":"send","msg":"<inner json string>"} —
                    // `onSocketMessage` case CMD_SEND → odmfc(msg).
                    let inner =
                        serde_json::json!({ "type": "offer", "sdp": sdp }).to_string();
                    let payload =
                        serde_json::json!({ "cmd": "send", "msg": inner }).to_string();
                    for tag in tags {
                        let _ = sig_channel().send((tag.clone(), payload.clone()));
                    }
                    *pending = Some((payload, p));
                    *mid = Some(m);
                    *chan = Some(cid);
                    *last = tokio::time::Instant::now();
                }
                None => tracing::warn!("[webrtc] offer apply returned None (no negotiation)"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offer must be exactly what libwebrtc's H.265 answerer needs:
    /// one recvonly AVPF video m-line with static PT 96 hevc.
    #[test]
    fn h265_only_recvonly_offer() {
        let mut rtc = rtc_build();
        let cand = Candidate::host("192.0.2.1:15550".parse().unwrap(), "udp").unwrap();
        rtc.add_local_candidate(cand);
        let mut api = rtc.sdp_api();
        api.add_media(MediaKind::Video, Direction::RecvOnly, None, None, None);
        api.add_channel("lplus-consult".to_string());
        let (offer, _pending) = api.apply().expect("offer");
        let sdp = offer.to_string();
        let lower = sdp.to_lowercase();
        assert!(lower.contains("m=video 9 udp/tls/rtp/savpf"), "{sdp}");
        assert!(lower.contains("recvonly"), "{sdp}");
        assert!(lower.contains("a=rtpmap:96 h265/90000"), "{sdp}");
        assert!(lower.contains("webrtc-datachannel"), "{sdp}");
        assert!(!lower.contains("vp8") && !lower.contains("h264"), "{sdp}");
        assert!(lower.contains("a=ice-lite") || lower.contains("ice-lite"), "{sdp}");
    }

    /// Only the SDP/candidate `type`s reach the WebRTC task (top level or
    /// inside the `cmd:send` envelope); cast-lane `cmd` messages never leak.
    #[test]
    fn dispatch_filters_by_type() {
        let (tx, mut rx) = unbounded_channel();
        dispatch(&tx, r#"{"type":"answer","sdp":"v=0\r\n"}"#);
        dispatch(
            &tx,
            r#"{"cmd":"send","msg":"{\"type\":\"candidate\",\"label\":0,\"id\":\"0\",\"candidate\":\"candidate:1 1 udp 1 192.0.2.15 9 typ host\"}"}"#,
        );
        dispatch(
            &tx,
            r#"{"cmd":"send","msg":"{\"type\":\"answer\",\"sdp\":\"v=0\\r\\n\"}"}"#,
        );
        dispatch(&tx, r#"{"cmd":"ping"}"#);
        dispatch(&tx, "not json");
        assert!(matches!(rx.try_recv().unwrap(), PcEvent::Answer { .. }));
        assert!(matches!(rx.try_recv().unwrap(), PcEvent::Candidate { .. }));
        assert!(matches!(rx.try_recv().unwrap(), PcEvent::Answer { .. }));
        assert!(rx.try_recv().is_err());
    }
}
