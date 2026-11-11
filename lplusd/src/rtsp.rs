//! Cast video lane driver (PROTOCOL.md §7.3): the PC connects to the
//! phone's RTSP server, drives OPTIONS/DESCRIBE/SETUP/PLAY, then receives
//! RTP/UDP H.264 on the advertised port pair. Wire types (RTSP messages,
//! RTP headers, SDP, depacketizer) live in `proto::rtsp`.

use anyhow::{Context, Result};
use std::io::{BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use proto::rtsp::{
    H264Depacketizer, PT_H264, RtspExt, RtspMethod, parse_rtp, parse_sdp, read_msg, request,
};

/// RTP data port the lane advertises when none is configured.
pub const DEFAULT_RTP_PORT: u16 = 15550;

// ---------------------------------------------------------------- lane ----

/// Kick the video lane once (guarded): RTSP client → target, RTP sink on
/// `DEFAULT_RTP_PORT`, Annex-B out to `out_dir/video.{h264,annexb}`.
pub fn spawn_lane(target: String, out_dir: String) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    tracing::info!("[rtsp] lane starting → {target} (rtp :{DEFAULT_RTP_PORT}, out {out_dir})");
    tokio::spawn(async move {
        match run(&target, &out_dir, DEFAULT_RTP_PORT).await {
            Ok(()) => tracing::info!("[rtsp] lane {target} finished"),
            Err(e) => tracing::warn!("[rtsp] lane {target} failed: {e:#}"),
        }
    });
}

/// Full client session, then RTP receive loop (returns only on fatal error).
pub async fn run(target: &str, out_dir: &str, rtp_port: u16) -> Result<()> {
    // RTP socket first so SETUP can advertise it.
    let udp =
        UdpSocket::bind(("0.0.0.0", rtp_port)).with_context(|| format!("bind udp :{rtp_port}"))?;
    // TCP with retry: the phone opens 7236 only after the cast trigger.
    let tcp = loop {
        match TcpStream::connect(target) {
            Ok(s) => break s,
            Err(e) => {
                tracing::info!("[rtsp] connect {target}: {e} (retry 2s)");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    tracing::info!("[rtsp] connected {target}");
    rtsp_handshake(tcp, target, rtp_port)?;
    let h264_path = format!("{out_dir}/video.h264");
    let annexb_path = format!("{out_dir}/video.annexb");
    let mut f1 = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&h264_path)
        .with_context(|| format!("open {h264_path}"))?;
    let mut f2 = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&annexb_path)
        .with_context(|| format!("open {annexb_path}"))?;
    let mut writers: Vec<&mut dyn Write> = vec![&mut f1, &mut f2];
    pump_rtp(&udp, &mut writers, None);
    Ok(())
}

/// Drive OPTIONS/DESCRIBE/SETUP/PLAY on an established RTSP control
/// connection (blocking; 10 s read deadline per hop).
pub fn rtsp_handshake(tcp: TcpStream, target: &str, rtp_port: u16) -> Result<()> {
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut rd = BufReader::new(tcp.try_clone()?);
    let mut wr = tcp;

    let uri = format!("rtsp://{target}/wfd1.0/streamid=0");
    let mut cseq = 0u32;
    macro_rules! sendm {
        ($m:expr) => {{
            let m = $m?; // built with `cseq + 1` at the call site
            cseq += 1;
            let bytes = m.to_bytes();
            wr.write_all(&bytes)?;
            wr.flush()?;
            if let (Some(mth), Some(uri)) = (m.method(), m.uri()) {
                tracing::info!("[rtsp] > {mth} {uri} (CSeq {cseq})");
            }
        }};
    }

    sendm!(request(
        RtspMethod::Options,
        "*",
        cseq + 1,
        &[("Require", "org.wfa.wfd1.0")]
    ));
    let r = read_msg(&mut rd)?;
    tracing::info!(
        "[rtsp] < OPTIONS {} Public={:?}",
        r.status().unwrap_or(0),
        r.header("Public")
    );

    sendm!(request(
        RtspMethod::Describe,
        &uri,
        cseq + 1,
        &[("Accept", "application/sdp")]
    ));
    let d = read_msg(&mut rd)?;
    let sdp = String::from_utf8_lossy(d.body()).to_string();
    let info = parse_sdp(&sdp);
    tracing::info!(
        "[rtsp] < DESCRIBE {} recvonly={} pt={:?} codec={:?} rtp_ports={:?}",
        d.status().unwrap_or(0),
        info.recvonly,
        info.payload_type,
        info.codec,
        info.client_rtp_ports,
    );

    let transport = format!(
        "RTP/AVP/UDP;unicast;client_port={}-{}",
        rtp_port,
        rtp_port + 1
    );
    sendm!(request(
        RtspMethod::Setup,
        &uri,
        cseq + 1,
        &[("Transport", &transport)]
    ));
    let s = read_msg(&mut rd)?;
    // Keep the full Session header (incl. ;timeout) — WFD sinks echo it.
    let session = s.header("Session").map(str::to_string);
    tracing::info!(
        "[rtsp] < SETUP {} session={:?} transport={:?}",
        s.status().unwrap_or(0),
        session,
        s.header("Transport")
    );

    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Some(sess) = session.as_deref() {
        extra.push(("Session", sess));
    }
    extra.push(("Range", "npt=0.000-"));
    sendm!(request(RtspMethod::Play, &uri, cseq + 1, &extra));
    let p = read_msg(&mut rd)?;
    tracing::info!(
        "[rtsp] < PLAY {} range={:?}",
        p.status().unwrap_or(0),
        p.header("Range")
    );
    Ok(())
}

/// Counters from an RTP pump pass.
#[derive(Debug, Default)]
pub struct RtpStats {
    pub pkts: u64,
    pub nals: u64,
    pub bytes: u64,
}

/// RTP receive pump on a bound socket: PT-96 H.264 → Annex-B AUs written to
/// every `Some` writer. `max_pkts` bounds the pass (tests); `None` runs
/// forever (lane). Non-PT96 and malformed packets are ignored.
pub fn pump_rtp(
    udp: &UdpSocket,
    writers: &mut [&mut dyn Write],
    max_pkts: Option<u64>,
) -> RtpStats {
    let _ = udp.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = vec![0u8; 65536];
    let mut dep = H264Depacketizer::default();
    let mut st = RtpStats::default();
    let mut last_seq: Option<u16> = None;
    let mut last_log = std::time::Instant::now();
    let started = std::time::Instant::now();
    loop {
        if let Some(m) = max_pkts {
            if st.pkts >= m {
                return st;
            }
            if started.elapsed() > Duration::from_secs(10) {
                return st; // bounded pass never got its packets
            }
        }
        let Ok(n) = udp.recv(&mut buf) else { continue };
        let Some(hdr) = parse_rtp(&buf[..n]) else {
            continue;
        };
        if hdr.pt != PT_H264 {
            continue;
        }
        st.pkts += 1;
        if last_seq.is_some_and(|s| hdr.seq.wrapping_sub(s) > 100) {
            tracing::info!("[rtp] seq jump {}→{}", last_seq.unwrap(), hdr.seq);
        }
        last_seq = Some(hdr.seq);
        for au in dep.push(hdr.payload) {
            st.nals += 1;
            st.bytes += au.len() as u64;
            for w in writers.iter_mut() {
                let _ = w.write_all(&au);
            }
        }
        if last_log.elapsed() >= Duration::from_secs(5) {
            last_log = std::time::Instant::now();
            tracing::info!(
                "[rtp] pkts={} nals={} bytes={} (last seq={} pt={})",
                st.pkts,
                st.nals,
                st.bytes,
                hdr.seq,
                hdr.pt
            );
            for w in writers.iter_mut() {
                let _ = w.flush();
            }
        }
    }
}

// --------------------------------------------------------------- tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use proto::rtsp::response_with_body;

    fn nalu(t: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![t];
        v.extend_from_slice(body);
        v
    }

    /// End-to-end against a scripted fake phone RTSP server + injected RTP.
    #[test]
    fn e2e_session_and_rtp_against_fake_phone() {
        use std::net::TcpListener;
        type SeenReq = (Option<RtspMethod>, Vec<(String, String)>);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut br = BufReader::new(sock.try_clone().unwrap());
            let mut seen: Vec<SeenReq> = Vec::new();
            for (i, body) in [
                Vec::new(),
                b"m=video 0 RTP/AVP 96\r\na=recvonly\r\n".to_vec(),
                Vec::new(),
                Vec::new(),
            ]
            .into_iter()
            .enumerate()
            {
                let m = read_msg(&mut br).unwrap();
                let cseq: u32 = m.header("CSeq").unwrap().parse().unwrap();
                seen.push((m.method(), m.headers_vec()));
                let mut extra: Vec<(&str, &str)> = Vec::new();
                if i == 0 {
                    extra.push(("Public", "org.wfa.wfd1.0, SETUP, PLAY"));
                }
                if i == 1 {
                    extra.push(("Content-Type", "application/sdp"));
                }
                if i == 2 {
                    extra.push((
                        "Transport",
                        "RTP/AVP;unicast;client_port=15550-15551;server_port=5000-5001",
                    ));
                }
                if i == 3 {
                    extra.push(("Range", "npt=0.000-"));
                }
                let rsp = response_with_body(
                    200,
                    Some("OK"),
                    cseq,
                    Some("4242;timeout=60"),
                    &extra,
                    body,
                );
                sock.write_all(&rsp.to_bytes()).unwrap();
            }
            seen
        });

        let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        rtsp_handshake(tcp, &format!("127.0.0.1:{port}"), DEFAULT_RTP_PORT).unwrap();
        let seen = server.join().unwrap();
        let methods: Vec<Option<RtspMethod>> = seen.iter().map(|(m, _)| *m).collect();
        assert_eq!(
            methods,
            [
                Some(RtspMethod::Options),
                Some(RtspMethod::Describe),
                Some(RtspMethod::Setup),
                Some(RtspMethod::Play)
            ]
        );
        let setup_hdrs = &seen[2].1;
        assert!(
            setup_hdrs.iter().any(
                |(k, v)| k == "Transport" && v == "RTP/AVP/UDP;unicast;client_port=15550-15551"
            )
        );
        assert!(
            seen[3]
                .1
                .iter()
                .any(|(k, v)| k == "Session" && v == "4242;timeout=60"),
            "PLAY headers: {:?}",
            seen[3].1
        );

        // RTP: STAP-A (SPS+PPS) then a 2-fragment FU-A IDR, PT 96.
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("0.0.0.0:0").unwrap();
        let to = rx.local_addr().unwrap();
        let pkt = |seq: u16, payload: &[u8]| {
            let mut p = vec![0x80, PT_H264, (seq >> 8) as u8, seq as u8, 0, 0, 0x0b, 0xad];
            p.extend_from_slice(&[0x0c, 0xfe, 0xe, 0xd0]);
            p.extend_from_slice(payload);
            p
        };
        let stap = {
            let (a, b) = (nalu(0x67, b"S"), nalu(0x68, b"P"));
            let mut v = vec![0x78];
            v.extend_from_slice(&(a.len() as u16).to_be_bytes());
            v.extend_from_slice(&a);
            v.extend_from_slice(&(b.len() as u16).to_be_bytes());
            v.extend_from_slice(&b);
            v
        };
        tx.send_to(&pkt(1, &stap), to).unwrap();
        tx.send_to(&pkt(2, &[0x7C, 0x85, 0xAA]), to).unwrap(); // S=1 type=5
        tx.send_to(&pkt(3, &[0x7C, 0x45, 0xBB]), to).unwrap(); // E=1
        tx.send_to(&[0x00, 0x01, 0x02], to).unwrap(); // junk, ignored
        let mut out: Vec<u8> = Vec::new();
        {
            let mut w: Vec<&mut dyn Write> = vec![&mut out];
            let st = pump_rtp(&rx, &mut w, Some(3));
            assert_eq!(st.pkts, 3);
            assert_eq!(st.nals, 3); // SPS, PPS, IDR
        }
        assert!(out.starts_with(b"\x00\x00\x00\x01\x67"));
        assert_eq!(out.windows(4).filter(|w| *w == [0, 0, 0, 1]).count(), 3);
        // Reassembled IDR header: NRI 3 | type 5.
        assert!(out.ends_with(&[0x65, 0xAA, 0xBB]));
    }
}
