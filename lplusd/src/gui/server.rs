//! Loopback contract server: the machine-facing lane of the daemon.
//!
//! One TCP listener on `127.0.0.1:1421` (ephemeral fallback); every
//! connection carries exactly one frame — a 4-byte big-endian length and
//! a prost [`lplus_ipc::pb::Frame`] — answered with one reply frame.
//! `Frame.method` selects an rpc of `service Lplusd`
//! (`ipc/protos/lplus.proto`); the payload is the rpc's request message
//! and the reply's payload its response message (or `Frame.error`).
//! The contract is strictly typed: each handler converts the daemon's
//! internal channel shapes (`lplus_ipc::api`) into protobuf at this
//! boundary — no JSON crosses. The dispatch table is test-enforced
//! complete against the descriptor-extracted `pb::SERVICE_METHODS`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use image::ImageEncoder as _;
use lplus_ipc::pb::{self, Frame};
use prost::Message as _;

/// Frame size cap, matching the phone-lane readers.
const MAX_FRAME: usize = 4 * 1024 * 1024;

/// gRPC-style full names, one per rpc of `service Lplusd`.
mod m {
    pub const PING: &str = "lplus.backend.v1.Lplusd/Ping";
    pub const LIST_DEVICES: &str = "lplus.backend.v1.Lplusd/ListDevices";
    pub const CONNECT: &str = "lplus.backend.v1.Lplusd/Connect";
    pub const DISCONNECT: &str = "lplus.backend.v1.Lplusd/Disconnect";
    pub const REMOVE_DEVICE: &str = "lplus.backend.v1.Lplusd/RemoveDevice";
    pub const GET_HOST_NAME: &str = "lplus.backend.v1.Lplusd/GetHostName";
    pub const SET_HOST_NAME: &str = "lplus.backend.v1.Lplusd/SetHostName";
    pub const GET_PAIRED_DEVICES: &str = "lplus.backend.v1.Lplusd/GetPairedDevices";
    pub const GET_LOCAL_DEVICE_ID: &str = "lplus.backend.v1.Lplusd/GetLocalDeviceId";
    pub const ENSURE_RUNNING: &str = "lplus.backend.v1.Lplusd/EnsureRunning";
    pub const GET_CLOUD_BIND: &str = "lplus.backend.v1.Lplusd/GetCloudBind";
    pub const SIDECAR_STATUS: &str = "lplus.backend.v1.Lplusd/SidecarStatus";
    pub const POLL_EVENTS: &str = "lplus.backend.v1.Lplusd/PollEvents";
    pub const STATUS: &str = "lplus.backend.v1.Lplusd/Status";
    pub const CAST_PUSH: &str = "lplus.backend.v1.Lplusd/CastPush";
    pub const ODMF_START: &str = "lplus.backend.v1.Lplusd/OdmfStart";
    pub const KMS_BOOTSTRAP: &str = "lplus.backend.v1.Lplusd/KmsBootstrap";
    pub const SINK_LIST: &str = "lplus.backend.v1.Lplusd/SinkList";
    pub const INJECT_FRAME: &str = "lplus.backend.v1.Lplusd/InjectFrame";
    pub const REQUEST_LIVE: &str = "lplus.backend.v1.Lplusd/RequestLive";
    pub const TAKE_FRAME: &str = "lplus.backend.v1.Lplusd/TakeFrame";
}

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 4];
    match stream.read_exact(&mut head) {
        Ok(()) => {}
        // Client closed before sending anything.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other(format!("frame too large: {len}")));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    stream.write_all(&out)?;
    stream.flush()
}

fn decode<T: prost::Message + Default>(method: &str, payload: &[u8]) -> Result<T, String> {
    T::decode(payload).map_err(|e| format!("decode {method}: {e}"))
}

fn ack(ok: bool, ip: Option<String>, error: Option<String>) -> Vec<u8> {
    pb::Ack { ok, ip, error }.encode_to_vec()
}

/// Encode one queued screencast frame as JPEG (the image lane ships
/// 8-bit colour only).
fn take_frame_payload() -> Result<Vec<u8>, String> {
    let img = lplus_ipc::live::take_frame().ok_or_else(|| "no frame".to_string())?;
    let (width, height) = (img.width(), img.height());
    let rgb = image::DynamicImage::ImageRgba8(img).to_rgb8();
    let mut buf = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 80)
        .write_image(rgb.as_raw(), width, height, image::ExtendedColorType::Rgb8)
        .map_err(|e| format!("frame encode: {e}"))?;
    Ok(pb::FrameReply {
        width,
        height,
        seq: lplus_ipc::live::produced() as u64,
        format: "jpeg".into(),
        image: buf,
    }
    .encode_to_vec())
}

/// Run one rpc; `Err(message)` becomes `Frame.error` on the reply.
fn handle_method(method: &str, payload: &[u8]) -> Result<Vec<u8>, String> {
    use crate::gui::{api, cast};
    match method {
        m::PING => Ok(pb::Pong {
            version: env!("CARGO_PKG_VERSION").into(),
            backend_up: crate::gui::backend_up(),
        }
        .encode_to_vec()),
        m::LIST_DEVICES => Ok(pb::Devices {
            devices: api::visible_rows(),
        }
        .encode_to_vec()),
        m::CONNECT => {
            let c = decode::<pb::ConnectCmd>(method, payload)?;
            let act = api::device_action(true, &c.ip);
            Ok(act.encode_to_vec())
        }
        m::DISCONNECT => {
            let c = decode::<pb::DisconnectCmd>(method, payload)?;
            let act = api::device_action(false, &c.ip);
            Ok(act.encode_to_vec())
        }
        m::REMOVE_DEVICE => {
            let c = decode::<pb::RemoveDeviceCmd>(method, payload)?;
            // `remove_state_dir` is accepted for contract stability; the
            // daemon keeps pairing material in one state dir today.
            let _ = c.remove_state_dir;
            Ok(pb::RemoveDeviceResult {
                ok: crate::gui::devices::remove_device(&c.device_id),
                device_id: c.device_id,
            }
            .encode_to_vec())
        }
        m::GET_HOST_NAME => Ok(pb::HostName {
            host_name: crate::gui::ipc::host_name(),
        }
        .encode_to_vec()),
        m::SET_HOST_NAME => {
            let c = decode::<pb::SetHostNameCmd>(method, payload)?;
            Ok(api::set_host_name(&c.name).encode_to_vec())
        }
        m::GET_PAIRED_DEVICES => Ok(api::paired_devices().encode_to_vec()),
        m::GET_LOCAL_DEVICE_ID => Ok(pb::LocalDeviceId {
            device_id: lplus_ipc::api::local_device_id(),
        }
        .encode_to_vec()),
        m::ENSURE_RUNNING => Ok(pb::EnsureRunningResult {
            ok: true,
            status: "idle".into(),
        }
        .encode_to_vec()),
        // No cloud lane yet: bound=false is the whole story.
        m::GET_CLOUD_BIND => Ok(pb::CloudBindResult {
            ok: true,
            bound: false,
        }
        .encode_to_vec()),
        m::SIDECAR_STATUS => Ok(api::sidecar_status().encode_to_vec()),
        m::POLL_EVENTS => {
            let p = decode::<pb::PollEventsRequest>(method, payload)?;
            let (next_seq, events) = lplus_ipc::take_events(p.since_seq, p.limit);
            Ok(pb::Events { next_seq, events }.encode_to_vec())
        }
        m::STATUS => Ok(cast::status().encode_to_vec()),
        m::CAST_PUSH => {
            let c = decode::<pb::CastPushRequest>(method, payload)?;
            Ok(cast::cast_push(&c.key, &c.value).encode_to_vec())
        }
        m::ODMF_START => Ok(cast::odmf_start().encode_to_vec()),
        m::KMS_BOOTSTRAP => {
            let c = decode::<pb::KmsBootstrapRequest>(method, payload)?;
            let act = api::kms_bootstrap(&c.ip);
            Ok(act.encode_to_vec())
        }
        m::SINK_LIST => Ok(pb::SinkRoster {
            keys: crate::sdpd::EPI_SINKS
                .blocking_lock()
                .keys()
                .cloned()
                .collect(),
        }
        .encode_to_vec()),
        m::INJECT_FRAME => {
            let c = decode::<pb::InjectFrameRequest>(method, payload)?;
            let bytes = hex::decode(c.hex.trim()).map_err(|e| format!("bad hex: {e}"))?;
            let queued = crate::sdpd::send_command(crate::sdpd::Command::SendFrame {
                key_substr: c.key_substr,
                hex: hex::encode(bytes),
            });
            Ok(ack(queued, None, None))
        }
        m::REQUEST_LIVE => Ok(ack(lplus_ipc::live::request_native(), None, None)),
        m::TAKE_FRAME => take_frame_payload(),
        other => Err(format!("unknown method: {other}")),
    }
}

/// Decode one request frame, run its rpc, and encode the reply frame.
fn rpc_reply(body: &[u8]) -> Vec<u8> {
    let req = match Frame::decode(body) {
        Ok(req) => req,
        Err(e) => {
            tracing::warn!("[contract] undecodable frame: {e}");
            return Frame {
                method: String::new(),
                error: format!("decode: {e}"),
                payload: Vec::new(),
            }
            .encode_to_vec();
        }
    };
    let (error, payload) = match handle_method(&req.method, &req.payload) {
        Ok(payload) => (String::new(), payload),
        Err(error) => {
            tracing::warn!("[contract] {} failed: {error}", req.method);
            (error, Vec::new())
        }
    };
    Frame {
        method: req.method,
        error,
        payload,
    }
    .encode_to_vec()
}

fn handle(stream: &mut TcpStream) -> std::io::Result<()> {
    if let Some(body) = read_frame(stream)? {
        let payload = rpc_reply(&body);
        write_frame(stream, &payload)?;
    }
    Ok(())
}

/// Start the loopback contract server; returns the bound port.
pub fn spawn() -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 1421))
        .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))
        .map_err(|e| format!("bind contract server: {e}"))?;
    serve_on(listener)
}

fn serve_on(listener: TcpListener) -> Result<u16, String> {
    let port = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();
    thread::Builder::new()
        .name("contract-rpc".into())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                // One thread per connection; a stalled client must not
                // starve other lanes' ticks.
                let _ = thread::Builder::new()
                    .name("contract-rpc-conn".into())
                    .spawn(move || {
                        let mut stream = stream;
                        // Client disconnects mid-frame are the normal end
                        // of a connection.
                        let _ = handle(&mut stream);
                    });
            }
        })
        .map_err(|e| format!("spawn contract server thread: {e}"))?;
    Ok(port)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use lplus_ipc::pb::{self, Frame};
    use prost::Message as _;

    use super::m;

    /// One request/response round trip on the frame socket.
    fn call(port: u16, method: &str, payload: &[u8]) -> Frame {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .expect("timeout");
        let req = Frame {
            method: method.into(),
            error: String::new(),
            payload: payload.to_vec(),
        }
        .encode_to_vec();
        let mut frame = Vec::new();
        frame.extend_from_slice(&(req.len() as u32).to_be_bytes());
        frame.extend_from_slice(&req);
        s.write_all(&frame).expect("send");
        let mut head = [0u8; 4];
        s.read_exact(&mut head).expect("read head");
        let len = u32::from_be_bytes(head) as usize;
        let mut payload = vec![0u8; len];
        s.read_exact(&mut payload).expect("read body");
        Frame::decode(&payload[..]).expect("decode reply")
    }

    fn ok(port: u16, method: &str, payload: &[u8]) -> Vec<u8> {
        let reply = call(port, method, payload);
        assert!(reply.error.is_empty(), "{}: {}", method, reply.error);
        assert_eq!(reply.method, method);
        reply.payload
    }

    fn serve() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        super::serve_on(listener).expect("serve_on");
        port
    }

    #[test]
    fn dispatch_table_covers_every_service_method() {
        // The schema is the source of truth: every rpc of
        // `service Lplusd` must be dispatched (empty payloads exercise
        // the arm without needing live state).
        for method in pb::SERVICE_METHODS {
            let (error, _) = call_probe(method);
            assert!(
                !error.contains("unknown method"),
                "rpc {method} missing from the dispatch table: {error}"
            );
        }
    }

    /// In-process dispatch probe (no socket needed).
    fn call_probe(method: &str) -> (String, Vec<u8>) {
        match super::handle_method(method, &[]) {
            Ok(payload) => (String::new(), payload),
            Err(error) => (error, Vec::new()),
        }
    }

    #[test]
    fn ping_pong_reports_version() {
        let port = serve();
        let pong = pb::Pong::decode(&ok(port, m::PING, &[])[..]).expect("pong");
        assert_eq!(pong.version, env!("CARGO_PKG_VERSION"));
        // The descriptor list and the dispatch table agree on spellings.
        assert!(pb::SERVICE_METHODS.contains(&m::PING));
    }

    #[test]
    fn list_devices_answers_with_the_device_model() {
        let port = serve();
        pb::Devices::decode(&ok(port, m::LIST_DEVICES, &[])[..]).expect("devices");
    }

    #[test]
    fn poll_events_drains_the_presence_ring() {
        let port = serve();
        crate::sdpd::emit_device(
            "epi",
            "192.0.2.210".into(),
            Some("ring-probe-phone".into()),
            true,
        );
        let body = ok(
            port,
            m::POLL_EVENTS,
            &pb::PollEventsRequest {
                since_seq: 0,
                limit: 0,
            }
            .encode_to_vec(),
        );
        let events = pb::Events::decode(&body[..]).expect("events");
        assert!(
            events.events.iter().any(|ev| matches!(
                &ev.body,
                Some(pb::event::Body::Device(d))
                    if d.lane == "epi"
                        && d.ip == "192.0.2.210"
                        && d.name == "ring-probe-phone"
                        && d.connected
            )),
            "presence event missing from ring"
        );
        assert!(events.next_seq >= events.events.iter().map(|ev| ev.seq).max().unwrap_or(0));
    }

    #[test]
    fn status_rpc_answers_fully_typed() {
        let port = serve();
        let st = pb::LplusStatus::decode(&ok(port, m::STATUS, &[])[..]).expect("status");
        assert!(st.ok);
        // Message-valued fields must be populated, not silently absent.
        let odmf = st.odmf.expect("odmf lane info");
        odmf.session_bin.expect("session_bin");
        odmf.video.expect("video");
        st.rtsp.expect("rtsp info");
    }

    #[test]
    fn connect_rpc_without_ip_is_rejected_as_ack() {
        let port = serve();
        let ack = pb::Ack::decode(
            &ok(
                port,
                m::CONNECT,
                &pb::ConnectCmd { ip: String::new() }.encode_to_vec(),
            )[..],
        )
        .expect("ack");
        assert!(!ack.ok);
        assert_eq!(ack.error.as_deref(), Some("missing ip"));
    }

    #[test]
    fn remove_device_rpc_echoes_the_identity() {
        let port = serve();
        let r = pb::RemoveDeviceResult::decode(
            &ok(
                port,
                m::REMOVE_DEVICE,
                &pb::RemoveDeviceCmd {
                    device_id: "no-such-device-zzz".into(),
                    remove_state_dir: false,
                }
                .encode_to_vec(),
            )[..],
        )
        .expect("remove result");
        assert_eq!(r.device_id, "no-such-device-zzz");
    }

    #[test]
    fn identity_and_probe_rpcs_answer_typed() {
        let port = serve();
        let hn = pb::HostName::decode(&ok(port, m::GET_HOST_NAME, &[])[..]).expect("host name");
        assert!(!hn.host_name.is_empty());

        // Blank names are refused without touching the stored value.
        let refusal = pb::SetHostNameResult::decode(
            &ok(
                port,
                m::SET_HOST_NAME,
                &pb::SetHostNameCmd { name: "  ".into() }.encode_to_vec(),
            )[..],
        )
        .expect("set-host-name result");
        assert!(!refusal.ok);
        assert!(refusal.error.is_some(), "{refusal:?}");

        let paired =
            pb::PairedDevices::decode(&ok(port, m::GET_PAIRED_DEVICES, &[])[..]).expect("paired");
        assert!(paired.ok);

        let id = pb::LocalDeviceId::decode(&ok(port, m::GET_LOCAL_DEVICE_ID, &[])[..])
            .expect("agent id");
        assert_eq!(id.device_id, lplus_ipc::api::local_device_id());

        let run =
            pb::EnsureRunningResult::decode(&ok(port, m::ENSURE_RUNNING, &[])[..]).expect("ready");
        assert!(run.ok && !run.status.is_empty(), "{run:?}");

        let bind =
            pb::CloudBindResult::decode(&ok(port, m::GET_CLOUD_BIND, &[])[..]).expect("bind");
        assert!(bind.ok && !bind.bound, "no cloud lane yet: {bind:?}");

        pb::SidecarLane::decode(&ok(port, m::SIDECAR_STATUS, &[])[..]).expect("sidecar");
    }

    #[test]
    fn sink_and_inject_rpcs_answer() {
        let port = serve();
        let roster = pb::SinkRoster::decode(&ok(port, m::SINK_LIST, &[])[..]).expect("roster");
        let _ = roster.keys;
        // Keep a command subscriber alive so the queue verdict is true.
        let _rx = crate::sdpd::subscribe_commands();
        let ack = pb::Ack::decode(
            &ok(
                port,
                m::INJECT_FRAME,
                &pb::InjectFrameRequest {
                    key_substr: "46888".into(),
                    hex: "deadbeef".into(),
                }
                .encode_to_vec(),
            )[..],
        )
        .expect("ack");
        assert!(ack.ok);
        let reply = call(
            port,
            m::INJECT_FRAME,
            &pb::InjectFrameRequest {
                key_substr: "46888".into(),
                hex: "zzz".into(),
            }
            .encode_to_vec(),
        );
        assert!(reply.error.contains("bad hex"), "{:?}", reply.error);
    }

    #[test]
    fn cast_and_odmf_rpcs_report_their_lanes() {
        let port = serve();
        let cast = pb::CastPushResult::decode(
            &ok(
                port,
                m::CAST_PUSH,
                &pb::CastPushRequest {
                    key: String::new(),
                    value: "{}".into(),
                }
                .encode_to_vec(),
            )[..],
        )
        .expect("cast push result");
        assert!(!cast.ok, "blank key must fail typed");
        assert!(cast.error.is_some(), "{cast:?}");

        pb::OdmfStartResult::decode(&ok(port, m::ODMF_START, &[])[..]).expect("odmf result");
    }

    #[test]
    fn screencast_rpcs_arm_and_pop_a_frame() {
        let port = serve();
        pb::Ack::decode(&ok(port, m::REQUEST_LIVE, &[])[..]).expect("ack");
        // No producer in this process: typed "no frame" until one is queued.
        let reply = call(port, m::TAKE_FRAME, &[]);
        assert!(reply.error.contains("no frame"), "{:?}", reply.error);
        lplus_ipc::live::push_frame(image::RgbaImage::from_pixel(
            4,
            2,
            image::Rgba([10, 20, 30, 255]),
        ));
        let frame = pb::FrameReply::decode(&ok(port, m::TAKE_FRAME, &[])[..]).expect("frame reply");
        assert_eq!(
            (frame.width, frame.height, frame.format.as_str()),
            (4, 2, "jpeg")
        );
        assert!(!frame.image.is_empty());
        assert_eq!(&frame.image[..2], &[0xff, 0xd8], "jpeg magic");
    }

    #[test]
    fn unknown_method_and_garbage_payload_answer_with_error() {
        let port = serve();
        let reply = call(port, "lplus.backend.v1.Lplusd/Nope", &[]);
        assert!(reply.error.contains("unknown method"), "{:?}", reply.error);
        let reply = call(port, m::CONNECT, b"not a prost ConnectCmd");
        assert!(reply.error.contains("decode"), "{:?}", reply.error);
    }

    #[test]
    fn undecodable_frame_answers_with_error() {
        let port = serve();
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        s.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .expect("timeout");
        let junk = b"not a prost frame";
        let mut frame = Vec::new();
        frame.extend_from_slice(&(junk.len() as u32).to_be_bytes());
        frame.extend_from_slice(junk);
        s.write_all(&frame).expect("send");
        let mut head = [0u8; 4];
        s.read_exact(&mut head).expect("read head");
        let mut payload = vec![0u8; u32::from_be_bytes(head) as usize];
        s.read_exact(&mut payload).expect("read body");
        let reply = Frame::decode(&payload[..]).expect("decode");
        assert!(reply.error.contains("decode"), "{reply:?}");
    }
}
