//! Loopback contract server: the machine-facing lane of the daemon.
//!
//! A gRPC server on `127.0.0.1:1421` (ephemeral fallback) exposes
//! `service Lplusd` (`ipc/protos/lplus.proto`) with the prost messages
//! and generated stubs in `lplus_ipc::pb`. Every rpc funnels through one
//! dispatch table below; the descriptor-extracted `pb::SERVICE_METHODS`
//! coverage is test-enforced, so the table is also the router's complete
//! surface. The contract is strictly typed: each handler converts the
//! daemon's internal channel shapes (`lplus_ipc::api`) into protobuf at
//! this boundary — no JSON crosses. Handler failures surface as gRPC
//! `internal` statuses with the message intact.

use std::thread;

use image::ImageEncoder as _;
use lplus_ipc::pb;
use prost::Message as _;

/// The contract lane port.
const CONTRACT_PORT: u16 = 1421;

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
fn handle_method(
    services: &std::sync::Arc<crate::svc::Services>,
    method: &str,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    use crate::backend::{api, cast};
    match method {
        m::PING => Ok(pb::Pong {
            version: env!("CARGO_PKG_VERSION").into(),
            backend_up: services.up.load(std::sync::atomic::Ordering::Relaxed),
        }
        .encode_to_vec()),
        m::LIST_DEVICES => Ok(pb::Devices {
            devices: api::visible_rows(),
        }
        .encode_to_vec()),
        m::CONNECT => {
            let c = decode::<pb::ConnectCmd>(method, payload)?;
            let act = api::device_action(&services.epi, true, &c.ip);
            Ok(act.encode_to_vec())
        }
        m::DISCONNECT => {
            let c = decode::<pb::DisconnectCmd>(method, payload)?;
            let act = api::device_action(&services.epi, false, &c.ip);
            Ok(act.encode_to_vec())
        }
        m::REMOVE_DEVICE => {
            let c = decode::<pb::RemoveDeviceCmd>(method, payload)?;
            // `remove_state_dir` is accepted for contract stability; the
            // daemon keeps pairing material in one state dir today.
            let _ = c.remove_state_dir;
            Ok(pb::RemoveDeviceResult {
                ok: crate::backend::devices::remove_device(&c.device_id),
                device_id: c.device_id,
            }
            .encode_to_vec())
        }
        m::GET_HOST_NAME => Ok(pb::HostName {
            host_name: crate::backend::ipc::host_name(),
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
        m::SIDECAR_STATUS => Ok(api::sidecar_status(
            services.up.load(std::sync::atomic::Ordering::Relaxed),
        )
        .encode_to_vec()),
        m::POLL_EVENTS => {
            let p = decode::<pb::PollEventsRequest>(method, payload)?;
            let (next_seq, events) = lplus_ipc::take_events(p.since_seq, p.limit);
            Ok(pb::Events { next_seq, events }.encode_to_vec())
        }
        m::STATUS => Ok(
            cast::status(services.up.load(std::sync::atomic::Ordering::Relaxed)).encode_to_vec(),
        ),
        m::CAST_PUSH => {
            let c = decode::<pb::CastPushRequest>(method, payload)?;
            Ok(cast::cast_push(&services.epi, &c.key, &c.value).encode_to_vec())
        }
        m::ODMF_START => Ok(cast::odmf_start(&services.epi).encode_to_vec()),
        m::KMS_BOOTSTRAP => {
            let c = decode::<pb::KmsBootstrapRequest>(method, payload)?;
            let act = api::kms_bootstrap(&services.epi, &c.ip);
            Ok(act.encode_to_vec())
        }
        m::SINK_LIST => Ok(pb::SinkRoster {
            // Non-blocking probe path; the gRPC handler awaits the
            // mutex directly (see `sink_list`).
            keys: services.epi.try_sink_keys(),
        }
        .encode_to_vec()),
        m::INJECT_FRAME => {
            let c = decode::<pb::InjectFrameRequest>(method, payload)?;
            let bytes = hex::decode(c.hex.trim()).map_err(|e| format!("bad hex: {e}"))?;
            let queued = services.epi.send(crate::svc::epi::Command::SendFrame {
                key_substr: c.key_substr,
                bytes,
            });
            Ok(ack(queued, None, None))
        }
        m::REQUEST_LIVE => Ok(ack(lplus_ipc::live::request_native(), None, None)),
        m::TAKE_FRAME => take_frame_payload(),
        other => Err(format!("unknown method: {other}")),
    }
}

/// The gRPC service facade: every rpc shares the dispatch table, so
/// the (test-enforced) coverage below is also the router's complete
/// surface; unknown methods never reach us (`Unimplemented` from the
/// generated router).
#[derive(Clone)]
struct LplusdSvc {
    services: std::sync::Arc<crate::svc::Services>,
}

/// Shared unary body: encode the typed request into the dispatch table,
/// then decode the typed reply from its bytes. One table for all rpcs
/// keeps the coverage guarantee meaningful; the encode/decode round
/// trip through prost is negligible at these message sizes.
fn rpc<Req, Res>(
    services: &std::sync::Arc<crate::svc::Services>,
    method: &str,
    request: tonic::Request<Req>,
) -> Result<tonic::Response<Res>, tonic::Status>
where
    Req: prost::Message,
    Res: prost::Message + Default,
{
    let payload = request.into_inner().encode_to_vec();
    let bytes = handle_method(services, method, &payload)
        .map_err(|e| tonic::Status::internal(format!("{method}: {e}")))?;
    Res::decode(bytes.as_slice())
        .map(tonic::Response::new)
        .map_err(|e| tonic::Status::internal(format!("{method} reply: {e}")))
}

/// Snapshot the live sink keys. The roster lives in a tokio mutex
/// (shared with the phone lanes), so it is awaited — the table above is
/// synchronous and must stay clear of runtime-parking calls.
async fn sink_roster_payload(services: &std::sync::Arc<crate::svc::Services>) -> Vec<u8> {
    let keys = services.epi.sink_keys().await;
    pb::SinkRoster { keys }.encode_to_vec()
}

#[tonic::async_trait]
impl pb::lplusd_server::Lplusd for LplusdSvc {
    async fn ping(
        &self,
        request: tonic::Request<pb::PingRequest>,
    ) -> Result<tonic::Response<pb::Pong>, tonic::Status> {
        rpc(&self.services, m::PING, request)
    }
    async fn list_devices(
        &self,
        request: tonic::Request<pb::ListDevicesRequest>,
    ) -> Result<tonic::Response<pb::Devices>, tonic::Status> {
        rpc(&self.services, m::LIST_DEVICES, request)
    }
    async fn connect(
        &self,
        request: tonic::Request<pb::ConnectCmd>,
    ) -> Result<tonic::Response<pb::Ack>, tonic::Status> {
        rpc(&self.services, m::CONNECT, request)
    }
    async fn disconnect(
        &self,
        request: tonic::Request<pb::DisconnectCmd>,
    ) -> Result<tonic::Response<pb::Ack>, tonic::Status> {
        rpc(&self.services, m::DISCONNECT, request)
    }
    async fn remove_device(
        &self,
        request: tonic::Request<pb::RemoveDeviceCmd>,
    ) -> Result<tonic::Response<pb::RemoveDeviceResult>, tonic::Status> {
        rpc(&self.services, m::REMOVE_DEVICE, request)
    }
    async fn get_host_name(
        &self,
        request: tonic::Request<pb::GetHostNameRequest>,
    ) -> Result<tonic::Response<pb::HostName>, tonic::Status> {
        rpc(&self.services, m::GET_HOST_NAME, request)
    }
    async fn set_host_name(
        &self,
        request: tonic::Request<pb::SetHostNameCmd>,
    ) -> Result<tonic::Response<pb::SetHostNameResult>, tonic::Status> {
        rpc(&self.services, m::SET_HOST_NAME, request)
    }
    async fn get_paired_devices(
        &self,
        request: tonic::Request<pb::GetPairedDevicesRequest>,
    ) -> Result<tonic::Response<pb::PairedDevices>, tonic::Status> {
        rpc(&self.services, m::GET_PAIRED_DEVICES, request)
    }
    async fn get_local_device_id(
        &self,
        request: tonic::Request<pb::GetLocalDeviceIdRequest>,
    ) -> Result<tonic::Response<pb::LocalDeviceId>, tonic::Status> {
        rpc(&self.services, m::GET_LOCAL_DEVICE_ID, request)
    }
    async fn ensure_running(
        &self,
        request: tonic::Request<pb::EnsureRunningRequest>,
    ) -> Result<tonic::Response<pb::EnsureRunningResult>, tonic::Status> {
        rpc(&self.services, m::ENSURE_RUNNING, request)
    }
    async fn get_cloud_bind(
        &self,
        request: tonic::Request<pb::GetCloudBindRequest>,
    ) -> Result<tonic::Response<pb::CloudBindResult>, tonic::Status> {
        rpc(&self.services, m::GET_CLOUD_BIND, request)
    }
    async fn sidecar_status(
        &self,
        request: tonic::Request<pb::SidecarStatusRequest>,
    ) -> Result<tonic::Response<pb::SidecarLane>, tonic::Status> {
        rpc(&self.services, m::SIDECAR_STATUS, request)
    }
    async fn poll_events(
        &self,
        request: tonic::Request<pb::PollEventsRequest>,
    ) -> Result<tonic::Response<pb::Events>, tonic::Status> {
        rpc(&self.services, m::POLL_EVENTS, request)
    }
    async fn status(
        &self,
        request: tonic::Request<pb::StatusRequest>,
    ) -> Result<tonic::Response<pb::LplusStatus>, tonic::Status> {
        rpc(&self.services, m::STATUS, request)
    }
    async fn cast_push(
        &self,
        request: tonic::Request<pb::CastPushRequest>,
    ) -> Result<tonic::Response<pb::CastPushResult>, tonic::Status> {
        rpc(&self.services, m::CAST_PUSH, request)
    }
    async fn odmf_start(
        &self,
        request: tonic::Request<pb::OdmfStartRequest>,
    ) -> Result<tonic::Response<pb::OdmfStartResult>, tonic::Status> {
        rpc(&self.services, m::ODMF_START, request)
    }
    async fn kms_bootstrap(
        &self,
        request: tonic::Request<pb::KmsBootstrapRequest>,
    ) -> Result<tonic::Response<pb::Ack>, tonic::Status> {
        rpc(&self.services, m::KMS_BOOTSTRAP, request)
    }
    async fn sink_list(
        &self,
        _request: tonic::Request<pb::SinkListRequest>,
    ) -> Result<tonic::Response<pb::SinkRoster>, tonic::Status> {
        let bytes = sink_roster_payload(&self.services).await;
        pb::SinkRoster::decode(bytes.as_slice())
            .map(tonic::Response::new)
            .map_err(|e| tonic::Status::internal(format!("{} reply: {e}", m::SINK_LIST)))
    }
    async fn inject_frame(
        &self,
        request: tonic::Request<pb::InjectFrameRequest>,
    ) -> Result<tonic::Response<pb::Ack>, tonic::Status> {
        rpc(&self.services, m::INJECT_FRAME, request)
    }
    async fn request_live(
        &self,
        request: tonic::Request<pb::RequestLiveRequest>,
    ) -> Result<tonic::Response<pb::Ack>, tonic::Status> {
        rpc(&self.services, m::REQUEST_LIVE, request)
    }
    async fn take_frame(
        &self,
        request: tonic::Request<pb::TakeFrameRequest>,
    ) -> Result<tonic::Response<pb::FrameReply>, tonic::Status> {
        rpc(&self.services, m::TAKE_FRAME, request)
    }
}

/// Start the loopback contract server; returns the bound port.
pub fn spawn(services: std::sync::Arc<crate::svc::Services>) -> Result<u16, String> {
    // One runtime owns both the bind and the serve: a tokio listener
    // registered on a runtime that is dropped afterwards would accept
    // on a dead reactor.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("contract runtime: {e}"))?;
    let listener = rt
        .block_on(async {
            if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", CONTRACT_PORT)).await
            {
                return Ok(listener);
            }
            tokio::net::TcpListener::bind(("127.0.0.1", 0)).await
        })
        .map_err(|e| format!("bind contract server: {e}"))?;
    serve_with(listener, rt, services)
}

/// Serve the contract on an already-bound tokio listener, on a dedicated
/// runtime (tonic's transport needs a reactor; the daemon proper keeps
/// its own runtimes per lane). Multi-thread flavor: handlers reach
/// tokio-mutex lane state via `blocking_lock`, which a current-thread
/// runtime refuses to park.
fn serve_with(
    listener: tokio::net::TcpListener,
    rt: tokio::runtime::Runtime,
    services: std::sync::Arc<crate::svc::Services>,
) -> Result<u16, String> {
    let addr = listener
        .local_addr()
        .map_err(|e| format!("contract addr: {e}"))?;
    thread::Builder::new()
        .name("contract-grpc".to_string())
        .spawn(move || {
            rt.block_on(async move {
                let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
                if let Err(e) = tonic::transport::Server::builder()
                    .add_service(pb::lplusd_server::LplusdServer::new(LplusdSvc {
                        services: services.clone(),
                    }))
                    .serve_with_incoming(incoming)
                    .await
                {
                    tracing::error!("[contract] grpc server stopped: {e}");
                }
            });
        })
        .map_err(|e| format!("spawn contract server: {e}"))?;
    Ok(addr.port())
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;
    use std::time::Duration;

    use lplus_ipc::pb;

    use super::m;

    /// Shared runtime driving the generated async client.
    fn rt() -> &'static tokio::runtime::Runtime {
        static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_all()
                .build()
                .expect("test grpc runtime")
        });
        &RT
    }

    /// Fresh contract server on an ephemeral port plus the generated
    /// gRPC client — the same surface any external gRPC tool reaches.
    fn services() -> std::sync::Arc<crate::svc::Services> {
        crate::svc::Services::new(crate::svc::sdp::SdpdConfig::default())
    }

    fn client_with(
        services: std::sync::Arc<crate::svc::Services>,
    ) -> pb::lplusd_client::LplusdClient<tonic::transport::Channel> {
        let listener = rt()
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("bind");
        let srv_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("contract runtime");
        let port = super::serve_with(listener, srv_rt, services).expect("serve");
        // Channel creation touches the hyper client's timers, so build
        // it inside the shared runtime.
        let channel = rt().block_on(async {
            tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{port}"))
                .expect("channel")
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .connect_lazy()
        });
        pb::lplusd_client::LplusdClient::new(channel)
    }

    fn client() -> pb::lplusd_client::LplusdClient<tonic::transport::Channel> {
        client_with(services())
    }

    #[test]
    fn dispatch_table_covers_every_service_method() {
        // The schema is the source of truth: every rpc of
        // `service Lplusd` must be dispatched (empty payloads exercise
        // the arm without needing live state).
        for method in pb::SERVICE_METHODS {
            let error = match super::handle_method(&services(), method, &[]) {
                Ok(_) => String::new(),
                Err(error) => error,
            };
            assert!(
                !error.contains("unknown method"),
                "rpc {method} missing from the dispatch table: {error}"
            );
        }
    }

    #[test]
    fn unknown_method_and_garbage_payload_fail_loudly() {
        // The generated router answers unknown methods with gRPC
        // `Unimplemented` before the table is consulted, so probe the
        // table directly: it must reject unknown rpcs and undecodable
        // payloads explicitly, never pass through.
        let err = super::handle_method(&services(), "lplus.backend.v1.Lplusd/Nope", &[])
            .expect_err("unknown");
        assert!(err.contains("unknown method"), "{err}");
        let err = super::handle_method(&services(), m::CONNECT, b"not a prost ConnectCmd")
            .expect_err("junk");
        assert!(err.contains("decode"), "{err}");
    }

    #[test]
    fn ping_pong_reports_version() {
        let mut c = client();
        let pong = rt()
            .block_on(c.ping(pb::PingRequest {}))
            .expect("ping")
            .into_inner();
        assert_eq!(pong.version, env!("CARGO_PKG_VERSION"));
        // The descriptor list and the dispatch table agree on spellings.
        assert!(pb::SERVICE_METHODS.contains(&m::PING));
    }

    #[test]
    fn list_devices_answers_with_the_device_model() {
        let mut c = client();
        rt().block_on(c.list_devices(pb::ListDevicesRequest {}))
            .expect("devices")
            .into_inner();
    }

    #[test]
    fn poll_events_drains_the_presence_ring() {
        let mut c = client();
        let svc = services();
        svc.sdp.emit_device(
            "epi",
            "192.0.2.210".into(),
            Some("ring-probe-phone".into()),
            true,
        );
        let events = rt()
            .block_on(c.poll_events(pb::PollEventsRequest {
                since_seq: 0,
                limit: 0,
            }))
            .expect("events")
            .into_inner();
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
        let mut c = client();
        let st = rt()
            .block_on(c.status(pb::StatusRequest {}))
            .expect("status")
            .into_inner();
        assert!(st.ok);
        // Message-valued fields must be populated, not silently absent.
        let odmf = st.odmf.expect("odmf lane info");
        odmf.session_bin.expect("session_bin");
        odmf.video.expect("video");
        st.rtsp.expect("rtsp info");
    }

    #[test]
    fn connect_rpc_without_ip_is_rejected_as_ack() {
        let mut c = client();
        let ack = rt()
            .block_on(c.connect(pb::ConnectCmd { ip: String::new() }))
            .expect("ack")
            .into_inner();
        assert!(!ack.ok);
        assert_eq!(ack.error.as_deref(), Some("missing ip"));
    }

    #[test]
    fn remove_device_rpc_echoes_the_identity() {
        let mut c = client();
        let r = rt()
            .block_on(c.remove_device(pb::RemoveDeviceCmd {
                device_id: "no-such-device-zzz".into(),
                remove_state_dir: false,
            }))
            .expect("remove result")
            .into_inner();
        assert_eq!(r.device_id, "no-such-device-zzz");
    }

    #[test]
    fn identity_and_probe_rpcs_answer_typed() {
        let mut c = client();
        let hn = rt()
            .block_on(c.get_host_name(pb::GetHostNameRequest {}))
            .expect("host name")
            .into_inner();
        assert!(!hn.host_name.is_empty());

        // Blank names are refused without touching the stored value.
        let refusal = rt()
            .block_on(c.set_host_name(pb::SetHostNameCmd { name: "  ".into() }))
            .expect("set-host-name result")
            .into_inner();
        assert!(!refusal.ok);
        assert!(refusal.error.is_some(), "{refusal:?}");

        let paired = rt()
            .block_on(c.get_paired_devices(pb::GetPairedDevicesRequest {}))
            .expect("paired")
            .into_inner();
        assert!(paired.ok);

        let id = rt()
            .block_on(c.get_local_device_id(pb::GetLocalDeviceIdRequest {}))
            .expect("agent id")
            .into_inner();
        assert_eq!(id.device_id, lplus_ipc::api::local_device_id());

        let run = rt()
            .block_on(c.ensure_running(pb::EnsureRunningRequest {}))
            .expect("ready")
            .into_inner();
        assert!(run.ok && !run.status.is_empty(), "{run:?}");

        let bind = rt()
            .block_on(c.get_cloud_bind(pb::GetCloudBindRequest {}))
            .expect("bind")
            .into_inner();
        assert!(bind.ok && !bind.bound, "no cloud lane yet: {bind:?}");

        rt().block_on(c.sidecar_status(pb::SidecarStatusRequest {}))
            .expect("sidecar");
    }

    #[test]
    fn sink_and_inject_rpcs_answer() {
        // Keep a command subscriber on the server's own bus alive so the
        // queue verdict is true.
        let services = services();
        let _rx = services.epi.subscribe();
        let mut c = client_with(services);
        let roster = rt()
            .block_on(c.sink_list(pb::SinkListRequest {}))
            .expect("roster")
            .into_inner();
        let _ = roster.keys;
        let ack = rt()
            .block_on(c.inject_frame(pb::InjectFrameRequest {
                key_substr: "46888".into(),
                hex: "deadbeef".into(),
            }))
            .expect("ack")
            .into_inner();
        assert!(ack.ok);
        let err = rt()
            .block_on(c.inject_frame(pb::InjectFrameRequest {
                key_substr: "46888".into(),
                hex: "zzz".into(),
            }))
            .expect_err("bad hex must fail");
        assert!(err.message().contains("bad hex"), "{err}");
    }

    #[test]
    fn cast_and_odmf_rpcs_report_their_lanes() {
        let mut c = client();
        let cast = rt()
            .block_on(c.cast_push(pb::CastPushRequest {
                key: String::new(),
                value: "{}".into(),
            }))
            .expect("cast push result")
            .into_inner();
        assert!(!cast.ok, "blank key must fail typed");
        assert!(cast.error.is_some(), "{cast:?}");

        rt().block_on(c.odmf_start(pb::OdmfStartRequest {}))
            .expect("odmf result");
    }

    #[test]
    fn screencast_rpcs_arm_and_pop_a_frame() {
        let mut c = client();
        rt().block_on(c.request_live(pb::RequestLiveRequest {}))
            .expect("arm");
        // No producer in this process: typed "no frame" until one is queued.
        let err = rt()
            .block_on(c.take_frame(pb::TakeFrameRequest {}))
            .expect_err("no frame yet");
        assert!(err.message().contains("no frame"), "{err}");
        lplus_ipc::live::push_frame(image::RgbaImage::from_pixel(
            4,
            2,
            image::Rgba([10, 20, 30, 255]),
        ));
        let frame = rt()
            .block_on(c.take_frame(pb::TakeFrameRequest {}))
            .expect("frame reply")
            .into_inner();
        assert_eq!(
            (frame.width, frame.height, frame.format.as_str()),
            (4, 2, "jpeg")
        );
        assert!(!frame.image.is_empty());
        assert_eq!(&frame.image[..2], &[0xff, 0xd8], "jpeg magic");
    }
}
