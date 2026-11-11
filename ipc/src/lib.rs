//! L+ connect backend contract: the crate the daemon serves and any
//! external control client speaks.
//!
//! * [`pb`] — prost types generated from `protos/lplus.proto`: the
//!   `service Lplusd` rpc surface (ping, devices, connect/disconnect/
//!   remove, identity, pairing, probes, events, status, cast/odmf/kms,
//!   sinks/inject, screencast), each rpc's request/response messages,
//!   and the `Frame` envelope of the loopback contract server (4-byte BE
//!   length + one prost frame per connection). `pb::SERVICE_METHODS` —
//!   extracted from the descriptor at build time — is the authoritative
//!   rpc list the server's dispatch table must cover. The contract is
//!   strictly typed: every rpc has a real protobuf response, no JSON
//!   carriers.
//! * [`api`] — the daemon's two persisted JSON shapes (`SettingsFile`,
//!   `local_device_id`); the contract itself carries no JSON.
//! * the process-global event ring ([`push_device_event`],
//!   [`push_log_event`], [`push_bus_event`] → [`take_events`]), drained
//!   by the `PollEvents` rpc.
//!
//! No sockets, no tokio, no daemon state.

pub mod api;
pub mod live;

mod pb_mod {
    include!(concat!(env!("OUT_DIR"), "/lplus.backend.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

/// Generated contract surface (see `protos/lplus.proto`).
pub mod pb {
    pub use super::pb_mod::{
        Ack, BusEvent, CastPushRequest, CastPushResult, CloudBindResult, ConnectCmd, Device,
        DeviceEvent, Devices, DisconnectCmd, EnsureRunningRequest, EnsureRunningResult, Event,
        Events, FileInfo, FrameReply, GetCloudBindRequest, GetHostNameRequest,
        GetLocalDeviceIdRequest, GetPairedDevicesRequest, HostName, InjectFrameRequest,
        KmsBootstrapRequest, ListDevicesRequest, LocalDeviceId, LogEvent, LplusStatus, OdmfInfo,
        OdmfStartRequest, OdmfStartResult, PairEntry, PairedDevices, PingRequest,
        PollEventsRequest, Pong, RemoveDeviceCmd, RemoveDeviceResult, RequestLiveRequest, RtspInfo,
        SERVICE_METHODS, SetHostNameCmd, SetHostNameResult, SidecarLane, SidecarStatusRequest,
        SinkListRequest, SinkRoster, StatusRequest, TakeFrameRequest, event, lplusd_client,
        lplusd_server,
    };
}

// ---------------------------------------------------------------- events --

use std::collections::VecDeque;
use std::sync::{LazyLock, Mutex};

use pb::{BusEvent, DeviceEvent, Event, LogEvent, event};

/// Event ring capacity; older happenings are dropped first.
pub const EVENT_RING: usize = 512;

static EVENTS: LazyLock<Mutex<(u64, VecDeque<Event>)>> = LazyLock::new(Mutex::default);

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Queue one daemon happening; stampers own the sequence and clock.
fn push(body: event::Body) {
    if let Ok(mut g) = EVENTS.lock() {
        g.0 += 1;
        let seq = g.0;
        g.1.push_back(Event {
            seq,
            ts_ms: now_ms(),
            body: Some(body),
        });
        while g.1.len() > EVENT_RING {
            g.1.pop_front();
        }
    }
}

/// Lane presence change (`lane`: epi|kms|sdp). Producer: `sdpd::emit_device`.
pub fn push_device_event(lane: &str, ip: &str, name: Option<&str>, connected: bool) {
    push(event::Body::Device(DeviceEvent {
        lane: lane.to_string(),
        ip: ip.to_string(),
        name: name.unwrap_or_default().to_string(),
        connected,
    }));
}

/// Mirrored console line. Producer: the renderer console bridge.
pub fn push_log_event(level: &str, text: &str) {
    push(event::Body::Log(LogEvent {
        level: level.to_string(),
        text: text.to_string(),
    }));
}

/// Renderer-bus reply (`ok` = a route handled the event name).
/// Producer: the channel dispatcher's bus arm.
pub fn push_bus_event(name: &str, ok: bool) {
    push(event::Body::Bus(BusEvent {
        name: name.to_string(),
        ok,
    }));
}

/// Drain events with `seq > since_seq`, keeping the newest `limit`
/// (0 = everything retained). Returns `(next_seq, events)`; feed
/// `next_seq` back as `since_seq`. A `since_seq` older than the ring
/// yields the retained tail.
pub fn take_events(since_seq: u64, limit: u32) -> (u64, Vec<Event>) {
    EVENTS
        .lock()
        .map(|g| {
            let cap = if limit == 0 {
                usize::MAX
            } else {
                limit as usize
            };
            let evs: Vec<Event> =
                g.1.iter()
                    .filter(|e| e.seq > since_seq)
                    .rev()
                    .take(cap)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .cloned()
                    .collect();
            (g.0, evs)
        })
        .unwrap_or((since_seq, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_json_keeps_camel_case_and_vendor_typo() {
        let row = pb::Device {
            device_id: "d1".into(),
            device_name: "Phone".into(),
            ip: "192.0.2.7".into(),
            connect_type: 1,
            device_type: 6,
            is_same_account: true,
            status: "online".into(),
            time: 42,
            usb_serial: Some("SN".into()),
            is_discovered: true,
            is_connected: true,
            is_paired: true,
            protcol_device_id: "p1".into(),
            last_seen: 1,
            last_session: 2,
        };
        let v = serde_json::to_value(&row).expect("serialize");
        assert_eq!(v["deviceId"], "d1");
        assert_eq!(v["isConnected"], true);
        assert_eq!(v["usbSerial"], "SN");
        assert_eq!(v["protcol_device_id"], "p1");
        assert_eq!(v["lastSeen"], 1);
        assert_eq!(v["lastSession"], 2);
        let back: pb::Device = serde_json::from_value(v).expect("deserialize");
        assert_eq!(back, row);
    }

    #[test]
    fn service_methods_are_extracted_from_the_descriptor() {
        assert!(pb::SERVICE_METHODS.contains(&"lplus.backend.v1.Lplusd/Ping"));
        assert!(
            pb::SERVICE_METHODS
                .iter()
                .all(|m| m.starts_with("lplus.backend.v1.Lplusd/"))
        );
        assert!(pb::SERVICE_METHODS.contains(&"lplus.backend.v1.Lplusd/GetHostName"));
        assert_eq!(pb::SERVICE_METHODS.len(), 21);
    }

    #[test]
    fn event_ring_sequences_filters_and_trims() {
        let marker = format!("ring-probe-{}", std::process::id());
        let (base, _) = take_events(0, 0);
        for i in 0..3 {
            push_log_event("info", &format!("{marker}-{i}"));
        }
        let (next, evs) = take_events(base, 0);
        assert_eq!(next, base + 3, "sequence advances per push");
        let mine: Vec<&Event> = evs
            .iter()
            .filter(|e| {
                matches!(&e.body,
                Some(pb::event::Body::Log(l)) if l.text.starts_with(&marker))
            })
            .collect();
        assert_eq!(mine.len(), 3);
        assert!(
            mine.windows(2).all(|w| w[0].seq < w[1].seq),
            "ascending seq"
        );

        // since_seq filters the tail; limit caps to the newest.
        let since = mine[1].seq - 1;
        let (_, evs) = take_events(since, 0);
        assert!(evs.iter().all(|e| e.seq > since));
        let (_, capped) = take_events(base, 2);
        assert_eq!(capped.len(), 2);
        assert_eq!(capped[1].seq, next);

        // The ring stays bounded no matter how many pushes happened.
        let (_, all) = take_events(0, 0);
        assert!(all.len() <= EVENT_RING);
    }
}
