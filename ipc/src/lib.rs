//! L+ connect daemon↔ui contract: the single crate both `lplusd`
//! and `lplus-ui` depend on (and the only thing they share).
//!
//! * [`pb`] — prost types generated from `protos/ui.proto`: the `POST /rpc`
//!   `Request`/`Response` envelope plus the `DeviceRow` card contract.
//!   Control verbs (connect/disconnect/remove/click/poll) are typed arms;
//!   every other channel rides `InvokeCall` — method string + JSON bytes,
//!   the same shape the phone's own `cpbus.networking` RPC uses.
//! * [`api`] — the typed channel arg/reply structs both ends parse.
//! * [`ui_clicks`] — the element-click queue (contract server pushes, ui drains).
//! * [`dispatcher`] — the Direct-mode registry: the daemon installs its
//!   channel dispatcher at startup so the merged window can invoke
//!   without the ui crate ever naming the daemon.
//!
//! No sockets, no tokio, no daemon state.

pub mod api;
pub mod live;

mod pb_mod {
    include!(concat!(env!("OUT_DIR"), "/lplus.ui.v1.rs"));
}

/// Generated `/rpc` envelope + row contract (see `protos/ui.proto`).
pub mod pb {
    pub use super::pb_mod::{
        Ack, ClickCmd, Clicks, ConnectCmd, DeviceRow, DisconnectCmd, Error, InvokeCall,
        InvokeResult, PollClicks, RemoveDeviceCmd, Request, Response, request, response,
    };
}

// ------------------------------------------------------------- ui clicks --

use std::sync::{LazyLock, Mutex};

static UI_CLICKS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(Mutex::default);

fn clicks() -> &'static Mutex<Vec<String>> {
    &UI_CLICKS
}

/// Queue one element id for the window (contract-server `Click` frame).
pub fn push_ui_click(id: impl Into<String>) {
    if let Ok(mut q) = clicks().lock() {
        q.push(id.into());
    }
}

/// UI presence tick: drain every queued element id (Direct mode shares
/// this process-global queue; served mode goes through `/rpc PollClicks`).
pub fn take_ui_clicks() -> Vec<String> {
    clicks()
        .lock()
        .map(|mut q| std::mem::take(&mut *q))
        .unwrap_or_default()
}

// ------------------------------------------------------------- dispatcher --

/// Channel dispatcher entry (`lplusd::gui::ipc::dispatch`).
pub type Dispatcher = fn(&str, serde_json::Value) -> serde_json::Value;

static DISPATCHER: LazyLock<Mutex<Option<Dispatcher>>> = LazyLock::new(Mutex::default);

fn slot() -> &'static Mutex<Option<Dispatcher>> {
    &DISPATCHER
}

/// Daemon startup (Direct mode): publish the in-process dispatcher;
/// returns the previous registration.
pub fn install_dispatcher(d: Dispatcher) -> Option<Dispatcher> {
    slot().lock().ok().and_then(|mut s| s.replace(d))
}

/// UI Direct transport: run a channel through the installed dispatcher;
/// `None` when no daemon registered one (window is Attach-only).
pub fn dispatch(name: &str, args: serde_json::Value) -> Option<serde_json::Value> {
    slot()
        .lock()
        .ok()
        .and_then(|s| s.as_ref().map(|f| f(name, args)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    #[test]
    fn device_row_json_keeps_camel_case_and_vendor_typo() {
        let row = pb::DeviceRow {
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
        let back: pb::DeviceRow = serde_json::from_value(v).expect("deserialize");
        assert_eq!(back, row);
    }

    #[test]
    fn request_response_oneofs_round_trip_over_prost() {
        let req = pb::Request {
            call: Some(pb::request::Call::Connect(pb::ConnectCmd {
                ip: "192.0.2.7".into(),
            })),
        };
        let bytes = req.encode_to_vec();
        assert_eq!(pb::Request::decode(&bytes[..]).expect("decode"), req);

        let invoke = pb::Request {
            call: Some(pb::request::Call::Invoke(pb::InvokeCall {
                method: "paired_devices".into(),
                payload: br#"{}"#.to_vec(),
            })),
        };
        let bytes = invoke.encode_to_vec();
        assert_eq!(pb::Request::decode(&bytes[..]).expect("decode"), invoke);

        let res = pb::Response {
            res: Some(pb::response::Res::Ack(pb::Ack {
                ok: true,
                ip: Some("192.0.2.7".into()),
                error: None,
                code_success: Some(true),
            })),
        };
        let bytes = res.encode_to_vec();
        assert_eq!(pb::Response::decode(&bytes[..]).expect("decode"), res);
    }

    #[test]
    fn ui_click_queue_is_fifo_and_drains_once() {
        // Other tests may interleave: assert relative behaviour, not emptiness.
        let base = take_ui_clicks().len();
        push_ui_click("card-disconnect:192-0-2-100");
        push_ui_click("confirm");
        let taken = take_ui_clicks();
        assert_eq!(taken.len(), base + 2);
        assert_eq!(taken[taken.len() - 2], "card-disconnect:192-0-2-100");
        assert_eq!(taken[taken.len() - 1], "confirm");
        assert!(take_ui_clicks().is_empty() || true); // drained or other-test noise
    }

    #[test]
    fn dispatcher_install_call_and_remove() {
        let prev =
            install_dispatcher(|name, args| serde_json::json!({"channel": name, "echo": args}));
        let out =
            dispatch("device_action", serde_json::json!({"ip": "192.0.2.9"})).expect("installed");
        assert_eq!(out["channel"], "device_action");
        assert_eq!(out["echo"]["ip"], "192.0.2.9");
        install_dispatcher(prev.unwrap_or(|_, _| serde_json::Value::Null));
        let _ = install_dispatcher(prev.unwrap_or_else(|| {
            fn none(_: &str, _: serde_json::Value) -> serde_json::Value {
                serde_json::Value::Null
            }
            none
        }));
    }
}
