//! Root application view: stores, router and the mock main-process seam.
//! Handlers are pure (testable); the thin `on_click` listeners in
//! `views.rs` call them and schedule a repaint.

use std::str::FromStr;

use gpui::{Context, Task};
use strum::EnumString;

use crate::ui::ipc::{ConnectApi, Ipc};

use crate::ui::router::{Route, Router};
use crate::ui::stores::connection::UiStore;
use crate::ui::stores::connection::{ConnectionStore, Device};
use crate::ui::stores::toast::{ToastKind, ToastStore};
use crate::ui::stores::transfer::{Direction, TransferItem, TransferStatus, TransferStore};
#[cfg(test)]
use serde_json::json;

/// Screen-mirroring (`screen.js`/odmf) panel state; backend via the
/// odmf channels, mock fallback only in `LPLUS_BACKEND=off` mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Quality {
    LowLatency,
    #[default]
    SuperSmooth,
    UltraHighDefinition,
}

impl Quality {
    pub fn label(self) -> &'static str {
        match self {
            Quality::LowLatency => "Low latency",
            Quality::SuperSmooth => "Super smooth",
            Quality::UltraHighDefinition => "Ultra high definition",
        }
    }
}

#[derive(Debug, Default)]
pub struct Mirroring {
    pub active_listen: Option<String>,
    pub quality: Quality,
    pub muted: bool,
    pub recording: bool,
}

pub struct AppState {
    pub router: Router,
    pub ipc: Ipc,
    pub connection: ConnectionStore,
    pub transfer: TransferStore,
    pub toast: ToastStore,
    pub ui: UiStore,
    /// Encoded by the connect dialog's QR tab once fetched (pairing payload
    /// from `Channel::GetPairingQrCode`).
    pub qr_content: Option<String>,
    pub mirroring: Mirroring,
    pub host_name: String,
    pub search_query: String,
    pub ai_results: Vec<String>,
    pub crossfile_category: Option<String>,
    pub crossfile_files: Vec<(String, u64)>,
    /// Assistant page facts, fetched once on first visit (generic_agent_*).
    pub ga_status: Option<String>,
    pub ga_local_id: Option<String>,
    pub ga_bound: Option<bool>,
    ga_loaded: bool,
    transfer_task: Option<Task<()>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let mut ipc = Ipc::from_env();
        let host_name = ipc.host_name().unwrap_or_else(|| "This PC".to_string());
        Self {
            router: Router::new(Route::Home),
            ipc,
            connection: ConnectionStore::new(),
            transfer: TransferStore::new(),
            toast: ToastStore::default(),
            ui: UiStore::default(),
            qr_content: None,
            mirroring: Mirroring::default(),
            host_name,
            search_query: String::new(),
            ai_results: Vec::new(),
            crossfile_category: None,
            crossfile_files: Vec::new(),
            ga_status: None,
            ga_local_id: None,
            ga_bound: None,
            ga_loaded: false,
            transfer_task: None,
        }
    }

    // ------------------------------------------------------------- routing
    pub fn navigate(&mut self, route: Route) {
        self.router.push(route);
    }

    pub fn go_back(&mut self) {
        self.router.back();
    }

    pub fn dismiss_toast(&mut self, id: u64) {
        self.toast.dismiss(id);
    }

    // ------------------------------------------------------------ devices
    /// Attach the real-launch transport (backend preferred) and re-read the
    /// host name from it. Tests keep `AppState::new()`'s mock-only default.
    pub fn use_launch_transport(&mut self) {
        self.ipc = Ipc::from_launch();
        if let Some(name) = self.ipc.host_name() {
            self.host_name = name;
        }
    }

    /// Pull connected + found device lists through the vendor channels.
    /// Typed service surface (`ConnectApi`): Direct calls the daemon API
    /// with no JSON round-trip, http/mock answers are parsed to `Device`.
    /// Unhandled answers parse to `None` and leave the store untouched.
    pub fn refresh_devices(&mut self) {
        if let Some(devices) = self.ipc.connected_devices() {
            self.connection.set_connected(devices);
        }
        // Persistent pairing bonds (offline ones included) are account-
        // local: fetched even signed out.
        if let Some(rows) = self.ipc.paired_devices() {
            self.connection.set_paired(rows);
        }
        if let Some(devices) = self.ipc.found_devices() {
            self.connection.set_found(devices);
        }
    }

    /// Fetch the assistant page facts once: daemon status, this PC's agent
    /// id, cloud-bind state, and the persistent pairing bonds.
    pub fn ensure_generic_agent(&mut self) {
        if self.ga_loaded {
            return;
        }
        self.ga_loaded = true;
        self.refresh_devices();
        if let Some(status) = self.ipc.ensure_running() {
            self.ga_status = Some(status.status);
        }
        if self.ga_local_id.is_none() {
            self.ga_local_id = self.ipc.local_device_id();
        }
        self.ga_bound = self.ipc.cloud_bound();
    }

    /// "Connect manually" (`ConnectMainDialogMultiDevice` entry point).
    pub fn connect_manually(&mut self) {
        self.connection.begin_searching();
        self.refresh_devices();
    }

    /// Open the manual-connect dialog and lazily fetch the QR pairing
    /// payload once (backend lane pending; the mock serves a demo code).
    pub fn open_connect_dialog(&mut self) {
        self.ui.open_connect_dialog();
        if self.qr_content.is_none() {
            self.qr_content = self.ipc.qr_code();
        }
    }

    /// "⋮" more-menu (`DeviceCardMoreMenu`): at most one card menu open.
    pub fn toggle_more_menu(&mut self, idx: usize) {
        self.ui.more_menu_for = if self.ui.more_menu_for == Some(idx) {
            None
        } else {
            Some(idx)
        };
    }

    pub fn close_more_menu(&mut self) {
        self.ui.more_menu_for = None;
    }

    /// Card "Connect" CTA. With another device already connected the vendor
    /// shows the "Connect to a new device?" conflict dialog
    /// (`MyDeviceDialogsSection` stopConnect) before starting the flow.
    pub fn request_connect(&mut self, device: &Device) {
        let other_connected = self
            .connection
            .connected()
            .iter()
            .any(|d| d.device_id != device.device_id);
        if other_connected {
            self.ui.connect_conflict = Some(device.device_id.clone());
        } else {
            self.connect_device(device);
        }
    }

    pub fn cancel_connect_conflict(&mut self) {
        self.ui.connect_conflict = None;
    }

    pub fn confirm_connect_conflict(&mut self) {
        let Some(id) = self.ui.connect_conflict.take() else {
            return;
        };
        let Some(device) = self
            .connection
            .wall()
            .into_iter()
            .find(|d| d.device_id == id)
        else {
            return;
        };
        self.connect_device(&device);
    }

    /// Card/menu "Disconnect": vendor `useDisconnectClick` asks first for
    /// devices under the persistent pairing bond (the same-account devices
    /// auto-connect governs here); merely-found devices disconnect directly.
    pub fn request_disconnect(&mut self, device: &Device) {
        self.ui.more_menu_for = None;
        if device.is_paired {
            self.ui.disconnect_pending = Some(device.device_id.clone());
        } else {
            self.disconnect_device(device);
        }
    }

    pub fn cancel_disconnect(&mut self) {
        self.ui.disconnect_pending = None;
    }

    pub fn confirm_disconnect(&mut self) {
        let Some(id) = self.ui.disconnect_pending.take() else {
            return;
        };
        let Some(device) = self
            .connection
            .wall()
            .into_iter()
            .find(|d| d.device_id == id)
        else {
            return;
        };
        self.disconnect_device(&device);
    }

    /// Card "Delete device": open the vendor's second-confirmation dialog.
    pub fn request_remove_device(&mut self, device: &Device) {
        self.ui.more_menu_for = None;
        self.ui.delete_pending = Some(device.device_id.clone());
    }

    pub fn cancel_remove_device(&mut self) {
        self.ui.delete_pending = None;
    }

    /// Vendor `handleConfirmDelete`: disconnect first if connected
    /// (`add_blacklist` semantics live backend-side), then unbind via
    /// `generic_agent_settings_remove_device { device_id, removeStateDir }`
    /// and drop the rows locally. Unhandled (mock-only) still removes
    /// locally; an explicit backend `ok:false` toasts, like the vendor.
    pub fn confirm_remove_device(&mut self) {
        let Some(id) = self.ui.delete_pending.take() else {
            return;
        };
        let row = self
            .connection
            .wall()
            .into_iter()
            .find(|d| d.device_id == id);
        let name = row
            .as_ref()
            .map(|d| d.device_name.clone())
            .unwrap_or_else(|| id.clone());
        if self.connection.is_connected(&id) {
            let row = row.unwrap_or_else(|| Device {
                device_id: id.clone(),
                device_name: name.clone(),
                ..Default::default()
            });
            self.disconnect_device(&row);
        }
        let removed = self.ipc.remove_device(&id);
        if removed {
            self.toast
                .push(format!("{name} removed"), ToastKind::Success);
        } else {
            self.toast
                .push(format!("Failed to unbind {name}"), ToastKind::Error);
        }
        self.connection.remove_device(&id);
    }

    /// Device card "Connect" action: full vendor flow — connecting →
    /// waiting-for-phone-permission → connected. The mock answers as if
    /// immediate (no `ip` in the ack); the real backend keys on `ip`
    /// (vendor contract) and acks `queued`, so connection completion is
    /// left to the authoritative device list instead of being faked here.
    pub fn connect_device(&mut self, device: &Device) {
        self.connection.begin_connect(&device.device_id);
        let ack = self.ipc.connect(&device.device_id, &device.ip);
        if ack.ok {
            self.connection.mark_waiting_permission(&device.device_id);
            if ack.ip.is_some() {
                self.toast.push(
                    format!("{}: connecting", device.device_name),
                    ToastKind::Info,
                );
                self.refresh_devices();
            } else {
                let mut ok = device.clone();
                ok.is_connected = true;
                self.connection.mark_connected(ok);
                self.toast.push(
                    format!("{} connected", device.device_name),
                    ToastKind::Success,
                );
            }
        } else {
            let reason = ack.error.unwrap_or_else(|| "phone unreachable".to_string());
            self.connection.mark_failed(&device.device_id, &reason);
            self.toast.push(
                format!("{}: {reason}", device.device_name),
                ToastKind::Error,
            );
        }
    }

    /// `DisconnectConfirm` accept action. Same payload contract as
    /// `connect_device`; a backend `queued` ack defers to the device list.
    pub fn disconnect_device(&mut self, device: &Device) {
        let ack = self.ipc.disconnect(&device.device_id, &device.ip);
        if ack.ok && ack.ip.is_some() {
            self.toast.push(
                format!("{}: disconnecting", device.device_name),
                ToastKind::Info,
            );
            self.refresh_devices();
        } else {
            self.connection.mark_disconnected(&device.device_id);
            self.toast.push(
                format!("{} disconnected", device.device_name),
                ToastKind::Info,
            );
        }
    }

    // ------------------------------------------------------------ mirroring
    pub fn toggle_mirroring(&mut self) {
        if self.mirroring.active_listen.take().is_some() {
            self.ipc.odmf_stop();
            self.toast.push("Mirroring stopped", ToastKind::Info);
            return;
        }
        if let Some(listen) = self.ipc.odmf_start() {
            self.mirroring.active_listen = Some(listen);
            self.toast.push("Mirroring started", ToastKind::Success);
        } else {
            self.toast
                .push("Mirroring failed to start", ToastKind::Error);
        }
    }

    pub fn set_quality(&mut self, q: Quality) {
        self.mirroring.quality = q;
    }

    pub fn toggle_muted(&mut self) {
        self.mirroring.muted = !self.mirroring.muted;
    }

    pub fn toggle_recording(&mut self) {
        self.mirroring.recording = !self.mirroring.recording;
    }

    // -------------------------------------------------------------- system
    pub fn toggle_sidebar(&mut self) {
        self.ui.toggle_sidebar();
    }

    pub fn set_host_name(&mut self, name: &str) {
        if self.ipc.set_host_name(name) {
            self.host_name = name.trim().to_string();
            self.toast.push("Host name saved", ToastKind::Success);
        } else {
            self.toast
                .push("Host name must not be empty", ToastKind::Error);
        }
    }

    // ------------------------------------------------------- cross-file UI
    /// Category tiles (`GroupBtns`): ported set from the vendor file groups.
    pub fn open_category(&mut self, category: &str) {
        self.crossfile_category = Some(category.to_string());
        // Ask the main process first; while unimplemented this lands in the
        // audit ring and we fall back to the mock tree.
        self.crossfile_files = self
            .ipc
            .crossfile(category)
            .map(|files| files.into_iter().map(|f| (f.name, f.size)).collect())
            .unwrap_or_else(|| mock_files(category));
    }

    // ------------------------------------------------------------ aiSearch
    /// `#/aiSearch`: asks the main process (`ai_search_execute`); unhandled
    /// channels fall back to the mock corpus and remain visible in the
    /// `ipc_registry` audit.
    pub fn run_search(&mut self, query: &str) {
        self.search_query = query.to_string();
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            self.ai_results = Vec::new();
            return;
        }
        self.ipc.run_ai_search(&q);
        self.ai_results = AI_CORPUS
            .iter()
            .filter(|f| f.to_lowercase().contains(&q))
            .map(|f| f.to_string())
            .collect();
    }

    // ------------------------------------------------------- uploadDownload
    /// MiniUploadDownload mount: pull the (mock-empty) queue.
    pub fn load_transfers(&mut self) {
        if let Some(items) = self.ipc.upload_items() {
            let fresh = items
                .into_iter()
                .map(|it| TransferItem {
                    id: it.id,
                    name: it.name,
                    size_bytes: it.size,
                    transferred: 0,
                    direction: if it.direction.as_deref() == Some("download") {
                        Direction::Download
                    } else {
                        Direction::Upload
                    },
                    status: TransferStatus::Queued,
                })
                .collect();
            self.transfer.set_items(fresh);
        }
    }

    /// Demo queue so the ported transfers UI has content in mock mode.
    pub fn seed_demo_transfers(&mut self) {
        if !self.transfer.items().is_empty() {
            return;
        }
        self.transfer.enqueue(TransferItem {
            id: "tx-1".into(),
            name: "IMG_2043.jpg".into(),
            size_bytes: 4_200_000,
            transferred: 1_680_000,
            direction: Direction::Upload,
            status: TransferStatus::Running,
        });
        self.transfer.enqueue(TransferItem {
            id: "tx-2".into(),
            name: "holiday-clip.mp4".into(),
            size_bytes: 98_000_000,
            transferred: 0,
            direction: Direction::Download,
            status: TransferStatus::Queued,
        });
        self.transfer.start("tx-2");
    }

    /// Simulated lane progress (mock); the real transport will push events.
    pub fn start_transfer_ticks(&mut self, cx: &mut Context<Self>) {
        if self.transfer_task.is_some() {
            return;
        }
        self.transfer_task = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(std::time::Duration::from_millis(200))
                    .await;
                let done = this
                    .update(cx, |app, cx| {
                        app.transfer.advance("tx-1", 600_000);
                        app.transfer.advance("tx-2", 9_000_000);
                        let done = !app.transfer.has_active();
                        cx.notify();
                        done
                    })
                    .unwrap_or(true);
                if done {
                    break;
                }
            }
        }));
    }

    pub fn clear_finished_transfers(&mut self) {
        self.transfer.clear_finished();
    }

    pub fn audit(&self) -> Vec<String> {
        self.ipc.audit()
    }
}

const AI_CORPUS: &[&str] = &[
    "passport_scan.pdf",
    "IMG_2043.jpg",
    "sunset_reel.mp4",
    "holiday-clip.mp4",
    "notes_marco.md",
    "invoice_april.pdf",
];

/// Categories the mock file list understands; any other spelling yields the
/// empty list, as before.
#[derive(Debug, Clone, Copy, EnumString)]
#[strum(serialize_all = "lowercase")]
enum FileCategory {
    Image,
    Video,
    Audio,
    Document,
}

fn mock_files(category: &str) -> Vec<(String, u64)> {
    let Ok(category) = FileCategory::from_str(category) else {
        return Vec::new();
    };
    match category {
        FileCategory::Image => vec![
            ("IMG_2043.jpg".into(), 4_200_000u64),
            ("passport_scan.pdf".into(), 900_000),
        ],
        FileCategory::Video => vec![
            ("sunset_reel.mp4".into(), 120_000_000),
            ("holiday-clip.mp4".into(), 98_000_000),
        ],
        FileCategory::Audio => vec![("voice_note.m4a".into(), 2_100_000)],
        FileCategory::Document => vec![
            ("invoice_april.pdf".into(), 180_000),
            ("notes_marco.md".into(), 4_200),
        ],
    }
}

/// Pure label model for headless tests: what the shell shows for a state.
pub fn sidebar_labels() -> Vec<&'static str> {
    // Measured from the live home sidebar: exactly two nav rows, separated
    // by a 1 px rule (transfers/settings live in the bottom action row).
    ["Devices", "Remote control"].to_vec()
}

/// Device-manager wall copy, measured from the live renderer
/// (`MS_NOT_LOGIN_TEXT`, `MINI_CONNECTION_DEVICE`, `MS_SENDFILE`,
/// `MS_NO_FOUND_DEVICE`, `MS_INITIATE_CONNECT`).
pub fn wall_labels() -> (&'static str, &'static str, &'static str) {
    (
        "Seamless connections, endless possibilities",
        "Connect device",
        "Connect your phone or tablet to use file management, screencasting, and more features.",
    )
}

/// Manual-connect dialog: tabs, QR tips, USB steps, connecting state copy
/// (vendor DOM-measured strings from `ds-panel-connection`).
pub fn qr_dialog_labels() -> (
    &'static str,
    &'static str,
    Vec<&'static str>,
    Vec<&'static str>,
    &'static str,
    &'static str,
) {
    (
        "Scan QR code",
        "Connect via USB",
        vec![
            "1. Ensure your computer and phone or tablet are connected to the same network, or that your computer is connected to the hotspot of your phone or tablet.",
            "2. Go to Settings on your phone or tablet, search for \"PC\" or \"Multi-Screen Connect\", and tap the  icon in the upper-right corner to scan the QR code.",
        ],
        vec![
            "1. Connect your phone or tablet to your PC using a USB cable.",
            "2. Confirm the connection on your phone or tablet.",
            "* Only phones or tablets running ColorOS 16/OxygenOS 16/realme UI 7.0 or later support USB connection.",
        ],
        "Connecting…",
        "Connect in background",
    )
}

/// Device-card tags and "⋮" more-menu items (`SingleDeviceCard.vue`,
/// `DeviceCardMoreMenu.vue`: `MS_CONNECTED_TAG`,
/// `MS_SECOND_NEAREST_CONNECTION`, `UTILS_DISCONNECT`, `MS_DElETE_DEVICE`).
pub fn card_menu_labels() -> (&'static str, &'static str, &'static str, &'static str) {
    (
        "Connected",
        "Recently connected",
        "Disconnect",
        "Delete device",
    )
}

/// Connected-card quick-feature entries (`deviceCardFeature.js`:
/// `MS_NAME_FILE`, `MS_NAME_PROJECTION`, `SCREEN_SHARE`, `CA_CONTENT_SYNC`).
pub fn quick_feature_labels() -> (&'static str, &'static str, &'static str, &'static str) {
    ("Files", "Screencast", "Screen Collaborate", "Content sync")
}

/// Vendor delete confirm (`MyDeviceDialogsSection`: `MS_DELETE_THIS_DEVICE`
/// + `MS_CONNECTING_TO_THIS_DEVICE`, danger `UTILS_DELETE`).
pub fn delete_confirm_labels() -> (&'static str, &'static str, &'static str, &'static str) {
    (
        "Delete this device?",
        "If there is an active connection to this device, it will be terminated.",
        "Cancel",
        "Delete",
    )
}

/// Vendor `DisconnectConfirm` (`MS_DISCONNECT_CONFIRM_TITLE`,
/// sharing-aware `MS_DISCONNECT_CONFIRM_TEXT` /
/// `EX_DISCONNECT_WHEN_SHARING_AND_SAME_ACCOUNT_TIP`, danger
/// `UTILS_DISCONNECT`).
pub fn disconnect_confirm_labels(
    sharing: bool,
) -> (&'static str, &'static str, &'static str, &'static str) {
    let message = if sharing {
        "This will end the screen collaboration session, and this device will no longer automatically connect today."
    } else {
        "It won't automatically connect again until tomorrow."
    };
    ("Disconnect this device?", message, "Cancel", "Disconnect")
}

/// Vendor stop-connect conflict dialog (`MS_DISCONNECT_TITLE` +
/// `MS_DISCONNECT_NEW_DEVICE`, `UTILS_CONNECT` confirm).
pub fn connect_conflict_labels() -> (&'static str, &'static str, &'static str, &'static str) {
    (
        "Connect to a new device?",
        "Active connections will be terminated.",
        "Cancel",
        "Connect",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::stores::connection::ConnectState;
    use base64::Engine as _;

    #[test]
    fn open_connect_dialog_fetches_qr_payload_once() {
        let mut a = device_app();
        assert!(a.qr_content.is_none(), "no fetch before the dialog opens");
        a.open_connect_dialog();
        assert!(a.ui.connect_dialog_open);
        let code = a.qr_content.clone().expect("pairing payload fetched");
        // Compatible with the phone's exported QrCodeScanActivity: the
        // heycast deep link carrying the base64 HeySynergy bean (PROTOCOL.md §3).
        assert!(code.starts_with("heycast://synergy/start?param="), "{code}");
        let param = code.split_once("param=").expect("param").1.to_string();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&param)
            .expect("base64 param");
        let bean: serde_json::Value = serde_json::from_slice(&decoded).expect("json bean");
        assert_eq!(bean["HeySynergy"]["DeviceType"], "SYNERGY_PC");
        assert_eq!(bean["HeySynergy"]["ServerPort"], "10152");
        let before = a.audit().len();
        a.open_connect_dialog();
        assert_eq!(a.audit().len(), before, "payload cached, no refetch");
    }

    #[test]
    fn connected_devices_visible_signed_out_with_add_device_header() {
        use crate::ui::ipc::http_tests::stub_backend;
        use gpui::{MouseButton, Size, TestApp, px};
        let addr = stub_backend(vec![(
            "via:get_current_connected_device_info_list",
            json!([{ "deviceId": "usb-FAKESERIAL000001", "deviceName": "CPH2745",
                     "isConnected": true, "connectType": 128, "deviceType": 8 }]),
        )]);
        let mut app = TestApp::new();
        let mut window = app.open_window_with_options(
            gpui::WindowOptions {
                window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds {
                    origin: gpui::point(px(0.), px(0.)),
                    size: Size {
                        width: px(1280.),
                        height: px(800.),
                    },
                })),
                ..Default::default()
            },
            |_window, _cx| {
                let mut a = AppState::new();
                a.ipc = Ipc::http(addr);
                a.refresh_devices();
                a
            },
        );
        window.draw();
        window.read(|a, _cx| assert!(a.connection.is_connected("usb-FAKESERIAL000001")));
        // Signed out but with a connected device the app must show the
        // device list (not not-login); the header's Add-device button is
        // the observable witness, clicked at the window's top-right.
        let mut opened = false;
        'outer: for y in (12..=84).step_by(4) {
            for x in (1120..=1272).step_by(6) {
                window.simulate_click(gpui::point(px(x as f32), px(y as f32)), MouseButton::Left);
                window.draw();
                if window.read(|a, _cx| a.ui.connect_dialog_open) {
                    opened = true;
                    break 'outer;
                }
            }
        }
        assert!(
            opened,
            "signed-out connected devices must render the list view"
        );
    }

    #[test]
    fn generic_agent_page_serves_status_bonds_and_unpair() {
        let mut app = AppState::new();
        app.ensure_generic_agent();
        assert_eq!(app.ga_status.as_deref(), Some("idle"));
        assert_eq!(app.ga_local_id.as_deref(), Some("mock-pc-001"));
        assert_eq!(app.ga_bound, Some(false));
        assert_eq!(
            app.connection.paired().len(),
            2,
            "mock bonds from mock main"
        );
        // Unpair rides the vendor request/confirm flow (wall cards and the
        // Assistant page share it).
        let row = app.connection.paired().first().expect("mock bond").clone();
        app.request_remove_device(&row);
        app.confirm_remove_device();
        assert_eq!(app.connection.paired().len(), 1);
        assert!(app.toast.items().iter().any(|t| t.text.contains("removed")));
    }

    #[test]
    fn confirm_remove_device_unbinds_via_backend_and_drops_row() {
        use crate::ui::ipc::http_tests::stub_backend;
        let addr = stub_backend(vec![
            (
                "generic_agent_get_paired_devices",
                json!({ "ok": true, "entries": [],
                        "devices": [{ "deviceId": "192-0-2-7",
                                      "deviceName": "OnePlus 12R",
                                      "ip": "192.0.2.7",
                                      "isConnected": false,
                                      "isPaired": true,
                                      "connectType": 16,
                                      "deviceType": 8 }] }),
            ),
            (
                "generic_agent_settings_remove_device",
                json!({ "ok": true, "deviceId": "192-0-2-7" }),
            ),
            (
                "via:device_found_list",
                json!({ "ok": true, "devices": [] }),
            ),
        ]);
        let mut a = AppState::new();
        a.ipc = Ipc::http(addr);
        a.refresh_devices();
        let dev = a.connection.wall()[0].clone();
        a.request_remove_device(&dev);
        assert_eq!(a.ui.delete_pending.as_deref(), Some("192-0-2-7"));
        a.confirm_remove_device();
        assert!(a.ui.delete_pending.is_none());
        assert!(a.connection.wall().is_empty());
        // The unbind really hit the backend stub.
        assert_eq!(a.ipc.last_served(), "backend");
    }

    #[test]
    fn card_delete_click_opens_confirm_then_removes() {
        use crate::ui::ipc::http_tests::stub_backend;
        use gpui::{MouseButton, Size, TestApp, px};
        let addr = stub_backend(vec![
            (
                "generic_agent_get_paired_devices",
                json!({ "ok": true, "entries": [],
                        "devices": [{ "deviceId": "192-0-2-7",
                                      "deviceName": "OnePlus 12R",
                                      "ip": "192.0.2.7",
                                      "isConnected": false,
                                      "isPaired": true,
                                      "connectType": 16,
                                      "deviceType": 8 }] }),
            ),
            (
                "generic_agent_settings_remove_device",
                json!({ "ok": true, "deviceId": "192-0-2-7" }),
            ),
            (
                "via:device_found_list",
                json!({ "ok": true, "devices": [] }),
            ),
        ]);
        let mut app = TestApp::new();
        let mut window = app.open_window_with_options(
            gpui::WindowOptions {
                window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds {
                    origin: gpui::point(px(0.), px(0.)),
                    size: Size {
                        width: px(1280.),
                        height: px(800.),
                    },
                })),
                ..Default::default()
            },
            |_window, _cx| {
                let mut a = AppState::new();
                a.ipc = Ipc::http(addr);
                a.refresh_devices();
                a
            },
        );
        window.draw();
        // Stage 1: find the card's "⋮" trigger (top-right of the first card).
        let mut more_pt = None;
        'more: for y in (60..=470).step_by(4) {
            for x in (380..=560).step_by(4) {
                window.simulate_click(gpui::point(px(x as f32), px(y as f32)), MouseButton::Left);
                window.draw();
                if window.read(|a, _cx| a.ui.more_menu_for == Some(0)) {
                    more_pt = Some((x, y));
                    break 'more;
                }
            }
        }
        let (more_x, more_y) = more_pt.expect("card ⋮ button must open the more-menu");
        // Stage 2: click the danger "Delete device" item. The scan stays
        // left of the ⋮ button so it can never toggle the menu closed.
        let mut del_pt = None;
        'del: for y in (more_y + 8..=more_y + 90).step_by(4) {
            for x in (more_x - 140..=more_x - 20).step_by(5) {
                window.simulate_click(gpui::point(px(x as f32), px(y as f32)), MouseButton::Left);
                window.draw();
                if window.read(|a, _cx| a.ui.delete_pending.is_some()) {
                    del_pt = Some((x, y));
                    break 'del;
                }
                if window.read(|a, _cx| a.ui.more_menu_for.is_none()) {
                    // Stray click closed the menu: re-open and retry.
                    window.simulate_click(
                        gpui::point(px(more_x as f32), px(more_y as f32)),
                        MouseButton::Left,
                    );
                    window.draw();
                }
            }
        }
        let (del_x, del_y) = del_pt.expect("more-menu Delete device must arm the confirm");
        assert!(
            window.read(|a, _cx| a.ui.delete_pending.is_some()),
            "Delete device arms the vendor confirm dialog"
        );
        // Click Delete in the dialog (bottom-right of the centered card).
        // A stray Cancel hit re-arms the flow via the saved menu points.
        let mut removed = false;
        'dialog: for y in (370..=520).step_by(4) {
            for x in (760..=950).step_by(6) {
                window.simulate_click(gpui::point(px(x as f32), px(y as f32)), MouseButton::Left);
                window.draw();
                if window
                    .read(|a, _cx| a.ui.delete_pending.is_none() && a.connection.wall().is_empty())
                {
                    removed = true;
                    break 'dialog;
                }
                if window.read(|a, _cx| a.ui.delete_pending.is_none()) {
                    // Cancel hit: re-open the menu path and retry.
                    for pt in [(more_x, more_y), (del_x, del_y)] {
                        window.simulate_click(
                            gpui::point(px(pt.0 as f32), px(pt.1 as f32)),
                            MouseButton::Left,
                        );
                        window.draw();
                    }
                }
            }
        }
        assert!(removed, "dialog Delete button must drop the device");
    }

    #[test]
    fn refresh_devices_includes_paired_offline_device() {
        use crate::ui::ipc::http_tests::stub_backend;
        let addr = stub_backend(vec![(
            "generic_agent_get_paired_devices",
            json!({ "ok": true,
                    "entries": [{ "deviceId": "192-0-2-7", "displayName": "OnePlus 12R" }],
                    "devices": [{ "deviceId": "192-0-2-7",
                                  "deviceName": "OnePlus 12R",
                                  "ip": "192.0.2.7",
                                  "isConnected": false,
                                  "isPaired": true,
                                  "connectType": 16,
                                  "deviceType": 8 }] }),
        )]);
        let mut a = AppState::new();
        a.ipc = Ipc::http(addr);
        a.refresh_devices();
        let wall = a.connection.wall();
        let offline = wall
            .iter()
            .find(|d| d.device_id == "192-0-2-7")
            .expect("paired offline device on the wall");
        assert!(offline.is_paired);
        assert!(!offline.is_connected);
        // Paired rows never fake a connected state.
        assert!(!a.connection.is_connected("192-0-2-7"));
    }

    #[test]
    fn refresh_devices_surfaces_backend_usb_connected_row() {
        use crate::ui::ipc::http_tests::stub_backend;
        let addr = stub_backend(vec![(
            "via:get_current_connected_device_info_list",
            json!([{ "deviceId": "usb-FAKESERIAL000001",
                     "deviceName": "OnePlus 15",
                     "isConnected": true,
                     "connectType": 128,
                     "deviceType": 8,
                     "usbSerial": "FAKESERIAL000001" }]),
        )]);
        let mut a = AppState::new();
        a.ipc = Ipc::http(addr);
        a.refresh_devices();
        assert!(a.connection.is_connected("usb-FAKESERIAL000001"));
        assert_eq!(a.connection.wall()[0].device_name, "OnePlus 15");
        assert_eq!(a.connection.wall()[0].connect_type, 128);
    }

    fn device_app() -> AppState {
        let mut a = AppState::new();
        a.refresh_devices();
        a
    }

    #[test]
    fn starts_on_home() {
        let a = AppState::new();
        assert_eq!(a.router.current(), &Route::Home);
    }

    #[test]
    fn connect_walks_waiting_permission_and_toasts_success() {
        let mut a = device_app();
        a.connect_manually();
        assert_eq!(a.connection.state, ConnectState::Searching);
        let phone = a
            .connection
            .found()
            .iter()
            .find(|d| d.device_type == 8)
            .cloned();
        let phone = phone.expect("mock found list has a phone");
        a.connect_device(&phone);
        assert!(a.connection.is_connected("mock-phone-1"));
        assert!(a.toast.items().iter().any(|t| t.text.contains("connected")));
        assert_eq!(
            a.connection.state,
            ConnectState::Connected(vec!["mock-phone-1".into()])
        );
    }

    #[test]
    fn connect_failure_surfaces_reason() {
        let mut a = device_app();
        let ghost = Device {
            device_id: "ghost".into(),
            device_name: "Ghost".into(),
            ip: String::new(),
            is_connected: false,
            is_discovered: true,
            connect_type: 2,
            device_type: 8,
            battery: None,
            is_paired: false,
        };
        a.connect_device(&ghost);
        assert_eq!(
            a.connection.state,
            ConnectState::Failed("ghost".into(), "unknown device ghost".into())
        );
        assert!(
            a.toast
                .items()
                .iter()
                .any(|t| matches!(t.kind, ToastKind::Error))
        );
    }

    #[test]
    fn disconnect_removes_device() {
        let mut a = device_app();
        a.connect_manually();
        let pad = a
            .connection
            .found()
            .iter()
            .find(|d| d.device_type == 10)
            .cloned()
            .expect("pad");
        a.connect_device(&pad);
        a.disconnect_device(&pad);
        assert!(!a.connection.is_connected("mock-pad-1"));
    }

    #[test]
    fn connect_device_against_backend_queues_and_defers_to_list() {
        use crate::ui::ipc::http_tests::stub_backend;
        let addr = stub_backend(vec![(
            "via:get_current_connected_device_info_list",
            json!([]),
        )]);
        let mut a = device_app();
        a.ipc = Ipc::http(addr);
        let phone = Device {
            device_id: "p1".into(),
            device_name: "Phone".into(),
            ip: "192.0.2.10".into(),
            is_connected: false,
            is_discovered: true,
            connect_type: 2,
            device_type: 8,
            battery: None,
            is_paired: false,
        };
        a.connect_device(&phone);
        // Queued ack: honest waiting state, no fake success toast; the
        // payload carried the ip (stub mirrors the backend's keying).
        assert_eq!(
            a.connection.state,
            ConnectState::WaitingPermission("p1".into())
        );
        assert!(!a.connection.is_connected("p1"));
        assert!(
            a.toast
                .items()
                .iter()
                .any(|t| t.text.contains("connecting"))
        );
        assert!(
            a.ipc
                .audit()
                .iter()
                .any(|e| e == "backend-invoke:connect_device")
        );
    }

    #[test]
    fn paired_disconnect_asks_confirm_unpaired_disconnects_directly() {
        let mut a = AppState::new();
        let bonded = Device {
            device_id: "bonded".into(),
            device_name: "Bonded".into(),
            ip: "192.0.2.1".into(),
            is_connected: true,
            is_discovered: true,
            connect_type: 2,
            device_type: 8,
            battery: None,
            is_paired: true,
        };
        let transient = Device {
            device_id: "transient".into(),
            is_paired: false,
            ..bonded.clone()
        };
        a.connection.mark_connected(bonded.clone());
        a.connection.mark_connected(transient.clone());
        // Persistent-bond device: vendor DisconnectConfirm gates the action.
        a.request_disconnect(&bonded);
        assert_eq!(a.ui.disconnect_pending.as_deref(), Some("bonded"));
        assert!(
            a.connection.is_connected("bonded"),
            "still connected pre-confirm"
        );
        a.confirm_disconnect();
        assert!(!a.connection.is_connected("bonded"));
        assert!(a.ui.disconnect_pending.is_none());
        // Merely-found device: disconnects without a dialog.
        a.request_disconnect(&transient);
        assert!(a.ui.disconnect_pending.is_none());
        assert!(!a.connection.is_connected("transient"));
    }

    #[test]
    fn connect_conflict_gates_second_connect_until_confirmed() {
        use crate::ui::ipc::http_tests::stub_backend;
        let addr = stub_backend(vec![
            (
                "via:get_current_connected_device_info_list",
                json!([{ "deviceId": "active", "deviceName": "Active", "ip": "192.0.2.1",
                         "isConnected": true, "isPaired": true, "connectType": 2,
                         "deviceType": 8 }]),
            ),
            (
                "generic_agent_get_paired_devices",
                json!({ "ok": true, "entries": [],
                        "devices": [{ "deviceId": "idle", "deviceName": "Idle",
                                      "ip": "192.0.2.2", "isConnected": false,
                                      "isPaired": true, "connectType": 16,
                                      "deviceType": 8 }] }),
            ),
            (
                "via:connect_device",
                json!({ "ok": true, "ip": "192.0.2.2" }),
            ),
        ]);
        let mut a = AppState::new();
        a.ipc = Ipc::http(addr);
        a.refresh_devices();
        let idle = a
            .connection
            .wall()
            .into_iter()
            .find(|d| d.device_id == "idle")
            .expect("paired offline row");
        // Another device is connected: the CTA raises the conflict dialog
        // instead of starting the connect.
        a.request_connect(&idle);
        assert_eq!(a.ui.connect_conflict.as_deref(), Some("idle"));
        assert!(
            !a.ipc
                .audit()
                .iter()
                .any(|e| e == "backend-invoke:connect_device"),
            "no connect request before the user confirms"
        );
        a.confirm_connect_conflict();
        assert!(a.ui.connect_conflict.is_none());
        // Confirmed: the queued ack defers completion to the device list.
        assert_eq!(
            a.connection.state,
            ConnectState::WaitingPermission("idle".into())
        );
    }

    #[test]
    fn connect_without_conflict_goes_directly() {
        use crate::ui::ipc::http_tests::stub_backend;
        let addr = stub_backend(vec![
            ("via:get_current_connected_device_info_list", json!([])),
            (
                "generic_agent_get_paired_devices",
                json!({ "ok": true, "entries": [],
                        "devices": [{ "deviceId": "idle", "deviceName": "Idle",
                                      "ip": "192.0.2.2", "isConnected": false,
                                      "isPaired": true, "connectType": 16,
                                      "deviceType": 8 }] }),
            ),
            (
                "via:connect_device",
                json!({ "ok": true, "ip": "192.0.2.2" }),
            ),
        ]);
        let mut a = AppState::new();
        a.ipc = Ipc::http(addr);
        a.refresh_devices();
        let idle = a
            .connection
            .wall()
            .into_iter()
            .find(|d| d.device_id == "idle")
            .expect("paired offline row");
        a.request_connect(&idle);
        assert!(a.ui.connect_conflict.is_none(), "no device in the way");
        assert_eq!(
            a.connection.state,
            ConnectState::WaitingPermission("idle".into())
        );
    }

    #[test]
    fn more_menu_opens_one_card_at_a_time() {
        let mut a = device_app();
        a.toggle_more_menu(0);
        assert_eq!(a.ui.more_menu_for, Some(0));
        a.toggle_more_menu(2);
        assert_eq!(a.ui.more_menu_for, Some(2));
        a.toggle_more_menu(2);
        assert_eq!(a.ui.more_menu_for, None);
    }

    #[test]
    fn more_menu_closes_on_outside_click() {
        use gpui::{MouseButton, Size, TestApp, px};
        let mut app = TestApp::new();
        let mut window = app.open_window_with_options(
            gpui::WindowOptions {
                window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds {
                    origin: gpui::point(px(0.), px(0.)),
                    size: Size {
                        width: px(1280.),
                        height: px(800.),
                    },
                })),
                ..Default::default()
            },
            |_window, _cx| {
                let mut a = AppState::new();
                a.refresh_devices();
                a
            },
        );
        window.draw();
        // Open the first card's "⋮" menu via its trigger.
        let mut opened = false;
        'open: for y in (60..=470).step_by(4) {
            for x in (380..=560).step_by(4) {
                window.simulate_click(gpui::point(px(x as f32), px(y as f32)), MouseButton::Left);
                window.draw();
                if window.read(|a, _cx| a.ui.more_menu_for == Some(0)) {
                    opened = true;
                    break 'open;
                }
            }
        }
        assert!(opened, "⋮ trigger opens the more-menu");
        // A click on empty content (root click-away) dismisses it without
        // triggering anything else.
        window.simulate_click(gpui::point(px(1150.), px(700.)), MouseButton::Left);
        window.draw();
        window.read(|a, _cx| {
            assert!(
                a.ui.more_menu_for.is_none(),
                "outside click closes the menu"
            );
            assert!(a.ui.delete_pending.is_none() && a.ui.disconnect_pending.is_none());
            assert!(!a.ui.connect_dialog_open);
        });
    }

    #[test]
    fn mirroring_toggle_round_trips_through_mock_odmf() {
        let mut a = AppState::new();
        a.toggle_mirroring();
        assert_eq!(a.mirroring.active_listen.as_deref(), Some("0.0.0.0:7536"));
        a.toggle_mirroring();
        assert_eq!(a.mirroring.active_listen, None);
    }

    #[test]
    fn quality_and_media_toggles_are_exclusive_flips() {
        let mut a = AppState::new();
        a.set_quality(Quality::UltraHighDefinition);
        assert_eq!(a.mirroring.quality, Quality::UltraHighDefinition);
        a.toggle_muted();
        a.toggle_recording();
        assert!(a.mirroring.muted && a.mirroring.recording);
        a.toggle_muted();
        assert!(!a.mirroring.muted);
    }

    #[test]
    fn host_name_validates_via_ipc() {
        let mut a = AppState::new();
        a.set_host_name("  ");
        assert!(
            a.toast
                .items()
                .iter()
                .any(|t| matches!(t.kind, ToastKind::Error))
        );
        a.set_host_name("desk-box");
        assert_eq!(a.host_name, "desk-box");
    }

    #[test]
    fn ai_search_falls_back_to_mock_corpus_and_audits_gap() {
        let mut a = AppState::new();
        a.run_search("mp4");
        assert_eq!(a.ai_results.len(), 2);
        assert!(a.audit().iter().any(|e| e.contains("ai_search_execute")));
    }

    #[test]
    fn crossfile_category_falls_back_to_mock_tree_and_audits_gap() {
        let mut a = AppState::new();
        a.open_category("video");
        assert_eq!(a.crossfile_category.as_deref(), Some("video"));
        assert_eq!(a.crossfile_files.len(), 2);
        assert!(a.audit().iter().any(|e| e.contains("cross_file_list")));
    }

    #[test]
    fn transfers_seed_start_and_clear_finished() {
        let mut a = AppState::new();
        a.seed_demo_transfers();
        assert_eq!(a.transfer.items().len(), 2);
        a.transfer.advance("tx-2", 98_000_000);
        a.clear_finished_transfers();
        assert!(a.transfer.items().iter().any(|i| i.id == "tx-1"));
    }

    #[test]
    fn sidebar_labels_match_vendor_nav() {
        assert_eq!(sidebar_labels(), vec!["Devices", "Remote control"]);
    }

    #[test]
    fn wall_and_dialog_copy_match_vendor_strings() {
        let (hero, section, subtitle) = wall_labels();
        assert_eq!(hero, "Seamless connections, endless possibilities");
        assert_eq!(section, "Connect device");
        assert!(subtitle.starts_with("Connect your phone or tablet to use file"));
        let (tab1, tab2, tips, usb, connecting, bg_btn) = qr_dialog_labels();
        assert_eq!(tab1, "Scan QR code");
        assert_eq!(tab2, "Connect via USB");
        assert_eq!(connecting, "Connecting…");
        assert_eq!(tips.len(), 2);
        assert!(tips[0].starts_with("1. Ensure your computer"));
        assert_eq!(usb.len(), 3);
        assert_eq!(
            usb[0],
            "1. Connect your phone or tablet to your PC using a USB cable."
        );
        assert!(usb[2].starts_with("* Only phones or tablets"));
        assert_eq!(bg_btn, "Connect in background");
        assert_eq!(
            card_menu_labels(),
            (
                "Connected",
                "Recently connected",
                "Disconnect",
                "Delete device"
            )
        );
        assert_eq!(
            quick_feature_labels(),
            ("Files", "Screencast", "Screen Collaborate", "Content sync")
        );
        assert_eq!(
            delete_confirm_labels(),
            (
                "Delete this device?",
                "If there is an active connection to this device, it will be terminated.",
                "Cancel",
                "Delete",
            )
        );
        let (d_title, d_msg, d_cancel, d_confirm) = disconnect_confirm_labels(false);
        assert_eq!(d_title, "Disconnect this device?");
        assert_eq!(
            d_msg,
            "It won't automatically connect again until tomorrow."
        );
        assert_eq!((d_cancel, d_confirm), ("Cancel", "Disconnect"));
        assert!(
            disconnect_confirm_labels(true)
                .1
                .starts_with("This will end the screen collaboration session")
        );
        assert_eq!(
            connect_conflict_labels(),
            (
                "Connect to a new device?",
                "Active connections will be terminated.",
                "Cancel",
                "Connect",
            )
        );
    }

    #[test]
    fn navigate_pushes_and_back_pops() {
        let mut a = AppState::new();
        a.navigate(Route::UploadDownload);
        a.navigate(Route::Settings);
        assert_eq!(a.router.current(), &Route::Settings);
        a.go_back();
        assert_eq!(a.router.current(), &Route::UploadDownload);
    }
}
