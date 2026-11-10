//! L+ connect desktop UI: the GPUI port of the vendored O+ Connect
//! renderer. In the combined binary the window dispatches straight into the
//! in-process daemon registry (`ipc::Transport::Direct` — same dispatcher,
//! no wire); `lplus gui` keeps the HTTP attach transport for connecting to
//! an externally running daemon.

// The UI port keeps the full vendor-facing surface (screens, stores,
// channels); members not yet wired into a reachable screen are kept for
// parity and exercised by the e2e tests instead of being pruned.
#[allow(dead_code)]
mod app;
#[allow(dead_code)]
mod ipc;
pub(crate) mod live;
#[allow(dead_code)]
mod router;
#[allow(dead_code)]
mod stores;
#[allow(dead_code)]
mod theme;
#[allow(dead_code)]
mod views;

#[cfg(test)]
mod e2e;

use std::str::FromStr;
use std::time::Duration;

use gpui::{
    App, AppContext as _, Bounds, Point, SharedString, Size, WindowBounds, WindowOptions, px,
};
use strum::EnumString;

pub use app::AppState;
use ipc::{Channel, Ipc};
use router::Route;

/// How the window reaches the daemon.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// Same-process daemon: dispatcher calls, no HTTP.
    Direct,
    /// External daemon: loopback `POST /__ipc` (respects `LPLUS_BACKEND`).
    Attach,
}

/// CLI launch flags for the window.
#[derive(Default, Clone)]
pub struct UiFlags {
    pub demo: bool,
    pub dialog: bool,
    pub usb: bool,
    pub start_home: bool,
    pub route: Option<String>,
}

/// Open the window and run the GPUI event loop (blocks until closed).
pub fn run(transport: Transport, flags: UiFlags) {
    let start = flags.route.as_deref().map(str::to_string);
    let start_home = flags.start_home;
    let demo = flags.demo;
    let dialog = flags.dialog;
    let usb = flags.usb;
    gpui_platform::application().run(move |cx: &mut App| {
        let bounds = Bounds {
            origin: Point {
                x: px(60.),
                y: px(40.),
            },
            size: Size {
                width: px(1280.),
                height: px(800.),
            },
        };
        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            // Stable compositor identity for sway rules ($popup) — survives
            // title renames; matches the binary name.
            app_id: Some("lplus".to_string()),
            window_min_size: Some(Size {
                width: px(960.),
                height: px(600.),
            }),
            titlebar: Some(gpui::TitlebarOptions {
                title: Some(SharedString::from("L+ connect")),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut root_state = None;
        let _window = cx
            .open_window(options, |_window, cx| {
                let entity = cx.new(|_cx| {
                    let mut app = AppState::new();
                    match transport {
                        Transport::Direct => app.ipc = Ipc::direct(),
                        // Attach the local daemon by default
                        // (LPLUS_BACKEND=off to force mock).
                        Transport::Attach => app.use_launch_transport(),
                    }
                    app.refresh_devices();
                    if demo {
                        app.connect_manually();
                    }
                    if dialog {
                        app.open_connect_dialog();
                        if usb {
                            app.ui.qr_tab = 1;
                        }
                    }
                    if let Some(route) = start_route(start.as_deref(), start_home) {
                        app.navigate(route);
                    }
                    app
                });
                root_state = Some(entity.clone());
                entity
            })
            .expect("open main window");
        live::start_bridge(cx);
        let state: gpui::Entity<AppState> = root_state.expect("window root view");
        // Live refresh: the merged app re-pulls the device lists on a timer
        // so adb/pairing changes surface without user action. Direct
        // dispatch is a cheap registry read; attach mode is loopback HTTP.
        let refresh_task = cx.spawn(async move |cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(2)).await;
                cx.update(|app| {
                    state.update(app, |app_state, _cx| app_state.refresh_devices());
                });
            }
        });
        live::retain_task(refresh_task);
        cx.activate(true);
    });
}

/// Accepted `--route` names; `serialize_all = "lowercase"` covers most, the
/// two camelCase vendor spellings carry an explicit `serialize`.
#[derive(Debug, Clone, Copy, EnumString)]
#[strum(serialize_all = "lowercase")]
enum StartRoute {
    Home,
    Remotecontrol,
    Screenshare,
    Screen,
    Uploaddownload,
    Settings,
    #[strum(serialize = "aiSearch")]
    AiSearch,
    Crossfile,
    #[strum(serialize = "genericAgent")]
    GenericAgent,
    Note,
}

impl StartRoute {
    fn route(self) -> Route {
        match self {
            StartRoute::Home => Route::Home,
            StartRoute::Remotecontrol => Route::RemoteControl { device_id: None },
            StartRoute::Screenshare => Route::ScreenShare { device_id: None },
            StartRoute::Screen => Route::Screen { device_id: None },
            StartRoute::Uploaddownload => Route::UploadDownload,
            StartRoute::Settings => Route::Settings,
            StartRoute::AiSearch => Route::AiSearch,
            StartRoute::Crossfile => Route::CrossFile {
                device_id: None,
                folder: None,
            },
            StartRoute::GenericAgent => Route::GenericAgent,
            StartRoute::Note => Route::Note,
        }
    }
}

/// `--route <name>` picks the initial screen; `--start-home` is the common
/// shorthand, matching the vendor default (Home).
fn start_route(route: Option<&str>, start_home: bool) -> Option<Route> {
    if let Some(name) = route {
        return StartRoute::from_str(name).ok().map(StartRoute::route);
    }
    if start_home {
        return Some(Route::Home);
    }
    None
}

/// `--probe-transport`: headless check of the real-backend wiring — runs the
/// channels the home screen depends on through `Ipc` (mock fallback included)
/// and prints one JSON line per channel plus the audit tail. Exit code 2
/// when the backend itself did not answer every probed channel.
pub fn probe_transport() -> bool {
    use serde_json::Value;
    let mut ipc = Ipc::from_launch();
    let mut all_real = true;
    for (channel, args) in [
        (Channel::LplusStatus, Value::Null),
        (Channel::ConnectedDeviceInfoList, Value::Null),
        (Channel::DeviceFoundList, Value::Null),
        (Channel::SettingsGetHostName, Value::Null),
    ] {
        let v = ipc.invoke(channel, args);
        let served = ipc.last_served();
        if served != "backend" {
            all_real = false;
        }
        println!(
            "probe {channel}: {served} {}",
            serde_json::to_string(&v).unwrap_or_default()
        );
    }
    for e in ipc.audit().iter().rev().take(5) {
        println!("audit {e}");
    }
    all_real
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_home_shorthand_maps_to_home() {
        assert_eq!(start_route(None, true), Some(Route::Home));
    }

    #[test]
    fn route_flag_maps_vendor_names() {
        assert_eq!(
            start_route(Some("uploaddownload"), false),
            Some(Route::UploadDownload)
        );
        assert_eq!(start_route(Some("aiSearch"), false), Some(Route::AiSearch));
    }

    #[test]
    fn unknown_route_stays_on_default() {
        assert_eq!(start_route(Some("bogus"), false), None);
        assert_eq!(start_route(None, false), None);
    }
}
