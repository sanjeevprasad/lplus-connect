//! Headless integration checks: the root view renders under gpui's test
//! harness, click handlers drive the router, and mock transfer ticks
//! converge on the executor.

use crate::ui::app::AppState;
use crate::ui::router::Route;
use gpui::{MouseButton, Size, TestApp, px};

#[test]
fn root_renders_home_and_secondary_nav_navigates() {
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
        |_window, _cx| AppState::new(),
    );
    window.draw();
    window.read(|app, _cx| {
        assert_eq!(app.router.current(), &Route::Home);
    });
    // Secondary rows (Transfers/Files/AI search/Settings) are always
    // reachable — no account gate. Sweep the sidebar band under the two
    // primary rows until Transfers takes the route.
    let mut navigated = false;
    for y in (200..=340).step_by(4) {
        window.simulate_click(gpui::point(px(80.), px(y as f32)), MouseButton::Left);
        window.draw();
        window.read(|app, _cx| {
            if app.router.current() == &Route::UploadDownload {
                navigated = true;
            }
        });
        if navigated {
            break;
        }
    }
    window.read(|_app, _cx| {
        assert!(navigated, "secondary nav rows must be clickable");
    });
}

#[test]
fn wall_lists_found_devices_without_any_account() {
    let mut app = TestApp::new();
    let mut window = app.open_window(|_window, _cx| AppState::new());
    window.update(|app, _window, _cx| {
        app.refresh_devices();
    });
    window.draw();
    window.read(|app, _cx| {
        assert_eq!(app.connection.wall().len(), 2);
        assert_eq!(app.connection.wall()[0].device_name, "OnePlus 12");
    });
}

#[test]
fn add_device_button_on_device_list_opens_dialog() {
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
    // The device list (mock seeds two found devices) carries its header row
    // at the content top: p16, button 115x34 right-aligned
    // at the window edge. Sweep that band.
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
    window.read(|a, _cx| {
        assert!(opened, "Add device on the device list must open the dialog");
        assert!(a.qr_content.is_some(), "opening must fetch the QR payload");
    });
}

#[test]
fn sidebar_labels_match_vendor_nav() {
    assert_eq!(
        crate::ui::app::sidebar_labels(),
        vec!["Devices", "Remote control"]
    );
}

#[test]
fn transfer_ticks_converge_on_executor() {
    let mut app = TestApp::new();
    let mut window = app.open_window(|_window, _cx| AppState::new());
    window.update(|app, _window, cx| {
        app.seed_demo_transfers();
        app.start_transfer_ticks(cx);
    });
    for _ in 0..60 {
        app.advance_clock(std::time::Duration::from_millis(250));
        app.run_until_parked();
        if window.read(|app, _cx| !app.transfer.has_active()) {
            break;
        }
    }
    window.read(|app, _cx| {
        assert!(!app.transfer.has_active());
        assert!(app.transfer.items().iter().all(|i| i.progress() >= 0.999));
    });
}
