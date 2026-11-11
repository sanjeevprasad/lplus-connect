//! Native live screencast preview: the ODMF webrtc lane (daemon side)
//! decodes received H.265 access units and hands the newest RGBA frame to
//! the shared [`lplus_ipc::live`] bus; this module polls that bus from the
//! GPUI main loop (16 ms) and renders it in its own window.
//!
//! The cross-thread handoff lives in `lplus_ipc` (raw pixels only — the
//! GPUI texture types belong here), so the daemon lane never names the ui
//! crate; the lane asks for the window via `lplus_ipc::live::request_native`
//! and if the GUI bridge never started (headless daemon) the caller falls
//! back to the external player sink.

use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use gpui::{
    App, Bounds, Context, ObjectFit, Point, Render, RenderImage, Size, TitlebarOptions, Window,
    WindowBounds, WindowOptions, div, img, prelude::*, px,
};
use image::{Frame, RgbaImage};

/// Letterbox backdrop behind the contained video frame.
const VIDEO_BG: u32 = 0x10_10_10;

/// Keeps long-lived `cx.spawn` futures alive for the process lifetime —
/// dropping a [`gpui::Task`] before completion cancels it.
static KEEPALIVE: Mutex<Vec<gpui::Task<()>>> = Mutex::new(Vec::new());

/// Hold a fire-and-forget task until process exit.
pub(crate) fn retain_task(task: gpui::Task<()>) {
    if let Ok(mut tasks) = KEEPALIVE.lock() {
        tasks.push(task);
    }
}

/// Test-only: end the bridge loop after its next iteration.
#[cfg(test)]
static STOP: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static WINDOW_OPENED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static APPLIED: AtomicUsize = AtomicUsize::new(0);

/// Root view of the preview window: the newest frame, contained.
pub struct LivePreview {
    image: Option<std::sync::Arc<RenderImage>>,
}

impl LivePreview {
    fn new() -> Self {
        Self { image: None }
    }

    fn window_options() -> WindowOptions {
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds {
                origin: Point {
                    x: px(120.),
                    y: px(60.),
                },
                size: Size {
                    width: px(424.),
                    height: px(924.),
                },
            })),
            app_id: Some("lplus".to_string()),
            titlebar: Some(TitlebarOptions {
                title: Some("L+ live preview".into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

impl Render for LivePreview {
    fn render(&mut self, _window: &mut Window, _cx: &mut Context<Self>) -> impl IntoElement {
        let body = match self.image.clone() {
            Some(frame) => div()
                .size_full()
                .child(img(frame).size_full().object_fit(ObjectFit::Contain)),
            None => div().size_full().child(
                div()
                    .flex()
                    .items_center()
                    .justify_center()
                    .size_full()
                    .text_size(px(14.))
                    .text_color(gpui::white())
                    .child("waiting for screencast stream…"),
            ),
        };
        div().size_full().bg(super::theme::h(VIDEO_BG)).child(body)
    }
}

/// Convert decoded RGBA pixels into a GPUI-renderable frame.
pub fn render_image(pixels: RgbaImage) -> std::sync::Arc<RenderImage> {
    std::sync::Arc::new(RenderImage::new(vec![Frame::new(pixels)]))
}

/// Start the 16 ms bridge loop; call once from `ui::run` on the main thread.
pub fn start_bridge(cx: &mut App) {
    lplus_ipc::live::mark_bridge_on();
    let mut handle: Option<gpui::WindowHandle<LivePreview>> = None;
    let bridge_task = cx.spawn(async move |cx| {
        loop {
            cx.background_executor()
                .timer(std::time::Duration::from_millis(16))
                .await;
            if lplus_ipc::live::take_request() && handle.is_none() {
                handle = match cx.open_window(LivePreview::window_options(), |_window, app_cx| {
                    app_cx.new(|_cx| LivePreview::new())
                }) {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!("[live] open preview window: {e}");
                        None
                    }
                };
                #[cfg(test)]
                WINDOW_OPENED.store(handle.is_some(), Ordering::Relaxed);
            }
            // Only consume once a window exists to show the frame; until
            // then the bus slot keeps the newest frame (overwrites, no
            // backlog).
            if let Some(h) = handle.as_mut()
                && let Some(pixels) = lplus_ipc::live::take_frame()
            {
                let image = render_image(pixels);
                let _ = h.update(cx, |view, _window, cx| {
                    view.image = Some(image);
                    cx.notify();
                });
                #[cfg(test)]
                APPLIED.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(test)]
            if STOP.load(Ordering::Relaxed) {
                break;
            }
        }
    });
    retain_task(bridge_task);
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::TestApp;
    use image::Rgba;

    fn test_pixels() -> RgbaImage {
        RgbaImage::from_pixel(2, 3, Rgba([10, 20, 30, 255]))
    }

    #[test]
    fn bridge_request_semantics_and_frame_apply() {
        let mut app = TestApp::new();
        STOP.store(false, Ordering::Relaxed);
        WINDOW_OPENED.store(false, Ordering::Relaxed);
        APPLIED.store(0, Ordering::Relaxed);
        // The bus is process-global: start from a drained slot.
        while lplus_ipc::live::take_frame().is_some() {}
        let _ = lplus_ipc::live::take_request();
        assert!(
            !lplus_ipc::live::request_native(),
            "no bridge yet: lane must decline native"
        );
        assert!(
            !lplus_ipc::live::take_request(),
            "no latch without a bridge"
        );
        app.update(start_bridge);
        assert!(
            lplus_ipc::live::request_native(),
            "bridge is up after start"
        );
        assert!(
            lplus_ipc::live::take_request(),
            "request latched for the loop"
        );
        // Re-latch for the loop itself (the assertion above consumed the
        // first request before any virtual tick could fire).
        lplus_ipc::live::request_native();
        lplus_ipc::live::push_frame(test_pixels());
        STOP.store(true, Ordering::Relaxed);
        // Each tick: the timer fires, the loop applies the frame and opens
        // the window, then sees STOP and exits. Two cycles cover the
        // spawn→arm→fire ordering.
        for _ in 0..4 {
            app.advance_clock(std::time::Duration::from_millis(16));
            app.run_until_parked();
        }
        assert!(
            WINDOW_OPENED.load(Ordering::Relaxed),
            "request opened the preview window"
        );
        assert!(
            APPLIED.load(Ordering::Relaxed) >= 1,
            "frame applied to the view"
        );
    }
}
