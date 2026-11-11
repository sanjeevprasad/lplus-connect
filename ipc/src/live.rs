//! Cross-thread live-screencast bus: the daemon's ODMF webrtc lane decodes
//! H.265 access units to RGBA frames and [`push_frame`]s them here; the ui
//! bridge loop polls [`take_request`]/[`take_frame`] on the GPUI main loop.
//! Raw pixels only — the GPUI texture types belong to the ui side.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use image::RgbaImage;

/// Latest decoded frame awaiting display (taken by the bridge loop).
static FRAME: Mutex<Option<RgbaImage>> = Mutex::new(None);
/// The lane wants a preview window (set cross-thread, consumed by the loop).
static REQUESTED: AtomicBool = AtomicBool::new(false);
/// The GPUI bridge loop is running in this process.
static BRIDGE_ON: AtomicBool = AtomicBool::new(false);
/// Total frames handed to the bus since process start (never reset; lets
/// the decoder test observe production regardless of consumers).
static PRODUCED: AtomicUsize = AtomicUsize::new(0);

/// Called by the ODMF lane (any thread) before building a native sink:
/// returns `true` when a GPUI bridge exists in this process, meaning the
/// window will materialize on the main loop.
pub fn request_native() -> bool {
    if !BRIDGE_ON.load(Ordering::Relaxed) {
        return false;
    }
    REQUESTED.store(true, Ordering::Relaxed);
    true
}

/// Hand the freshly decoded frame to the bridge (any thread).
pub fn push_frame(pixels: RgbaImage) {
    PRODUCED.fetch_add(1, Ordering::Relaxed);
    if let Ok(mut slot) = FRAME.lock() {
        *slot = Some(pixels);
    }
}

/// Bridge loop (ui main thread): latch and clear a window request.
pub fn take_request() -> bool {
    REQUESTED.swap(false, Ordering::Relaxed)
}

/// Bridge loop (ui main thread): consume the newest frame, if any.
pub fn take_frame() -> Option<RgbaImage> {
    FRAME.lock().ok().and_then(|mut s| s.take())
}

/// Bridge loop (ui main thread): announce that it is running.
pub fn mark_bridge_on() {
    BRIDGE_ON.store(true, Ordering::Relaxed);
}

/// Total frames handed to the bus (test observation for the lane).
pub fn produced() -> usize {
    PRODUCED.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_latches_only_with_a_bridge() {
        mark_bridge_on();
        assert!(request_native());
        assert!(take_request(), "request was latched");
        assert!(!take_request(), "latch is single-consume");
    }

    #[test]
    fn push_then_take_keeps_newest_frame() {
        push_frame(RgbaImage::from_pixel(1, 1, image::Rgba([1, 2, 3, 255])));
        let before = produced();
        push_frame(RgbaImage::from_pixel(2, 2, image::Rgba([4, 5, 6, 255])));
        assert_eq!(produced(), before + 1);
        let frame = take_frame().expect("frame pending");
        assert_eq!(frame.width(), 2);
        assert!(take_frame().is_none(), "single-consume slot");
    }
}
