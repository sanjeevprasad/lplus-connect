//! Design tokens ported from the vendored O+ Connect renderer.
//!
//! Values are measured from the live renderer (computed styles at
//! 1280x800 + reference captures): light theme, transparent window chrome
//! composited over white, `el-aside` sidebar 180 px, nav items 32 px tall
//! with 6 px radius, pill buttons (radius 100, padding 8/22, ~43 px tall),
//! primary CTA `rgb(0, 128, 255)`, links/dialog actions `rgb(0, 102, 255)`,
//! body text `rgba(0, 0, 0, 0.9)`, secondary text `rgba(0, 0, 0, 0.54)`.
//!
//! Tokens are stored as hex and converted at use through `h()`, gpui-ce's
//! explicit sRGB→Hsla boundary (`rgb_to_hsla`).

use gpui::{Hsla, SharedString, rgb, rgb_to_hsla};

/// sRGB hex → gpui solid color.
pub fn h(hex: u32) -> Hsla {
    rgb_to_hsla(rgb(hex))
}

/// sRGB hex with alpha (e.g. vendor `rgba(0, 0, 0, .9)` overlays).
pub fn a(hex: u32, alpha: f32) -> Hsla {
    let mut c = h(hex);
    c.alpha = alpha;
    c
}

/// Font shipped by the vendor renderer itself ("OPPO Sans 4.0 SC",
/// installed system-wide from `vendor/renderer/fonts/`).
pub const FONT_FAMILY: &str = "OPPO Sans 4.0 SC";

/// Effective UI family; `LPLUS_FONT` overrides for render experiments.
pub fn font_family() -> SharedString {
    SharedString::from(std::env::var("LPLUS_FONT").unwrap_or_else(|_| FONT_FAMILY.to_string()))
}

/// Nav-rail glyph tint, measured from the swapped-out raster (lum 76).
pub const NAV_ICON: u32 = 0x4c_4c_4c;
/// QR overlay play glyph, measured from the swapped-out raster (lum ~104).
pub const QR_PLAY: u32 = 0x68_68_68;

/// Window/content base (body is rgba(255,255,255,.74) over a white desktop;
/// GPUI windows are opaque, so composite once against white).
pub const BG: u32 = 0xff_ff_ff;
/// `[class*="content"]` background rgba(255,255,255,.3) over white chrome.
pub const CONTENT_BG: u32 = 0xff_ff_ff;
pub const CARD_BG: u32 = 0xf7_f7_f7;
pub const HOVER_BG: u32 = 0xf0_f1_f2;
pub const SELECTED_BG: u32 = 0xe6_f0_ff;
pub const DIVIDER: u32 = 0xeb_eb_eb;
pub const TEXT: u32 = 0x1a_1a_1a; // rgba(0,0,0,.9) on white
pub const TEXT_SECONDARY: u32 = 0x75_75_75; // rgba(0,0,0,.54)
pub const TEXT_DISABLED: u32 = 0xad_ad_ad;
pub const PRIMARY: u32 = 0x00_80_ff;
pub const LINK: u32 = 0x00_66_ff;
pub const ON_PRIMARY: u32 = 0xff_ff_ff;
pub const OK: u32 = 0x34_c3_99;
pub const ERROR: u32 = 0xf8_71_71;
pub const MASK: u32 = 0xcc_cc_cc; // connect-dialog dimming (measured)
/// Device-card screens (mock art, not a vendor token).
pub const CARD_SCREEN_PHONE: u32 = 0x1f_2a_44;
pub const CARD_SCREEN_PAD: u32 = 0x35_1f_44;
pub const CARD_INNER: u32 = 0x10_18_28;
pub const CARD_INNER_BORDER: u32 = 0x3a_46_5c;
pub const CARD_INNER_TEXT: u32 = 0xbf_d4_ff;
pub const PROGRESS_TRACK: u32 = 0xe6_e8_ec;
pub const NAV_ICON_REMOTE: u32 = 0x8b_5c_f6;
pub const NAV_ICON_SECONDARY: u32 = 0xbd_c5_cf;

/// `el-aside sidebar` width.
pub const SIDEBAR_W: f32 = 180.0;
pub const SIDEBAR_PAD_X: f32 = 10.0;
/// Nav item box.
pub const NAV_ITEM_H: f32 = 32.0;
pub const NAV_ITEM_R: f32 = 6.0;
/// Measured `.navli` selected fill rgba(0, 0, 0, .08) on white.
pub const NAV_SELECTED: u32 = 0xeb_eb_eb;
/// Measured sidebar separator rgba(0, 0, 0, .04).
pub const DIVIDER_SOFT: u32 = 0xf5_f5_f5;
/// Measured device-manager card fill rgba(255, 255, 255, .72) on white.
pub const GLASS: u32 = 0xf7_f7_f7;
/// Pill button (`.btn` with border-radius 100, padding 8px 22px).
pub const PILL_R: f32 = 100.0;
pub const PILL_PAD_X: f32 = 22.0;
pub const PILL_PAD_Y: f32 = 8.0;
/// Type scale (measured): hero 32 px w600, card headline 28 px w600,
/// section titles 16 px, nav labels 13 px w500, body 16 px.
pub const FONT_HERO: f32 = 32.0;
pub const FONT_H28: f32 = 28.0;
pub const FONT_TITLE: f32 = 16.0;
pub const FONT_BODY: f32 = 16.0;
pub const FONT_LABEL: f32 = 13.0;
pub const FONT_SMALL: f32 = 12.0;
/// Card radius (`.card`/el-card family uses 6-12 px; content corners 6).
pub const CARD_R: f32 = 12.0;

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::Rgba;

    fn channels(color: Hsla) -> (f32, f32, f32) {
        let c: Rgba = rgb_back(color);
        (c.color.red, c.color.green, c.color.blue)
    }

    fn rgb_back(c: Hsla) -> Rgba {
        gpui::hsla_to_rgba(c)
    }

    #[test]
    fn primary_cta_matches_vendor_computed_style() {
        // rgb(0, 128, 255) from the "Sign in to connect automatically" button.
        let (r, g, b) = channels(h(PRIMARY));
        assert!(r < 1e-3 && (g - 128.0 / 255.0).abs() < 1e-3 && (b - 1.0).abs() < 1e-3);
    }

    #[test]
    fn link_blue_matches_dialog_action() {
        let (r, g, b) = channels(h(LINK));
        assert!(r < 1e-3 && (g - 102.0 / 255.0).abs() < 1e-3 && (b - 1.0).abs() < 1e-3);
    }

    #[test]
    fn body_text_is_ninety_percent_black_on_white() {
        let (r, g, b) = channels(h(TEXT));
        let want = 26.0 / 255.0;
        assert!((r - want).abs() < 1e-3 && (g - want).abs() < 1e-3 && (b - want).abs() < 1e-3);
    }

    #[test]
    fn sidebar_geometry_matches_el_aside() {
        assert_eq!(SIDEBAR_W, 180.0);
        assert_eq!(SIDEBAR_PAD_X, 10.0);
        assert_eq!(NAV_ITEM_H, 32.0);
        assert_eq!(NAV_ITEM_R, 6.0);
        assert_eq!(PILL_R, 100.0);
    }
}
