//! Element trees for the ported screens. Layout tokens come from
//! `theme.rs` (measured from the live renderer); copy strings are the
//! vendor's captured strings.

use gpui::{
    AnyElement, Context, FontWeight, Render, SharedString, Window, div, prelude::*, px, svg,
};

use crate::ui::app::{AppState, Quality, qr_dialog_labels, wall_labels};
use crate::ui::ipc::Channel;
use crate::ui::router::Route;
use crate::ui::stores::connection::{ConnectState, DEVICE_TYPE_PAD};
use crate::ui::stores::toast::ToastKind;
use crate::ui::stores::transfer::{Direction, TransferStatus};
use crate::ui::theme::*;
use lucide_static_svg::Icon;

impl AppState {
    // ---------------------------------------------------------- home shell
    fn render_home_shell(&mut self, cx: &mut Context<Self>, route: Route) -> AnyElement {
        let sidebar = self.render_sidebar(cx, &route);
        let header = if route == Route::Home {
            div().into_any_element()
        } else {
            self.render_headpiece(cx)
        };
        let content = match &route {
            Route::Home => self.render_devices(cx),
            Route::RemoteControl { .. } => self.render_stub(
                cx,
                "Remote control",
                &[
                    Channel::RemoteControlConnect,
                    Channel::RemoteControlAuth,
                    Channel::HistoricalConnections,
                ],
            ),
            Route::ScreenShare { .. } => self.render_multi_screen(cx),
            Route::Screen { .. } => self.render_mirroring(cx),
            Route::UploadDownload => self.render_transfers(cx),
            Route::Settings => self.render_settings(cx),
            Route::AiSearch => self.render_ai_search(cx),
            Route::CrossFile { .. }
            | Route::CrossFileList { .. }
            | Route::CrossFileSearch { .. } => self.render_crossfile(cx),
            Route::AiSearchDetail => {
                self.render_stub(cx, "Search detail", &[Channel::AiSearchDetail])
            }
            Route::GenericAgent => self.render_generic_agent(cx),
            Route::Note => self.render_stub(cx, "Notes", &[Channel::NoteList]),
        };
        div()
            .size_full()
            .flex()
            .flex_row()
            .bg(h(BG))
            .child(sidebar)
            .child(
                div()
                    .flex_1()
                    .relative()
                    .flex()
                    .flex_col()
                    .bg(h(CONTENT_BG))
                    .child(header)
                    .child(
                        div()
                            .flex_1()
                            .id("content-scroll")
                            .overflow_y_scroll()
                            .child(content),
                    )
                    .when(self.ui.connect_dialog_open, |d| {
                        d.child(self.render_qr_dialog(cx))
                    })
                    .when(self.ui.delete_pending.is_some(), |d| {
                        d.child(self.render_delete_dialog(cx))
                    }),
            )
            .into_any_element()
    }

    fn render_sidebar(&mut self, cx: &mut Context<Self>, route: &Route) -> AnyElement {
        let width = self.ui.sidebar_width();
        let collapsed = self.ui.sidebar_collapsed;
        let selected: Option<usize> = match route {
            Route::Home => Some(0),
            Route::RemoteControl { .. } => Some(1),
            _ => None,
        };
        let mut col = div()
            .w(px(width))
            .h_full()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .px(px(SIDEBAR_PAD_X));
        if !collapsed {
            // `.sidebar-search-header` (10,32) 160x60 with `.ds-search-bar`
            // (10,48) 160x28: 14px icon + "Search" placeholder fs12.
            col = col.child(
                div()
                    .id("sidebar-search")
                    .h(px(28.))
                    .mt(px(48.))
                    .rounded(px(8.))
                    .px(px(6.))
                    .flex()
                    .items_center()
                    .gap(px(6.))
                    .cursor_pointer()
                    .hover(|d| d.bg(h(HOVER_BG)))
                    .child(
                        div()
                            .size(px(14.))
                            .flex_shrink_0()
                            .rounded(px(7.))
                            .border_1()
                            .border_color(h(TEXT_SECONDARY))
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(
                                div()
                                    .text_size(px(9.))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(h(TEXT_SECONDARY))
                                    .child("⌕"),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(12.))
                            .text_color(h(TEXT_SECONDARY))
                            .child("Search"),
                    )
                    .on_click(cx.listener(|app, _e, _w, cx| {
                        app.navigate(Route::AiSearch);
                        cx.notify();
                    })),
            );
            let nav_rows: [(&'static str, Route); 2] = [
                ("Devices", Route::Home),
                (
                    "Remote control",
                    Route::RemoteControl { device_id: None },
                ),
            ];
            for (idx, (label, target)) in nav_rows.into_iter().enumerate() {
                let is_sel = selected == Some(idx);
                if idx == 1 {
                    // measured `.navli + .navli` separator (13,143) 155x1.
                    col = col.child(div().h(px(1.)).mt(px(19.)).mx(px(3.)).bg(h(DIVIDER_SOFT)));
                }
                col = col.child(
                    div()
                        .id(("nav", idx))
                        .h(px(NAV_ITEM_H))
                        .when(idx == 1, |d| d.mt(px(14.)))
                        .when(idx == 0, |d| d.mt(px(16.)))
                        .rounded(px(NAV_ITEM_R))
                        .px(px(6.))
                        .flex()
                        .items_center()
                        .gap(px(8.))
                        .cursor_pointer()
                        .when(is_sel, |d| d.bg(h(NAV_SELECTED)))
                        .child(
                            svg()
                                .data(target.icon().svg_bytes())
                                .w(px(20.))
                                .h(px(20.))
                                .text_color(h(NAV_ICON)),
                        )
                        .child(
                            div()
                                .text_size(px(FONT_LABEL))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(h(TEXT))
                                .child(label),
                        )
                        .on_click(cx.listener(move |app, _e, _w, cx| {
                            app.navigate(target.clone());
                            cx.notify();
                        })),
                );
            }
            // The remaining vendor routes (transfers and settings live in
            // the bottom action row of the measured build; surfaced here
            // as extra rows for reachability).
            {
                let secondary: [(&str, Route); 4] = [
                    ("Transfers", Route::UploadDownload),
                    (
                        "Files",
                        Route::CrossFile {
                            device_id: None,
                            folder: None,
                        },
                    ),
                    ("AI search", Route::AiSearch),
                    ("Settings", Route::Settings),
                ];
                for (idx, (label, target)) in secondary.into_iter().enumerate() {
                    let is_sel = *route == target;
                    col = col.child(
                        div()
                            .id(("nav2", idx))
                            .h(px(NAV_ITEM_H))
                            .mt(px(4.))
                            .rounded(px(NAV_ITEM_R))
                            .px(px(6.))
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .cursor_pointer()
                            .when(is_sel, |d| d.bg(h(NAV_SELECTED)))
                            .child(
                                div()
                                    .size(px(20.))
                                    .flex_shrink_0()
                                    .rounded(px(4.))
                                    .bg(h(NAV_ICON_SECONDARY)),
                            )
                            .child(
                                div()
                                    .text_size(px(FONT_LABEL))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(if is_sel { h(TEXT) } else { h(TEXT_SECONDARY) })
                                    .child(label),
                            )
                            .on_click(cx.listener(move |app, _e, _w, cx| {
                                app.navigate(target.clone());
                                cx.notify();
                            })),
                    );
                }
            }
        }
        // `.floor_set_hasnew` bottom action row (0,H-48) 180x48: three 20 px
        // circle icons at x=16 / x=112 / x=144.
        col = col.child(
            div()
                .h(px(48.))
                .mt_auto()
                .flex()
                .items_center()
                .pl(px(6.))
                .pr(px(6.))
                .child(
                    div()
                        .id("floor-settings")
                        .size(px(20.))
                        .rounded(px(10.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .hover(|d| d.bg(h(HOVER_BG)))
                        .child(
                            svg()
                                .data(Icon::Settings.svg_bytes())
                                .size(px(20.))
                                .text_color(h(TEXT)),
                        )
                        .on_click(cx.listener(|app, _e, _w, cx| {
                            app.navigate(Route::Settings);
                            cx.notify();
                        })),
                )
                .child(div().flex_1())
                .child(
                    div()
                        .id("floor-help")
                        .size(px(20.))
                        .rounded(px(10.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .hover(|d| d.bg(h(HOVER_BG)))
                        .child(
                            svg()
                                .data(Icon::CircleQuestionMark.svg_bytes())
                                .size(px(20.))
                                .text_color(h(TEXT)),
                        )
                        .on_click(cx.listener(|app, _e, _w, cx| {
                            app.toast
                                .push("Help center is provided by the vendor app", ToastKind::Info);
                            cx.notify();
                        })),
                )
                .child(
                    div()
                        .id("floor-mini")
                        .ml(px(12.))
                        .size(px(20.))
                        .rounded(px(10.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .hover(|d| d.bg(h(HOVER_BG)))
                        .child(
                            svg()
                                .data(Icon::Minimize2.svg_bytes())
                                .size(px(20.))
                                .text_color(h(TEXT)),
                        )
                        .on_click(cx.listener(|app, _e, _w, cx| {
                            app.toast.push("Minimized to tray (mock)", ToastKind::Info);
                            cx.notify();
                        })),
                ),
        );
        col.into_any_element()
    }

    fn render_headpiece(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let title = self.router.current().title();
        let route_icon = self.router.current().icon().svg_bytes();
        let active = self.transfer.has_active();
        div()
            .h(px(52.))
            .flex_shrink_0()
            .flex()
            .items_center()
            .px(px(16.))
            .gap(px(10.))
            .border_b_1()
            .border_color(h(DIVIDER))
            .when(self.router.can_go_back(), |d| {
                d.child(
                    div()
                        .id("back")
                        .size(px(28.))
                        .rounded(px(NAV_ITEM_R))
                        .flex()
                        .items_center()
                        .justify_center()
                        .cursor_pointer()
                        .child(
                            div()
                                .text_size(px(FONT_BODY))
                                .text_color(h(TEXT))
                                .child("‹"),
                        )
                        .on_click(cx.listener(|app, _e, _w, cx| {
                            app.go_back();
                            cx.notify();
                        })),
                )
            })
            .child(
                svg()
                    .data(route_icon)
                    .size(px(20.))
                    .text_color(h(TEXT_SECONDARY)),
            )
            .child(
                div()
                    .text_size(px(FONT_TITLE))
                    .font_weight(FontWeight::BOLD)
                    .text_color(h(TEXT))
                    .child(title),
            )
            .child(div().flex_1())
            .when(active, |d| {
                d.child(
                    div()
                        .id("mini-queue")
                        .h(px(28.))
                        .px(px(10.))
                        .rounded(px(PILL_R))
                        .bg(h(SELECTED_BG))
                        .flex()
                        .items_center()
                        .gap(px(4.))
                        .cursor_pointer()
                        .child(
                            div()
                                .text_size(px(FONT_LABEL))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(h(LINK))
                                .child("⇅ transferring"),
                        )
                        .on_click(cx.listener(|app, _e, _w, cx| {
                            app.navigate(Route::UploadDownload);
                            cx.notify();
                        })),
                )
            })
            .into_any_element()
    }

    // ----------------------------------------------------- devices (home)
    fn render_devices(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let wall = self.connection.wall();
        if wall.is_empty() {
            return self.render_wall(cx);
        }
        let mut wrap = div().p(px(16.)).flex().flex_col().gap(px(14.));
        // Vendor device-page header: section title + subtitle left,
        // "+ Add device" right (same action as the empty-wall button).
        let (_, section, subtitle) = wall_labels();
        wrap = wrap.child(
            div()
                .flex()
                .flex_row()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap(px(2.))
                        .child(
                            div()
                                .text_size(px(FONT_TITLE))
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(h(TEXT))
                                .child(section),
                        )
                        .child(
                            div()
                                .text_size(px(FONT_SMALL))
                                .font_weight(FontWeight::NORMAL)
                                .text_color(a(0x00_00_00, 0.54))
                                .child(subtitle),
                        ),
                )
                .child(
                    div()
                        .id("add-device")
                        .w(px(115.))
                        .h(px(34.))
                        .rounded(px(6.))
                        .flex()
                        .items_center()
                        .justify_center()
                        .gap(px(6.))
                        .cursor_pointer()
                        .hover(|d| d.bg(h(HOVER_BG)))
                        .child(
                            svg()
                                .data(Icon::Plus.svg_bytes())
                                .size(px(18.))
                                .text_color(h(LINK)),
                        )
                        .child(
                            div()
                                .text_size(px(16.))
                                .font_weight(FontWeight::NORMAL)
                                .text_color(h(LINK))
                                .child("Add device"),
                        )
                        .on_click(cx.listener(|app, _e, _w, cx| {
                            app.open_connect_dialog();
                            cx.notify();
                        })),
                ),
        );
        if let Some(status) = self.connect_status_line() {
            wrap = wrap.child(
                div()
                    .id("connect-status")
                    .h(px(34.))
                    .px(px(12.))
                    .rounded(px(NAV_ITEM_R))
                    .bg(h(SELECTED_BG))
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .text_size(px(FONT_LABEL))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(h(LINK))
                            .child(status),
                    ),
            );
        }
        let mut grid = div().flex().flex_row().flex_wrap().gap(px(14.));
        for (idx, dev) in wall.iter().enumerate() {
            let connected = self.connection.is_connected(&dev.device_id);
            let device = dev.clone();
            let del_device = dev.clone();
            let battery = dev.battery.map(|b| format!("{}%", b)).unwrap_or_default();
            let kind = if dev.device_type == DEVICE_TYPE_PAD {
                "Tablet"
            } else {
                "Phone"
            };
            grid = grid.child(
                div()
                    .id(("device-card", idx))
                    .w(px(260.))
                    .rounded(px(CARD_R))
                    .bg(h(CARD_BG))
                    .border_1()
                    .border_color(h(DIVIDER))
                    .p(px(14.))
                    .flex()
                    .flex_col()
                    .gap(px(10.))
                    .child(
                        div()
                            .h(px(120.))
                            .rounded(px(10.))
                            .bg(h(if dev.device_type == DEVICE_TYPE_PAD {
                                CARD_SCREEN_PAD
                            } else {
                                CARD_SCREEN_PHONE
                            }))
                            .flex()
                            .items_center()
                            .justify_center()
                            .child(
                                div()
                                    .w(px(54.))
                                    .h(px(100.))
                                    .rounded(px(10.))
                                    .bg(h(CARD_INNER))
                                    .border_1()
                                    .border_color(h(CARD_INNER_BORDER))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(
                                        div()
                                            .text_size(px(20.))
                                            .text_color(h(CARD_INNER_TEXT))
                                            .child("+"),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .child(
                                div()
                                    .text_size(px(15.))
                                    .font_weight(FontWeight::BOLD)
                                    .text_color(h(TEXT))
                                    .child(device.device_name.clone()),
                            )
                            .child(
                                div()
                                    .text_size(px(FONT_SMALL))
                                    .text_color(h(TEXT_SECONDARY))
                                    .child(battery),
                            ),
                    )
                    .child(
                        div()
                            .text_size(px(FONT_SMALL))
                            .text_color(h(TEXT_SECONDARY))
                            .child({
                                let mut meta = kind.to_string();
                                if !dev.ip.is_empty() {
                                    meta.push_str(&format!(" · {}", dev.ip));
                                }
                                if dev.is_paired {
                                    meta.push_str(" · Paired");
                                }
                                meta
                            }),
                    )
                    .child(
                        div()
                            .id(("device-connect", idx))
                            .h(px(32.))
                            .rounded(px(PILL_R))
                            .flex()
                            .items_center()
                            .justify_center()
                            .cursor_pointer()
                            .bg(if connected { h(CARD_BG) } else { h(PRIMARY) })
                            .child(
                                div()
                                    .text_size(px(FONT_LABEL))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(if connected {
                                        h(TEXT_SECONDARY)
                                    } else {
                                        h(ON_PRIMARY)
                                    })
                                    .child(if connected { "Disconnect" } else { "Connect" }),
                            )
                            .on_click(cx.listener(move |app, _e, _w, cx| {
                                if app.connection.is_connected(&device.device_id) {
                                    app.disconnect_device(&device);
                                } else {
                                    app.connect_device(&device);
                                }
                                cx.notify();
                            })),
                    )
                    .child(
                        div()
                            .id(("device-delete", idx))
                            .h(px(20.))
                            .flex()
                            .items_center()
                            .justify_end()
                            .cursor_pointer()
                            .child(
                                div()
                                    .text_size(px(FONT_SMALL))
                                    .text_color(h(TEXT_SECONDARY))
                                    .child("Delete"),
                            )
                            .on_click(cx.listener(move |app, _e, _w, cx| {
                                app.request_remove_device(&del_device);
                                cx.notify();
                            })),
                    ),
            );
        }
        wrap.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_size(px(FONT_BODY))
                        .font_weight(FontWeight::BOLD)
                        .text_color(h(TEXT))
                        .child("Devices"),
                )
                .child(
                    div()
                        .id("refresh-devices")
                        .h(px(28.))
                        .px(px(12.))
                        .rounded(px(PILL_R))
                        .bg(h(CARD_BG))
                        .flex()
                        .items_center()
                        .cursor_pointer()
                        .child(
                            div()
                                .text_size(px(FONT_LABEL))
                                .text_color(h(LINK))
                                .child("Refresh"),
                        )
                        .on_click(cx.listener(|app, _e, _w, cx| {
                            app.refresh_devices();
                            cx.notify();
                        })),
                ),
        )
        .child(grid)
        .into_any_element()
    }

    fn connect_status_line(&self) -> Option<String> {
        match &self.connection.state {
            ConnectState::Searching => Some("Searching for nearby devices…".into()),
            ConnectState::Connecting(id) => Some(format!("Connecting to {id}…")),
            ConnectState::WaitingPermission(id) => {
                Some(format!("Waiting for {id} to confirm on the phone…"))
            }
            ConnectState::Failed(id, why) => Some(format!("Could not connect {id}: {why}")),
            _ => None,
        }
    }

    // --------------------------------------------- signed-in device wall
    fn render_wall(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let (hero, section, subtitle) = wall_labels();
        let status = self.connect_status_line();
        div()
            .size_full()
            .relative()
            .flex()
            .flex_col()
            .px(px(16.))
            .pt(px(32.))
            .pb(px(16.))
            .when_some(status, |d, status| {
                d.child(
                    div()
                        .id("wall-status")
                        .absolute()
                        .top(px(32.))
                        .left_0()
                        .right_0()
                        .flex()
                        .justify_center()
                        .child(
                            div()
                                .h(px(24.))
                                .px(px(10.))
                                .rounded(px(8.))
                                .bg(h(BG))
                                .flex()
                                .items_center()
                                .child(
                                    div()
                                        .text_size(px(FONT_SMALL))
                                        .text_color(h(TEXT))
                                        .child(status),
                                ),
                        ),
                )
            })
            .child(
                div()
                    .h(px(51.))
                    .mt(px(4.))
                    .text_size(px(FONT_HERO))
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(h(TEXT))
                    .child(hero),
            )
            .child(
                div()
                    .id("wall-topright")
                    .absolute()
                    .right(px(16.))
                    .top(px(16.))
                    .size(px(45.))
                    .rounded(px(23.))
                    .bg(a(0x00_00_00, 0.03))
                    .cursor_pointer(),
            )
            .child(div().h(px(100.)))
            // `.connect` section header: title 16/500 + 18 px info icon,
            // subtitle 14/400 .54, "Add device" action 115x34 r6 #0080FF.
            .child(
                div()
                    .relative()
                    .h(px(58.))
                    .child(
                        div()
                            .mt(px(8.))
                            .h(px(22.))
                            .flex()
                            .items_center()
                            .gap(px(8.))
                            .child(
                                div()
                                    .text_size(px(FONT_TITLE))
                                    .font_weight(FontWeight::MEDIUM)
                                    .text_color(h(TEXT))
                                    .child(section),
                            )
                            .child(
                                div()
                                    .size(px(18.))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .child(
                                        div()
                                            .size(px(16.))
                                            .rounded(px(8.))
                                            .border_1()
                                            .border_color(h(LINK))
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .child(
                                                div()
                                                    .text_size(px(10.))
                                                    .font_weight(FontWeight::BOLD)
                                                    .text_color(h(LINK))
                                                    .child("i"),
                                            ),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .mt(px(2.))
                            .text_size(px(FONT_SMALL))
                            .font_weight(FontWeight::NORMAL)
                            .text_color(a(0x00_00_00, 0.54))
                            .child(subtitle),
                    )
                    .child(
                        div()
                            .id("add-device")
                            .absolute()
                            .right_0()
                            .top(px(12.))
                            .w(px(115.))
                            .h(px(34.))
                            .rounded(px(6.))
                            .flex()
                            .items_center()
                            .justify_center()
                            .gap(px(6.))
                            .cursor_pointer()
                            .hover(|d| d.bg(h(HOVER_BG)))
                            .child(
                                svg()
                                    .data(Icon::Plus.svg_bytes())
                                    .size(px(18.))
                                    .text_color(h(LINK)),
                            )
                            .child(
                                div()
                                    .text_size(px(16.))
                                    .font_weight(FontWeight::NORMAL)
                                    .text_color(h(LINK))
                                    .child("Add device"),
                            )
                            .on_click(cx.listener(|app, _e, _w, cx| {
                                app.open_connect_dialog();
                                cx.notify();
                            })),
                    ),
            )
            // `.card` (196,266) 1068x518 r16 rgba(255,255,255,.72):
            // left 420 px art panel + right text column with Connect pill.
            .child(
                div()
                    .h(px(518.))
                    .mt(px(16.))
                    .rounded(px(16.))
                    .bg(h(BG))
                    .flex()
                    .flex_row()
                    .child(div().w(px(420.)).flex_shrink_0())
                    .child(
                        div()
                            .flex_1()
                            .relative()
                            .child(
                                div()
                                    .id("wall-clear")
                                    .absolute()
                                    .right(px(4.))
                                    .top(px(4.))
                                    .size(px(36.))
                                    .rounded(px(18.))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .hover(|d| d.bg(h(HOVER_BG)))
                                    .on_click(cx.listener(|app, _e, _w, cx| {
                                        app.connection.reset();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                div()
                                    .id("wall-connect")
                                    .absolute()
                                    .left(px(64.))
                                    .top(px(272.))
                                    .w(px(180.))
                                    .h(px(40.))
                                    .rounded(px(PILL_R))
                                    .bg(h(PRIMARY))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .child(
                                        div()
                                            .text_size(px(14.))
                                            .font_weight(FontWeight::NORMAL)
                                            .text_color(h(ON_PRIMARY))
                                            .child("Connect"),
                                    )
                                    .on_click(cx.listener(|app, _e, _w, cx| {
                                        app.open_connect_dialog();
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            .into_any_element()
    }

    // --------------------------------------------- delete-confirm dialog
    fn render_delete_dialog(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let id = self.ui.delete_pending.clone().unwrap_or_default();
        let name = self
            .connection
            .wall()
            .into_iter()
            .find(|d| d.device_id == id)
            .map(|d| d.device_name.clone())
            .unwrap_or_else(|| id.clone());
        div()
            .absolute()
            .left(px(0.))
            .top(px(0.))
            .size_full()
            .bg(a(0x00_00_00, 0.45))
            .child(
                div()
                    .absolute()
                    .left(px(400.))
                    .top(px(270.))
                    .w(px(360.))
                    .rounded(px(16.))
                    .bg(h(CARD_BG))
                    .p(px(20.))
                    .flex()
                    .flex_col()
                    .gap(px(16.))
                    .child(
                        div()
                            .text_size(px(FONT_TITLE))
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(h(TEXT))
                            .child(format!("Remove {name}?")),
                    )
                    .child(
                        div()
                            .text_size(px(FONT_BODY))
                            .text_color(h(TEXT_SECONDARY))
                            .child(
                                "Unpair this device and remove it from the list. \
                                 It must pair again to return.",
                            ),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_row()
                            .justify_end()
                            .gap(px(10.))
                            .child(
                                div()
                                    .id("delete-cancel")
                                    .h(px(32.))
                                    .px(px(14.))
                                    .rounded(px(PILL_R))
                                    .bg(h(CARD_BG))
                                    .border_1()
                                    .border_color(h(DIVIDER))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .child(
                                        div()
                                            .text_size(px(FONT_LABEL))
                                            .text_color(h(TEXT_SECONDARY))
                                            .child("Cancel"),
                                    )
                                    .on_click(cx.listener(|app, _e, _w, cx| {
                                        app.cancel_remove_device();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                div()
                                    .id("delete-confirm")
                                    .h(px(32.))
                                    .px(px(14.))
                                    .rounded(px(PILL_R))
                                    .bg(h(PRIMARY))
                                    .flex()
                                    .items_center()
                                    .justify_center()
                                    .cursor_pointer()
                                    .child(
                                        div()
                                            .text_size(px(FONT_LABEL))
                                            .font_weight(FontWeight::MEDIUM)
                                            .text_color(h(ON_PRIMARY))
                                            .child("Remove"),
                                    )
                                    .on_click(cx.listener(|app, _e, _w, cx| {
                                        app.confirm_remove_device();
                                        cx.notify();
                                    })),
                            ),
                    ),
            )
            .into_any_element()
    }

    // --------------------------------------------- manual-connect dialog
    fn render_qr_dialog(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let (tab1, tab2, tips, usb_lines, connecting, bg_btn) = qr_dialog_labels();
        let active = self.ui.qr_tab;
        let connecting_now = matches!(self.connection.state, ConnectState::Connecting(_));
        let tabs = [tab1, tab2];
        let mut header = div()
            .absolute()
            .left(px(26.))
            .top(px(24.))
            .h(px(38.))
            .flex()
            .flex_row()
            .items_start();
        for (idx, label) in tabs.into_iter().enumerate() {
            let is_active = idx == active;
            header = header.child(
                div()
                    .id(("qr-tab", idx))
                    .w(if idx == 0 { px(108.) } else { px(130.) })
                    .h(px(30.))
                    .ml(if idx == 0 { px(0.) } else { px(16.) })
                    .flex()
                    .flex_col()
                    .justify_between()
                    .cursor_pointer()
                    .child(
                        div()
                            .text_size(px(FONT_TITLE))
                            .font_weight(if is_active {
                                FontWeight::SEMIBOLD
                            } else {
                                FontWeight::NORMAL
                            })
                            .text_color(if is_active {
                                h(TEXT)
                            } else {
                                a(0x00_00_00, 0.54)
                            })
                            .child(label),
                    )
                    .child(div().h(px(2.)).rounded(px(1.)).bg(if is_active {
                        h(0x1d_1d_1f)
                    } else {
                        h(GLASS)
                    }))
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        app.ui.qr_tab = idx;
                        cx.notify();
                    })),
            );
        }
        let card = div()
            .absolute()
            .left(px(316.))
            .top(px(179.))
            .w(px(648.))
            .h(px(442.))
            .rounded(px(16.))
            .bg(h(GLASS))
            .relative()
            .child(header)
            .child(
                div()
                    .id("qr-close")
                    .absolute()
                    .left(px(597.))
                    .top(px(16.))
                    .size(px(35.))
                    .rounded(px(18.))
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .hover(|d| d.bg(h(HOVER_BG)))
                    .child(
                        svg()
                            .data(Icon::X.svg_bytes())
                            .size(px(18.))
                            .text_color(h(TEXT)),
                    )
                    .on_click(cx.listener(|app, _e, _w, cx| {
                        app.ui.close_connect_dialog();
                        cx.notify();
                    })),
            );
        let card = if connecting_now {
            card.child(
                div()
                    .absolute()
                    .left(px(36.))
                    .top(px(254.))
                    .w(px(563.))
                    .text_size(px(20.))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(h(TEXT))
                    .text_center()
                    .child(connecting),
            )
            .child(
                div()
                    .id("qr-background")
                    .absolute()
                    .left(px(230.))
                    .top(px(378.))
                    .w(px(188.))
                    .h(px(40.))
                    .rounded(px(PILL_R))
                    .bg(a(0xff_ff_ff, 0.55))
                    .flex()
                    .items_center()
                    .justify_center()
                    .cursor_pointer()
                    .child(
                        div()
                            .text_size(px(14.))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(a(0x00_00_00, 0.9))
                            .child(bg_btn),
                    )
                    .on_click(cx.listener(|app, _e, _w, cx| {
                        app.ui.close_connect_dialog();
                        app.toast.push("Connecting in background", ToastKind::Info);
                        cx.notify();
                    })),
            )
        } else if active == 0 {
            card.child(
                div()
                    .absolute()
                    .left(px(83.))
                    .top(px(104.))
                    .w(px(182.))
                    .h(px(180.))
                    .rounded(px(8.))
                    .bg(h(BG))
                    .flex()
                    .items_center()
                    .justify_center()
                    .child(match self.qr_content.clone() {
                        Some(content) => qr_modules(content),
                        None => svg()
                            .data(Icon::LoaderCircle.svg_bytes())
                            .w(px(36.))
                            .h(px(36.))
                            .text_color(h(TEXT_DISABLED))
                            .into_any_element(),
                    }),
            )
            .child(
                div()
                    .absolute()
                    .left(px(12.))
                    .top(px(308.))
                    .w(px(324.))
                    .h(px(92.))
                    .overflow_hidden()
                    .child(div().pt(px(94.)).flex().flex_col().gap(px(8.)).children(
                        tips.into_iter().map(|line| {
                            div()
                                .text_size(px(14.))
                                .text_color(a(0x00_00_00, 0.9))
                                .child(line)
                        }),
                    )),
            )
            .child(
                div()
                    .absolute()
                    .left(px(466.))
                    .top(px(232.))
                    .size(px(40.))
                    .id("qr-play")
                    .cursor_pointer()
                    .child(
                        svg()
                            .data(Icon::CirclePlay.svg_bytes())
                            .w(px(40.))
                            .h(px(40.))
                            .text_color(h(QR_PLAY)),
                    ),
            )
        } else {
            card.child(
                div()
                    .absolute()
                    .left(px(81.))
                    .top(px(274.))
                    .w(px(474.))
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_size(px(14.))
                            .text_color(a(0x00_00_00, 0.5))
                            .child(usb_lines[0]),
                    )
                    .child(
                        div()
                            .mt(px(8.))
                            .text_size(px(14.))
                            .text_color(a(0x00_00_00, 0.5))
                            .child(usb_lines[1]),
                    )
                    .child(
                        div()
                            .mt(px(24.))
                            .text_size(px(10.))
                            .text_color(a(0x00_00_00, 0.5))
                            .child(usb_lines[2]),
                    ),
            )
        };
        div()
            .id("qr-mask")
            .absolute()
            .top_0()
            .left(px(-180.))
            .w(px(1280.))
            .h(px(800.))
            .bg(a(0x00_00_00, 0.2))
            .child(card)
            .into_any_element()
    }

    // ------------------------------------------------- multi-screen (stub+)
    fn render_multi_screen(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let mut wrap = div().p(px(16.)).flex().flex_col().gap(px(14.));
        wrap = wrap.child(
            div()
                .text_size(px(FONT_BODY))
                .font_weight(FontWeight::BOLD)
                .text_color(h(TEXT))
                .child("Choose a mode"),
        );
        for (idx, (icon, name, note)) in [
            (
                Icon::MousePointerClick,
                "Use keyboard and mouse",
                "Control the phone from this PC",
            ),
            (
                Icon::Columns2,
                "Extend computer screen",
                "Put the phone as a second screen",
            ),
            (
                Icon::ScreenShare,
                "Mirror computer screen",
                "Show this PC on the phone",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            wrap = wrap.child(
                div()
                    .id(("share-mode", idx))
                    .w(px(340.))
                    .rounded(px(CARD_R))
                    .bg(h(CARD_BG))
                    .border_1()
                    .border_color(h(DIVIDER))
                    .p(px(14.))
                    .flex()
                    .flex_col()
                    .gap(px(2.))
                    .child(
                        svg()
                            .data(icon.svg_bytes())
                            .size(px(20.))
                            .text_color(h(LINK))
                            .pt(px(4.))
                            .pb(px(6.)),
                    )
                    .child(
                        div()
                            .text_size(px(15.))
                            .font_weight(FontWeight::BOLD)
                            .text_color(h(TEXT))
                            .child(name),
                    )
                    .child(
                        div()
                            .text_size(px(FONT_SMALL))
                            .text_color(h(TEXT_SECONDARY))
                            .child(note),
                    )
                    .child(
                        div()
                            .text_size(px(FONT_SMALL))
                            .text_color(h(TEXT_DISABLED))
                            .child("pending backend · audited"),
                    ),
            );
        }
        wrap.child(pill_button(
            "mirr-open",
            "Open screen mirroring",
            true,
            cx,
            |app, _cx| {
                app.navigate(Route::Screen { device_id: None });
            },
        ))
        .into_any_element()
    }

    // ------------------------------------------------------ mirroring view
    fn render_mirroring(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let active = self.mirroring.active_listen.clone();
        let mut wrap = div().p(px(16.)).flex().flex_col().gap(px(14.));
        wrap = wrap.child(
            div()
                .flex()
                .items_center()
                .gap(px(10.))
                .child(pill_button(
                    "mirr-toggle",
                    if active.is_some() {
                        "Stop mirroring"
                    } else {
                        "Start mirroring"
                    },
                    true,
                    cx,
                    |app, _cx| {
                        app.toggle_mirroring();
                    },
                ))
                .child(
                    div()
                        .text_size(px(FONT_LABEL))
                        .text_color(h(TEXT_SECONDARY))
                        .child(
                            active
                                .map(|l| format!("Mirroring → {l} (mock sink)"))
                                .unwrap_or_else(|| "Not mirroring".into()),
                        ),
                ),
        );
        let mut chips = div().flex().flex_row().gap(px(8.));
        for (idx, q) in [
            Quality::LowLatency,
            Quality::SuperSmooth,
            Quality::UltraHighDefinition,
        ]
        .into_iter()
        .enumerate()
        {
            let sel = self.mirroring.quality == q;
            chips = chips.child(
                div()
                    .id(("quality", idx))
                    .h(px(30.))
                    .px(px(12.))
                    .rounded(px(PILL_R))
                    .bg(if sel { h(SELECTED_BG) } else { h(CARD_BG) })
                    .flex()
                    .items_center()
                    .cursor_pointer()
                    .child(
                        div()
                            .text_size(px(FONT_LABEL))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(if sel { h(LINK) } else { h(TEXT_SECONDARY) })
                            .child(q.label()),
                    )
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        app.set_quality(q);
                        cx.notify();
                    })),
            );
        }
        let mut media = div().flex().flex_row().gap(px(8.));
        for (idx, (label, on)) in [
            ("Sound", !self.mirroring.muted),
            ("Record", self.mirroring.recording),
        ]
        .into_iter()
        .enumerate()
        {
            media = media.child(
                div()
                    .id(("media", idx))
                    .h(px(30.))
                    .px(px(12.))
                    .rounded(px(PILL_R))
                    .bg(if on { h(SELECTED_BG) } else { h(CARD_BG) })
                    .flex()
                    .items_center()
                    .cursor_pointer()
                    .child(
                        div()
                            .text_size(px(FONT_LABEL))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(if on { h(LINK) } else { h(TEXT_SECONDARY) })
                            .child(label),
                    )
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        if idx == 0 {
                            app.toggle_muted();
                        } else {
                            app.toggle_recording();
                        }
                        cx.notify();
                    })),
            );
        }
        wrap.child(chips).child(media).into_any_element()
    }

    // ------------------------------------------------------- transfers view
    fn render_transfers(&mut self, cx: &mut Context<Self>) -> AnyElement {
        self.seed_demo_transfers();
        self.start_transfer_ticks(cx);
        let mut wrap = div().p(px(16.)).flex().flex_col().gap(px(8.));
        wrap = wrap.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_size(px(FONT_BODY))
                        .font_weight(FontWeight::BOLD)
                        .text_color(h(TEXT))
                        .child("Transfer history"),
                )
                .child(
                    div()
                        .id("clear-finished")
                        .h(px(28.))
                        .px(px(12.))
                        .rounded(px(PILL_R))
                        .bg(h(CARD_BG))
                        .cursor_pointer()
                        .flex()
                        .items_center()
                        .child(
                            div()
                                .text_size(px(FONT_LABEL))
                                .text_color(h(LINK))
                                .child("Clear completed"),
                        )
                        .on_click(cx.listener(|app, _e, _w, cx| {
                            app.clear_finished_transfers();
                            cx.notify();
                        })),
                ),
        );
        if self.transfer.items().is_empty() {
            wrap = wrap.child(
                div()
                    .text_size(px(FONT_BODY))
                    .text_color(h(TEXT_SECONDARY))
                    .child("No transfers yet"),
            );
        }
        for (idx, item) in self.transfer.items().iter().enumerate() {
            let pct = item.progress();
            let arrow = match item.direction {
                Direction::Upload => "↑",
                Direction::Download => "↓",
            };
            let status = match item.status {
                TransferStatus::Queued => "queued",
                TransferStatus::Running => "transferring",
                TransferStatus::Done => "done",
                TransferStatus::Failed => "failed",
            };
            let bar_w = px(240. * pct);
            wrap = wrap.child(
                div()
                    .id(("transfer", idx))
                    .h(px(52.))
                    .px(px(12.))
                    .rounded(px(NAV_ITEM_R))
                    .bg(h(CARD_BG))
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .child(
                        div()
                            .text_size(px(15.))
                            .text_color(if item.direction == Direction::Upload {
                                h(LINK)
                            } else {
                                h(OK)
                            })
                            .child(arrow),
                    )
                    .child(
                        div()
                            .w(px(180.))
                            .text_size(px(FONT_LABEL))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(h(TEXT))
                            .child(item.name.clone()),
                    )
                    .child(
                        div()
                            .w(px(240.))
                            .h(px(6.))
                            .rounded(px(3.))
                            .bg(h(PROGRESS_TRACK))
                            .child(div().w(bar_w).h(px(6.)).rounded(px(3.)).bg(h(PRIMARY))),
                    )
                    .child(
                        div()
                            .text_size(px(FONT_SMALL))
                            .text_color(h(TEXT_SECONDARY))
                            .child(format!("{:.0}% · {status}", pct * 100.0)),
                    ),
            );
        }
        wrap.into_any_element()
    }

    // ------------------------------------------------------------ settings
    fn render_settings(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let mut wrap = div()
            .p(px(16.))
            .flex()
            .flex_col()
            .gap(px(16.))
            .max_w(px(640.));
        let mut names = div().flex().flex_row().gap(px(8.));
        for (idx, preset) in ["desk-box", "workstation", "lplus-pc"]
            .into_iter()
            .enumerate()
        {
            let sel = self.host_name == preset;
            names = names.child(
                div()
                    .id(("hostname", idx))
                    .h(px(30.))
                    .px(px(12.))
                    .rounded(px(PILL_R))
                    .bg(if sel { h(SELECTED_BG) } else { h(CARD_BG) })
                    .cursor_pointer()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .text_size(px(FONT_LABEL))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(if sel { h(LINK) } else { h(TEXT_SECONDARY) })
                            .child(preset),
                    )
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        app.set_host_name(preset);
                        cx.notify();
                    })),
            );
        }
        let host_line = format!("Host name: {}", self.host_name.clone());
        wrap = wrap.child(
            div()
                .flex()
                .flex_col()
                .gap(px(2.))
                .child(
                    div()
                        .text_size(px(15.))
                        .font_weight(FontWeight::BOLD)
                        .text_color(h(TEXT))
                        .child("This device"),
                )
                .child(
                    div()
                        .text_size(px(FONT_SMALL))
                        .text_color(h(TEXT_SECONDARY))
                        .child(host_line),
                )
                .child(names),
        );
        wrap = wrap.child(div().h(px(1.)).bg(h(DIVIDER)));
        wrap = wrap.child(self.settings_row(
            cx,
            "General",
            "Launch at login · language (mock config)",
        ));
        wrap = wrap.child(self.settings_row(
            cx,
            "Cast screen",
            "Quality presets, shortcuts (Alt+W hidden cast)",
        ));
        wrap = wrap.child(self.settings_row(
            cx,
            "Remote control",
            "Password connection, historical connections",
        ));
        wrap = wrap.child(self.settings_row(
            cx,
            "Help & feedback",
            "Network diagnostics, feedback list",
        ));
        wrap = wrap.child(self.settings_row(cx, "Multilingual", "Interface language"));
        wrap.into_any_element()
    }

    fn settings_row(&mut self, cx: &mut Context<Self>, title: &str, note: &str) -> AnyElement {
        let title_s = title.to_string();
        div()
            .id(SharedString::from(format!("settings-{title_s}")))
            .h(px(58.))
            .px(px(12.))
            .rounded(px(NAV_ITEM_R))
            .bg(h(CARD_BG))
            .flex()
            .items_center()
            .justify_between()
            .cursor_pointer()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .child(
                        div()
                            .text_size(px(15.))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(h(TEXT))
                            .child(title.to_string()),
                    )
                    .child(
                        div()
                            .text_size(px(FONT_SMALL))
                            .text_color(h(TEXT_SECONDARY))
                            .child(note.to_string()),
                    ),
            )
            .child(
                div()
                    .text_size(px(16.))
                    .text_color(h(TEXT_DISABLED))
                    .child("›"),
            )
            .on_click(cx.listener(move |app, _e, _w, cx| {
                app.ipc
                    .invoke_raw(&format!("settings_open_{title_s}"), serde_json::Value::Null);
                app.toast.push(
                    format!("{title_s}: backend panel pending (audited)"),
                    ToastKind::Info,
                );
                cx.notify();
            }))
            .into_any_element()
    }

    // ------------------------------------------------------- ai search view
    fn render_ai_search(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let mut wrap = div().p(px(16.)).flex().flex_col().gap(px(10.));
        wrap = wrap.child(
            div()
                .text_size(px(FONT_BODY))
                .text_color(h(TEXT_SECONDARY))
                .child(if self.search_query.is_empty() {
                    "Search files and notes across devices".into()
                } else {
                    format!("Results for “{}”", self.search_query)
                }),
        );
        let mut chips = div().flex().flex_row().gap(px(8.));
        for (idx, preset) in ["mp4", "pdf", "jpg", "notes"].into_iter().enumerate() {
            chips = chips.child(
                div()
                    .id(("ai-chip", idx))
                    .h(px(30.))
                    .px(px(12.))
                    .rounded(px(PILL_R))
                    .bg(h(CARD_BG))
                    .cursor_pointer()
                    .flex()
                    .items_center()
                    .child(
                        div()
                            .text_size(px(FONT_LABEL))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(h(LINK))
                            .child(preset),
                    )
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        app.run_search(preset);
                        cx.notify();
                    })),
            );
        }
        wrap = wrap.child(chips);
        if !self.search_query.is_empty() {
            if self.ai_results.is_empty() {
                wrap = wrap.child(
                    div()
                        .text_size(px(FONT_BODY))
                        .text_color(h(TEXT_SECONDARY))
                        .child("No matches"),
                );
            }
            for (idx, name) in self.ai_results.clone().into_iter().enumerate() {
                wrap = wrap.child(
                    div()
                        .id(("ai-row", idx))
                        .h(px(40.))
                        .px(px(12.))
                        .rounded(px(NAV_ITEM_R))
                        .bg(h(CARD_BG))
                        .flex()
                        .items_center()
                        .child(
                            div()
                                .text_size(px(FONT_LABEL))
                                .text_color(h(TEXT))
                                .child(name),
                        ),
                );
            }
        }
        wrap.into_any_element()
    }

    // ------------------------------------------------------- crossfile view
    fn render_crossfile(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let mut wrap = div().p(px(16.)).flex().flex_col().gap(px(12.));
        let mut tiles = div().flex().flex_row().flex_wrap().gap(px(10.));
        for (idx, (label, key)) in [
            ("Images", "image"),
            ("Videos", "video"),
            ("Audio", "audio"),
            ("Documents", "document"),
        ]
        .into_iter()
        .enumerate()
        {
            let sel = self.crossfile_category.as_deref() == Some(key);
            tiles = tiles.child(
                div()
                    .id(("category", idx))
                    .w(px(150.))
                    .h(px(84.))
                    .rounded(px(CARD_R))
                    .bg(if sel { h(SELECTED_BG) } else { h(CARD_BG) })
                    .border_1()
                    .border_color(h(DIVIDER))
                    .p(px(10.))
                    .flex()
                    .flex_col()
                    .justify_end()
                    .cursor_pointer()
                    .child(
                        div()
                            .text_size(px(15.))
                            .font_weight(FontWeight::BOLD)
                            .text_color(if sel { h(LINK) } else { h(TEXT) })
                            .child(label),
                    )
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        app.open_category(key);
                        cx.notify();
                    })),
            );
        }
        wrap = wrap.child(tiles);
        if let Some(cat) = self.crossfile_category.clone() {
            wrap = wrap.child(
                div()
                    .text_size(px(15.))
                    .font_weight(FontWeight::BOLD)
                    .text_color(h(TEXT))
                    .child(cat),
            );
            for (idx, (name, size)) in self.crossfile_files.clone().into_iter().enumerate() {
                wrap = wrap.child(
                    div()
                        .id(("file", idx))
                        .h(px(40.))
                        .px(px(12.))
                        .rounded(px(NAV_ITEM_R))
                        .bg(h(CARD_BG))
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .text_size(px(FONT_LABEL))
                                .text_color(h(TEXT))
                                .child(name),
                        )
                        .child(
                            div()
                                .text_size(px(FONT_SMALL))
                                .text_color(h(TEXT_SECONDARY))
                                .child(format_size(size)),
                        ),
                );
            }
        }
        wrap.into_any_element()
    }

    // ------------------------------------------------- assistant (real data)

    /// Vendor `genericAgent` binding page, backed by the `generic_agent_*`
    /// channels: daemon status, this PC's agent id, cloud-bind state and
    /// the persistent pairing bonds with per-row unpair.
    fn render_generic_agent(&mut self, cx: &mut Context<Self>) -> AnyElement {
        self.ensure_generic_agent();
        let status = self
            .ga_status
            .clone()
            .unwrap_or_else(|| "unknown (channel pending)".into());
        let local_id = self.ga_local_id.clone().unwrap_or_else(|| "unknown".into());
        let bound = match self.ga_bound {
            Some(true) => "bound",
            Some(false) => "unbound",
            None => "unknown",
        };
        let mut wrap = div()
            .p(px(16.))
            .flex()
            .flex_col()
            .gap(px(10.))
            .max_w(px(560.));
        wrap = wrap
            .child(
                div()
                    .text_size(px(20.))
                    .font_weight(FontWeight::BOLD)
                    .text_color(h(TEXT))
                    .child("Assistant"),
            )
            .child(
                div()
                    .text_size(px(FONT_BODY))
                    .text_color(h(TEXT_SECONDARY))
                    .child(format!(
                        "Daemon: {status}   ·   this device: {local_id}   ·   cloud: {bound}"
                    )),
            );
        let paired = self.connection.paired().to_vec();
        if paired.is_empty() {
            wrap = wrap.child(
                div()
                    .text_size(px(FONT_BODY))
                    .text_color(h(TEXT_DISABLED))
                    .child("No paired devices yet — connect a device to create a bond."),
            );
        }
        for (idx, dev) in paired.iter().enumerate() {
            let dev_row = dev.clone();
            wrap = wrap.child(
                div()
                    .id(("ga-remove", idx))
                    .h(px(34.))
                    .px(px(12.))
                    .rounded(px(PILL_R))
                    .bg(h(CARD_BG))
                    .flex()
                    .items_center()
                    .justify_between()
                    .cursor_pointer()
                    .child(
                        div()
                            .text_size(px(FONT_LABEL))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(h(TEXT))
                            .child(format!(
                                "{} · {}{}",
                                dev.device_name,
                                dev.ip,
                                if dev.is_connected {
                                    " · connected"
                                } else {
                                    ""
                                }
                            )),
                    )
                    .child(
                        div()
                            .text_size(px(FONT_SMALL))
                            .text_color(h(TEXT_DISABLED))
                            .child("remove"),
                    )
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        app.request_remove_device(&dev_row);
                        cx.notify();
                    })),
            );
        }
        wrap.into_any_element()
    }

    // ---------------------------------------------------------- generic stub
    fn render_stub(
        &mut self,
        cx: &mut Context<Self>,
        title: &str,
        channels: &[Channel],
    ) -> AnyElement {
        let mut wrap = div()
            .p(px(16.))
            .flex()
            .flex_col()
            .gap(px(10.))
            .max_w(px(560.));
        wrap = wrap
            .child(div().text_size(px(20.)).font_weight(FontWeight::BOLD).text_color(h(TEXT)).child(title.to_string()))
            .child(
                div()
                    .text_size(px(FONT_BODY))
                    .text_color(h(TEXT_SECONDARY))
                    .child("Screen ported from the vendor renderer; backend channel(s) not implemented yet — invocations are recorded in the mock audit ring."),
            );
        for (idx, ch) in channels.iter().copied().enumerate() {
            wrap = wrap.child(
                div()
                    .id(("stub-invoke", idx))
                    .h(px(34.))
                    .px(px(12.))
                    .rounded(px(PILL_R))
                    .bg(h(CARD_BG))
                    .flex()
                    .items_center()
                    .justify_between()
                    .cursor_pointer()
                    .child(
                        div()
                            .text_size(px(FONT_LABEL))
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(h(TEXT))
                            .child(ch.to_string()),
                    )
                    .child(
                        div()
                            .text_size(px(FONT_SMALL))
                            .text_color(h(TEXT_DISABLED))
                            .child("try"),
                    )
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        app.ipc.invoke(ch, serde_json::Value::Null);
                        app.toast
                            .push(format!("{ch} pending backend (audited)"), ToastKind::Info);
                        cx.notify();
                    })),
            );
        }
        wrap.into_any_element()
    }

    // --------------------------------------------------------------- toasts
    fn render_toasts(&mut self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        self.toast
            .items()
            .iter()
            .enumerate()
            .map(|(idx, t)| {
                let id = t.id;
                let (text, kind) = (t.text.clone(), t.kind);
                div()
                    .id(("toast", idx))
                    .absolute()
                    .bottom(px(16.))
                    .right(px(16.))
                    .px(px(14.))
                    .py(px(9.))
                    .rounded(px(NAV_ITEM_R))
                    .bg(h(CARD_BG))
                    .border_1()
                    .border_color(h(DIVIDER))
                    .flex()
                    .items_center()
                    .gap(px(8.))
                    .cursor_pointer()
                    .child(div().size(px(8.)).rounded(px(4.)).bg(match kind {
                        ToastKind::Success => h(OK),
                        ToastKind::Error => h(ERROR),
                        ToastKind::Info => h(LINK),
                    }))
                    .child(
                        div()
                            .text_size(px(FONT_LABEL))
                            .text_color(h(TEXT))
                            .child(text),
                    )
                    .on_click(cx.listener(move |app, _e, _w, cx| {
                        app.dismiss_toast(id);
                        cx.notify();
                    }))
                    .into_any_element()
            })
            .collect()
    }
}

impl Render for AppState {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let route = self.router.current().clone();
        let body: AnyElement = self.render_home_shell(cx, route);
        div()
            .size_full()
            .bg(h(BG))
            .font_family(font_family())
            .flex()
            .flex_col()
            .child(body)
            .children(self.render_toasts(cx))
    }
}

fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Render the pairing payload as a real QR grid (fast_qr encoder). The
/// modules fill the dialog's 182 px frame; an unpublishable payload draws
/// nothing rather than a stale code.
fn qr_modules(content: String) -> AnyElement {
    let Ok(qr) = fast_qr::qr::QRBuilder::new(content).build() else {
        return div().into_any_element();
    };
    let n = qr.size;
    let cell = px(182. / n as f32);
    div()
        .flex()
        .flex_col()
        .children((0..n).map(|y| {
            div().flex().flex_row().children((0..n).map(|x| {
                div().w(cell).h(cell).bg(if qr.data[y * n + x].value() {
                    h(0x00_00_00)
                } else {
                    h(BG)
                })
            }))
        }))
        .into_any_element()
}

/// Pill button per measured style (radius 100, padding 8/22, primary #0080FF
/// or ghost with rgba(0,0,0,.54) text).
fn pill_button(
    id: &'static str,
    label: &str,
    primary: bool,
    cx: &mut Context<AppState>,
    on: impl Fn(&mut AppState, &mut Context<AppState>) + 'static,
) -> AnyElement {
    div()
        .id(id)
        .h(px(43.))
        .px(px(PILL_PAD_X))
        .py(px(PILL_PAD_Y))
        .rounded(px(PILL_R))
        .bg(if primary { h(PRIMARY) } else { h(BG) })
        .border_1()
        .border_color(if primary { h(PRIMARY) } else { h(DIVIDER) })
        .flex()
        .items_center()
        .justify_center()
        .cursor_pointer()
        .child(
            div()
                .text_size(px(16.))
                .font_weight(FontWeight::MEDIUM)
                .text_color(if primary {
                    h(ON_PRIMARY)
                } else {
                    h(TEXT_SECONDARY)
                })
                .child(label.to_string()),
        )
        .on_click(cx.listener(move |app, _e, _w, cx| {
            on(app, cx);
            cx.notify();
        }))
        .into_any_element()
}
