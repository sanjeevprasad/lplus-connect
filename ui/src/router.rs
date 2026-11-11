//! Router: the vendor uses vue-router with hash history
//! (`createWebHashHistory`) over `#/…` paths. This is the typed port:
//! every vendor route becomes a `Route` variant, `Router` keeps the
//! navigation stack (back) and the current route.

use lucide_static_svg::Icon;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `#/home` (interconnection device wall is its index child)
    Home,
    /// `#/crossfile/:deviceId?`
    CrossFile {
        device_id: Option<String>,
        folder: Option<String>,
    },
    /// `#/crossfile/…/list/:pageName/:folder?`
    CrossFileList {
        device_id: Option<String>,
        page_name: String,
        folder: Option<String>,
    },
    /// `#/search/searchPage`
    CrossFileSearch { device_id: Option<String> },
    /// `#/aiSearch`
    AiSearch,
    /// `#/searchDetail`
    AiSearchDetail,
    /// `#/screen/:deviceId?`
    Screen { device_id: Option<String> },
    /// `#/screenshare/:deviceId?`
    ScreenShare { device_id: Option<String> },
    /// `#/remotecontrol/:deviceId?`
    RemoteControl { device_id: Option<String> },
    /// `#/settings`
    Settings,
    /// `#/uploaddownload`
    UploadDownload,
    /// `#/generic-agent`
    GenericAgent,
    /// `#/note`
    Note,
}

impl Route {
    /// Headpiece title, verbatim from the vendor pages.
    pub fn title(&self) -> &'static str {
        match self {
            Route::Home => "Devices",
            Route::RemoteControl { .. } => "Remote control",
            Route::ScreenShare { .. } => "Multi-Screen Connect",
            Route::Screen { .. } => "Screen mirroring",
            Route::UploadDownload => "Transfers",
            Route::Settings => "Settings",
            Route::AiSearch => "AI search",
            Route::CrossFile { .. }
            | Route::CrossFileList { .. }
            | Route::CrossFileSearch { .. } => "File management",
            Route::AiSearchDetail => "Search detail",
            Route::GenericAgent => "Assistant",
            Route::Note => "Notes",
        }
    }

    /// Nav/headpiece glyph for this route.
    pub fn icon(&self) -> Icon {
        match self {
            Route::Home => Icon::MonitorSmartphone,
            Route::RemoteControl { .. } => Icon::ScreenShare,
            Route::ScreenShare { .. } => Icon::Columns2,
            Route::Screen { .. } => Icon::MonitorUp,
            Route::UploadDownload => Icon::ArrowUpDown,
            Route::Settings => Icon::Settings,
            Route::AiSearch | Route::AiSearchDetail => Icon::Search,
            Route::CrossFile { .. }
            | Route::CrossFileList { .. }
            | Route::CrossFileSearch { .. } => Icon::FolderOpen,
            Route::GenericAgent => Icon::Bot,
            Route::Note => Icon::StickyNote,
        }
    }
}

/// Navigation stack mirroring vue-router history semantics.
#[derive(Debug, Default)]
pub struct Router {
    stack: Vec<Route>,
}

impl Router {
    pub fn new(initial: Route) -> Self {
        Self {
            stack: vec![initial],
        }
    }

    pub fn current(&self) -> &Route {
        self.stack.last().expect("router always keeps one route")
    }

    pub fn push(&mut self, route: Route) {
        if self.current() == &route {
            return;
        }
        self.stack.push(route);
    }

    /// `router.replace`: swap the top of the stack (used for redirect
    /// welcome→home and post-connect jumps).
    pub fn replace(&mut self, route: Route) {
        match self.stack.last_mut() {
            Some(top) => *top = route,
            None => self.stack.push(route),
        }
    }

    /// `router.back()`; false when the stack cannot pop further.
    pub fn back(&mut self) -> bool {
        if self.stack.len() <= 1 {
            return false;
        }
        self.stack.pop();
        true
    }

    pub fn can_go_back(&self) -> bool {
        self.stack.len() > 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_starts_on_initial_route() {
        let r = Router::new(Route::Home);
        assert_eq!(r.current(), &Route::Home);
        assert!(!r.can_go_back());
    }

    #[test]
    fn push_and_back_walk_the_stack() {
        let mut r = Router::new(Route::Home);
        r.push(Route::UploadDownload);
        r.push(Route::Settings);
        assert_eq!(r.current(), &Route::Settings);
        assert!(r.back());
        assert_eq!(r.current(), &Route::UploadDownload);
        assert!(r.back());
        assert_eq!(r.current(), &Route::Home);
        assert!(!r.back());
    }

    #[test]
    fn pushing_the_current_route_is_a_no_op() {
        let mut r = Router::new(Route::Home);
        r.push(Route::Home);
        assert!(!r.can_go_back());
    }

    #[test]
    fn replace_does_not_grow_history() {
        let mut r = Router::new(Route::Settings);
        r.replace(Route::Home);
        assert_eq!(r.current(), &Route::Home);
        assert!(!r.can_go_back());
    }
}
