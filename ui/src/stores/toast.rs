//! Port of the vendor `toast.js` vuex module (DsToast surface).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToastKind {
    Success,
    Error,
    Info,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Toast {
    pub id: u64,
    pub text: String,
    pub kind: ToastKind,
}

#[derive(Debug, Default)]
pub struct ToastStore {
    next_id: u64,
    items: Vec<Toast>,
}

impl ToastStore {
    pub fn push(&mut self, text: impl Into<String>, kind: ToastKind) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.items.push(Toast {
            id,
            text: text.into(),
            kind,
        });
        id
    }

    pub fn dismiss(&mut self, id: u64) {
        self.items.retain(|t| t.id != id);
    }

    pub fn items(&self) -> &[Toast] {
        &self.items
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_monotonic_and_dismiss_removes_one() {
        let mut s = ToastStore::default();
        let a = s.push("connected", ToastKind::Success);
        let b = s.push("failed", ToastKind::Error);
        assert!(b > a);
        assert_eq!(s.items().len(), 2);
        s.dismiss(a);
        assert_eq!(s.items().len(), 1);
        assert_eq!(s.items()[0].kind, ToastKind::Error);
    }

    #[test]
    fn dismiss_unknown_is_a_no_op() {
        let mut s = ToastStore::default();
        s.push("x", ToastKind::Info);
        s.dismiss(999);
        assert_eq!(s.items().len(), 1);
    }
}
