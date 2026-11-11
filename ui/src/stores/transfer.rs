//! Port of the vendor `uploadDownload.js` vuex module: the transfer queue
//! behind `#/uploaddownload` and the MiniUploadDownload widget.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Upload,   // PC -> phone
    Download, // phone -> PC
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    Running,
    Done,
    Failed,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TransferItem {
    pub id: String,
    pub name: String,
    pub size_bytes: u64,
    pub transferred: u64,
    pub direction: Direction,
    pub status: TransferStatus,
}

impl TransferItem {
    pub fn progress(&self) -> f32 {
        if self.size_bytes == 0 {
            return if self.status == TransferStatus::Done {
                1.0
            } else {
                0.0
            };
        }
        (self.transferred as f64 / self.size_bytes as f64).clamp(0.0, 1.0) as f32
    }
}

#[derive(Debug, Default)]
pub struct TransferStore {
    items: Vec<TransferItem>,
}

impl TransferStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// MiniUploadDownload mount hook: pull the queue from the main process.
    pub fn set_items(&mut self, items: Vec<TransferItem>) {
        self.items = items;
    }

    pub fn enqueue(&mut self, item: TransferItem) {
        self.items.push(item);
    }

    pub fn items(&self) -> &[TransferItem] {
        &self.items
    }

    /// Drive one tick of progress for a running item; completion flips the
    /// status, clamping at the file size.
    pub fn advance(&mut self, id: &str, delta_bytes: u64) {
        let Some(item) = self.items.iter_mut().find(|i| i.id == id) else {
            return;
        };
        if item.status != TransferStatus::Running {
            return;
        }
        item.transferred = item
            .transferred
            .saturating_add(delta_bytes)
            .min(item.size_bytes);
        if item.transferred == item.size_bytes {
            item.status = TransferStatus::Done;
        }
    }

    pub fn start(&mut self, id: &str) {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.status = TransferStatus::Running;
        }
    }

    pub fn fail(&mut self, id: &str) {
        if let Some(item) = self.items.iter_mut().find(|i| i.id == id) {
            item.status = TransferStatus::Failed;
        }
    }

    /// "clear completed" affordance on the transfers page.
    pub fn clear_finished(&mut self) {
        self.items
            .retain(|i| !matches!(i.status, TransferStatus::Done | TransferStatus::Failed));
    }

    pub fn has_active(&self) -> bool {
        self.items
            .iter()
            .any(|i| matches!(i.status, TransferStatus::Queued | TransferStatus::Running))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, size: u64) -> TransferItem {
        TransferItem {
            id: id.into(),
            name: format!("{id}.mp4"),
            size_bytes: size,
            transferred: 0,
            direction: Direction::Upload,
            status: TransferStatus::Queued,
        }
    }

    #[test]
    fn enqueue_then_start_then_progress_to_done() {
        let mut s = TransferStore::new();
        s.enqueue(item("t1", 1000));
        s.start("t1");
        s.advance("t1", 400);
        assert_eq!(s.items()[0].status, TransferStatus::Running);
        assert!((s.items()[0].progress() - 0.4).abs() < 1e-6);
        s.advance("t1", 900);
        assert_eq!(s.items()[0].status, TransferStatus::Done);
        assert_eq!(s.items()[0].transferred, 1000);
        assert_eq!(s.items()[0].progress(), 1.0);
    }

    #[test]
    fn advance_on_queued_is_ignored() {
        let mut s = TransferStore::new();
        s.enqueue(item("t1", 100));
        s.advance("t1", 50);
        assert_eq!(s.items()[0].transferred, 0);
    }

    #[test]
    fn zero_size_done_item_reports_full_progress() {
        let mut it = item("t0", 0);
        it.status = TransferStatus::Done;
        assert_eq!(it.progress(), 1.0);
    }

    #[test]
    fn clear_finished_keeps_active_only() {
        let mut s = TransferStore::new();
        s.enqueue(item("a", 10));
        s.enqueue(item("b", 10));
        s.enqueue(item("c", 10));
        s.start("a");
        s.advance("a", 10); // done
        s.start("b");
        s.fail("b"); // failed
        s.clear_finished();
        assert_eq!(s.items().len(), 1);
        assert_eq!(s.items()[0].id, "c");
        assert!(s.has_active());
    }

    #[test]
    fn advance_unknown_id_is_a_no_op() {
        let mut s = TransferStore::new();
        s.enqueue(item("a", 10));
        s.start("a");
        s.advance("nope", 5);
        assert_eq!(s.items()[0].transferred, 0);
    }
}
