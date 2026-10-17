//! The progress bar drawn on stderr during long AES-KDF runs.

use std::sync::{Arc, Mutex};

use indicatif::{ProgressBar, ProgressStyle};

/// Fewer AES-KDF rounds than this finish too quickly to need a bar.
const MIN_ROUNDS: u64 = 50_000;

static BAR: Mutex<Option<ProgressBar>> = Mutex::new(None);

/// Draw a bar for every long key derivation this process runs.
pub(crate) fn install() {
    crate::crypto::set_kdf_progress_hook(Some(Arc::new(update)));
}

fn update(done: u64, total: u64) {
    if total < MIN_ROUNDS {
        return;
    }
    let Ok(mut bar) = BAR.lock() else {
        return;
    };
    if done == 0 {
        let pb = ProgressBar::new(total);
        if let Ok(style) = ProgressStyle::with_template("{msg} {wide_bar} {pos}/{len}") {
            pb.set_style(style);
        }
        pb.set_message("AES-KDF");
        *bar = Some(pb);
    } else if let Some(pb) = bar.as_ref() {
        pb.set_position(done);
    }
    if done >= total
        && let Some(pb) = bar.take()
    {
        pb.finish_and_clear();
    }
}
