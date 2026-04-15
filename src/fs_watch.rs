use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, warn};

/// Spawn a background task that watches `root` for filesystem changes and
/// broadcasts a `()` token to `tx` whenever something is created or deleted
/// (debounced to at most one signal per 500 ms).
pub fn spawn_watcher(root: PathBuf, tx: broadcast::Sender<()>) {
    std::thread::spawn(move || {
        use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

        let (event_tx, event_rx) = std::sync::mpsc::channel();

        let mut watcher = match RecommendedWatcher::new(event_tx, Config::default()) {
            Ok(w) => w,
            Err(e) => {
                warn!("fs_watch: failed to create watcher: {e}");
                return;
            }
        };

        if let Err(e) = watcher.watch(&root, RecursiveMode::Recursive) {
            warn!("fs_watch: failed to watch {}: {e}", root.display());
            return;
        }

        debug!("fs_watch: watching {}", root.display());

        // Debounce: track last-sent time, only emit once per 500 ms
        let debounce = Duration::from_millis(500);
        let mut last_sent = std::time::Instant::now()
            .checked_sub(debounce)
            .unwrap_or(std::time::Instant::now());

        loop {
            match event_rx.recv_timeout(Duration::from_secs(60)) {
                Ok(Ok(ev)) => {
                    // Only care about create / remove / rename events
                    let interesting = matches!(
                        ev.kind,
                        EventKind::Create(_) | EventKind::Remove(_) | EventKind::Modify(
                            notify::event::ModifyKind::Name(_)
                        )
                    );
                    if interesting {
                        let now = std::time::Instant::now();
                        if now.duration_since(last_sent) >= debounce {
                            last_sent = now;
                            // If all subscribers dropped, channel is closed — stop.
                            if tx.send(()).is_err() {
                                debug!("fs_watch: broadcast channel closed, stopping");
                                break;
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("fs_watch: watcher error: {e}");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // no events, keep looping
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    debug!("fs_watch: event channel disconnected");
                    break;
                }
            }
        }
    });
}
