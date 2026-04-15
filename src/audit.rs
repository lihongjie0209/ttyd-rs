use serde::Serialize;
use std::{
    fs::OpenOptions,
    io::Write,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Serialize)]
pub struct AuditEvent {
    pub ts_ms: u128,
    pub actor: String,
    pub ip: Option<String>,
    pub action: String,
    pub command: Option<String>,
    pub target: Option<String>,
    pub success: bool,
    pub message: Option<String>,
}

impl AuditEvent {
    pub fn new(
        actor: impl Into<String>,
        ip: Option<String>,
        action: impl Into<String>,
        command: Option<String>,
        target: Option<String>,
        success: bool,
        message: Option<String>,
    ) -> Self {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        Self {
            ts_ms,
            actor: actor.into(),
            ip,
            action: action.into(),
            command,
            target,
            success,
            message,
        }
    }
}

pub struct AuditLogger {
    file: Mutex<std::fs::File>,
}

impl AuditLogger {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    pub fn log(&self, event: AuditEvent) {
        let Ok(line) = serde_json::to_vec(&event) else {
            return;
        };
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(&line);
            let _ = f.write_all(b"\n");
        }
    }
}
