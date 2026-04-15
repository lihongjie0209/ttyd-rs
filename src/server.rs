use crate::audit::AuditLogger;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::AtomicI32;
use std::time::Instant;
use tokio::sync::Mutex;

/// Token lifetime in seconds (24 h)
pub const TOKEN_TTL_SECS: u64 = 86_400;
/// Number of consecutive failures before an IP is locked
pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
/// Lock-out duration in seconds (15 min)
pub const LOGIN_LOCKOUT_SECS: u64 = 900;

/// An active session token stored server-side
pub struct TokenEntry {
    pub username: String,
    pub expires_at: Instant,
}

/// Per-IP login attempt state
pub struct LoginAttempts {
    pub count: u32,
    pub locked_until: Option<Instant>,
}

/// URL endpoint paths, configurable via --base-path
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub ws: String,
    pub index: String,
    pub login: String,
    pub logout: String,
    pub parent: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            ws: "/ws".to_string(),
            index: "/".to_string(),
            login: "/login".to_string(),
            logout: "/logout".to_string(),
            parent: String::new(),
        }
    }
}

/// Shared server configuration and runtime state
pub struct ServerState {
    /// Current connected client count
    pub client_count: Mutex<i32>,
    /// Client JSON preferences string (sent via SET_PREFERENCES)
    pub prefs_json: String,
    /// Base64-encoded "username:password" credential for login validation (None = no auth)
    pub credential: Option<String>,
    /// HTTP header name used for proxy authentication
    pub auth_header: Option<String>,
    /// Path to custom index.html (None = use embedded)
    pub index: Option<String>,
    /// The command being run (as a display string)
    pub command: String,
    /// Command + args to exec
    pub argv: Vec<String>,
    /// Working directory for child process
    pub cwd: Option<String>,
    /// Signal to send to child on WS close (Unix signal number)
    pub sig_code: i32,
    /// Human-readable signal name
    pub sig_name: String,
    /// Allow clients to pass args via URL query string
    pub url_arg: bool,
    /// Allow clients to write to the TTY (false = read-only)
    pub writable: bool,
    /// Reject WebSocket connections from different origins
    pub check_origin: bool,
    /// Maximum simultaneous clients (0 = unlimited)
    pub max_clients: i32,
    /// Accept only one client, then exit
    pub once: bool,
    /// Exit when all clients disconnect
    pub exit_no_conn: bool,
    /// TERM environment variable to set for child process
    pub terminal_type: String,
    /// WebSocket ping interval in seconds
    pub ping_interval: u64,
    /// Preferred server-side chunk/read buffer size
    pub srv_buf_size: usize,
    /// Whether `rz`/`sz` are available in runtime environment
    pub lrzsz_supported: bool,
    /// Whether to protect WS payloads with Noise transport encryption
    pub ws_noise: bool,
    /// Active session tokens: token → TokenEntry (expiry + username)
    pub token_store: StdMutex<HashMap<String, TokenEntry>>,
    /// Per-IP login attempt tracking for brute-force protection
    pub login_limiter: StdMutex<HashMap<IpAddr, LoginAttempts>>,
    /// Whether the server is listening with TLS (used to set Secure cookie flag)
    pub tls_enabled: bool,
    /// Optional JSONL audit log sink
    pub audit_logger: Option<Arc<AuditLogger>>,
    /// Allowed client IP/CIDR list; empty means allow all
    pub ip_whitelist: Vec<IpNet>,
    /// URL endpoint paths
    pub endpoints: Endpoints,
    /// Port actually bound (may differ from requested if 0 was given)
    pub bound_port: AtomicI32,
}

pub type SharedState = Arc<ServerState>;

impl ServerState {
    pub fn is_ip_allowed(&self, ip: Option<IpAddr>) -> bool {
        if self.ip_whitelist.is_empty() {
            return true;
        }
        match ip {
            Some(addr) => self.ip_whitelist.iter().any(|net| net.contains(&addr)),
            None => false,
        }
    }
}
