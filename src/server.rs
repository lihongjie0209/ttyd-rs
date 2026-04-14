use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use tokio::sync::Mutex;

/// URL endpoint paths, configurable via --base-path
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub ws: String,
    pub index: String,
    pub token: String,
    pub parent: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            ws: "/ws".to_string(),
            index: "/".to_string(),
            token: "/token".to_string(),
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
    /// Base64-encoded credential for Basic Auth (None = no auth)
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
