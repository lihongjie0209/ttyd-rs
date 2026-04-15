mod assets;
mod audit;
mod file_api;
mod http;
mod noise;
mod pty;
mod server;
mod ws;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Json, State, WebSocketUpgrade},
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use clap::Parser;
use ipnet::IpNet;
use serde_json::{Map, Value};
use std::net::IpAddr;
use tokio::sync::Mutex;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use audit::AuditLogger;
use server::{Endpoints, ServerState, SharedState};

#[derive(Parser, Debug)]
#[command(
    name = "ttyd",
    about = "Share your terminal over the web",
    version = env!("CARGO_PKG_VERSION"),
    after_help = "Visit https://github.com/tsl0922/ttyd for more information."
)]
struct Cli {
    #[arg(long, help = "Path to TOML/JSON config file")]
    config: Option<String>,

    #[arg(
        short = 'p',
        long,
        default_value = "7681",
        help = "Port to listen (0 = random)"
    )]
    port: u16,

    #[arg(short = 'i', long, help = "Network interface or UNIX socket path")]
    interface: Option<String>,

    #[arg(
        short = 'U',
        long = "socket-owner",
        help = "Owner of the UNIX socket file"
    )]
    socket_owner: Option<String>,

    #[arg(short = 'c', long, help = "Login credential (username:password)")]
    credential: Option<String>,

    #[arg(long, help = "Username for authentication")]
    username: Option<String>,

    #[arg(long, help = "Password for authentication")]
    password: Option<String>,

    #[arg(
        short = 'H',
        long = "auth-header",
        help = "HTTP header name for proxy auth"
    )]
    auth_header: Option<String>,

    #[arg(short = 'u', long, help = "User id to run with (Unix only)")]
    uid: Option<u32>,

    #[arg(short = 'g', long, help = "Group id to run with (Unix only)")]
    gid: Option<u32>,

    #[arg(
        short = 's',
        long,
        default_value = "1",
        help = "Signal to send on client exit (Unix only)"
    )]
    signal: i32,

    #[arg(short = 'w', long, help = "Working directory for child process")]
    cwd: Option<String>,

    #[arg(short = 'I', long, help = "Custom index.html path")]
    index: Option<String>,

    #[arg(
        short = 'b',
        long = "base-path",
        help = "Base path for reverse proxy (e.g. /mounted/here)"
    )]
    base_path: Option<String>,

    #[arg(
        short = 'P',
        long = "ping-interval",
        default_value = "5",
        help = "WebSocket ping interval (seconds)"
    )]
    ping_interval: u64,

    #[arg(
        short = 'f',
        long = "srv-buf-size",
        default_value = "4096",
        help = "Max chunk size in bytes"
    )]
    srv_buf_size: usize,

    #[arg(short = '6', long, help = "Enable IPv6")]
    ipv6: bool,

    #[arg(short = 'S', long, help = "Enable SSL/TLS")]
    ssl: bool,

    #[arg(short = 'C', long = "ssl-cert", help = "SSL certificate file")]
    ssl_cert: Option<String>,

    #[arg(short = 'K', long = "ssl-key", help = "SSL key file")]
    ssl_key: Option<String>,

    #[arg(
        short = 'A',
        long = "ssl-ca",
        help = "SSL CA file for client cert verification"
    )]
    ssl_ca: Option<String>,

    #[arg(short = 'a', long = "url-arg", help = "Allow URL arguments (?arg=foo)")]
    url_arg: bool,

    #[arg(short = 'R', long = "readonly", help = "Make the terminal read-only (disable input)")]
    readonly: bool,

    #[arg(
        short = 'T',
        long = "terminal-type",
        default_value = "xterm-256color",
        help = "TERM environment variable"
    )]
    terminal_type: String,

    #[arg(
        short = 't',
        long = "client-option",
        help = "Client option (key=value), repeatable"
    )]
    client_option: Vec<String>,

    #[arg(
        short = 'O',
        long = "check-origin",
        help = "Reject cross-origin WebSocket connections"
    )]
    check_origin: bool,

    #[arg(
        short = 'm',
        long = "max-clients",
        default_value = "0",
        help = "Max simultaneous clients (0=unlimited)"
    )]
    max_clients: i32,

    #[arg(long = "ip-whitelist", help = "Allow client IP/CIDR (repeatable)")]
    ip_whitelist: Vec<String>,

    #[arg(short = 'o', long, help = "Exit after first client disconnects")]
    once: bool,

    #[arg(
        short = 'q',
        long = "exit-no-conn",
        help = "Exit when all clients disconnect"
    )]
    exit_no_conn: bool,

    #[arg(short = 'B', long, help = "Open browser on start")]
    browser: bool,

    #[arg(long = "audit-log", help = "Write detailed audit logs (JSONL) to file")]
    audit_log: Option<String>,

    #[arg(
        long = "disable-ws-noise",
        help = "Disable Noise encryption for WebSocket payloads"
    )]
    disable_ws_noise: bool,

    #[arg(short = 'd', long, default_value = "7", help = "Log level 0-7")]
    debug: u8,

    #[arg(required = true, trailing_var_arg = true, help = "Command to run")]
    command: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct FileConfig {
    username: Option<String>,
    password: Option<String>,
    ip_whitelist: Option<Vec<String>>,
}

fn sig_name(sig: i32) -> String {
    match sig {
        1 => "SIGHUP".into(),
        2 => "SIGINT".into(),
        3 => "SIGQUIT".into(),
        9 => "SIGKILL".into(),
        15 => "SIGTERM".into(),
        _ => format!("SIG{}", sig),
    }
}

fn load_file_config(path: &str) -> anyhow::Result<FileConfig> {
    let content = std::fs::read_to_string(path)?;
    if path.to_ascii_lowercase().ends_with(".json") {
        Ok(serde_json::from_str(&content)?)
    } else {
        Ok(toml::from_str(&content)?)
    }
}

fn parse_ip_whitelist(items: &[String]) -> anyhow::Result<Vec<IpNet>> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if let Ok(net) = item.parse::<IpNet>() {
            out.push(net);
        } else if let Ok(addr) = item.parse::<IpAddr>() {
            out.push(IpNet::from(addr));
        } else {
            anyhow::bail!("invalid whitelist entry: {item}");
        }
    }
    Ok(out)
}

fn has_cmd(cmd: &str, arg: &str) -> bool {
    std::process::Command::new(cmd)
        .arg(arg)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn detect_lrzsz_support() -> bool {
    has_cmd("rz", "--version") && has_cmd("sz", "--version")
}

fn build_state(
    cli: &Cli,
    credential_raw: Option<String>,
    ip_whitelist: Vec<IpNet>,
    lrzsz_supported: bool,
    audit_logger: Option<Arc<AuditLogger>>,
) -> SharedState {
    let credential = credential_raw.as_ref().map(|c| {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(c.as_bytes())
    });
    let mut prefs: Map<String, Value> = Map::new();
    #[cfg(windows)]
    prefs.insert("isWindows".to_string(), Value::Bool(true));
    for opt in &cli.client_option {
        if let Some((k, v)) = opt.split_once('=') {
            let val: Value = serde_json::from_str(v).unwrap_or(Value::String(v.to_string()));
            prefs.insert(k.to_string(), val);
        } else {
            warn!("invalid client-option: {}", opt);
        }
    }

    let endpoints = if let Some(base) = &cli.base_path {
        let b = base.trim_end_matches('/');
        Endpoints {
            ws: format!("{}/ws", b),
            index: format!("{}/", b),
            login: format!("{}/login", b),
            logout: format!("{}/logout", b),
            parent: b.to_string(),
        }
    } else {
        Endpoints::default()
    };

    Arc::new(ServerState {
        client_count: Mutex::new(0),
        prefs_json: serde_json::to_string(&prefs).unwrap_or_else(|_| "{}".into()),
        credential,
        auth_header: cli.auth_header.clone(),
        index: cli.index.clone(),
        command: cli.command.join(" "),
        argv: cli.command.clone(),
        cwd: cli.cwd.clone(),
        sig_code: cli.signal,
        sig_name: sig_name(cli.signal),
        url_arg: cli.url_arg,
        writable: !cli.readonly,
        check_origin: cli.check_origin,
        max_clients: cli.max_clients,
        once: cli.once,
        exit_no_conn: cli.exit_no_conn,
        terminal_type: cli.terminal_type.clone(),
        ping_interval: cli.ping_interval,
        srv_buf_size: cli.srv_buf_size.max(128),
        lrzsz_supported,
        ws_noise: !cli.disable_ws_noise,
        token_store: std::sync::Mutex::new(std::collections::HashMap::new()),
        login_limiter: std::sync::Mutex::new(std::collections::HashMap::new()),
        tls_enabled: cli.ssl_cert.is_some(),
        audit_logger,
        ip_whitelist,
        endpoints,
        bound_port: std::sync::atomic::AtomicI32::new(0),
    })
}

async fn route_http(
    State(state): State<SharedState>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> impl IntoResponse {
    let client_ip = peer.map(|p| p.0.ip());
    http::handle_request(uri.path().to_string(), headers, state, client_ip).await
}

async fn route_ws(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
    headers: HeaderMap,
    uri: Uri,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> impl IntoResponse {
    let client_ip = peer.map(|p| p.0.ip());
    // ttyd frontend requests Sec-WebSocket-Protocol: tty
    ws::handle_upgrade(
        ws.protocols(["tty", "webtty"]),
        state,
        headers,
        uri,
        client_ip,
    )
}

async fn route_login_get(
    State(state): State<SharedState>,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> impl IntoResponse {
    let client_ip = peer.map(|p| p.0.ip());
    if !state.is_ip_allowed(client_ip) {
        return StatusCode::FORBIDDEN.into_response();
    }
    http::login_page(State(state)).await
}

async fn route_login_post(
    State(state): State<SharedState>,
    peer: Option<ConnectInfo<SocketAddr>>,
    Json(payload): Json<http::LoginRequest>,
) -> impl IntoResponse {
    let client_ip = peer.map(|p| p.0.ip());
    if !state.is_ip_allowed(client_ip) {
        return StatusCode::FORBIDDEN.into_response();
    }
    http::login_submit(State(state), client_ip, Json(payload)).await
}

async fn route_logout_post(
    State(state): State<SharedState>,
    headers: HeaderMap,
    peer: Option<ConnectInfo<SocketAddr>>,
) -> impl IntoResponse {
    let client_ip = peer.map(|p| p.0.ip());
    if !state.is_ip_allowed(client_ip) {
        return StatusCode::FORBIDDEN.into_response();
    }
    http::logout(State(state), headers).await
}

fn make_addr(cli: &Cli) -> anyhow::Result<SocketAddr> {
    let host = match cli.interface.as_deref() {
        Some(i) if i.ends_with(".sock") || i.ends_with(".socket") => "0.0.0.0",
        Some(i) => i,
        None => "0.0.0.0",
    };
    Ok(if cli.ipv6 {
        format!("[::]:{}", cli.port).parse()?
    } else {
        format!("{}:{}", host, cli.port).parse()?
    })
}

async fn shutdown_signal() {
    let ctrl_c = async { tokio::signal::ctrl_c().await.expect("ctrl+c failed") };
    #[cfg(unix)]
    let sigterm = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm failed")
            .recv()
            .await
    };
    #[cfg(not(unix))]
    let sigterm = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = sigterm => {} }
    info!("shutdown signal received");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let file_cfg = if let Some(path) = &cli.config {
        Some(load_file_config(path)?)
    } else {
        None
    };

    let username = cli
        .username
        .clone()
        .or_else(|| file_cfg.as_ref().and_then(|c| c.username.clone()));
    let password = cli
        .password
        .clone()
        .or_else(|| file_cfg.as_ref().and_then(|c| c.password.clone()));

    if (username.is_some() && password.is_none()) || (username.is_none() && password.is_some()) {
        anyhow::bail!("username/password must be provided together");
    }

    let credential_raw = if let Some(c) = cli.credential.clone() {
        Some(c)
    } else {
        username.zip(password).map(|(u, p)| format!("{u}:{p}"))
    };

    let whitelist_items = if !cli.ip_whitelist.is_empty() {
        cli.ip_whitelist.clone()
    } else {
        file_cfg
            .as_ref()
            .and_then(|c| c.ip_whitelist.clone())
            .unwrap_or_default()
    };
    let ip_whitelist = parse_ip_whitelist(&whitelist_items)?;
    let lrzsz_supported = detect_lrzsz_support();

    let log_level = match cli.debug {
        0 => "off",
        1 | 2 => "error",
        3 | 4 => "warn",
        5 | 6 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .init();

    #[cfg(unix)]
    {
        if let Some(gid) = cli.gid {
            unsafe {
                libc::setgid(gid);
            }
        }
        if let Some(uid) = cli.uid {
            unsafe {
                libc::setuid(uid);
            }
        }
    }

    let audit_logger = if let Some(path) = &cli.audit_log {
        Some(Arc::new(AuditLogger::open(std::path::Path::new(path))?))
    } else {
        None
    };

    let state = build_state(
        &cli,
        credential_raw,
        ip_whitelist,
        lrzsz_supported,
        audit_logger,
    );
    info!(
        "ttyd-rs {} | command: {} | signal: {} ({})",
        env!("CARGO_PKG_VERSION"),
        state.command,
        state.sig_name,
        state.sig_code
    );
    if !state.writable {
        warn!("readonly mode (--readonly flag set)");
    }
    if state.lrzsz_supported {
        info!("lrzsz support detected (rz/sz available)");
    }

    let ws_path = state.endpoints.ws.clone();
    let login_path = state.endpoints.login.clone();
    let logout_path = state.endpoints.logout.clone();
    let app = Router::new()
        .route(&ws_path, get(route_ws))
        .route(&login_path, get(route_login_get).post(route_login_post))
        .route(&logout_path, post(route_logout_post))
        .fallback(route_http)
        .with_state(state.clone());

    // UNIX domain socket
    #[cfg(unix)]
    let use_unix = cli
        .interface
        .as_deref()
        .map(|i| i.ends_with(".sock") || i.ends_with(".socket"))
        .unwrap_or(false);
    #[cfg(not(unix))]
    let use_unix = false;

    if use_unix {
        #[cfg(unix)]
        {
            use hyper_util::rt::{TokioExecutor, TokioIo};
            use hyper_util::server::conn::auto::Builder as HyperBuilder;
            use tower::Service;
            let path = cli.interface.as_deref().unwrap();
            let _ = std::fs::remove_file(path);
            let listener = tokio::net::UnixListener::bind(path)?;
            if let Some(owner) = &cli.socket_owner {
                #[cfg(unix)]
                {
                    use std::ffi::CString;
                    let mut parts = owner.split(':');
                    let uid = parts
                        .next()
                        .and_then(|s| s.parse::<u32>().ok())
                        .unwrap_or(u32::MAX);
                    let gid = parts
                        .next()
                        .and_then(|s| s.parse::<u32>().ok())
                        .unwrap_or(u32::MAX);
                    if let Ok(cpath) = CString::new(path) {
                        unsafe {
                            libc::chown(cpath.as_ptr(), uid, gid);
                        }
                    }
                }
            }
            info!("Listening on unix:{}", path);
            if cli.browser {
                let _ = open::that("http://localhost");
            }
            let mut make_service = app.into_make_service();
            let mut shutdown = std::pin::pin!(shutdown_signal());
            loop {
                tokio::select! {
                    _ = &mut shutdown => break,
                    result = listener.accept() => {
                        let (stream, _) = match result { Ok(x) => x, Err(_) => continue };
                        let svc = match make_service.call(()).await {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let hyper_svc = hyper_util::service::TowerToHyperService::new(svc);
                            let _ = HyperBuilder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(io, hyper_svc)
                                .await;
                        });
                    }
                }
            }
        }
    } else if cli.ssl {
        use hyper_util::rt::{TokioExecutor, TokioIo};
        use hyper_util::server::conn::auto::Builder as HyperBuilder;
        use rustls::ServerConfig;
        use std::fs::File;
        use std::io::BufReader;
        use tokio_rustls::TlsAcceptor;
        use tower::Service;

        let cert_path = cli
            .ssl_cert
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--ssl-cert required"))?;
        let key_path = cli
            .ssl_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--ssl-key required"))?;

        let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(cert_path)?))
            .collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key_path)?))?
            .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;

        let mut tls_config = if let Some(ca_path) = &cli.ssl_ca {
            let mut roots = rustls::RootCertStore::empty();
            let ca_certs = rustls_pemfile::certs(&mut BufReader::new(File::open(ca_path)?))
                .collect::<Result<Vec<_>, _>>()?;
            for cert in ca_certs {
                roots.add(cert)?;
            }
            let verifier =
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)?
        } else {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)?
        };
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        let addr = make_addr(&cli)?;
        let tcp = tokio::net::TcpListener::bind(addr).await?;
        let actual = tcp.local_addr()?;
        state
            .bound_port
            .store(actual.port() as i32, Ordering::SeqCst);
        info!("Listening on https://{}", actual);
        if cli.browser {
            let _ = open::that(format!("https://localhost:{}", actual.port()));
        }

        let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();
        let mut shutdown = std::pin::pin!(shutdown_signal());
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                result = tcp.accept() => {
                    let (stream, peer_addr) = match result { Ok(x) => x, Err(_) => continue };
                    let acceptor = acceptor.clone();
                    let svc = match make_service.call(peer_addr).await {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    tokio::spawn(async move {
                        if let Ok(tls_stream) = acceptor.accept(stream).await {
                            let io = TokioIo::new(tls_stream);
                            let hyper_svc = hyper_util::service::TowerToHyperService::new(svc);
                            let _ = HyperBuilder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(io, hyper_svc)
                                .await;
                        }
                    });
                }
            }
        }
    } else {
        let addr = make_addr(&cli)?;
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let actual = listener.local_addr()?;
        state
            .bound_port
            .store(actual.port() as i32, Ordering::SeqCst);
        info!("Listening on http://{}", actual);
        if cli.browser {
            let _ = open::that(format!("http://localhost:{}", actual.port()));
        }
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    }

    Ok(())
}
