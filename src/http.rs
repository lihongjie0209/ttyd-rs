use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::fs;
use tracing::info;

use crate::assets;
use crate::audit::AuditEvent;
use crate::server::{
    LoginAttempts, SharedState, TokenEntry, LOGIN_LOCKOUT_SECS, LOGIN_MAX_ATTEMPTS, TOKEN_TTL_SECS,
};

const SESSION_COOKIE_NAME: &str = "ttyd_session";

#[derive(Serialize)]
struct TokenResponse {
    token: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Extract the raw session token from either `Authorization: Bearer <tok>` or the session cookie.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    // Bearer header takes priority
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(tok) = auth.strip_prefix("Bearer ") {
            return Some(tok.to_string());
        }
    }
    // Fall back to session cookie
    if let Some(cookie) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        if let Some(val) = parse_cookie_value(cookie, SESSION_COOKIE_NAME) {
            return Some(val);
        }
    }
    None
}

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("gzip"))
        .unwrap_or(false)
}

fn login_page_html(state: &SharedState) -> String {
    let login_path = &state.endpoints.login;
    let index_path = &state.endpoints.index;
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ttyd Login</title>
  <style>
    body {{ margin:0; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#111; color:#eee; }}
    .wrap {{ min-height:100vh; display:flex; align-items:center; justify-content:center; }}
    .card {{ width: 320px; background:#1b1b1b; border:1px solid #333; border-radius:8px; padding:20px; }}
    h1 {{ margin:0 0 12px; font-size:20px; }}
    input {{ width:100%; box-sizing:border-box; margin:6px 0; padding:10px; border-radius:6px; border:1px solid #444; background:#0f0f0f; color:#eee; }}
    button {{ width:100%; margin-top:8px; padding:10px; border-radius:6px; border:1px solid #3b6ad9; background:#2b4db1; color:#fff; cursor:pointer; }}
    .err {{ color:#ff8b8b; min-height:18px; margin-top:8px; font-size:13px; }}
  </style>
</head>
<body>
  <div class="wrap">
    <form class="card" id="f">
      <h1>Sign in</h1>
      <input id="u" type="text" placeholder="Username" autocomplete="username" required>
      <input id="p" type="password" placeholder="Password" autocomplete="current-password" required>
      <button type="submit">Login</button>
      <div class="err" id="e"></div>
    </form>
  </div>
  <script>
    const f = document.getElementById('f');
    const e = document.getElementById('e');
    f.addEventListener('submit', async (ev) => {{
      ev.preventDefault();
      e.textContent = '';
      const username = document.getElementById('u').value;
      const password = document.getElementById('p').value;
      const r = await fetch('{login_path}', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ username, password }})
      }});
      if (r.ok) {{
        location.href = '{index_path}';
      }} else {{
        e.textContent = 'Login failed';
      }}
    }});
  </script>
</body>
</html>"#
    )
}

fn parse_cookie_value(cookie_header: &str, key: &str) -> Option<String> {
    for part in cookie_header.split(';') {
        let kv = part.trim();
        if let Some((k, v)) = kv.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Returns Some(username) if authenticated, None if rejected.
pub fn check_auth(headers: &HeaderMap, state: &SharedState) -> Option<String> {
    // Proxy-header auth (e.g. X-Remote-User set by nginx)
    if let Some(auth_header_name) = &state.auth_header {
        let name_lower = auth_header_name.to_lowercase();
        for (k, v) in headers.iter() {
            if k.as_str().to_lowercase() == name_lower {
                return Some(v.to_str().unwrap_or("").to_string());
            }
        }
        return None;
    }

    // Token-based auth
    if state.credential.is_some() {
        let token = match extract_bearer(headers) {
            Some(t) => t,
            None => return None,
        };
        let mut store = state.token_store.lock().unwrap();
        let entry = store.get(&token)?;
        if Instant::now() >= entry.expires_at {
            // Expired: evict and deny
            let token_clone = token.clone();
            store.remove(&token_clone);
            return None;
        }
        return Some(entry.username.clone());
    }

    // No auth configured → allow all
    Some(String::new())
}

pub async fn login_page(State(state): State<SharedState>) -> Response {
    if state.credential.is_none() {
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, &state.endpoints.index)
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap();
    }
    let body = login_page_html(&state);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html;charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap()
}

pub async fn login_submit(
    State(state): State<SharedState>,
    client_ip: Option<IpAddr>,
    Json(req): Json<LoginRequest>,
) -> Response {
    let Some(credential) = state.credential.as_ref() else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap();
    };

    // sec-1: rate-limit check
    if let Some(ip) = client_ip {
        let limiter = state.login_limiter.lock().unwrap();
        if let Some(entry) = limiter.get(&ip) {
            if let Some(locked_until) = entry.locked_until {
                if Instant::now() < locked_until {
                    return Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .body(Body::from("Too many login attempts. Try again later."))
                        .unwrap();
                }
            }
        }
    }

    let expected = STANDARD.encode(format!("{}:{}", req.username, req.password).as_bytes());
    if !bool::from(expected.as_bytes().ct_eq(credential.as_bytes())) {
        // sec-1: increment failure counter
        if let Some(ip) = client_ip {
            let mut limiter = state.login_limiter.lock().unwrap();
            let entry = limiter.entry(ip).or_insert(LoginAttempts { count: 0, locked_until: None });
            entry.count += 1;
            if entry.count >= LOGIN_MAX_ATTEMPTS {
                entry.locked_until =
                    Some(Instant::now() + Duration::from_secs(LOGIN_LOCKOUT_SECS));
            }
        }
        if let Some(logger) = &state.audit_logger {
            logger.log(AuditEvent::new(
                req.username.clone(),
                client_ip.map(|ip| ip.to_string()),
                "login",
                None,
                None,
                false,
                Some("invalid credentials".to_string()),
            ));
        }
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap();
    }

    // sec-1: clear failure counter on success
    if let Some(ip) = client_ip {
        state.login_limiter.lock().unwrap().remove(&ip);
    }

    // sec-2: issue a fresh token with expiry; also prune expired tokens
    let token = {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use rand_core::RngCore;
        let mut raw = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut raw);
        URL_SAFE_NO_PAD.encode(raw)
    };
    let expires_at = Instant::now() + Duration::from_secs(TOKEN_TTL_SECS);
    {
        let mut store = state.token_store.lock().unwrap();
        // Prune expired entries
        let now = Instant::now();
        store.retain(|_, e| e.expires_at > now);
        store.insert(token.clone(), TokenEntry { username: req.username.clone(), expires_at });
    }

    let cookie_path = if state.endpoints.parent.is_empty() {
        "/".to_string()
    } else {
        state.endpoints.parent.clone()
    };
    // sec-4: add Secure flag when running over TLS
    let secure_flag = if state.tls_enabled { "; Secure" } else { "" };
    let cookie = format!(
        "{}={}; Path={}; HttpOnly; SameSite=Lax; Max-Age={}{}",
        SESSION_COOKIE_NAME, token, cookie_path, TOKEN_TTL_SECS, secure_flag
    );

    if let Some(logger) = &state.audit_logger {
        logger.log(AuditEvent::new(
            req.username,
            client_ip.map(|ip| ip.to_string()),
            "login",
            None,
            None,
            true,
            None,
        ));
    }
    let body = serde_json::to_string(&TokenResponse { token }).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap()
}

/// sec-3: Logout — revoke the current session token and clear the cookie.
pub async fn logout(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    if let Some(token) = extract_bearer(&headers) {
        state.token_store.lock().unwrap().remove(&token);
    }
    let cookie_path = if state.endpoints.parent.is_empty() {
        "/".to_string()
    } else {
        state.endpoints.parent.clone()
    };
    let clear_cookie = format!(
        "{}=; Path={}; HttpOnly; SameSite=Lax; Max-Age=0",
        SESSION_COOKIE_NAME, cookie_path
    );
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::SET_COOKIE, clear_cookie)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

fn unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

fn proxy_auth_required() -> Response {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

fn forbidden() -> Response {
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

pub async fn handle_request(
    path: String,
    headers: HeaderMap,
    state: SharedState,
    client_ip: Option<IpAddr>,
) -> Response {
    info!("HTTP {}", path);
    let ep = &state.endpoints;

    if !state.is_ip_allowed(client_ip) {
        return forbidden();
    }

    if check_auth(&headers, &state).is_none() {
        if state.credential.is_some() && (path == ep.index || path == ep.parent) {
            let body = login_page_html(&state);
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html;charset=utf-8")
                .header(header::CACHE_CONTROL, "no-store")
                .header(header::CONTENT_LENGTH, body.len().to_string())
                .body(Body::from(body))
                .unwrap();
        }
        return if state.auth_header.is_some() {
            proxy_auth_required()
        } else {
            unauthorized()
        };
    }

    if !ep.parent.is_empty() && path == ep.parent {
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, &ep.index)
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap();
    }

    if path == ep.index {
        if let Some(index_path) = &state.index {
            match fs::read(index_path).await {
                Ok(bytes) => {
                    return Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/html")
                        .header(header::CONTENT_LENGTH, bytes.len().to_string())
                        .body(Body::from(bytes))
                        .unwrap();
                }
                Err(e) => {
                    tracing::error!("failed to read custom index: {}", e);
                    return Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap();
                }
            }
        }

        if accepts_gzip(&headers) {
            let gz = assets::INDEX_HTML_GZ;
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html")
                .header(header::CONTENT_ENCODING, "gzip")
                .header(header::CONTENT_LENGTH, gz.len().to_string())
                .body(Body::from(gz))
                .unwrap();
        } else {
            let html = assets::decompress_html();
            return Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/html")
                .header(header::CONTENT_LENGTH, html.len().to_string())
                .body(Body::from(html))
                .unwrap();
        }
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::empty())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{Endpoints, ServerState};
    use axum::body::to_bytes;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::collections::HashMap;
    use std::sync::atomic::AtomicI32;
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::Mutex;

    fn test_state() -> SharedState {
        Arc::new(ServerState {
            client_count: Mutex::new(0),
            prefs_json: "{}".to_string(),
            credential: None,
            auth_header: None,
            index: None,
            command: "cmd".to_string(),
            argv: vec!["cmd".to_string()],
            cwd: None,
            sig_code: 15,
            sig_name: "SIGTERM".to_string(),
            url_arg: false,
            writable: false,
            check_origin: false,
            max_clients: 0,
            once: false,
            exit_no_conn: false,
            terminal_type: "xterm-256color".to_string(),
            ping_interval: 5,
            srv_buf_size: 4096,
            lrzsz_supported: false,
            ws_noise: false,
            token_store: StdMutex::new(HashMap::new()),
            login_limiter: StdMutex::new(HashMap::new()),
            tls_enabled: false,
            audit_logger: None,
            ip_whitelist: vec![],
            endpoints: Endpoints::default(),
            bound_port: AtomicI32::new(0),
        })
    }

    /// Insert a live token into the token store for testing.
    fn insert_token(state: &SharedState, token: &str, username: &str) {
        let expires_at =
            std::time::Instant::now() + std::time::Duration::from_secs(TOKEN_TTL_SECS);
        state
            .token_store
            .lock()
            .unwrap()
            .insert(token.to_string(), TokenEntry { username: username.to_string(), expires_at });
    }

    #[test]
    fn auth_accepts_valid_bearer() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        insert_token(&state, "mytoken123", "u");
        headers.insert(header::AUTHORIZATION, "Bearer mytoken123".parse().unwrap());
        assert!(check_auth(&headers, &state).is_some());
    }

    #[test]
    fn auth_rejects_invalid_bearer() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        insert_token(&state, "mytoken123", "u");
        headers.insert(header::AUTHORIZATION, "Bearer wrongtoken".parse().unwrap());
        assert!(check_auth(&headers, &state).is_none());
    }

    #[test]
    fn auth_rejects_basic_header() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        insert_token(&state, "mytoken123", "u");
        // Basic auth should no longer be accepted
        headers.insert(header::AUTHORIZATION, "Basic dTpw".parse().unwrap());
        assert!(check_auth(&headers, &state).is_none());
    }

    #[test]
    fn auth_accepts_session_cookie() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        insert_token(&state, "cookietoken", "u");
        headers.insert(header::COOKIE, "ttyd_session=cookietoken".parse().unwrap());
        assert!(check_auth(&headers, &state).is_some());
    }

    #[test]
    fn auth_rejects_expired_token() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        // Insert already-expired token
        let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
        state.token_store.lock().unwrap().insert(
            "expiredtoken".to_string(),
            TokenEntry { username: "u".to_string(), expires_at: past },
        );
        headers.insert(header::AUTHORIZATION, "Bearer expiredtoken".parse().unwrap());
        assert!(check_auth(&headers, &state).is_none());
    }

    #[test]
    fn auth_accepts_proxy_header() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().auth_header = Some("X-Auth-User".to_string());
        headers.insert("X-Auth-User", "alice".parse().unwrap());
        assert_eq!(check_auth(&headers, &state).as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn token_endpoint_not_exposed_over_http() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        insert_token(&state, "tok", "u");
        headers.insert(header::AUTHORIZATION, "Bearer tok".parse().unwrap());
        let resp = handle_request("/token".to_string(), headers, state, None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn base_path_redirects_to_index() {
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().endpoints = Endpoints {
            ws: "/base/ws".to_string(),
            index: "/base/".to_string(),
            login: "/base/login".to_string(),
            logout: "/base/logout".to_string(),
            parent: "/base".to_string(),
        };
        let resp = handle_request("/base".to_string(), HeaderMap::new(), state, None).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/base/");
    }

    #[tokio::test]
    async fn unauthenticated_request_shows_login_page() {
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        let resp = handle_request("/".to_string(), HeaderMap::new(), state, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("Sign in"));
    }

    #[tokio::test]
    async fn missing_proxy_auth_returns_407() {
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().auth_header = Some("X-Auth-User".to_string());
        let resp = handle_request("/".to_string(), HeaderMap::new(), state, None).await;
        assert_eq!(resp.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }

    #[tokio::test]
    async fn embedded_index_respects_gzip_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_ENCODING, "gzip, deflate".parse().unwrap());
        let resp = handle_request("/".to_string(), headers, test_state(), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
    }

    #[tokio::test]
    async fn embedded_index_without_gzip_is_plain_html() {
        let resp = handle_request("/".to_string(), HeaderMap::new(), test_state(), None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(header::CONTENT_ENCODING).is_none());
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("<html") || text.contains("<!doctype html"));
    }

    #[tokio::test]
    async fn custom_index_file_is_served() {
        let temp = std::env::temp_dir().join("ttyd-rs-http-test-index.html");
        tokio::fs::write(&temp, "<html>custom</html>")
            .await
            .unwrap();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().index = Some(temp.to_string_lossy().to_string());
        let resp = handle_request("/".to_string(), HeaderMap::new(), state, None).await;
        let _ = tokio::fs::remove_file(temp).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, "<html>custom</html>");
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let resp = handle_request("/nope".to_string(), HeaderMap::new(), test_state(), None).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn ip_not_in_whitelist_is_forbidden() {
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().ip_whitelist = vec!["10.0.0.0/8".parse().unwrap()];
        let resp = handle_request(
            "/".to_string(),
            HeaderMap::new(),
            state,
            Some("192.168.1.3".parse().unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
