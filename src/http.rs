use axum::{
    body::Body,
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use std::net::IpAddr;
use tokio::fs;
use tracing::info;

use crate::assets;
use crate::server::SharedState;

fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("gzip"))
        .unwrap_or(false)
}

/// Returns Some(username) if authenticated, None if rejected.
pub fn check_auth(headers: &HeaderMap, state: &SharedState) -> Option<String> {
    if let Some(auth_header_name) = &state.auth_header {
        let name_lower = auth_header_name.to_lowercase();
        for (k, v) in headers.iter() {
            if k.as_str().to_lowercase() == name_lower {
                return Some(v.to_str().unwrap_or("").to_string());
            }
        }
        return None;
    }
    if let Some(credential) = &state.credential {
        let auth_value = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if auth_value.len() > 6
            && auth_value.starts_with("Basic ")
            && &auth_value[6..] == credential
        {
            return Some(String::new());
        }
        return None;
    }
    Some(String::new())
}

fn unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, r#"Basic realm="ttyd""#)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .unwrap()
}

fn proxy_auth_required() -> Response {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(header::PROXY_AUTHENTICATE, r#"Basic realm="ttyd""#)
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

    if !state.is_ip_allowed(client_ip) {
        return forbidden();
    }

    if check_auth(&headers, &state).is_none() {
        return if state.auth_header.is_some() {
            proxy_auth_required()
        } else {
            unauthorized()
        };
    }

    let ep = &state.endpoints;

    if path == ep.token {
        let cred = state.credential.as_deref().unwrap_or("");
        let body = format!(
            r#"{{"token": "{}", "ws_noise": {}}}"#,
            cred,
            if state.ws_noise { "true" } else { "false" }
        );
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json;charset=utf-8")
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body))
            .unwrap();
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
    use std::sync::atomic::AtomicI32;
    use std::sync::Arc;
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
            ip_whitelist: vec![],
            endpoints: Endpoints::default(),
            bound_port: AtomicI32::new(0),
        })
    }

    #[test]
    fn auth_accepts_valid_basic() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        headers.insert(header::AUTHORIZATION, "Basic dTpw".parse().unwrap());
        assert!(check_auth(&headers, &state).is_some());
    }

    #[test]
    fn auth_rejects_invalid_basic() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some(STANDARD.encode("u:p"));
        headers.insert(header::AUTHORIZATION, "Basic invalid".parse().unwrap());
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
    async fn token_endpoint_returns_credential() {
        let mut headers = HeaderMap::new();
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some("abc".to_string());
        headers.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        let resp = handle_request("/token".to_string(), headers, state, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body, r#"{"token": "abc", "ws_noise": false}"#);
    }

    #[tokio::test]
    async fn base_path_redirects_to_index() {
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().endpoints = Endpoints {
            ws: "/base/ws".to_string(),
            index: "/base/".to_string(),
            token: "/base/token".to_string(),
            parent: "/base".to_string(),
        };
        let resp = handle_request("/base".to_string(), HeaderMap::new(), state, None).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/base/");
    }

    #[tokio::test]
    async fn missing_basic_auth_returns_401() {
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().credential = Some("abc".to_string());
        let resp = handle_request("/".to_string(), HeaderMap::new(), state, None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn missing_proxy_auth_returns_407() {
        let mut state = test_state();
        Arc::get_mut(&mut state).unwrap().auth_header = Some("X-Auth-User".to_string());
        let resp = handle_request("/".to_string(), HeaderMap::new(), state, None).await;
        assert_eq!(resp.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);
        assert!(resp.headers().contains_key(header::PROXY_AUTHENTICATE));
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
