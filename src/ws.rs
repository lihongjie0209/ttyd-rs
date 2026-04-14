use axum::{
    extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use std::net::IpAddr;
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::http::check_auth;
use crate::noise::{
    responder_handshake, NoiseReceiver, NoiseSender, NOISE_CLIENT_HELLO, NOISE_DATA,
    NOISE_SERVER_HELLO,
};
use crate::pty::{spawn_pty, PtyCommand, PtyEvent};
use crate::server::SharedState;

// ttyd protocol byte constants
const CMD_INPUT: u8 = b'0';
const CMD_RESIZE: u8 = b'1';
const CMD_PAUSE: u8 = b'2';
const CMD_RESUME: u8 = b'3';
const CMD_JSON_DATA: u8 = b'{';

const SRV_OUTPUT: u8 = b'0';
const SRV_SET_TITLE: u8 = b'1';
const SRV_SET_PREFS: u8 = b'2';
const MAX_WS_FRAME_SIZE: usize = 1024 * 1024;
const MAX_WS_INPUT_SIZE: usize = 64 * 1024;
const MAX_WS_JSON_SIZE: usize = 8 * 1024;
const MAX_WS_FRAMES_PER_SEC: u32 = 500;

fn to_bytes(msg: Message) -> Option<Vec<u8>> {
    match msg {
        Message::Binary(b) => Some(b.to_vec()),
        Message::Text(t) => Some(t.into_bytes()),
        Message::Ping(_) | Message::Pong(_) => Some(Vec::new()),
        Message::Close(_) => None,
    }
}

fn encode_ws_binary(
    payload: Vec<u8>,
    noise_tx: &mut Option<NoiseSender>,
) -> Result<Vec<u8>, String> {
    if let Some(tx) = noise_tx.as_mut() {
        let mut out = Vec::with_capacity(1 + payload.len() + 16);
        out.push(NOISE_DATA);
        out.extend_from_slice(&tx.encrypt(&payload)?);
        Ok(out)
    } else {
        Ok(payload)
    }
}

async fn negotiate_noise(
    ws_tx: &mut SplitSink<WebSocket, Message>,
    ws_rx: &mut SplitStream<WebSocket>,
) -> Result<(Option<NoiseSender>, Option<NoiseReceiver>), String> {
    let Some(msg_result) = ws_rx.next().await else {
        return Err("missing noise client hello".to_string());
    };
    let data = to_bytes(msg_result.map_err(|_| "invalid websocket frame".to_string())?)
        .ok_or_else(|| "websocket closed before noise handshake".to_string())?;
    if data.is_empty() {
        return Err("empty noise client hello".to_string());
    }
    if data[0] != NOISE_CLIENT_HELLO || data.len() != 33 {
        return Err("invalid noise client hello".to_string());
    }
    let (server_hello, tx, rx) = responder_handshake(&data[1..])?;
    let mut out = Vec::with_capacity(1 + server_hello.len());
    out.push(NOISE_SERVER_HELLO);
    out.extend_from_slice(&server_hello);
    ws_tx
        .send(Message::Binary(out.into()))
        .await
        .map_err(|_| "failed to send noise server hello".to_string())?;
    Ok((Some(tx), Some(rx)))
}

fn extract_host_from_origin(origin: &str) -> &str {
    let s = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin);
    s.split('/').next().unwrap_or(s)
}

fn normalize_host_port(host: &str) -> String {
    let h = host.trim().to_ascii_lowercase();
    if let Some(stripped) = h.strip_suffix(":80") {
        return stripped.to_string();
    }
    if let Some(stripped) = h.strip_suffix(":443") {
        return stripped.to_string();
    }
    h
}

fn extract_url_args(query: Option<&str>, enabled: bool) -> Vec<String> {
    if !enabled {
        return vec![];
    }
    query
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| {
            let mut it = kv.splitn(2, '=');
            let k = it.next()?;
            let v = it.next()?;
            if k == "arg" {
                Some(v.to_string())
            } else {
                None
            }
        })
        .collect()
}

pub fn handle_upgrade(
    ws: WebSocketUpgrade,
    state: SharedState,
    headers: HeaderMap,
    uri: Uri,
    client_ip: Option<IpAddr>,
) -> impl IntoResponse {
    if !state.is_ip_allowed(client_ip) {
        return StatusCode::FORBIDDEN.into_response();
    }

    // Auth check
    let auth_user = if let Some(user) = check_auth(&headers, &state) {
        user
    } else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // Origin check
    if state.check_origin {
        let origin = headers
            .get(axum::http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let host = headers
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !origin.is_empty() {
            let origin_host = extract_host_from_origin(origin);
            if normalize_host_port(origin_host) != normalize_host_port(host) {
                warn!("refusing WS from different origin: {}", origin);
                return StatusCode::FORBIDDEN.into_response();
            }
        }
    }

    // URL args (?arg=foo&arg=bar)
    let url_args = extract_url_args(uri.query(), state.url_arg);

    ws.on_upgrade(move |socket| handle_socket(socket, state, url_args, auth_user))
}

async fn handle_socket(
    socket: WebSocket,
    state: SharedState,
    url_args: Vec<String>,
    auth_user: String,
) {
    // Check once / max_clients
    {
        let count = *state.client_count.lock().await;
        if state.once && count > 0 {
            warn!("refusing WS due to --once");
            return;
        }
        if state.max_clients > 0 && count >= state.max_clients {
            warn!("refusing WS due to --max-clients");
            return;
        }
        // increment
        *state.client_count.lock().await += 1;
        info!("WS connected, clients: {}", count + 1);
    }

    let (mut ws_tx, mut ws_rx) = socket.split();

    let (mut noise_tx, mut noise_rx) = if state.ws_noise {
        match negotiate_noise(&mut ws_tx, &mut ws_rx).await {
            Ok(ctx) => ctx,
            Err(e) => {
                warn!("noise handshake failed: {}", e);
                cleanup(&state).await;
                return;
            }
        }
    } else {
        (None, None)
    };

    // Send SET_WINDOW_TITLE
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "localhost".into());
    let mut title_bytes = vec![SRV_SET_TITLE];
    title_bytes.extend_from_slice(format!("{} ({})", state.command, hostname).as_bytes());
    let title_wire = match encode_ws_binary(title_bytes, &mut noise_tx) {
        Ok(v) => v,
        Err(e) => {
            warn!("noise encode title failed: {}", e);
            cleanup(&state).await;
            return;
        }
    };
    if ws_tx
        .send(Message::Binary(title_wire.into()))
        .await
        .is_err()
    {
        cleanup(&state).await;
        return;
    }

    // Send SET_PREFERENCES
    let mut prefs_bytes = vec![SRV_SET_PREFS];
    prefs_bytes.extend_from_slice(state.prefs_json.as_bytes());
    let prefs_wire = match encode_ws_binary(prefs_bytes, &mut noise_tx) {
        Ok(v) => v,
        Err(e) => {
            warn!("noise encode prefs failed: {}", e);
            cleanup(&state).await;
            return;
        }
    };
    if ws_tx
        .send(Message::Binary(prefs_wire.into()))
        .await
        .is_err()
    {
        cleanup(&state).await;
        return;
    }

    // Channel: PTY events -> WS output task
    let (pty_event_tx, mut pty_event_rx) = mpsc::channel::<PtyEvent>(256);

    // Spawn output forwarding task
    let state_for_output = state.clone();
    let mut noise_tx_for_output = noise_tx;
    let output_task = tokio::spawn(async move {
        let mut ping = tokio::time::interval(std::time::Duration::from_secs(
            state_for_output.ping_interval.max(1),
        ));
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    if ws_tx.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
                maybe_event = pty_event_rx.recv() => {
                    let Some(event) = maybe_event else { break };
                    match event {
                        PtyEvent::Output(data) => {
                            let mut msg = Vec::with_capacity(1 + data.len());
                            msg.push(SRV_OUTPUT);
                            msg.extend_from_slice(&data);
                            let wire = match encode_ws_binary(msg, &mut noise_tx_for_output) {
                                Ok(v) => v,
                                Err(_) => break,
                            };
                            if ws_tx.send(Message::Binary(wire.into())).await.is_err() {
                                break;
                            }
                        }
                        PtyEvent::Exit(code) => {
                            let close_code = if code == 0 { 1000u16 } else { 1006 };
                            let _ = ws_tx
                                .send(Message::Close(Some(CloseFrame {
                                    code: close_code,
                                    reason: "process exited".into(),
                                })))
                                .await;
                            break;
                        }
                    }
                }
            }
        }
        cleanup(&state_for_output).await;
    });

    // Receive loop
    let mut pty_handle: Option<crate::pty::PtyHandle> = None;
    let mut authenticated = state.credential.is_none();
    let mut lrzsz_notice_sent = false;
    let mut frame_count: u32 = 0;
    let mut frame_window_start = Instant::now();

    'recv: while let Some(msg_result) = ws_rx.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(_) => break,
        };
        let mut data = match to_bytes(msg) {
            Some(v) => v,
            None => break,
        };
        if data.is_empty() {
            continue;
        }
        if data.len() > MAX_WS_FRAME_SIZE {
            warn!("ws frame too large: {}", data.len());
            break;
        }
        if let Some(rx) = noise_rx.as_mut() {
            if data[0] != NOISE_DATA || data.len() < 2 {
                warn!("invalid encrypted ws frame");
                break;
            }
            data = match rx.decrypt(&data[1..]) {
                Ok(v) => v,
                Err(e) => {
                    warn!("noise decrypt failed: {}", e);
                    break;
                }
            };
            if data.is_empty() {
                continue;
            }
        }
        if data.len() > MAX_WS_FRAME_SIZE {
            warn!("decrypted ws frame too large: {}", data.len());
            break;
        }
        if frame_window_start.elapsed() >= Duration::from_secs(1) {
            frame_window_start = Instant::now();
            frame_count = 0;
        }
        frame_count = frame_count.saturating_add(1);
        if frame_count > MAX_WS_FRAMES_PER_SEC {
            warn!("ws frame rate exceeded");
            break;
        }

        let cmd = data[0];
        if cmd == CMD_INPUT && data.len() > (1 + MAX_WS_INPUT_SIZE) {
            warn!("ws input payload too large");
            break;
        }
        if (cmd == CMD_RESIZE || cmd == CMD_JSON_DATA) && data.len() > (1 + MAX_WS_JSON_SIZE) {
            warn!("ws json payload too large");
            break;
        }

        if state.credential.is_some() && !authenticated && cmd != CMD_JSON_DATA {
            warn!("WS client not authenticated");
            break;
        }

        match cmd {
            CMD_INPUT => {
                if state.writable {
                    if let Some(h) = &pty_handle {
                        let _ = h.cmd_tx.send(PtyCommand::Input(data[1..].to_vec())).await;
                    }
                }
            }
            CMD_RESIZE => {
                if let Some(h) = &pty_handle {
                    let json = std::str::from_utf8(&data[1..]).unwrap_or("{}");
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
                        let cols = v["columns"].as_u64().unwrap_or(80) as u16;
                        let rows = v["rows"].as_u64().unwrap_or(24) as u16;
                        let _ = h.cmd_tx.send(PtyCommand::Resize { cols, rows }).await;
                    }
                }
            }
            CMD_PAUSE => {
                if let Some(h) = &pty_handle {
                    let _ = h.cmd_tx.send(PtyCommand::Pause).await;
                }
            }
            CMD_RESUME => {
                if let Some(h) = &pty_handle {
                    let _ = h.cmd_tx.send(PtyCommand::Resume).await;
                }
            }
            CMD_JSON_DATA => {
                let json = std::str::from_utf8(&data).unwrap_or("{}");
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
                    if let Some(credential) = &state.credential {
                        let token = v["AuthToken"].as_str().unwrap_or("");
                        if credential.as_bytes().ct_eq(token.as_bytes()).into() {
                            authenticated = true;
                        } else {
                            warn!("WS auth failed");
                            break 'recv;
                        }
                    }

                    if pty_handle.is_none() {
                        let cols = v["columns"].as_u64().unwrap_or(80) as u16;
                        let rows = v["rows"].as_u64().unwrap_or(24) as u16;

                        let mut argv = state.argv.clone();
                        argv.extend(url_args.iter().cloned());

                        let mut envp = vec![("TERM".to_string(), state.terminal_type.clone())];
                        if !auth_user.is_empty() {
                            envp.push(("TTYD_USER".to_string(), auth_user.clone()));
                        }

                        match spawn_pty(
                            argv,
                            envp,
                            state.cwd.clone(),
                            cols,
                            rows,
                            state.srv_buf_size,
                            pty_event_tx.clone(),
                        ) {
                            Ok(handle) => {
                                pty_handle = Some(handle);
                                if state.lrzsz_supported && !lrzsz_notice_sent {
                                    lrzsz_notice_sent = true;
                                    let notice = b"\r\n[ttyd] Server supports lrzsz (rz/sz) file transfer.\r\n";
                                    let _ =
                                        pty_event_tx.send(PtyEvent::Output(notice.to_vec())).await;
                                }
                            }
                            Err(e) => {
                                warn!("spawn_pty failed: {}", e);
                                break 'recv;
                            }
                        }
                    }
                }
            }
            _ => {
                warn!("unknown WS cmd: {:?}", cmd as char);
                break 'recv;
            }
        }
    }

    if let Some(h) = pty_handle {
        let _ = h
            .cmd_tx
            .send(PtyCommand::Kill {
                sig_code: state.sig_code,
            })
            .await;
    }
    output_task.abort();
    cleanup(&state).await;
}

async fn cleanup(state: &SharedState) {
    let count = {
        let mut c = state.client_count.lock().await;
        *c = (*c - 1).max(0);
        *c
    };
    info!("WS closed, clients: {}", count);
    if (state.once || state.exit_no_conn) && count == 0 {
        info!("exiting due to --once/--exit-no-conn");
        std::process::exit(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_port_strips_default_ports() {
        assert_eq!(normalize_host_port("example.com:80"), "example.com");
        assert_eq!(normalize_host_port("Example.COM:443"), "example.com");
        assert_eq!(normalize_host_port("example.com:8443"), "example.com:8443");
    }

    #[test]
    fn extract_host_from_origin_handles_scheme_and_path() {
        assert_eq!(
            extract_host_from_origin("https://example.com/path"),
            "example.com"
        );
        assert_eq!(
            extract_host_from_origin("http://example.com:8080/a"),
            "example.com:8080"
        );
        assert_eq!(
            extract_host_from_origin("example.com:9000"),
            "example.com:9000"
        );
    }

    #[test]
    fn extract_url_args_filters_arg_keys() {
        let args = extract_url_args(Some("arg=foo&x=1&arg=bar"), true);
        assert_eq!(args, vec!["foo".to_string(), "bar".to_string()]);
        assert!(extract_url_args(Some("arg=foo"), false).is_empty());
    }
}
