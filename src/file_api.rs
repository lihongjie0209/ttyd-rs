#![allow(dead_code)]

use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use async_compression::tokio::bufread::GzipEncoder;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::fs;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio_util::io::ReaderStream;

use crate::{audit::AuditEvent, http::check_auth, server::{DownloadTokenEntry, SharedState, DOWNLOAD_TOKEN_TTL_SECS}};

const MAX_RPC_FILE_BYTES: usize = 8 * 1024 * 1024;
/// Files above this size (50 MB) are offered gzip compression on the frontend
pub const LARGE_FILE_THRESHOLD: u64 = 50 * 1024 * 1024;

#[derive(Serialize)]
pub struct ApiResponse<T>
where
    T: Serialize,
{
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl<T> ApiResponse<T>
where
    T: Serialize,
{
    fn ok(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error: None,
        }
    }
}

impl ApiResponse<()> {
    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub path: Option<String>,
}

#[derive(Serialize)]
pub struct ListResult {
    pub entries: Vec<FileEntry>,
}

#[derive(Serialize, Clone)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
}

#[derive(Deserialize)]
pub struct CreateRequest {
    pub path: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct RenameRequest {
    pub path: String,
    pub new_name: String,
}

#[derive(Deserialize)]
pub struct DeleteRequest {
    pub path: String,
}

fn unauthorized_status(state: &SharedState) -> StatusCode {
    if state.auth_header.is_some() {
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    } else {
        StatusCode::UNAUTHORIZED
    }
}

fn current_ip(client: Option<ConnectInfo<SocketAddr>>) -> Option<IpAddr> {
    client.map(|c| c.ip())
}

fn ip_text(ip: Option<IpAddr>) -> Option<String> {
    ip.map(|x| x.to_string())
}

fn actor_text(actor: &str) -> String {
    if actor.is_empty() {
        "anonymous".to_string()
    } else {
        actor.to_string()
    }
}

fn audit_log(
    state: &SharedState,
    actor: &str,
    ip: Option<IpAddr>,
    action: &str,
    target: Option<String>,
    success: bool,
    message: Option<String>,
) {
    if let Some(logger) = &state.audit_logger {
        logger.log(AuditEvent::new(
            actor_text(actor),
            ip_text(ip),
            action,
            None,
            target,
            success,
            message,
        ));
    }
}

fn ensure_allowed(
    state: &SharedState,
    headers: &HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
) -> Result<(String, Option<IpAddr>), (StatusCode, Json<ApiResponse<()>>)> {
    let ip = current_ip(client);
    if let Some(addr) = ip {
        if !state.is_ip_allowed(Some(addr)) {
            audit_log(
                state,
                "anonymous",
                ip,
                "file_api_auth",
                None,
                false,
                Some("forbidden: ip not in whitelist".to_string()),
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiResponse::err("forbidden: ip not in whitelist")),
            ));
        }
    }
    let Some(actor) = check_auth(headers, state) else {
        audit_log(
            state,
            "anonymous",
            ip,
            "file_api_auth",
            None,
            false,
            Some("authentication required".to_string()),
        );
        return Err((
            unauthorized_status(state),
            Json(ApiResponse::err("authentication required")),
        ));
    };
    Ok((actor, ip))
}

fn root_dir(state: &SharedState) -> Result<PathBuf, String> {
    if let Some(cwd) = &state.cwd {
        Ok(PathBuf::from(cwd))
    } else {
        std::env::current_dir().map_err(|e| format!("resolve current dir failed: {e}"))
    }
}

fn canonical_root_dir(state: &SharedState) -> Result<PathBuf, String> {
    let root = root_dir(state)?;
    std::fs::canonicalize(&root).map_err(|e| format!("resolve root dir failed: {e}"))
}

fn normalize_rel_path(raw: &str) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for c in Path::new(raw).components() {
        match c {
            Component::CurDir => {}
            Component::Normal(seg) => out.push(seg),
            Component::ParentDir => return Err("path traversal is not allowed".to_string()),
            Component::RootDir | Component::Prefix(_) => {
                return Err("absolute path is not allowed".to_string());
            }
        }
    }
    Ok(out)
}

fn sanitize_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("name cannot be empty".to_string());
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        return Err("name cannot contain path separators".to_string());
    }
    if trimmed == "." || trimmed == ".." {
        return Err("invalid name".to_string());
    }
    Ok(trimmed.to_string())
}

fn rel_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn join_rel(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn resolve_target(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let clean = normalize_rel_path(rel)?;
    Ok(root.join(clean))
}

fn canonicalize_in_root(root: &Path, target: &Path) -> Result<PathBuf, String> {
    let canonical =
        std::fs::canonicalize(target).map_err(|e| format!("resolve path failed: {e}"))?;
    if !canonical.starts_with(root) {
        return Err("path escapes root directory".to_string());
    }
    Ok(canonical)
}

fn download_name(rel: &str, is_dir: bool) -> String {
    let base = rel.rsplit('/').next().unwrap_or("").trim();
    let safe = if base.is_empty() { "download" } else { base };
    if is_dir {
        format!("{safe}.tar.gz")
    } else {
        safe.to_string()
    }
}

/// A `std::io::Write` adapter that forwards bytes to a tokio `DuplexStream`
/// by blocking on the current tokio runtime handle.
/// Must only be used inside `spawn_blocking`.
struct SyncDuplexWriter {
    inner: tokio::io::DuplexStream,
    handle: tokio::runtime::Handle,
}

impl std::io::Write for SyncDuplexWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.handle
            .block_on(self.inner.write_all(buf))
            .map(|_| buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn make_temp_zip_path() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("ttyd-rs-download-{}-{millis}.zip", std::process::id()))
}

#[allow(dead_code)]

async fn list_entries(root: &Path, rel_path: &str) -> Result<Vec<FileEntry>, String> {
    let dir_path = resolve_target(root, rel_path)?;
    let meta = fs::metadata(&dir_path)
        .await
        .map_err(|e| format!("stat path failed: {e}"))?;
    if !meta.is_dir() {
        return Err("target is not a directory".to_string());
    }

    let mut rd = fs::read_dir(&dir_path)
        .await
        .map_err(|e| format!("read directory failed: {e}"))?;
    let mut entries = Vec::new();
    while let Some(entry) = rd
        .next_entry()
        .await
        .map_err(|e| format!("read directory entry failed: {e}"))?
    {
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry
            .metadata()
            .await
            .map_err(|e| format!("read metadata failed: {e}"))?;
        let is_dir = meta.is_dir();
        let size = if is_dir { 0 } else { meta.len() };
        entries.push(FileEntry {
            path: join_rel(rel_path, &name),
            name,
            is_dir,
            size,
        });
    }
    entries.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });
    Ok(entries)
}

pub async fn handle_ws_rpc(
    state: &SharedState,
    actor: &str,
    ip: Option<IpAddr>,
    method: &str,
    params: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    match method {
        "file.list" => {
            let root = canonical_root_dir(state)?;
            let rel = params
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let rel_norm = normalize_rel_path(&rel)?;
            let rel_s = rel_to_string(&rel_norm);
            let entries = list_entries(&root, &rel_s).await?;
            audit_log(
                state,
                actor,
                ip,
                "file_list",
                Some(rel_s),
                true,
                Some(format!("entries={}", entries.len())),
            );
            Ok(serde_json::json!({ "entries": entries }))
        }
        "file.mkdir" => {
            let root = canonical_root_dir(state)?;
            let parent_rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            let name = sanitize_name(
                params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?;
            let parent_target = resolve_target(&root, &parent_rel)?;
            let parent_canonical = canonicalize_in_root(&root, &parent_target)?;
            let parent_meta = std::fs::metadata(&parent_canonical)
                .map_err(|e| format!("stat parent failed: {e}"))?;
            if !parent_meta.is_dir() {
                return Err("parent is not a directory".to_string());
            }
            let target_rel = join_rel(&parent_rel, &name);
            let target = parent_canonical.join(&name);
            let _ = resolve_target(&root, &target_rel)?;
            fs::create_dir(&target)
                .await
                .map_err(|e| format!("mkdir failed: {e}"))?;
            audit_log(
                state,
                actor,
                ip,
                "file_mkdir",
                Some(target_rel.clone()),
                true,
                None,
            );
            Ok(serde_json::json!({ "path": target_rel }))
        }
        "file.new-file" => {
            let root = canonical_root_dir(state)?;
            let parent_rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            let name = sanitize_name(
                params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?;
            let parent_target = resolve_target(&root, &parent_rel)?;
            let parent_canonical = canonicalize_in_root(&root, &parent_target)?;
            let parent_meta = std::fs::metadata(&parent_canonical)
                .map_err(|e| format!("stat parent failed: {e}"))?;
            if !parent_meta.is_dir() {
                return Err("parent is not a directory".to_string());
            }
            let target_rel = join_rel(&parent_rel, &name);
            let target = parent_canonical.join(&name);
            let _ = resolve_target(&root, &target_rel)?;
            fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(target)
                .await
                .map_err(|e| format!("create file failed: {e}"))?;
            audit_log(
                state,
                actor,
                ip,
                "file_new",
                Some(target_rel.clone()),
                true,
                None,
            );
            Ok(serde_json::json!({ "path": target_rel }))
        }
        "file.rename" => {
            let root = canonical_root_dir(state)?;
            let src_rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            if src_rel.is_empty() {
                return Err("cannot rename root".to_string());
            }
            let new_name = sanitize_name(
                params
                    .get("new_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?;
            let parent_rel = src_rel
                .rsplit_once('/')
                .map(|(parent, _)| parent.to_string())
                .unwrap_or_default();
            let dst_rel = join_rel(&parent_rel, &new_name);
            let src = resolve_target(&root, &src_rel)?;
            let src_canonical = canonicalize_in_root(&root, &src)?;
            let dst_parent_target = resolve_target(&root, &parent_rel)?;
            let dst_parent_canonical = canonicalize_in_root(&root, &dst_parent_target)?;
            let dst = dst_parent_canonical.join(&new_name);
            let _ = resolve_target(&root, &dst_rel)?;
            fs::rename(src_canonical, dst)
                .await
                .map_err(|e| format!("rename failed: {e}"))?;
            audit_log(
                state,
                actor,
                ip,
                "file_rename",
                Some(src_rel),
                true,
                Some(format!("new_path={dst_rel}")),
            );
            Ok(serde_json::json!({ "path": dst_rel }))
        }
        "file.delete" => {
            let root = canonical_root_dir(state)?;
            let rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            if rel.is_empty() {
                return Err("cannot delete root".to_string());
            }
            let target = resolve_target(&root, &rel)?;
            let target = canonicalize_in_root(&root, &target)?;
            let meta = fs::metadata(&target)
                .await
                .map_err(|e| format!("stat target failed: {e}"))?;
            if meta.is_dir() {
                fs::remove_dir_all(&target)
                    .await
                    .map_err(|e| format!("delete directory failed: {e}"))?;
            } else {
                fs::remove_file(&target)
                    .await
                    .map_err(|e| format!("delete file failed: {e}"))?;
            }
            audit_log(
                state,
                actor,
                ip,
                "file_delete",
                Some(rel.clone()),
                true,
                None,
            );
            Ok(serde_json::json!({ "path": rel }))
        }
        "file.upload" => {
            let root = canonical_root_dir(state)?;
            let parent_rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            let name = sanitize_name(
                params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?;
            let content_b64 = params
                .get("content_base64")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "content_base64 is required".to_string())?;
            let overwrite = params
                .get("overwrite")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let bytes = STANDARD
                .decode(content_b64)
                .map_err(|e| format!("decode file content failed: {e}"))?;
            if bytes.len() > MAX_RPC_FILE_BYTES {
                return Err(format!(
                    "file too large, max {} bytes",
                    MAX_RPC_FILE_BYTES
                ));
            }
            let parent_target = resolve_target(&root, &parent_rel)?;
            let parent_canonical = canonicalize_in_root(&root, &parent_target)?;
            let parent_meta = std::fs::metadata(&parent_canonical)
                .map_err(|e| format!("stat parent failed: {e}"))?;
            if !parent_meta.is_dir() {
                return Err("parent is not a directory".to_string());
            }
            let target_rel = join_rel(&parent_rel, &name);
            let target = parent_canonical.join(&name);
            let _ = resolve_target(&root, &target_rel)?;
            let mut open_opts = fs::OpenOptions::new();
            open_opts.write(true);
            if overwrite {
                open_opts.create(true).truncate(true);
            } else {
                open_opts.create_new(true);
            }
            let mut file = open_opts
                .open(&target)
                .await
                .map_err(|e| format!("open upload target failed: {e}"))?;
            file.write_all(&bytes)
                .await
                .map_err(|e| format!("write upload target failed: {e}"))?;
            audit_log(
                state,
                actor,
                ip,
                "file_upload",
                Some(target_rel.clone()),
                true,
                Some(format!("size={}", bytes.len())),
            );
            Ok(serde_json::json!({ "path": target_rel, "size": bytes.len() }))
        }
        "file.download" => {
            // Deprecated: use GET /download?path=... HTTP endpoint instead (no size limit, streaming).
            // Kept for backward-compat; returns file size + redirect info for small files only.
            let root = canonical_root_dir(state)?;
            let rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            if rel.is_empty() {
                return Err("path is required".to_string());
            }
            let target = resolve_target(&root, &rel)?;
            let target = canonicalize_in_root(&root, &target)?;
            let meta = fs::metadata(&target)
                .await
                .map_err(|e| format!("stat target failed: {e}"))?;
            let is_dir = meta.is_dir();
            if is_dir || meta.len() > MAX_RPC_FILE_BYTES as u64 {
                return Err(format!(
                    "use HTTP endpoint: GET /download?path={rel}"
                ));
            }
            let name = download_name(&rel, false);
            let bytes = fs::read(&target)
                .await
                .map_err(|e| format!("read file failed: {e}"))?;
            audit_log(
                state,
                actor,
                ip,
                "file_download",
                Some(rel.clone()),
                true,
                Some(format!("size={}", bytes.len())),
            );
            Ok(serde_json::json!({
                "path": rel,
                "name": name,
                "size": bytes.len(),
                "is_dir": false,
                "content_base64": STANDARD.encode(bytes),
            }))
        }
        "file.read" => {
            let root = canonical_root_dir(state)?;
            let rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            if rel.is_empty() {
                return Err("path is required".to_string());
            }
            let target = resolve_target(&root, &rel)?;
            let target = canonicalize_in_root(&root, &target)?;
            let meta = fs::metadata(&target)
                .await
                .map_err(|e| format!("stat failed: {e}"))?;
            if meta.is_dir() {
                return Err("cannot read a directory".to_string());
            }
            if meta.len() > MAX_RPC_FILE_BYTES as u64 {
                return Err(format!(
                    "file too large for editing, max {} bytes",
                    MAX_RPC_FILE_BYTES
                ));
            }
            let bytes = fs::read(&target)
                .await
                .map_err(|e| format!("read file failed: {e}"))?;
            audit_log(
                state,
                actor,
                ip,
                "file_read",
                Some(rel.clone()),
                true,
                Some(format!("size={}", bytes.len())),
            );
            Ok(serde_json::json!({
                "path": rel,
                "size": bytes.len(),
                "content_base64": STANDARD.encode(&bytes),
            }))
        }
        "file.write" => {
            let root = canonical_root_dir(state)?;
            let rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            if rel.is_empty() {
                return Err("path is required".to_string());
            }
            let content_b64 = params
                .get("content_base64")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "content_base64 is required".to_string())?;
            let bytes = STANDARD
                .decode(content_b64)
                .map_err(|e| format!("decode content failed: {e}"))?;
            if bytes.len() > MAX_RPC_FILE_BYTES {
                return Err(format!(
                    "content too large, max {} bytes",
                    MAX_RPC_FILE_BYTES
                ));
            }
            let target = resolve_target(&root, &rel)?;
            let target = canonicalize_in_root(&root, &target)?;
            let meta = fs::metadata(&target)
                .await
                .map_err(|e| format!("stat failed: {e}"))?;
            if meta.is_dir() {
                return Err("cannot write to a directory".to_string());
            }
            fs::write(&target, &bytes)
                .await
                .map_err(|e| format!("write file failed: {e}"))?;
            audit_log(
                state,
                actor,
                ip,
                "file_write",
                Some(rel.clone()),
                true,
                Some(format!("size={}", bytes.len())),
            );
            Ok(serde_json::json!({ "path": rel, "size": bytes.len() }))
        }
        "file.stat" => {
            let root = canonical_root_dir(state)?;
            let rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            if rel.is_empty() {
                return Err("path is required".to_string());
            }
            let target = resolve_target(&root, &rel)?;
            let target = canonicalize_in_root(&root, &target)?;
            let meta = fs::metadata(&target)
                .await
                .map_err(|e| format!("stat failed: {e}"))?;
            let name = rel.rsplit('/').next().unwrap_or(&rel).to_string();
            Ok(serde_json::json!({
                "path": rel,
                "name": name,
                "size": meta.len(),
                "is_dir": meta.is_dir(),
            }))
        }
        "file.download.token" => {
            // Generate a single-use, time-limited download token for a pre-validated path.
            // The token is returned to the authenticated WS client; no path info leaks in the URL.
            let root = canonical_root_dir(state)?;
            let rel = rel_to_string(&normalize_rel_path(
                params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?);
            if rel.is_empty() {
                return Err("path is required".to_string());
            }
            let target = resolve_target(&root, &rel)?;
            let target = canonicalize_in_root(&root, &target)?;
            let meta = fs::metadata(&target)
                .await
                .map_err(|e| format!("stat failed: {e}"))?;
            let is_dir = meta.is_dir();
            let compress = params
                .get("compress")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            // Generate random 32-hex-char token
            use rand_core::RngCore;
            let mut bytes = [0u8; 16];
            rand_core::OsRng.fill_bytes(&mut bytes);
            let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();

            let expires_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + DOWNLOAD_TOKEN_TTL_SECS;

            let entry = DownloadTokenEntry {
                abs_path: target,
                is_dir,
                compress,
                expires_at,
                actor: actor.to_string(),
            };

            state
                .download_tokens
                .lock()
                .map_err(|_| "lock poisoned".to_string())?
                .insert(token.clone(), entry);

            audit_log(
                state,
                actor,
                ip,
                "download_token_issued",
                Some(rel),
                true,
                Some(format!("ttl={DOWNLOAD_TOKEN_TTL_SECS},compress={compress}")),
            );
            Ok(serde_json::json!({ "token": token }))
        }
        "health.live" => Ok(serde_json::json!({ "status": "ok" })),
        "health.ready" => {
            let clients = *state.client_count.lock().await;
            Ok(serde_json::json!({ "status": "ready", "clients": clients }))
        }
        _ => Err("unknown rpc method".to_string()),
    }
}

pub async fn list_files(
    State(state): State<SharedState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<ApiResponse<ListResult>>, (StatusCode, Json<ApiResponse<()>>)> {
    let (actor, ip) = ensure_allowed(&state, &headers, client)?;
    let root = canonical_root_dir(&state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e))))?;
    let rel = q.path.unwrap_or_default();
    let rel_norm = normalize_rel_path(&rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let rel_s = rel_to_string(&rel_norm);
    let entries = list_entries(&root, &rel_s)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    audit_log(
        &state,
        &actor,
        ip,
        "file_list",
        Some(rel_s),
        true,
        Some(format!("entries={}", entries.len())),
    );
    Ok(Json(ApiResponse::ok(ListResult { entries })))
}

pub async fn mkdir(
    State(state): State<SharedState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<CreateRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    let (actor, ip) = ensure_allowed(&state, &headers, client)?;
    let root = canonical_root_dir(&state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e))))?;
    let parent_rel = rel_to_string(
        &normalize_rel_path(&req.path)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?,
    );
    let name = sanitize_name(&req.name)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let parent_target = resolve_target(&root, &parent_rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let parent_canonical = canonicalize_in_root(&root, &parent_target)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let parent_meta = std::fs::metadata(&parent_canonical).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!("stat parent failed: {e}"))),
        )
    })?;
    if !parent_meta.is_dir() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("parent is not a directory")),
        ));
    }
    let target_rel = join_rel(&parent_rel, &name);
    let target = parent_canonical.join(&name);
    resolve_target(&root, &target_rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    fs::create_dir(&target).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!("mkdir failed: {e}"))),
        )
    })?;
    audit_log(
        &state,
        &actor,
        ip,
        "file_mkdir",
        Some(target_rel.clone()),
        true,
        None,
    );
    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "path": target_rel }),
    )))
}

pub async fn new_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<CreateRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    let (actor, ip) = ensure_allowed(&state, &headers, client)?;
    let root = canonical_root_dir(&state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e))))?;
    let parent_rel = rel_to_string(
        &normalize_rel_path(&req.path)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?,
    );
    let name = sanitize_name(&req.name)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let parent_target = resolve_target(&root, &parent_rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let parent_canonical = canonicalize_in_root(&root, &parent_target)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let parent_meta = std::fs::metadata(&parent_canonical).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!("stat parent failed: {e}"))),
        )
    })?;
    if !parent_meta.is_dir() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("parent is not a directory")),
        ));
    }
    let target_rel = join_rel(&parent_rel, &name);
    let target = parent_canonical.join(&name);
    resolve_target(&root, &target_rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(target)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err(format!("create file failed: {e}"))),
            )
        })?;
    audit_log(
        &state,
        &actor,
        ip,
        "file_new",
        Some(target_rel.clone()),
        true,
        None,
    );
    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "path": target_rel }),
    )))
}

pub async fn rename(
    State(state): State<SharedState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<RenameRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    let (actor, ip) = ensure_allowed(&state, &headers, client)?;
    let root = canonical_root_dir(&state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e))))?;
    let src_rel = rel_to_string(
        &normalize_rel_path(&req.path)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?,
    );
    if src_rel.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("cannot rename root")),
        ));
    }
    let new_name = sanitize_name(&req.new_name)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let parent_rel = src_rel
        .rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_default();
    let dst_rel = join_rel(&parent_rel, &new_name);
    let src = resolve_target(&root, &src_rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let src_canonical = canonicalize_in_root(&root, &src)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let dst_parent_target = resolve_target(&root, &parent_rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let dst_parent_canonical = canonicalize_in_root(&root, &dst_parent_target)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let dst = dst_parent_canonical.join(&new_name);
    resolve_target(&root, &dst_rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    fs::rename(src_canonical, dst).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!("rename failed: {e}"))),
        )
    })?;
    audit_log(
        &state,
        &actor,
        ip,
        "file_rename",
        Some(src_rel),
        true,
        Some(format!("new_path={dst_rel}")),
    );
    Ok(Json(ApiResponse::ok(
        serde_json::json!({ "path": dst_rel }),
    )))
}

pub async fn delete(
    State(state): State<SharedState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    let (actor, ip) = ensure_allowed(&state, &headers, client)?;
    let root = canonical_root_dir(&state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e))))?;
    let rel = rel_to_string(
        &normalize_rel_path(&req.path)
            .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?,
    );
    if rel.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err("cannot delete root")),
        ));
    }
    let target = resolve_target(&root, &rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let target = canonicalize_in_root(&root, &target)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let meta = fs::metadata(&target).await.map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::err(format!("stat target failed: {e}"))),
        )
    })?;
    if meta.is_dir() {
        fs::remove_dir_all(&target).await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err(format!("delete directory failed: {e}"))),
            )
        })?;
    } else {
        fs::remove_file(&target).await.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::err(format!("delete file failed: {e}"))),
            )
        })?;
    }
    audit_log(
        &state,
        &actor,
        ip,
        "file_delete",
        Some(rel.clone()),
        true,
        None,
    );
    Ok(Json(ApiResponse::ok(serde_json::json!({ "path": rel }))))
}

// ── HTTP streaming download ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DownloadQuery {
    pub token: Option<String>,
}

fn err_response(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

/// `GET /download?token=<token>`
/// Single-use, pre-authenticated streaming download.
/// The token is obtained via the `file.download.token` WS RPC.
pub async fn download_file(
    State(state): State<SharedState>,
    _headers: HeaderMap,
    _client: Option<axum::extract::ConnectInfo<SocketAddr>>,
    Query(q): Query<DownloadQuery>,
) -> Response {
    let token = match q.token.as_deref().filter(|s| !s.is_empty()) {
        Some(t) => t.to_string(),
        None => return err_response(StatusCode::BAD_REQUEST, "token is required"),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Consume the token (single-use)
    let entry = match state.download_tokens.lock() {
        Ok(mut map) => {
            match map.remove(&token) {
                Some(e) => e,
                None => return err_response(StatusCode::NOT_FOUND, "invalid or expired token"),
            }
        }
        Err(_) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, "lock error"),
    };

    if entry.expires_at < now {
        return err_response(StatusCode::GONE, "download token has expired");
    }

    let target = &entry.abs_path;
    let meta = match fs::metadata(target).await {
        Ok(m) => m,
        Err(e) => return err_response(StatusCode::NOT_FOUND, &format!("stat failed: {e}")),
    };

    let rel = target.to_string_lossy().to_string();
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());

    if entry.is_dir {
        let filename = format!("{}.tar.gz", name);
        let disposition = format!("attachment; filename=\"{}\"", filename);
        let dir_label = name.clone();
        let target_owned = target.clone();

        let (async_write, async_read) = tokio::io::duplex(256 * 1024);
        let handle = tokio::runtime::Handle::current();

        let _tar_task = tokio::task::spawn_blocking(move || {
            let writer = SyncDuplexWriter { inner: async_write, handle };
            let mut archive = tar::Builder::new(writer);
            if let Err(e) = archive.append_dir_all(&dir_label, &target_owned) {
                tracing::warn!("tar error: {e}");
                return;
            }
            if let Err(e) = archive.finish() {
                tracing::warn!("tar finish error: {e}");
            }
        });

        let encoder = GzipEncoder::new(BufReader::new(async_read));
        let stream = ReaderStream::new(encoder);

        audit_log(&state, &entry.actor, None, "file_download", Some(rel), true, Some("dir=true,fmt=tar.gz".into()));

        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/gzip")
            .header(header::CONTENT_DISPOSITION, disposition)
            .body(Body::from_stream(stream))
            .unwrap();
    }

    if entry.compress {
        let filename = format!("{}.gz", name);
        let disposition = format!("attachment; filename=\"{}\"", filename);
        let file = match tokio::fs::File::open(target).await {
            Ok(f) => f,
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("open: {e}")),
        };
        let encoder = GzipEncoder::new(BufReader::new(file));
        let stream = ReaderStream::new(encoder);

        audit_log(&state, &entry.actor, None, "file_download", Some(rel), true,
            Some(format!("size={},compressed=true", meta.len())));

        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/gzip")
            .header(header::CONTENT_DISPOSITION, disposition)
            .body(Body::from_stream(stream))
            .unwrap();
    }

    // Raw streaming download
    let filename = name;
    let disposition = format!("attachment; filename=\"{}\"", filename);
    let file_size = meta.len();
    let file = match tokio::fs::File::open(target).await {
        Ok(f) => f,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("open: {e}")),
    };
    let stream = ReaderStream::new(file);

    audit_log(&state, &entry.actor, None, "file_download", Some(rel), true,
        Some(format!("size={file_size},compressed=false")));

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CONTENT_LENGTH, file_size)
        .body(Body::from_stream(stream))
        .unwrap()
}
