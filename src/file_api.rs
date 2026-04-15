#![allow(dead_code)]

use axum::{
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio_util::io::ReaderStream;
use zip::write::FileOptions;

use crate::{audit::AuditEvent, http::check_auth, server::SharedState};

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
        format!("{safe}.zip")
    } else {
        safe.to_string()
    }
}

fn make_temp_zip_path() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("ttyd-rs-download-{}-{millis}.zip", std::process::id()))
}

fn zip_dir_recursive(
    writer: &mut zip::ZipWriter<std::fs::File>,
    root_dir: &Path,
    current_dir: &Path,
) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(current_dir)
        .map_err(|e| format!("read directory failed: {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("read directory entry failed: {e}"))?;
    entries.sort_by_key(|e| e.file_name().to_string_lossy().to_string());
    let options = FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for entry in entries {
        let path = entry.path();
        let file_type = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("read metadata failed: {e}"))?
            .file_type();
        if file_type.is_symlink() {
            continue;
        }
        let rel = path
            .strip_prefix(root_dir)
            .map_err(|e| format!("resolve relative path failed: {e}"))?
            .to_string_lossy()
            .replace('\\', "/");
        if file_type.is_dir() {
            writer
                .add_directory(format!("{rel}/"), options)
                .map_err(|e| format!("zip add directory failed: {e}"))?;
            zip_dir_recursive(writer, root_dir, &path)?;
            continue;
        }
        if file_type.is_file() {
            let bytes = std::fs::read(&path).map_err(|e| format!("read file failed: {e}"))?;
            writer
                .start_file(rel, options)
                .map_err(|e| format!("zip add file failed: {e}"))?;
            writer
                .write_all(&bytes)
                .map_err(|e| format!("zip write file failed: {e}"))?;
        }
    }
    Ok(())
}

fn create_temp_zip_from_dir(dir: &Path) -> Result<PathBuf, String> {
    let zip_path = make_temp_zip_path();
    let file = std::fs::File::create(&zip_path).map_err(|e| format!("create zip failed: {e}"))?;
    let mut writer = zip::ZipWriter::new(file);
    zip_dir_recursive(&mut writer, dir, dir)?;
    writer
        .finish()
        .map_err(|e| format!("finalize zip failed: {e}"))?;
    Ok(zip_path)
}

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
            let name = download_name(&rel, is_dir);
            let bytes = if is_dir {
                let target_for_zip = target.clone();
                let zip_path = tokio::task::spawn_blocking(move || create_temp_zip_from_dir(&target_for_zip))
                    .await
                    .map_err(|e| format!("zip task failed: {e}"))??;
                let zip_meta = fs::metadata(&zip_path)
                    .await
                    .map_err(|e| format!("stat zip failed: {e}"))?;
                if zip_meta.len() > MAX_RPC_FILE_BYTES as u64 {
                    let _ = fs::remove_file(&zip_path).await;
                    return Err(format!(
                        "archive too large, max {} bytes",
                        MAX_RPC_FILE_BYTES
                    ));
                }
                let bytes = fs::read(&zip_path)
                    .await
                    .map_err(|e| format!("read zip failed: {e}"))?;
                let _ = fs::remove_file(&zip_path).await;
                bytes
            } else {
                if meta.len() > MAX_RPC_FILE_BYTES as u64 {
                    return Err(format!(
                        "file too large, max {} bytes",
                        MAX_RPC_FILE_BYTES
                    ));
                }
                fs::read(&target)
                    .await
                    .map_err(|e| format!("read file failed: {e}"))?
            };
            audit_log(
                state,
                actor,
                ip,
                "file_download",
                Some(rel.clone()),
                true,
                Some(format!("size={}, dir={}", bytes.len(), is_dir)),
            );
            Ok(serde_json::json!({
                "path": rel,
                "name": name,
                "size": bytes.len(),
                "is_dir": is_dir,
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
    pub path: Option<String>,
    /// "1" = gzip-compress the file before sending
    pub compress: Option<String>,
}

fn err_response(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .unwrap()
}

/// `GET /download?path=<rel>&compress=0|1`
/// Streams files (and directories as zip) directly without the 8 MB WS limit.
/// Supports optional gzip compression for single files via `?compress=1`.
pub async fn download_file(
    State(state): State<SharedState>,
    headers: HeaderMap,
    client: Option<axum::extract::ConnectInfo<SocketAddr>>,
    Query(q): Query<DownloadQuery>,
) -> Response {
    let ip = client.map(|c| c.0.ip());
    let actor = match check_auth(&headers, &state) {
        Some(u) => u,
        None => return err_response(StatusCode::UNAUTHORIZED, "unauthorized"),
    };

    let rel = match q.path.as_deref().filter(|s| !s.is_empty()) {
        Some(p) => match normalize_rel_path(p) {
            Ok(n) => rel_to_string(&n),
            Err(e) => return err_response(StatusCode::BAD_REQUEST, &e),
        },
        None => return err_response(StatusCode::BAD_REQUEST, "path is required"),
    };
    if rel.is_empty() {
        return err_response(StatusCode::BAD_REQUEST, "path is required");
    }

    let root = match canonical_root_dir(&state) {
        Ok(r) => r,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
    };

    let target = match resolve_target(&root, &rel) {
        Ok(t) => t,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, &e),
    };
    let target = match canonicalize_in_root(&root, &target) {
        Ok(t) => t,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, &e),
    };

    let meta = match fs::metadata(&target).await {
        Ok(m) => m,
        Err(e) => return err_response(StatusCode::NOT_FOUND, &format!("stat failed: {e}")),
    };

    let compress = q.compress.as_deref() == Some("1");
    let is_dir = meta.is_dir();

    if is_dir {
        // Directories: always zip regardless of compress flag
        let zip_path = match tokio::task::spawn_blocking({
            let t = target.clone();
            move || create_temp_zip_from_dir(&t)
        })
        .await
        {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("zip task: {e}")),
        };

        let filename = download_name(&rel, true);
        let disposition = format!("attachment; filename=\"{}\"", filename);
        let zip_file = match tokio::fs::File::open(&zip_path).await {
            Ok(f) => f,
            Err(e) => {
                let _ = tokio::fs::remove_file(&zip_path).await;
                return err_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("open zip: {e}"));
            }
        };
        let stream = ReaderStream::new(zip_file);
        // Clean up temp file after open (OS keeps file alive until closed on Unix)
        // On Windows we can't delete while open — best effort
        let _ = tokio::fs::remove_file(&zip_path).await;

        audit_log(&state, &actor, ip, "file_download", Some(rel), true, Some("dir=true".into()));

        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/zip")
            .header(header::CONTENT_DISPOSITION, disposition)
            .body(Body::from_stream(stream))
            .unwrap();
    }

    if compress {
        // Gzip: compress in blocking task, then stream
        let filename = format!("{}.gz", download_name(&rel, false));
        let disposition = format!("attachment; filename=\"{}\"", filename);
        let target_clone = target.clone();
        let gz_bytes = match tokio::task::spawn_blocking(move || {
            use flate2::{write::GzEncoder, Compression};
            let data = std::fs::read(&target_clone)
                .map_err(|e| format!("read failed: {e}"))?;
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&data).map_err(|e| format!("compress failed: {e}"))?;
            enc.finish().map_err(|e| format!("finalize failed: {e}"))
        })
        .await
        {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &e),
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("task: {e}")),
        };

        let size = gz_bytes.len();
        audit_log(&state, &actor, ip, "file_download", Some(rel), true,
            Some(format!("size={size},compressed=true")));

        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/gzip")
            .header(header::CONTENT_DISPOSITION, disposition)
            .header(header::CONTENT_LENGTH, size)
            .body(Body::from(gz_bytes))
            .unwrap();
    }

    // Raw streaming download — no size limit, no buffering
    let filename = download_name(&rel, false);
    let disposition = format!("attachment; filename=\"{}\"", filename);
    let file_size = meta.len();
    let file = match tokio::fs::File::open(&target).await {
        Ok(f) => f,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("open: {e}")),
    };
    let stream = ReaderStream::new(file);

    audit_log(&state, &actor, ip, "file_download", Some(rel), true,
        Some(format!("size={file_size},compressed=false")));

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CONTENT_LENGTH, file_size)
        .body(Body::from_stream(stream))
        .unwrap()
}
