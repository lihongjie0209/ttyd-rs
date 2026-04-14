use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
};
use tokio::fs;

use crate::{http::check_auth, server::SharedState};

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

fn ensure_allowed(
    state: &SharedState,
    headers: &HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
) -> Result<(), (StatusCode, Json<ApiResponse<()>>)> {
    if let Some(ip) = current_ip(client) {
        if !state.is_ip_allowed(Some(ip)) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ApiResponse::err("forbidden: ip not in whitelist")),
            ));
        }
    }
    if check_auth(headers, state).is_none() {
        return Err((
            unauthorized_status(state),
            Json(ApiResponse::err("authentication required")),
        ));
    }
    Ok(())
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

pub async fn list_files(
    State(state): State<SharedState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<ApiResponse<ListResult>>, (StatusCode, Json<ApiResponse<()>>)> {
    ensure_allowed(&state, &headers, client)?;
    let root = canonical_root_dir(&state)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiResponse::err(e))))?;
    let rel = q.path.unwrap_or_default();
    let rel_norm = normalize_rel_path(&rel)
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    let rel_s = rel_to_string(&rel_norm);
    let entries = list_entries(&root, &rel_s)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, Json(ApiResponse::err(e))))?;
    Ok(Json(ApiResponse::ok(ListResult { entries })))
}

pub async fn mkdir(
    State(state): State<SharedState>,
    headers: HeaderMap,
    client: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<CreateRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, (StatusCode, Json<ApiResponse<()>>)> {
    ensure_allowed(&state, &headers, client)?;
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
    ensure_allowed(&state, &headers, client)?;
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
    ensure_allowed(&state, &headers, client)?;
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
    ensure_allowed(&state, &headers, client)?;
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
    Ok(Json(ApiResponse::ok(serde_json::json!({ "path": rel }))))
}
