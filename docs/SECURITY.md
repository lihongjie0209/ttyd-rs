# Security

This document records the security architecture of ttyd-rs, the full findings from the v0.3.1 security audit, and the status of every issue.

---

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Threat Model](#threat-model)
3. [v0.3.1 Security Audit](#v031-security-audit)
   - [FIXED — Critical](#fixed--critical)
   - [FIXED — High](#fixed--high)
   - [FIXED — Medium](#fixed--medium)
   - [DEFERRED — Medium / Low](#deferred--medium--low)
4. [Defense-in-Depth Summary](#defense-in-depth-summary)
5. [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Security Architecture

### Authentication layers

| Layer | Mechanism | Notes |
|-------|-----------|-------|
| Login form | Username + password (base64-encoded in config, checked in constant-time) | Enabled only when `--credential` is set |
| Session cookie | 32-byte random token, `HttpOnly; SameSite=Lax; Max-Age=86400` (+ `Secure` when TLS) | Stored in `token_store` with 24-hour TTL |
| WebSocket upgrade | Auth checked at WS handshake before any PTY is opened | Same token store |
| IP allowlist | CIDR filtering via `--ip-whitelist` (applied before auth) | Optional, off by default |
| Proxy auth | `--auth-header` delegates to upstream (e.g., nginx `auth_basic`) | Optional |

### Path security (file browser)

All file-browser paths go through a **two-stage** validation pipeline:

1. **`normalize_rel_path`** — rejects any path segment containing `..`, absolute paths, and path separators in filenames.
2. **`canonicalize_in_root`** — resolves the resulting path on disk (following symlinks) and asserts the canonical path starts with the canonical root. Rejects symlinks that escape the root.

This means both lexical (`../`) traversal **and** symlink-based traversal are blocked.

### Download tokens

File downloads use **single-use, time-limited tokens** (30-second TTL):

1. Authenticated WS client calls `file.download.token` RPC → receives a random 32-hex-char token.
2. Client makes `GET /download?token=<token>` — token is consumed immediately (removed from store).
3. Expired or already-used tokens return `404 Not Found`.

This prevents direct path exposure in URLs and requires WS authentication before any download is possible.

### Brute-force protection

- **5 consecutive failures** from the same IP → 15-minute lockout (in-memory, resets on restart).
- Login request body is capped at **8 KB** to prevent memory exhaustion from large payloads.

### Request limits

| Endpoint | Body limit |
|----------|-----------|
| `POST /login` | 8 KB |
| All other HTTP routes | 16 MB |
| WS RPC messages | 16 MB |
| WS PTY frames | 24 MB |

---

## Threat Model

**In scope**

- Unauthenticated network access to the HTTP/WS server
- Path traversal / file escaping via the file browser
- Session hijacking / token theft
- Header injection via user-controlled filenames
- Denial-of-service via large request bodies or symlink loops

**Out of scope**

- Compromise of the host OS or user running ttyd-rs
- Attacks on downstream shells or commands run inside the terminal
- Physical access or side-channel attacks
- SSRF/RCE via the terminal (the terminal _is_ a shell by design — restrict with `--readonly` or network isolation)

---

## v0.3.1 Security Audit

Audit conducted: **2025-04** (scope: all Rust source files in `src/`, frontend JS, Dockerfile, CI configuration).

### FIXED — Critical

#### 1. Missing HTTP security response headers

**Risk:** Browsers default to permissive behavior without explicit opt-out headers. Missing headers allow clickjacking, MIME sniffing, and reflected XSS.

**Root cause:** No middleware was injecting standard security headers.

**Fix (v0.3.1):** Added `security_headers_middleware` in `src/main.rs` that wraps every response:

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing |
| `X-Frame-Options` | `DENY` | Prevents clickjacking via iframes |
| `X-XSS-Protection` | `1; mode=block` | Instructs older browsers to block reflected XSS |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limits referrer leakage |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | Forces HTTPS (injected only when `--tls` is active) |

**File:** `src/main.rs` — `security_headers_middleware()`

---

#### 2. No request body size limit

**Risk:** A client could POST an arbitrarily large body to `/login`, exhausting server memory (OOM DoS).

**Root cause:** axum's default `DefaultBodyLimit` is 2 MB; the login handler had no additional restriction and the global router had no limit set.

**Fix (v0.3.1):**
- Login route: `DefaultBodyLimit::max(8 * 1024)` (8 KB)
- Global router: `DefaultBodyLimit::max(16 * 1024 * 1024)` (16 MB)

**File:** `src/main.rs` — router setup

---

### FIXED — High

#### 3. Symlink traversal in directory listing

**Risk:** A symlink inside the root directory pointing to a path outside the root (e.g., `/etc`) would be followed during `list_entries`, leaking directory contents from outside the allowed tree.

**Root cause:** `list_entries` called `resolve_target` (lexical join) without the second stage `canonicalize_in_root` (symlink resolution + bounds check).

**Fix (v0.3.1):** `list_entries` now calls `canonicalize_in_root` on each entry before including it in the response. Entries that resolve outside the root are silently skipped.

**File:** `src/file_api.rs` — `list_entries()`

---

#### 4. Content-Disposition header injection via filename

**Risk:** A filename containing `"`, `\`, CR, or LF characters could break the `Content-Disposition` header, enabling header injection and potentially forcing arbitrary downloads in some browsers.

**Root cause:** The original code interpolated the raw filename directly into `attachment; filename="<raw>"`.

**Fix (v0.3.1):** Added `content_disposition_attachment()` that produces RFC 6266 / RFC 5987-compliant output:

```
attachment; filename="<ascii_safe>"; filename*=UTF-8''<percent_encoded>
```

- ASCII fallback replaces `"`, `\`, CR, LF with `_`.
- `filename*` takes priority in all modern browsers and handles full Unicode safely.

**File:** `src/file_api.rs` — `content_disposition_attachment()`

---

### FIXED — Medium

#### 5. Session token store never pruned

**Risk:** Expired session tokens accumulate in `token_store` indefinitely, causing unbounded memory growth in long-running deployments. An attacker creating many short-lived sessions could accelerate the leak.

**Root cause:** No cleanup task existed; tokens were only removed on explicit logout.

**Fix (v0.3.1):** Background Tokio task spawned at startup runs every **300 seconds**, removes all entries whose `expires_at` timestamp has passed.

**File:** `src/main.rs` — token cleanup task in `main()`

---

### DEFERRED — Medium / Low

The following issues were identified but not fixed in v0.3.1. Each is tracked with a rationale for deferral.

| ID | Severity | Issue | Rationale |
|----|----------|-------|-----------|
| D-1 | Medium | Credentials stored as base64, not hashed (argon2/bcrypt) | Breaking change to config format; requires a migration path. Planned for a future release. |
| D-2 | Medium | Brute-force lockout is in-memory (resets on restart) | By design for the current in-memory state model; acceptable for single-instance deployments. |
| D-3 | Medium | `--check-origin` is opt-in (off by default) | Intentional UX choice; documented. Users behind a reverse proxy should enable it. |
| D-4 | Medium | No CSRF token on login form | Partially mitigated: `SameSite=Lax` cookie attribute blocks cross-site form POST in all modern browsers. Full CSRF tokens planned for a future hardening pass. |
| D-5 | Low | TOCTOU race in file rename/delete | Requires platform-specific atomic `openat`/`renameat`. Low exploitability in practice; deferred. |
| D-6 | Low | Audit log has no rotation | Nice-to-have; users can use logrotate externally. |
| D-7 | Low | Tar/gzip download has no size/depth limit | Potential DoS via deeply nested directory trees. Planned guard in a future release. |

---

## Defense-in-Depth Summary

```
Internet
    │
    ▼
[nginx / reverse proxy]  ← TLS termination, rate limiting, auth_basic (optional)
    │
    ▼
[ttyd-rs]
    ├── IP allowlist (--ip-whitelist)
    ├── Login + session cookie (--credential)
    ├── Brute-force lockout (5 failures → 15 min)
    ├── Security headers middleware
    ├── Request body size limits
    ├── WS auth check at upgrade
    ├── Path normalization + canonicalization (file browser)
    ├── Single-use download tokens
    └── Audit log (--audit-log)
```

---

## Reporting Vulnerabilities

Please report security issues privately by opening a [GitHub Security Advisory](https://github.com/lihongjie0209/ttyd-rs/security/advisories/new) rather than a public issue.

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested mitigations (optional)

We aim to respond within 72 hours.
