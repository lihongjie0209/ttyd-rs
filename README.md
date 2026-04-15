# ttyd-rs

A Rust rewrite of [ttyd](https://github.com/tsl0922/ttyd) — share your terminal over the web as a single self-contained binary. Features a dark-themed UI with a file browser sidebar, WS Noise encryption, Basic Auth, and lrzsz file transfer.

## Screenshots

| Login | Terminal |
|-------|----------|
| ![Login](docs/images/login.png) | ![Terminal](docs/images/terminal.png) |

| File Browser | Context Menu |
|-------------|--------------|
| ![File Browser](docs/images/file-tree.png) | ![Context Menu](docs/images/context-menu.png) |

## Features

- **PTY over WebSocket** — full xterm.js terminal in the browser
- **Auth-gated login page** — login page served when `--credential` is set; main terminal hidden until authenticated
- **File browser sidebar** — list, expand, upload, download (directories as `.zip`), rename, delete, new file/dir, right-click context menu
- **WS Noise encryption** — Noise_NN_25519_ChaChaPoly_SHA256 enabled by default (`--disable-ws-noise` to turn off)
- **Basic Auth** (`-c user:pass` / `--username` + `--password`) and proxy auth header (`--auth-header`)
- **IP allowlist** — CIDR-based (`--allow-ip`)
- **lrzsz** — `rz`/`sz` file transfer with first-login hint
- **Audit log** — JSONL structured log of every connection, command, and file operation (`--audit-log <path>`)
- **`--base-path`** — reverse-proxy sub-path support
- **Read-only mode** — `--readonly` disables terminal input
- **Single binary** — frontend assets are gzip-embedded at build time via `build.rs`

## Quick Start

```bash
# Linux / macOS
cargo run -- -c admin:admin --port 7681 bash

# Windows
cargo run -- -c admin:admin --port 7681 cmd
```

Open `http://localhost:7681`, sign in with `admin / admin`.

### Common options

```bash
# Disable WS Noise (plain WebSocket)
cargo run -- --disable-ws-noise -c admin:admin --port 7681 bash

# Enable audit log
cargo run -- --audit-log ./audit.log -c admin:admin --port 7681 bash

# Read-only terminal (no keyboard input forwarded)
cargo run -- --readonly -c admin:admin --port 7681 bash

# Set file browser root to a specific directory
cargo run -- --cwd /srv/data -c admin:admin --port 7681 bash
```

## Build

`build.rs` automatically runs `npm install && npm run build` inside `frontend/` and embeds the output:

```bash
cargo build --release
# Output: target/release/ttyd  (or ttyd.exe on Windows)
```

## Docker

```bash
docker build -t ttyd-rs:latest .

# No auth
docker run --rm -p 7681:7681 ttyd-rs:latest bash

# With auth via TTYD_ARGS
docker run --rm -p 7681:7681 -e TTYD_ARGS="-c admin:admin" ttyd-rs:latest bash
```

The `docker-entrypoint.sh` reads `TTYD_ARGS` and prepends them to the command, so you can configure the server entirely via environment variables.

## Integration Tests

```bash
python scripts/integration_test.py
```

Covers: auth, IP allowlist, file API CRUD, path-traversal rejection, WS regression, base-path.

## CI / Releases

GitHub Actions workflow: `.github/workflows/release.yml`

- Triggers on `v*` tag push or manual dispatch
- Builds on `ubuntu-latest` and `macos-latest`
- Artifacts: `ttyd-${platform}.tar.gz` uploaded to GitHub Release

## Security Notes

- **WS Noise (Noise_NN)** encrypts payloads but does **not** authenticate the server. Use HTTPS/TLS in front of ttyd-rs in production.
- Set a strong `--credential` and restrict access with `--allow-ip` or a reverse proxy.
