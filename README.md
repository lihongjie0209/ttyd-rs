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

### Minimal image (`Dockerfile`)

```bash
docker build -t ttyd-rs:latest .

# No auth
docker run --rm -p 7681:7681 ttyd-rs:latest

# With auth (via TTYD_ARGS)
docker run --rm -p 7681:7681 -e TTYD_ARGS="-c admin:admin" ttyd-rs:latest
```

### Full Ubuntu image (`Dockerfile.ubuntu`)

Pre-installed: vim, zsh, git, curl, wget, htop, jq, python3, ripgrep, lrzsz, and more. Apt/pip are configured with Aliyun mirrors for fast installs in China.

```bash
docker build -f Dockerfile.ubuntu -t ttyd-rs-ubuntu:latest .
docker run --rm -p 7681:7681 -e TTYD_ARGS="-c admin:admin" ttyd-rs-ubuntu:latest

# Or pull from DockerHub
docker pull lihongjie0209/ttyd-rs-ubuntu:latest
docker run --rm -p 7681:7681 -e TTYD_ARGS="-c admin:admin" lihongjie0209/ttyd-rs-ubuntu:latest
```

The `docker-entrypoint.sh` reads `TTYD_ARGS` and prepends them to the command.

## Nginx Reverse Proxy

ttyd-rs uses WebSocket (with optional Noise encryption) and needs proper proxy headers. Below are common nginx configurations.

### Basic HTTP proxy

```nginx
server {
    listen 80;
    server_name terminal.example.com;

    location / {
        proxy_pass         http://127.0.0.1:7681;
        proxy_http_version 1.1;

        # WebSocket upgrade
        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Pass real client info
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts — keep WS alive
        proxy_read_timeout  3600s;
        proxy_send_timeout  3600s;
    }
}
```

### HTTPS + WSS (recommended for production)

```nginx
server {
    listen 443 ssl http2;
    server_name terminal.example.com;

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://127.0.0.1:7681;
        proxy_http_version 1.1;

        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_read_timeout  3600s;
        proxy_send_timeout  3600s;
    }
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name terminal.example.com;
    return 301 https://$host$request_uri;
}
```

### Sub-path proxy (`--base-path`)

Start ttyd-rs with `--base-path /ttyd`:

```bash
ttyd --base-path /ttyd -c admin:admin bash
```

Then proxy only that prefix in nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    # ... other locations ...

    location /ttyd/ {
        proxy_pass         http://127.0.0.1:7681/ttyd/;
        proxy_http_version 1.1;

        proxy_set_header Upgrade    $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_read_timeout  3600s;
        proxy_send_timeout  3600s;
    }
}
```

### Proxy auth header

If nginx handles authentication and you want to pass the username to ttyd-rs, start with `--auth-header X-Remote-User`:

```nginx
location / {
    # ... your nginx auth ...
    proxy_set_header X-Remote-User $remote_user;
    proxy_pass http://127.0.0.1:7681;
    # ... ws headers ...
}
```

```bash
ttyd --auth-header X-Remote-User bash
```

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
