# ttyd-rs

Rust 版本的 ttyd 独立复刻，实现 Web 终端共享、认证、IP 白名单、lrzsz、文件树操作，并将前端打包进单二进制。

## 主要功能

- PTY over WebSocket（xterm.js 前端）
- Basic Auth / 代理认证头
- IP 白名单（CIDR）
- lrzsz（rz/sz）文件传输与首次登录提示
- 左侧文件树与常见文件操作（list/mkdir/new-file/rename/delete）
- `--base-path` 反向代理路径支持
- 可选 WS 噪声加密：`--ws-noise`（Noise_NN_25519_ChaChaPoly_SHA256）

## 本地运行

```bash
cargo run -- --port 7681 --username admin --password admin --writable -- cmd
```

Linux/macOS:

```bash
cargo run -- --port 7681 --username admin --password admin --writable -- bash
```

启用 WS Noise：

```bash
cargo run -- --ws-noise --port 7681 --username admin --password admin --writable -- bash
```

## 构建说明

- `build.rs` 会自动执行前端安装与构建（`frontend`）
- 构建产物会 gzip 并嵌入 Rust 二进制

```bash
cargo build --release
```

输出：

- Windows: `target/release/ttyd.exe`
- Linux/macOS: `target/release/ttyd`

## Python 集成测试

```bash
python scripts/integration_test.py
```

覆盖认证、白名单、文件 API CRUD、路径穿越负向用例、WS 回归与 base-path。

## Docker 运行

```bash
docker build -t ttyd-rs:latest .
docker run --rm -p 7681:7681 ttyd-rs:latest
```

## CI 发布（Linux / macOS）

已提供 GitHub Actions 工作流：`.github/workflows/release.yml`

- 触发条件：`v*` tag push 或手动触发
- 构建平台：`ubuntu-latest`、`macos-latest`
- 产物：`ttyd-${platform}.tar.gz`
- 自动上传到 GitHub Release

## 安全建议

- 生产环境建议启用 HTTPS/TLS，并配合 `--ws-noise`。
- Noise NN 不提供服务端身份认证，TLS 仍然是必须的身份保障层。
