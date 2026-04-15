import argparse
import asyncio
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

import websockets


SRV_OUTPUT = ord("0")
SRV_SET_TITLE = ord("1")
SRV_SET_PREFS = ord("2")
SRV_RPC = ord("4")
CMD_INPUT = b"0"
CMD_RPC = b"4"


def is_windows() -> bool:
    return os.name == "nt"


def pick_shell() -> str:
    return "cmd" if is_windows() else "sh"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def basic_auth_header(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


@dataclass
class HttpResult:
    status: int
    body: str


def http_request(url: str, method: str = "GET", headers: dict[str, str] | None = None, payload: dict | None = None) -> HttpResult:
    data = None
    req_headers = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        req_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, method=method, headers=req_headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            return HttpResult(status=resp.status, body=body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        return HttpResult(status=e.code, body=body)


class TtydProc:
    def __init__(self, binary: str, args: list[str], ready_path: str = "/login", ready_statuses: set[int] | None = None):
        self.binary = binary
        self.args = args
        self.ready_path = ready_path
        self.ready_statuses = ready_statuses or {200, 403}
        self.proc: subprocess.Popen | None = None
        self.port = self._read_port(args)
        self.base_url = f"http://127.0.0.1:{self.port}"

    @staticmethod
    def _read_port(args: list[str]) -> int:
        for i in range(len(args) - 1):
            if args[i] in ("-p", "--port"):
                return int(args[i + 1])
        raise ValueError("missing --port in args")

    def __enter__(self):
        self.proc = subprocess.Popen([self.binary, *self.args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self._wait_ready()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=3)

    def _wait_ready(self):
        deadline = time.time() + 20
        url = f"{self.base_url}{self.ready_path}"
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                stderr = self.proc.stderr.read() if self.proc.stderr else ""
                raise RuntimeError(f"ttyd exited early with code {self.proc.returncode}\n{stderr}")
            try:
                res = http_request(url)
                if res.status in self.ready_statuses:
                    return
            except Exception:
                pass
            time.sleep(0.2)
        raise TimeoutError(f"timed out waiting server ready at {url}")


async def ws_connect(base_url: str, ws_path: str, auth_header: dict[str, str] | None):
    ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://") + ws_path
    ws = await websockets.connect(ws_url, subprotocols=["tty"], additional_headers=auth_header or {})
    if ws.subprotocol != "tty":
        raise AssertionError(f"unexpected subprotocol: {ws.subprotocol!r}")
    m1 = await asyncio.wait_for(ws.recv(), timeout=8)
    m2 = await asyncio.wait_for(ws.recv(), timeout=8)
    if isinstance(m1, str):
        m1 = m1.encode("utf-8")
    if isinstance(m2, str):
        m2 = m2.encode("utf-8")
    kinds = {m1[0], m2[0]}
    if SRV_SET_TITLE not in kinds or SRV_SET_PREFS not in kinds:
        raise AssertionError(f"missing initial frames, got {sorted(kinds)}")
    await ws.send(json.dumps({"columns": 100, "rows": 30}))
    return ws


async def ws_rpc(ws, rpc_id: int, method: str, params: dict):
    await ws.send(CMD_RPC + json.dumps({"id": rpc_id, "method": method, "params": params}).encode("utf-8"))
    deadline = time.time() + 8
    while time.time() < deadline:
        msg = await asyncio.wait_for(ws.recv(), timeout=8)
        if isinstance(msg, str):
            msg = msg.encode("utf-8")
        if msg and msg[0] == SRV_RPC:
            payload = json.loads(msg[1:].decode("utf-8"))
            if payload.get("id") == rpc_id:
                return payload
    raise AssertionError(f"rpc timeout: {method}")


async def ws_roundtrip(base_url: str, ws_path: str, auth_header: dict[str, str] | None):
    ws = await ws_connect(base_url, ws_path, auth_header)
    try:
        await ws.send(b'1{"columns":90,"rows":28}')
        await ws.send(b"2")
        await asyncio.sleep(0.05)
        await ws.send(b"3")
        health = await ws_rpc(ws, 1, "health.live", {})
        if not health.get("ok"):
            raise AssertionError(f"health rpc failed: {health}")
        await ws.send(CMD_INPUT + b"echo __INT_TEST_OK__\r")
        deadline = time.time() + 10
        buf = ""
        while time.time() < deadline:
            msg = await asyncio.wait_for(ws.recv(), timeout=8)
            if isinstance(msg, str):
                msg = msg.encode("utf-8")
            if msg and msg[0] == SRV_OUTPUT:
                buf += msg[1:].decode("utf-8", errors="ignore")
                if "__INT_TEST_OK__" in buf:
                    return
        raise AssertionError("did not receive ws output marker")
    finally:
        await ws.close()


async def ws_file_crud(base_url: str, ws_path: str, auth_header: dict[str, str] | None):
    ws = await ws_connect(base_url, ws_path, auth_header)
    try:
        mk = await ws_rpc(ws, 10, "file.mkdir", {"path": "", "name": "dir1"})
        if not mk.get("ok"):
            raise AssertionError(f"mkdir failed: {mk}")
        nf = await ws_rpc(ws, 11, "file.new-file", {"path": "dir1", "name": "a.txt"})
        if not nf.get("ok"):
            raise AssertionError(f"new-file failed: {nf}")
        rn = await ws_rpc(ws, 12, "file.rename", {"path": "dir1/a.txt", "new_name": "b.txt"})
        if not rn.get("ok"):
            raise AssertionError(f"rename failed: {rn}")
        ls = await ws_rpc(ws, 13, "file.list", {"path": "dir1"})
        if not ls.get("ok"):
            raise AssertionError(f"list failed: {ls}")
        names = [e["name"] for e in ls["data"]["entries"]]
        if "b.txt" not in names:
            raise AssertionError("renamed file not listed")
        rmf = await ws_rpc(ws, 14, "file.delete", {"path": "dir1/b.txt"})
        if not rmf.get("ok"):
            raise AssertionError(f"delete file failed: {rmf}")
        rmd = await ws_rpc(ws, 15, "file.delete", {"path": "dir1"})
        if not rmd.get("ok"):
            raise AssertionError(f"delete dir failed: {rmd}")
    finally:
        await ws.close()


async def ws_file_path_traversal(base_url: str, ws_path: str, auth_header: dict[str, str] | None):
    ws = await ws_connect(base_url, ws_path, auth_header)
    try:
        bad = await ws_rpc(ws, 21, "file.new-file", {"path": "../escape", "name": "x.txt"})
        if bad.get("ok"):
            raise AssertionError("path traversal should be blocked")
    finally:
        await ws.close()


def test_auth(binary: str):
    port = free_port()
    args = ["--port", str(port), "--username", "u1", "--password", "p1", "--disable-ws-noise", pick_shell()]
    with TtydProc(binary, args):
        base = f"http://127.0.0.1:{port}"
        login = http_request(base + "/login")
        assert login.status == 200, f"login expected 200, got {login.status}"
        hidden = http_request(base + "/token")
        assert hidden.status in {401, 404}, f"token should not be exposed, got {hidden.status}"


def test_ip_whitelist(binary: str):
    port = free_port()
    args = ["--port", str(port), "--username", "u1", "--password", "p1", "--disable-ws-noise", "--ip-whitelist", "10.10.10.0/24", pick_shell()]
    with TtydProc(binary, args, ready_path="/login", ready_statuses={403}):
        base = f"http://127.0.0.1:{port}"
        blocked = http_request(base + "/login")
        assert blocked.status == 403, f"expected 403, got {blocked.status}"


def test_ws_with_auth(binary: str):
    port = free_port()
    args = ["--port", str(port), "--username", "u1", "--password", "p1", "--disable-ws-noise", "--writable", pick_shell()]
    headers = basic_auth_header("u1", "p1")
    with TtydProc(binary, args):
        base = f"http://127.0.0.1:{port}"
        asyncio.run(ws_roundtrip(base, "/ws", headers))


def test_ws_file_crud(binary: str):
    port = free_port()
    args = ["--port", str(port), "--username", "u1", "--password", "p1", "--disable-ws-noise", "--writable", pick_shell()]
    headers = basic_auth_header("u1", "p1")
    with TtydProc(binary, args):
        base = f"http://127.0.0.1:{port}"
        asyncio.run(ws_file_crud(base, "/ws", headers))


def test_ws_file_path_traversal(binary: str):
    port = free_port()
    args = ["--port", str(port), "--username", "u1", "--password", "p1", "--disable-ws-noise", "--writable", pick_shell()]
    headers = basic_auth_header("u1", "p1")
    with TtydProc(binary, args):
        base = f"http://127.0.0.1:{port}"
        asyncio.run(ws_file_path_traversal(base, "/ws", headers))


def test_base_path(binary: str):
    port = free_port()
    args = ["--port", str(port), "--username", "u1", "--password", "p1", "--disable-ws-noise", "--writable", "--base-path", "/tty", pick_shell()]
    headers = basic_auth_header("u1", "p1")
    with TtydProc(binary, args, ready_path="/tty/login", ready_statuses={200, 403}):
        base = f"http://127.0.0.1:{port}"
        login = http_request(base + "/tty/login")
        assert login.status == 200, f"base login expected 200, got {login.status}"
        asyncio.run(ws_roundtrip(base, "/tty/ws", headers))


def test_audit_log(binary: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        port = free_port()
        log_path = os.path.join(tmpdir, "audit.log")
        args = ["--port", str(port), "--username", "u1", "--password", "p1", "--disable-ws-noise", "--writable", "--audit-log", log_path, pick_shell()]
        headers = basic_auth_header("u1", "p1")
        with TtydProc(binary, args):
            base = f"http://127.0.0.1:{port}"
            asyncio.run(ws_roundtrip(base, "/ws", headers))
            time.sleep(0.3)
        assert os.path.exists(log_path), "audit log file not created"
        with open(log_path, "r", encoding="utf-8") as f:
            rows = [json.loads(x) for x in f if x.strip()]
        assert rows, "audit log is empty"
        keys = {"actor", "action", "success", "ts_ms"}
        assert any(keys.issubset(set(r.keys())) for r in rows), "audit record schema invalid"
        assert any(r.get("action") == "terminal_command" for r in rows), "terminal command not logged"


def resolve_binary(path: str | None) -> str:
    if path:
        return path
    exe = "ttyd.exe" if is_windows() else "ttyd"
    candidate = os.path.join("target", "debug", exe)
    if not os.path.exists(candidate):
        raise FileNotFoundError(f"binary not found: {candidate}. build first or use --binary.")
    return candidate


def main():
    parser = argparse.ArgumentParser(description="ttyd Python integration test suite")
    parser.add_argument("--binary", help="Path to ttyd binary (default: target/debug/ttyd[.exe])")
    args = parser.parse_args()
    binary = resolve_binary(args.binary)
    tests: list[tuple[str, callable]] = [
        ("auth", test_auth),
        ("ip-whitelist", test_ip_whitelist),
        ("ws-auth-roundtrip", test_ws_with_auth),
        ("ws-file-crud", test_ws_file_crud),
        ("ws-file-path-traversal", test_ws_file_path_traversal),
        ("base-path", test_base_path),
        ("audit-log", test_audit_log),
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn(binary)
            print(f"[PASS] {name}")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {name}: {e}", file=sys.stderr)
    if failed:
        print(f"integration suite failed: {failed} test(s) failed", file=sys.stderr)
        sys.exit(1)
    print("integration suite passed")


if __name__ == "__main__":
    main()
