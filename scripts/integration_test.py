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
CMD_INPUT = b"0"


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
    def __init__(self, binary: str, args: list[str], ready_path: str = "/token", ready_statuses: set[int] | None = None):
        self.binary = binary
        self.args = args
        self.ready_path = ready_path
        self.ready_statuses = ready_statuses or {200, 401, 403, 407}
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
        self.proc = subprocess.Popen(
            [self.binary, *self.args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._wait_ready()
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.proc:
            return
        if self.proc.poll() is None:
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
            res = http_request(url)
            if res.status in self.ready_statuses:
                return
            time.sleep(0.2)
        raise TimeoutError(f"timed out waiting server ready at {url}")


def parse_json(body: str) -> dict:
    return json.loads(body) if body.strip() else {}


async def ws_roundtrip(base_url: str, ws_path: str, auth_header: dict[str, str] | None):
    ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://") + ws_path
    token_resp = http_request(base_url + ws_path.replace("/ws", "/token"), headers=auth_header)
    if token_resp.status != 200:
        raise AssertionError(f"token status expected 200, got {token_resp.status}")
    token = parse_json(token_resp.body).get("token", "")

    async with websockets.connect(ws_url, subprotocols=["tty"], additional_headers=auth_header or {}) as ws:
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

        await ws.send(json.dumps({"AuthToken": token, "columns": 100, "rows": 30}))
        await ws.send('1{"columns":90,"rows":28}')
        await ws.send("2")
        await asyncio.sleep(0.05)
        await ws.send("3")
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



def test_auth(binary: str):
    port = free_port()
    args = ["--port", str(port), "--username", "u1", "--password", "p1", pick_shell()]
    with TtydProc(binary, args):
        base = f"http://127.0.0.1:{port}"
        no_auth = http_request(base + "/token")
        assert no_auth.status == 401, f"expected 401, got {no_auth.status}"

        bad_auth = http_request(base + "/token", headers=basic_auth_header("u1", "bad"))
        assert bad_auth.status == 401, f"expected 401, got {bad_auth.status}"

        ok_auth = http_request(base + "/token", headers=basic_auth_header("u1", "p1"))
        assert ok_auth.status == 200, f"expected 200, got {ok_auth.status}"
        assert "token" in parse_json(ok_auth.body), "token missing in response"


def test_ip_whitelist(binary: str):
    port = free_port()
    args = [
        "--port",
        str(port),
        "--username",
        "u1",
        "--password",
        "p1",
        "--ip-whitelist",
        "10.10.10.0/24",
        pick_shell(),
    ]
    with TtydProc(binary, args, ready_path="/", ready_statuses={403}):
        base = f"http://127.0.0.1:{port}"
        blocked = http_request(base + "/token", headers=basic_auth_header("u1", "p1"))
        assert blocked.status == 403, f"expected 403, got {blocked.status}"


def test_file_api_crud(binary: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        port = free_port()
        args = [
            "--port",
            str(port),
            "--username",
            "u1",
            "--password",
            "p1",
            "--cwd",
            tmpdir,
            pick_shell(),
        ]
        headers = basic_auth_header("u1", "p1")
        with TtydProc(binary, args):
            base = f"http://127.0.0.1:{port}"
            mk = http_request(base + "/api/files/mkdir", method="POST", headers=headers, payload={"path": "", "name": "dir1"})
            assert mk.status == 200, f"mkdir status expected 200, got {mk.status}"

            new_file = http_request(
                base + "/api/files/new-file",
                method="POST",
                headers=headers,
                payload={"path": "dir1", "name": "a.txt"},
            )
            assert new_file.status == 200, f"new-file status expected 200, got {new_file.status}"

            ren = http_request(
                base + "/api/files/rename",
                method="POST",
                headers=headers,
                payload={"path": "dir1/a.txt", "new_name": "b.txt"},
            )
            assert ren.status == 200, f"rename status expected 200, got {ren.status}"

            listed = http_request(base + "/api/files/list?path=dir1", headers=headers)
            assert listed.status == 200, f"list status expected 200, got {listed.status}"
            names = [e["name"] for e in parse_json(listed.body)["data"]["entries"]]
            assert "b.txt" in names, "renamed file not listed"

            rm_file = http_request(
                base + "/api/files/delete",
                method="POST",
                headers=headers,
                payload={"path": "dir1/b.txt"},
            )
            assert rm_file.status == 200, f"delete file status expected 200, got {rm_file.status}"

            rm_dir = http_request(
                base + "/api/files/delete",
                method="POST",
                headers=headers,
                payload={"path": "dir1"},
            )
            assert rm_dir.status == 200, f"delete dir status expected 200, got {rm_dir.status}"


def test_file_api_path_traversal_blocked(binary: str):
    with tempfile.TemporaryDirectory() as tmpdir:
        port = free_port()
        args = [
            "--port",
            str(port),
            "--username",
            "u1",
            "--password",
            "p1",
            "--cwd",
            tmpdir,
            pick_shell(),
        ]
        headers = basic_auth_header("u1", "p1")
        with TtydProc(binary, args):
            base = f"http://127.0.0.1:{port}"
            bad = http_request(
                base + "/api/files/new-file",
                method="POST",
                headers=headers,
                payload={"path": "../escape", "name": "x.txt"},
            )
            assert bad.status == 400, f"path traversal should be blocked, got {bad.status}"


def test_ws_with_auth(binary: str):
    port = free_port()
    args = ["--port", str(port), "--username", "u1", "--password", "p1", "--writable", pick_shell()]
    headers = basic_auth_header("u1", "p1")
    with TtydProc(binary, args):
        base = f"http://127.0.0.1:{port}"
        asyncio.run(ws_roundtrip(base, "/ws", headers))


def test_base_path(binary: str):
    port = free_port()
    args = [
        "--port",
        str(port),
        "--username",
        "u1",
        "--password",
        "p1",
        "--writable",
        "--base-path",
        "/tty",
        pick_shell(),
    ]
    headers = basic_auth_header("u1", "p1")
    with TtydProc(binary, args, ready_path="/tty/token", ready_statuses={401, 200}):
        base = f"http://127.0.0.1:{port}"
        tok = http_request(base + "/tty/token", headers=headers)
        assert tok.status == 200, f"base token status expected 200, got {tok.status}"
        asyncio.run(ws_roundtrip(base, "/tty/ws", headers))


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
        ("file-api-crud", test_file_api_crud),
        ("file-api-path-traversal", test_file_api_path_traversal_blocked),
        ("ws-auth-roundtrip", test_ws_with_auth),
        ("base-path", test_base_path),
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
