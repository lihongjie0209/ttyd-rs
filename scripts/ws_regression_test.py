import argparse
import asyncio
import base64
import json
import sys
import urllib.request

import websockets


SRV_OUTPUT = ord("0")
SRV_SET_TITLE = ord("1")
SRV_SET_PREFS = ord("2")
CMD_INPUT = b"0"


def fetch_token(base_url: str, auth_header: str | None) -> str:
    req = urllib.request.Request(f"{base_url}/token")
    if auth_header:
        req.add_header("Authorization", auth_header)
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        return payload.get("token", "")


async def read_message(ws, timeout: float = 10.0):
    msg = await asyncio.wait_for(ws.recv(), timeout=timeout)
    if isinstance(msg, str):
        msg = msg.encode("utf-8")
    return msg


async def wait_for_output_contains(ws, needle: str, timeout: float = 10.0) -> str:
    deadline = asyncio.get_running_loop().time() + timeout
    buf = ""
    while asyncio.get_running_loop().time() < deadline:
        msg = await read_message(ws, timeout=timeout)
        if not msg:
            continue
        if msg[0] == SRV_OUTPUT:
            chunk = msg[1:].decode("utf-8", errors="ignore")
            buf += chunk
            if needle in buf:
                return buf
    raise TimeoutError(f"did not receive expected output: {needle}")


async def run(base_url: str, auth_header: str | None):
    ws_url = base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws"
    token = fetch_token(base_url, auth_header)

    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header

    async with websockets.connect(ws_url, subprotocols=["tty"], additional_headers=headers) as ws:
        if ws.subprotocol != "tty":
            raise AssertionError(f"unexpected subprotocol: {ws.subprotocol!r}")

        m1 = await read_message(ws)
        m2 = await read_message(ws)
        kinds = {m1[0], m2[0]}
        if SRV_SET_TITLE not in kinds or SRV_SET_PREFS not in kinds:
            raise AssertionError(f"missing initial frames, got: {sorted(kinds)}")

        await ws.send(json.dumps({"AuthToken": token, "columns": 120, "rows": 30}))
        await ws.send('1{"columns":100,"rows":28}')
        await ws.send("2")
        await asyncio.sleep(0.05)
        await ws.send("3")

        await ws.send(CMD_INPUT + b"echo __WS_REGRESSION_OK__\r")
        output = await wait_for_output_contains(ws, "__WS_REGRESSION_OK__", timeout=12)
        if "__WS_REGRESSION_OK__" not in output:
            raise AssertionError("marker not found in PTY output")


def main():
    parser = argparse.ArgumentParser(description="ttyd websocket regression test")
    parser.add_argument("--base-url", default="http://127.0.0.1:18761")
    parser.add_argument("--username")
    parser.add_argument("--password")
    args = parser.parse_args()
    if (args.username and not args.password) or (args.password and not args.username):
        print("username/password must be provided together", file=sys.stderr)
        sys.exit(2)

    auth_header = None
    if args.username and args.password:
        token = base64.b64encode(f"{args.username}:{args.password}".encode("utf-8")).decode("ascii")
        auth_header = f"Basic {token}"

    try:
        asyncio.run(run(args.base_url.rstrip("/"), auth_header))
    except Exception as e:
        print(f"WS regression failed: {e}", file=sys.stderr)
        sys.exit(1)

    print("WS regression passed")


if __name__ == "__main__":
    main()
