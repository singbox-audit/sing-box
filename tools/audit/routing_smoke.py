# /// script
# requires-python = ">=3.11"
# dependencies = ["dnspython>=2.7,<3"]
# ///
"""Check route decisions, byte accounting, live group changes and crash recovery."""

import argparse
import concurrent.futures
import json
import pathlib
import socket
import subprocess
import threading
import time
import urllib.request

from smoke import HOST, address, bound, free_port, process, read_n, socks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument(
        "--output", type=pathlib.Path, required=True, help="new private test directory"
    )
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    exe = str(args.binary.resolve())
    audit = not args.baseline
    proxy, api = free_port(), free_port()
    listener = bound()
    listener.listen(100)

    def echo(c):
        with c:
            while data := c.recv(65536):
                c.sendall(data)

    def accept():
        while True:
            threading.Thread(
                target=echo, args=(listener.accept()[0],), daemon=True
            ).start()

    threading.Thread(target=accept, daemon=True).start()
    port = listener.getsockname()[1]
    config = {
        "log": {"level": "info"},
        "inbounds": [
            {"type": "socks", "tag": "entry", "listen": HOST, "listen_port": proxy}
        ],
        "outbounds": [
            {"type": "direct", "tag": "first"},
            {"type": "direct", "tag": "second"},
            {"type": "selector", "tag": "group", "outbounds": ["first", "second"]},
            {"type": "http", "tag": "only-tcp", "server": HOST, "server_port": 9},
        ],
        "route": {
            "rule_set": [{"type": "inline", "tag": "blocked", "rules": [{"port": 21}]}],
            "rules": [
                {"rule_set": "blocked", "action": "reject"},
                {"port": 33, "action": "route", "outbound": "only-tcp"},
            ],
            "final": "group",
        },
        "experimental": {"clash_api": {"external_controller": f"{HOST}:{api}"}},
    }
    flags = ["--audit-directory", root / "spool"] if audit else []

    def send(_):
        with socks(proxy, port) as c:
            c.sendall(b"hello")
            assert read_n(c, 5) == b"hello"

    def switch():
        r = urllib.request.Request(
            f"http://{HOST}:{api}/proxies/group",
            data=b'{"name":"second"}',
            method="PUT",
            headers={"Content-Type": "application/json"},
        )
        assert urllib.request.urlopen(r).status == 204

    with process(exe, root, "proxy", config, flags) as p:
        with socks(proxy, port) as old:
            old.sendall(b"before")
            assert read_n(old, 6) == b"before"
            switch()
            started = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(16) as pool:
                list(pool.map(send, range(512)))
            print("512 connections sec", time.monotonic() - started, flush=True)
            old.sendall(b"after")
            assert read_n(old, 5) == b"after"
            old.shutdown(socket.SHUT_WR)
            assert old.recv(1) == b""
        with socks(proxy, port) as c:
            block = b"x" * (1 << 16)
            start = time.monotonic()
            for i in range(256):
                c.sendall(block)
                assert read_n(c, len(block)) == block
            print("16 MiB each direction sec", time.monotonic() - start, flush=True)
        for dest in [21, free_port()]:
            try:
                with socks(proxy, dest) as c:
                    c.sendall(b"test")
                    reply = c.recv(1)
            except (AssertionError, OSError, EOFError):
                continue
            assert not reply, "unexpected traffic on rejected connection"
        with socks(proxy, 33, True) as u:
            u.send(b"\0\0\0" + address(33) + b"test")
            time.sleep(0.05)
        print(
            [
                line
                for line in pathlib.Path(f"/proc/{p.pid}/status")
                .read_text()
                .splitlines()
                if line.startswith(("VmHWM", "VmSwap"))
            ],
            flush=True,
        )
        if audit:
            with socks(proxy, port) as live:
                live.sendall(b"ongoing")
                assert read_n(live, 7) == b"ongoing"
                time.sleep(62)
                p.kill()
                p.wait()
    if audit:
        with process(exe, root, "restart", config, flags):
            pass
        files = sorted((root / "spool").glob("*.zst"))
        rows = list(
            map(
                json.loads,
                subprocess.check_output(["zstd", "-qdc", *files]).splitlines(),
            )
        )
        ends = [e for e in rows if e["event_type"] == "end"]
        assert (
            sum(
                e["upload_bytes"] == 5
                and e["download_bytes"] == 5
                and e["outbound_chain"] == ["group", "second"]
                for e in ends
            )
            == 512
        )
        assert any(
            e["upload_bytes"] == 11
            and e["download_bytes"] == 11
            and e["outbound_chain"] == ["group", "first"]
            for e in ends
        )
        assert any(
            e["upload_bytes"] == 16 << 20 and e["download_bytes"] == 16 << 20
            for e in ends
        )
        assert any(
            e["event_type"] == "snapshot" and e["upload_bytes"] == 7 for e in rows
        )
        for result in ("rejected", "selection_error", "dial_error"):
            assert any(e["result"] == result for e in rows), result
        print(
            "confirmed counters, rules, group switching, half-close, snapshot and SIGKILL recovery",
            flush=True,
        )


if __name__ == "__main__":
    main()
