# /// script
# requires-python = ">=3.11"
# dependencies = ["dnspython>=2.7,<3"]
# ///
"""Run two proxy clients and two deterministic DNS upstreams on loopback."""

import argparse
import contextlib
import json
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from collections import Counter
from pathlib import Path

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

HOST = "127.0.0.1"


def bound(kind=socket.SOCK_STREAM):
    sock = socket.socket(socket.AF_INET, kind)
    sock.bind((HOST, 0))
    return sock


def free_port(kind=socket.SOCK_STREAM):
    with bound(kind) as sock:
        return sock.getsockname()[1]


def read_n(conn, n):
    data = bytearray()
    while len(data) < n:
        part = conn.recv(n - len(data))
        if not part:
            raise EOFError("connection closed")
        data.extend(part)
    return bytes(data)


def address(port):
    return b"\x01" + socket.inet_aton(HOST) + struct.pack("!H", port)


@contextlib.contextmanager
def socks(port, dst, udp=False):
    with socket.create_connection((HOST, port), timeout=5) as conn:
        conn.sendall(b"\x05\x01\x00")
        assert read_n(conn, 2) == b"\x05\x00"
        conn.sendall(bytes([5, 3 if udp else 1, 0]) + address(0 if udp else dst))
        response = read_n(conn, 10)
        assert response[:2] == b"\x05\x00", response
        if udp:
            with bound(socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.connect((HOST, int.from_bytes(response[-2:])))
                yield sock
        else:
            yield conn


def dns_server(sock, received):
    while True:
        data, peer = sock.recvfrom(65535)
        query = dns.message.from_wire(data)
        question = query.question[0]
        name = question.name.to_text()
        received[name] += 1
        reply = dns.message.make_response(query)
        if name == "timeout.test.":
            continue
        if name == "absent.test.":
            reply.set_rcode(dns.rcode.NXDOMAIN)
        elif name == "large.test.":
            reply.answer.append(
                dns.rrset.from_text(
                    name, 60, "IN", "TXT", *[f'"{i:03d}{"x" * 120}"' for i in range(12)]
                )
            )
        elif name == "svc.test.":
            reply.answer.append(
                dns.rrset.from_text(name, 60, "IN", "HTTPS", '1 . alpn="h2"')
            )
        else:
            reply.answer.append(
                dns.rrset.from_text(name, 60, "IN", "CNAME", "target.test.")
            )
            reply.answer.append(
                dns.rrset.from_text("target.test.", 60, "IN", "A", "192.0.2.1")
            )
        sock.sendto(reply.to_wire(max_size=65535), peer)


@contextlib.contextmanager
def process(exe, root, name, config, flags):
    path = root / (name + ".json")
    path.write_text(json.dumps(config))
    log = root / (name + ".log")
    with log.open("w") as output:
        proc = subprocess.Popen(
            [exe, "run", "-c", path, *flags], stdout=output, stderr=subprocess.STDOUT
        )
    try:
        for _ in range(200):
            if "sing-box started" in log.read_text():
                break
            if proc.poll() is not None:
                raise RuntimeError(log.read_text())
            time.sleep(0.025)
        else:
            raise TimeoutError(log.read_text())
        yield proc
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=15)


def exercise(port):
    with socks(port, 53, udp=True) as sock:
        for name in ["repeat.test", "repeat.test", "svc.test", "large.test"]:
            query = dns.message.make_query(
                name, {"svc.test": "HTTPS", "large.test": "TXT"}.get(name, "A")
            )
            sock.send(b"\0\0\0" + address(53) + query.to_wire())
            reply = dns.message.from_wire(sock.recv(65535)[10:])
            assert reply.id == query.id
            if name == "large.test":
                assert reply.flags & dns.flags.TC
            else:
                assert reply.answer
    with socks(port, 53) as conn:
        queries = [
            dns.message.make_query(name, "A") for name in ("repeat.test", "absent.test")
        ]
        for query in queries:
            wire = query.to_wire()
            conn.sendall(struct.pack("!H", len(wire)) + wire)
        replies = {}
        for _ in queries:
            msg = dns.message.from_wire(read_n(conn, int.from_bytes(read_n(conn, 2))))
            replies[msg.id] = msg.rcode()
        assert [replies[q.id] for q in queries] == [0, 3]
    with socks(port, 53) as conn:
        wire = dns.message.make_query("timeout.test", "A").to_wire()
        conn.sendall(struct.pack("!H", len(wire)) + wire)
        assert not conn.recv(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="omit audit flag; check upstream behavior",
    )
    parser.add_argument(
        "--output", type=Path, help="new directory for records and logs"
    )
    args = parser.parse_args()
    with contextlib.ExitStack() as stack:
        if args.output:
            root = args.output.resolve()
            root.mkdir(mode=0o700)
        else:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        exe = str(args.binary.resolve())
        upstreams = []
        counts = []
        for tag in ["default", "media"]:
            sock = stack.enter_context(bound(socket.SOCK_DGRAM))
            count = Counter()
            counts.append(count)
            threading.Thread(target=dns_server, args=(sock, count), daemon=True).start()
            upstreams.append(
                {
                    "type": "udp",
                    "tag": tag,
                    "server": HOST,
                    "server_port": sock.getsockname()[1],
                }
            )
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-keyout",
                str(root / "key"),
                "-out",
                str(root / "crt"),
            ],
            check=True,
            capture_output=True,
        )
        identity = str(uuid.uuid4())
        vp, hp = free_port(), free_port(socket.SOCK_DGRAM)
        ports = [free_port(), free_port()]
        server = {
            "inbounds": [
                {
                    "type": "vless",
                    "tag": "vless-in",
                    "listen": HOST,
                    "listen_port": vp,
                    "users": [{"name": "alice", "uuid": identity}],
                },
                {
                    "type": "hysteria2",
                    "tag": "hy-in",
                    "listen": HOST,
                    "listen_port": hp,
                    "users": [{"name": "alice", "password": "local-only"}],
                    "tls": {
                        "enabled": True,
                        "certificate_path": str(root / "crt"),
                        "key_path": str(root / "key"),
                    },
                },
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "selector", "tag": "inner", "outbounds": ["direct"]},
                {"type": "selector", "tag": "outer", "outbounds": ["inner"]},
            ],
            "dns": {
                "servers": upstreams,
                "rules": [
                    {
                        "domain": ["svc.test", "large.test"],
                        "action": "route",
                        "server": "media",
                    }
                ],
                "final": "default",
                "timeout": "500ms",
            },
            "route": {
                "rules": [{"port": 53, "action": "hijack-dns"}],
                "final": "outer",
                "default_domain_resolver": "default",
            },
        }
        client = {
            "inbounds": [
                {"type": "socks", "tag": f"in{i}", "listen": HOST, "listen_port": p}
                for i, p in enumerate(ports)
            ],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "v",
                    "server": HOST,
                    "server_port": vp,
                    "uuid": identity,
                },
                {
                    "type": "hysteria2",
                    "tag": "h",
                    "server": HOST,
                    "server_port": hp,
                    "password": "local-only",
                    "tls": {"enabled": True, "insecure": True},
                },
            ],
            "route": {
                "rules": [
                    {"inbound": "in0", "action": "route", "outbound": "v"},
                    {"inbound": "in1", "action": "route", "outbound": "h"},
                ]
            },
        }
        flags = [] if args.baseline else ["--audit-directory", root / "audit"]
        with (
            process(exe, root, "server", server, flags) as service,
            process(exe, root, "client", client, []),
        ):
            for port in ports:
                exercise(port)
            status = Path(f"/proc/{service.pid}/status").read_text().splitlines()
            print(next(line for line in status if line.startswith("VmHWM:")))
        assert counts[0]["repeat.test."] == 1, counts
        assert counts[1]["svc.test."] == 1 and counts[0]["svc.test."] == 0, counts
        if not args.baseline:
            volumes = list((root / "audit").glob("dns_*.jsonl.zst"))
            rows = [
                json.loads(line)
                for line in subprocess.check_output(
                    ["zstd", "-qdc", *volumes]
                ).splitlines()
            ]
            starts = {e["request_id"] for e in rows if e["event_type"] == "start"}
            ends = [e for e in rows if e["event_type"] == "end"]
            assert (
                len(rows) == 28
                and len(ends) == 14
                and starts == {e["request_id"] for e in ends}
            ), rows
            assert Counter(e["inbound_tag"] for e in ends) == {
                "hy-in": 7,
                "vless-in": 7,
            }
            assert all(
                e["auth_user"] == "alice" and e["upload_bytes"] > 0 for e in ends
            )
            for e in ends:
                name = e["questions"][0]["Name"]
                if name == "timeout.test.":
                    assert e["resolve_error"] and e["download_bytes"] == 0, e
                else:
                    assert e["resolver"] == (
                        "media" if name in {"svc.test.", "large.test."} else "default"
                    ), e
                    assert e["download_bytes"] > 0
                if name == "large.test.":
                    assert e["truncated"]
                if name == "absent.test.":
                    assert e["rcode"] == 3
            repeats = [e for e in ends if e["questions"][0]["Name"] == "repeat.test."]
            assert sum(e["cache_hit"] for e in repeats) == 5
            assert sum(len(e.get("upstreams", [])) for e in repeats) == 1
            assert not list((root / "audit").glob("conn_*.jsonl.zst"))
        print("14 client DNS requests verified", counts)


if __name__ == "__main__":
    main()
