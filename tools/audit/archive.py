# /// script
# requires-python = ">=3.11"
# dependencies = ["duckdb==2.0.1"]
# ///
"""Archive sealed sing-box volumes and query the local DuckDB catalog."""

import argparse
import csv
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import duckdb

VOLUME = re.compile(r"(conn|dns)_(\d{4})(\d\d)(\d\d)T\d\dZ_[a-zA-Z0-9-]+\.jsonl\.zst")
COMMON = {
    "run_id": "VARCHAR",
    "event_type": "VARCHAR",
    "event_time": "BIGINT",
    "inbound_tag": "VARCHAR",
    "inbound_type": "VARCHAR",
    "auth_user": "VARCHAR",
    "network": "VARCHAR",
    "upload_bytes": "BIGINT",
    "download_bytes": "BIGINT",
}
COLUMNS = {
    "conn": dict(
        COMMON,
        conn_id="VARCHAR",
        seq="BIGINT",
        route_outbound="VARCHAR",
        route_rule="VARCHAR",
        outbound_chain="VARCHAR[]",
        requested_host="VARCHAR",
        requested_port="USMALLINT",
        target_ip="VARCHAR",
        routed_destination="VARCHAR",
        sniffed_domain="VARCHAR",
        result="VARCHAR",
        error="VARCHAR",
    ),
    "dns": dict(
        COMMON,
        request_id="VARCHAR",
        questions="STRUCT(Name VARCHAR, Qtype USMALLINT, Qclass USMALLINT)[]",
        resolver="VARCHAR",
        cache_hit="BOOLEAN",
        upstreams="VARCHAR[]",
        rcode="INTEGER",
        answers="VARCHAR[]",
        truncated="BOOLEAN",
        resolve_error="VARCHAR",
        write_error="VARCHAR",
    ),
}


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def sync(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def setup(db, root):
    db.execute(
        "CREATE TABLE IF NOT EXISTS volumes(name VARCHAR PRIMARY KEY, sha256 VARCHAR NOT NULL)"
    )
    db.execute("""CREATE TABLE IF NOT EXISTS accounts(inbound_tag VARCHAR, auth_user VARCHAR,
               account_id VARCHAR NOT NULL, PRIMARY KEY(inbound_tag,auth_user))""")
    for kind, columns in COLUMNS.items():
        base = root / "parquet" / kind
        base.mkdir(parents=True, exist_ok=True)
        # A typed empty file makes the views usable before the first DNS or connection.
        empty = base / "empty.parquet"
        fields = ", ".join(f'NULL::{t} AS "{k}"' for k, t in columns.items())
        db.execute(
            f"COPY (SELECT {fields} WHERE FALSE) TO ? (FORMAT parquet)",
            [str(empty) + ".tmp"],
        )
        os.replace(str(empty) + ".tmp", empty)
        paths = literal(base / "**/*.parquet")
        db.execute(f"""CREATE OR REPLACE VIEW {kind}_events AS SELECT * FROM
                    read_parquet({paths}, hive_partitioning=false, union_by_name=true)
                    QUALIFY row_number() OVER (PARTITION BY
                    {"conn_id, seq" if kind == "conn" else "request_id, event_type"}
                    ORDER BY event_time DESC)=1""")
    db.execute(Path(__file__).with_name("views.sql").read_text())


def ingest(db, root, path):
    match = VOLUME.fullmatch(path.name)
    if not match or path.is_symlink() or not path.is_file():
        raise ValueError(f"invalid sealed volume: {path}")
    kind, year, month, day = match.groups()
    checksum = digest(path)
    raw = root / "raw" / path.name
    partition = root / "parquet" / kind / f"day={year}-{month}-{day}"
    parquet = partition / (path.name + ".parquet")
    row = db.execute("SELECT sha256 FROM volumes WHERE name=?", [path.name]).fetchone()
    if row and row[0] != checksum:
        raise ValueError(f"volume name reused with different contents: {path.name}")
    if raw.exists() and digest(raw) != checksum:
        raise ValueError(f"archived bytes differ: {raw}")
    if row and raw.exists() and parquet.exists():
        return checksum

    partition.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=root) as staging:
        staged = Path(staging) / path.name
        shutil.copyfile(path, staged)
        if digest(staged) != checksum:
            raise ValueError(f"source changed during import: {path}")
        subprocess.run(["zstd", "-qt", "--", staged], check=True)
        values = db.read_json(
            str(staged),
            columns=COLUMNS[kind],
            format="newline_delimited",
            compression="zstd",
        )
        values.create_view("incoming", replace=True)
        key = "conn_id" if kind == "conn" else "request_id"
        if db.execute(
            f"SELECT count(*) FROM incoming WHERE {key} IS NULL OR event_time IS NULL OR event_type IS NULL"
        ).fetchone()[0]:
            raise ValueError(f"missing event identity: {path}")
        tmp = Path(staging) / "events.parquet"
        db.execute("COPY incoming TO ? (FORMAT parquet, COMPRESSION zstd)", [str(tmp)])
        for src, dst in [(staged, raw), (tmp, parquet)]:
            sync(src)
            os.replace(src, dst)
            sync(dst.parent)
        sync(partition.parent)
        sync(root)
        db.execute("INSERT OR IGNORE INTO volumes VALUES (?, ?)", [path.name, checksum])
    return checksum


# Runs on the source host. Only immutable, sealed files with the acknowledged
# content hash qualify, including when a previous acknowledgement was interrupted.
ACK = """
import hashlib,json,os,sys
from pathlib import Path
root=Path(sys.argv[1])
for name,expected in json.load(sys.stdin):
    if Path(name).name!=name or not name.endswith('.jsonl.zst'): raise ValueError(name)
    p=root/name
    if p.is_symlink(): raise ValueError(name)
    if not p.exists(): continue
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    if h.hexdigest()!=expected:raise ValueError('source changed: '+name)
    p.unlink()
"""


def pull(db, root, source, remove):
    with tempfile.TemporaryDirectory(dir=root) as staging:
        subprocess.run(
            [
                "rsync",
                "-rtcs",
                "--fsync",
                "--link-dest=" + str(root / "raw"),
                "--include=conn_*.jsonl.zst",
                "--include=dns_*.jsonl.zst",
                "--exclude=*",
                "--",
                source.rstrip("/") + "/",
                staging + "/",
            ],
            check=True,
        )
        receipts = [
            (p.name, ingest(db, root, p)) for p in sorted(Path(staging).iterdir())
        ]
        if remove and receipts:
            if ":" in source:
                host, path = source.split(":", 1)
                command = ["ssh", "--", host, shlex.join(["python3", "-c", ACK, path])]
            else:
                command = [sys.executable, "-c", ACK, source]
            subprocess.run(command, input=json.dumps(receipts), text=True, check=True)
        print(f"verified {len(receipts)} volumes")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("import").add_argument("source", type=Path)
    pull_parser = sub.add_parser("pull")
    pull_parser.add_argument("source", help="directory or SSH host:/absolute/path")
    pull_parser.add_argument("--remove-source", action="store_true")
    sub.add_parser("query").add_argument("sql", help="SQL query; writes CSV to stdout")
    args = parser.parse_args()
    root = args.archive.resolve()
    os.umask(0o077)
    if args.command == "query":
        with duckdb.connect(str(root / "audit.duckdb"), read_only=True) as db:
            cur = db.execute(args.sql)
            out = csv.writer(sys.stdout)
            out.writerow(c[0] for c in cur.description)
            while batch := cur.fetchmany(4096):
                out.writerows(batch)
        return
    (root / "raw").mkdir(parents=True, exist_ok=True)
    with duckdb.connect(str(root / "audit.duckdb")) as db:
        setup(db, root)
        if args.command == "pull":
            if ":" not in args.source and Path(args.source).resolve().is_relative_to(
                root
            ):
                parser.error("pull source must be outside the archive")
            pull(db, root, args.source, args.remove_source)
        else:
            for p in sorted(args.source.iterdir()):
                if VOLUME.fullmatch(p.name):
                    ingest(db, root, p)


if __name__ == "__main__":
    main()
