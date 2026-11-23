"""Regression cases for replayed volumes, UTC boundaries and interrupted requests."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import duckdb
from archive import ingest, setup


class ArchiveTest(unittest.TestCase):
    def test_replay_across_midnight_and_restart(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            raw = root / "raw"
            raw.mkdir()
            midnight = 86400000
            identity = {"inbound_tag": "v", "auth_user": "alice", "run_id": "old"}
            start = dict(
                identity,
                conn_id="one",
                event_type="start",
                event_time=midnight - 2,
                seq=0,
                upload_bytes=0,
                download_bytes=0,
            )
            snap = dict(
                start,
                event_type="snapshot",
                event_time=midnight - 1,
                seq=1,
                upload_bytes=7,
            )
            final = dict(
                snap, seq=2, event_type="end", event_time=midnight + 1, upload_bytes=10
            )
            marker = dict(
                start, event_type="run_closed", conn_id="old", event_time=midnight + 3
            )
            dns = dict(
                identity,
                request_id="q",
                event_type="start",
                event_time=midnight - 1,
                questions=[{"Name": "example.", "Qtype": 1, "Qclass": 1}],
                upload_bytes=35,
                download_bytes=0,
            )
            with duckdb.connect(str(root / "audit.duckdb")) as db:
                setup(db, root)
                for name, events in [
                    ("conn_19700101T23Z_a", [start, snap]),
                    ("conn_19700102T00Z_b", [snap, final, marker]),
                    ("dns_19700101T23Z_c", [dns]),
                ]:
                    path = root / (name + ".jsonl.zst")
                    data = "".join(json.dumps(e) + "\n" for e in events)
                    path.write_bytes(
                        subprocess.check_output(["zstd", "-qc"], input=data.encode())
                    )
                    ingest(db, root, path)
                    ingest(db, root, path)
                self.assertEqual(
                    db.execute("SELECT count(*) FROM connections").fetchone(), (1,)
                )
                self.assertEqual(
                    db.execute("SELECT state FROM dns_requests").fetchone(),
                    ("interrupted",),
                )
                self.assertEqual(
                    db.execute(
                        "SELECT sum(upload_bytes) FROM daily_usage GROUP BY utc_day ORDER BY utc_day"
                    ).fetchall(),
                    [(42,), (3,)],
                )
                path.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "different contents"):
                    ingest(db, root, path)


if __name__ == "__main__":
    unittest.main()
