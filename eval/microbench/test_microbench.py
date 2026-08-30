from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from eval.microbench import microbench


class MicrobenchTests(unittest.TestCase):
    def test_schema_is_small_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bench.sqlite"
            conn = microbench.connect(path)
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            conn.close()
            self.assertTrue({"targets", "cases", "runs", "results", "steps", "hypotheses"} <= tables)
            self.assertLess(path.stat().st_size, microbench.MAX_DB_BYTES)

    def test_deterministic_oracles(self) -> None:
        self.assertEqual(microbench.score("exact_va", json.dumps("0x140001000"), "0x140001000"), (True, False, False))
        self.assertEqual(microbench.score("exact_text", json.dumps("UNKNOWN"), "0x140001000"), (False, False, True))
        self.assertEqual(microbench.score("exact_text", json.dumps("CONTRADICTED"), "CONTRADICTED"), (True, False, False))
        self.assertTrue(microbench.score("contains_all", json.dumps(["byte", "xor"]), "BYTE then XOR")[0])

    def test_map_parser_rejects_ambiguous_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.map"
            path.write_text(
                " 0001:00000000 mx_a 0000000140001000 f x.obj\n"
                " 0001:00000010 mx_a 0000000140001010 f x.obj\n"
                " 0001:00000020 mx_b 0000000140001020 f x.obj\n",
                encoding="utf-8",
            )
            parsed = microbench.parse_map(path)
            self.assertNotIn("mx_a", parsed)
            self.assertEqual(parsed["mx_b"], 0x140001020)

    def test_sidecar_ingest_enforces_limits_and_scores(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db = root / "bench.sqlite"
            conn = microbench.connect(db)
            target_id = conn.execute(
                "INSERT INTO targets(program,profile,path,sha256) VALUES('a','P0','x.exe','abc')"
            ).lastrowid
            conn.execute(
                "INSERT INTO cases VALUES(?,?,?,?,?,?,?,?,?,?)",
                ("case", "canary", "locate", target_id, "question", "exact_va",
                 json.dumps("0x140001000"), 2, 512, 250),
            )
            conn.commit(); conn.close()
            sidecars = root / "sidecars"; sidecars.mkdir()
            (sidecars / "case.json").write_text(json.dumps({
                "case_id":"case", "answer":"0x140001000", "wall_ms":4,
                "steps":[{"tool":"investigation_start","arguments":{},"response_bytes":100,"latency_ms":3}],
            }), encoding="utf-8")
            microbench.ingest(root, Path("bench.sqlite"), "run", "v03", Path("sidecars"), "luna", "low", "test")
            conn = sqlite3.connect(db)
            row = conn.execute("SELECT success,tool_calls,tool_bytes FROM results").fetchone()
            conn.close()
            self.assertEqual(row, (1, 1, 100))


if __name__ == "__main__":
    unittest.main()
