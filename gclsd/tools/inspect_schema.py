import sqlite3
import sys
from pathlib import Path


def inspect(db_path: Path) -> None:
    uri = f"file:{db_path}?mode=ro".replace("\\", "/")
    conn = sqlite3.connect(uri, uri=True)
    print(f"--- {db_path} ---")
    print("Tables:")
    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        print(f"  {row[0]}")

    for table in ["binaries", "functions", "rvas", "lines", "pdbs"]:
        print(f"\n{table} schema:")
        try:
            for row in conn.execute(f"PRAGMA table_info({table})"):
                print(f"  {row}")
        except Exception as e:
            print(f"  error: {e}")

    # Sample counts.
    for table in ["binaries", "functions", "rvas", "lines", "pdbs"]:
        try:
            (count,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            print(f"  {table}: {count:,} rows")
        except Exception as e:
            pass

    conn.close()


if __name__ == "__main__":
    inspect(Path(sys.argv[1]))
