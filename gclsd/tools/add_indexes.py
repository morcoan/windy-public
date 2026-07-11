import sqlite3
import sys
from pathlib import Path


def add_indexes(db_path: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    tables = {
        "functions": ["binary_id"],
        "rvas": ["function_id"],
        "lines": ["function_id"],
    }
    for table, columns in tables.items():
        for col in columns:
            idx_name = f"idx_{table}_{col}"
            print(f"Creating {idx_name}...")
            conn.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table}({col})")

    conn.commit()
    conn.close()
    print("Done.")


if __name__ == "__main__":
    add_indexes(Path(sys.argv[1]))
