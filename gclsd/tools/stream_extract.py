"""Stream-concatenate split tar.xz parts directly into tar extraction.

Usage:
    python stream_extract.py output_dir part1 part2 part3 ...

This avoids creating an intermediate concatenated .tar.xz file. Each part is
read in chunks and written to tar's stdin.
"""

import argparse
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Stream-concatenate tar parts")
    parser.add_argument("output_dir", help="Directory to extract into")
    parser.add_argument("parts", nargs="+", help="Ordered split parts")
    args = parser.parse_args()

    proc = subprocess.Popen(
        ["tar", "-xf", "-"],
        stdin=subprocess.PIPE,
        cwd=args.output_dir,
    )
    assert proc.stdin is not None

    chunk_size = 4 * 1024 * 1024
    written = 0
    for part_path in args.parts:
        with open(part_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                proc.stdin.write(chunk)
                written += len(chunk)

    proc.stdin.close()
    returncode = proc.wait()
    print(f"Wrote {written} bytes ({written / 1024 / 1024 / 1024:.2f} GiB); tar exit={returncode}")
    return returncode


if __name__ == "__main__":
    sys.exit(main())
