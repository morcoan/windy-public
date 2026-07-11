"""Real smoke test: load LLM4Decompile and decompile a tiny function."""

from __future__ import annotations

import sys
import time

import windy_gclsd.server as srv
from windy_gclsd.contract import GclsdInstr, GclsdInput, GclsdBlock

# Windows console defaults to cp1252; force UTF-8 so BPE chars print.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except AttributeError:
    pass


def main() -> None:
    # A realistic GCC -O0 function: int f() { return 1; }
    #   pushq %rbp       -> 55
    #   movq %rsp, %rbp  -> 48 89 e5
    #   movl $1, %eax    -> b8 01 00 00 00
    #   popq %rbp        -> 5d
    #   retq             -> c3
    g = GclsdInput(
        name="func0",
        entry_va=0x1000,
        image_base=0x1000_0000,
        bitness=64,
        calling_conv=None,
        params=[],
        return_type="int",
        instructions=[
            GclsdInstr(
                ip=0x1000, bytes_hex="55", mnemonic="push",
                operands="rbp", operands_annotated=None,
                flow="Next", class_="Logic", reads=[], writes=["rbp", "rsp"],
                mem_refs=[],
            ),
            GclsdInstr(
                ip=0x1001, bytes_hex="4889e5", mnemonic="mov",
                operands="rbp, rsp", operands_annotated=None,
                flow="Next", class_="Logic", reads=["rsp"], writes=["rbp"],
                mem_refs=[],
            ),
            GclsdInstr(
                ip=0x1004, bytes_hex="b801000000", mnemonic="mov",
                operands="eax, 1", operands_annotated=None,
                flow="Next", class_="Logic", reads=[], writes=["rax"],
                mem_refs=[],
            ),
            GclsdInstr(
                ip=0x1009, bytes_hex="5d", mnemonic="pop",
                operands="rbp", operands_annotated=None,
                flow="Next", class_="Logic", reads=["rsp"], writes=["rbp"],
                mem_refs=[],
            ),
            GclsdInstr(
                ip=0x100a, bytes_hex="c3", mnemonic="ret",
                operands="", operands_annotated=None,
                flow="Return", class_="ControlFlow", reads=["rsp"],
                writes=[], mem_refs=[],
            ),
        ],
        blocks=[
            GclsdBlock(entry_va=0x1000, instr_ips=[0x1000, 0x1001, 0x1004, 0x1009, 0x100a], successors=[]),
        ],
        xrefs_in=[],
        xrefs_out=[],
    )

    t0 = time.time()
    srv._load_model()
    print(f"[load] {time.time()-t0:.1f}s")

    asm = srv.build_asm_text(g)
    print(f"[asm]\n{asm}\n")

    t0 = time.time()
    out = srv._generate(asm)
    print(f"[generate] {time.time()-t0:.1f}s")
    print(f"[pseudocode]\n{out}")


if __name__ == "__main__":
    main()
