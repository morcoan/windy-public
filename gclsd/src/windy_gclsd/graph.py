"""Convert a GclsdInput into torch_geometric Data objects.

Two granularities are supported:

* Instruction-level graph (legacy / sanity use): each instruction is a node.
* Basic-block-level graph (GCLSD spec): each basic block is a node, edges are
  CFG edges between blocks, and node features are pooled from the block's
  instructions.

The block-level graph also ships a cheap register liveness bitset that the
auxiliary dataflow heads can use as a supervised target.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

import torch
from torch_geometric.data import Data

from windy_gclsd.contract import GclsdInput


EDGE_KIND_TO_ID = {
    "fallthrough": 0,
    "unconditional": 1,
    "conditional": 2,
    "call": 3,
    "tail_call": 4,
    "indirect": 5,
    "return": 6,
}

# Canonical 64-bit register vocabulary for the auxiliary liveness head.
REGISTER_VOCAB = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]
REGEX_WORD_BOUNDARY = re.compile(r"\b(" + "|".join(REGISTER_VOCAB) + r")\b")


_TAG_RE = re.compile(r"[^a-z0-9_]+")


def _tokenize_for_registers(text: str) -> Set[str]:
    """Return any canonical registers appearing in ``text``."""
    text = text.lower()
    return set(REGEX_WORD_BOUNDARY.findall(text))


def _instruction_registers(
    instr, reg_vocab: List[str] = REGISTER_VOCAB
) -> Tuple[Set[str], Set[str]]:
    """Return (read_regs, written_regs) for a single instruction."""
    read_text = " ".join(instr.reads)
    write_text = " ".join(instr.writes)
    for mem in instr.mem_refs or []:
        if mem.base:
            read_text += " " + mem.base
        if mem.index:
            read_text += " " + mem.index
    return _tokenize_for_registers(read_text), _tokenize_for_registers(write_text)


def build_instruction_graph(inp: GclsdInput) -> Data:
    """Return a PyG Data object representing the function CFG at instruction
    granularity. Kept for backward compatibility with older tests.
    """
    ip_to_idx: Dict[int, int] = {instr.ip: i for i, instr in enumerate(inp.instructions)}
    block_entry_to_block = {block.entry_va: block for block in inp.blocks}

    edge_index: List[Tuple[int, int]] = []
    edge_kind: List[int] = []

    def add_edge(src_ip: int, tgt_ip: int, kind: str) -> None:
        if src_ip in ip_to_idx and tgt_ip in ip_to_idx:
            edge_index.append((ip_to_idx[src_ip], ip_to_idx[tgt_ip]))
            edge_kind.append(EDGE_KIND_TO_ID.get(kind, 0))

    for block in inp.blocks:
        ips = block.instr_ips
        for i in range(len(ips) - 1):
            add_edge(ips[i], ips[i + 1], "fallthrough")

        if ips:
            last_ip = ips[-1]
            for succ in block.successors:
                if succ.target == 0:
                    continue
                if succ.target in block_entry_to_block:
                    target_first_ip = block_entry_to_block[succ.target].instr_ips[0]
                else:
                    target_first_ip = succ.target
                add_edge(last_ip, target_first_ip, succ.kind)

    num_nodes = len(inp.instructions)
    if edge_index:
        ei = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        ek = torch.tensor(edge_kind, dtype=torch.long)
    else:
        ei = torch.empty((2, 0), dtype=torch.long)
        ek = torch.empty((0,), dtype=torch.long)

    return Data(
        edge_index=ei,
        edge_attr=ek,
        num_nodes=num_nodes,
        x=torch.zeros(num_nodes, 1),
        num_instr=num_nodes,
    )


def build_block_graph(inp: GclsdInput) -> Data:
    """Return a PyG Data object whose nodes are basic blocks.

    ``instr_token_ids`` and ``instr_token_mask`` are attached later by collate
    so the model can pool each block's instruction tokens into a node feature.
    """
    block_entry_to_idx = {block.entry_va: i for i, block in enumerate(inp.blocks)}

    edge_index: List[Tuple[int, int]] = []
    edge_kind: List[int] = []

    for src_idx, block in enumerate(inp.blocks):
        for succ in block.successors:
            if succ.target == 0:
                continue
            tgt_idx = block_entry_to_idx.get(succ.target)
            if tgt_idx is None:
                continue
            edge_index.append((src_idx, tgt_idx))
            edge_kind.append(EDGE_KIND_TO_ID.get(succ.kind, 0))

    num_nodes = len(inp.blocks)
    if edge_index:
        ei = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        ek = torch.tensor(edge_kind, dtype=torch.long)
    else:
        ei = torch.empty((2, 0), dtype=torch.long)
        ek = torch.empty((0,), dtype=torch.long)

    return Data(
        edge_index=ei,
        edge_attr=ek,
        num_nodes=num_nodes,
        x=torch.zeros(num_nodes, 1),
        num_blocks=num_nodes,
        # Map from instruction index to its block index; filled by collate.
        instr_to_block=torch.zeros(len(inp.instructions), dtype=torch.long),
    )


def compute_register_liveness(
    inp: GclsdInput,
    reg_vocab: Optional[List[str]] = None,
    max_iters: int = 100,
) -> torch.Tensor:
    """Return a (num_blocks, len(reg_vocab)) float bitset of live-out regs.

    The implementation is a standard backwards dataflow analysis over the CFG:

        live_out[B] = union live_in[S] for successors S of B
        live_in[B]  = use[B] union (live_out[B] - def[B])

    where ``use[B]`` are registers read before being written inside B, and
    ``def[B]`` are registers written anywhere in B.
    """
    if reg_vocab is None:
        reg_vocab = REGISTER_VOCAB
    reg_to_idx = {r: i for i, r in enumerate(reg_vocab)}
    num_blocks = len(inp.blocks)

    instr_by_ip = {instr.ip: instr for instr in inp.instructions}
    block_entry_to_idx = {block.entry_va: i for i, block in enumerate(inp.blocks)}

    # Per-block local use and def sets.
    local_use: List[Set[int]] = [set() for _ in range(num_blocks)]
    local_def: List[Set[int]] = [set() for _ in range(num_blocks)]
    succs: List[List[int]] = [[] for _ in range(num_blocks)]

    for bi, block in enumerate(inp.blocks):
        seen_def: Set[int] = set()
        for ip in block.instr_ips:
            instr = instr_by_ip.get(ip)
            if instr is None:
                continue
            reads, writes = _instruction_registers(instr, reg_vocab)
            for r in reads:
                idx = reg_to_idx.get(r)
                if idx is not None and idx not in seen_def:
                    local_use[bi].add(idx)
            for r in writes:
                idx = reg_to_idx.get(r)
                if idx is not None:
                    seen_def.add(idx)
                    local_def[bi].add(idx)
        for succ in block.successors:
            if succ.target == 0:
                continue
            tidx = block_entry_to_idx.get(succ.target)
            if tidx is not None:
                succs[bi].append(tidx)

    live_in: List[Set[int]] = [set() for _ in range(num_blocks)]
    live_out: List[Set[int]] = [set() for _ in range(num_blocks)]
    for _ in range(max_iters):
        changed = False
        for bi in range(num_blocks):
            new_out: Set[int] = set()
            for sj in succs[bi]:
                new_out |= live_in[sj]
            if new_out != live_out[bi]:
                live_out[bi] = new_out
                changed = True
            new_in = local_use[bi] | (live_out[bi] - local_def[bi])
            if new_in != live_in[bi]:
                live_in[bi] = new_in
                changed = True
        if not changed:
            break

    live_out_bits = torch.zeros(num_blocks, len(reg_vocab), dtype=torch.float32)
    for bi in range(num_blocks):
        for ridx in live_out[bi]:
            live_out_bits[bi, ridx] = 1.0
    return live_out_bits
