"""Batching helpers for the GCLSD model.

The collate builder constructs:

* An asm token sequence with block-boundary markers.
* A basic-block-level CFG (PyG Batch).
* A decoder prefix of C tokens for teacher-forced training.
* Auxiliary targets: sampled CFG edge pairs + register live-out bitsets.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import torch
import torch.nn.functional as F
from torch_geometric.data import Batch

from windy_gclsd.contract import GclsdInput
from windy_gclsd.graph import build_block_graph, compute_register_liveness
from windy_gclsd.tokenizer import AsmTokenizer, OutputTokenizer


@dataclass
class GclsdBatch:
    """Everything a GCLSD model needs in a single forward pass."""

    # Asm sequence tokens and block-boundary positions.
    asm_input_ids: torch.Tensor
    asm_attention_mask: torch.Tensor
    token_to_block: torch.Tensor  # -1 everywhere except first token of each block

    # Batched PyG block-level graph with instruction token ids/mask attached.
    graph: Batch

    # Output-token decoder prefix (teacher-forced C generation).
    output_input_ids: torch.Tensor
    output_attention_mask: torch.Tensor

    # Full-sequence labels: -100 for asm positions and output padding.
    labels: torch.Tensor

    # Auxiliary targets (training only).
    edge_pairs: torch.Tensor
    liveness_targets: torch.Tensor
    num_positive_edges: torch.Tensor  # per batch


_MAX_EDGE_NEGATIVES = 64


def collate_gclsd_batch(
    inputs: List[GclsdInput],
    asm_tokenizer: AsmTokenizer,
    output_tokenizer: Optional[OutputTokenizer] = None,
    ground_truth: Optional[List[str]] = None,
    max_asm_length: Optional[int] = None,
    max_output_length: Optional[int] = None,
    max_edges_per_sample: int = _MAX_EDGE_NEGATIVES,
    device: torch.device = torch.device("cpu"),
) -> GclsdBatch:
    """Build a :class:`GclsdBatch` from raw Rust-exported inputs."""
    pad_id = asm_tokenizer.pad_id
    out_pad: Optional[int] = None
    bos_id: Optional[int] = None

    # ------------------------------------------------------------------
    # Tokenize assembly and discover block boundaries.
    # ------------------------------------------------------------------
    asm_ids_list: List[List[int]] = []
    token_to_block_list: List[List[int]] = []
    graphs = []
    all_live_out_bits: List[torch.Tensor] = []
    all_edge_pairs: List[torch.Tensor] = []
    num_positive_edges_list: List[int] = []

    for inp in inputs:
        asm_ids, token_to_instr = asm_tokenizer.encode(inp, max_length=max_asm_length)

        # Map instruction index -> block index.
        instr_to_block = [-1] * len(inp.instructions)
        for bi, block in enumerate(inp.blocks):
            for ip in block.instr_ips:
                for ii, instr in enumerate(inp.instructions):
                    if instr.ip == ip:
                        instr_to_block[ii] = bi
                        break

        # Mark the first asm token of each block as a boundary token.
        token_to_block = [-1] * len(asm_ids)
        seen_block: set[int] = set()
        for tok_pos, instr_idx in enumerate(token_to_instr):
            if instr_idx < 0:
                continue
            blk = instr_to_block[instr_idx]
            if blk >= 0 and blk not in seen_block:
                token_to_block[tok_pos] = blk
                seen_block.add(blk)

        asm_ids_list.append(asm_ids)
        token_to_block_list.append(token_to_block)

        graph = build_block_graph(inp)
        instr_ids = asm_tokenizer.encode_instructions(inp)
        num_nodes = len(instr_ids)
        max_node_len = max((len(ids) for ids in instr_ids), default=1)
        node_token_ids = torch.full(
            (num_nodes, max_node_len), pad_id, dtype=torch.long, device=device
        )
        node_token_mask = torch.zeros(
            (num_nodes, max_node_len), dtype=torch.bool, device=device
        )
        for i, ids in enumerate(instr_ids):
            if ids:
                length = len(ids)
                node_token_ids[i, :length] = torch.tensor(ids, dtype=torch.long, device=device)
                node_token_mask[i, :length] = True
        graph.instr_token_ids = node_token_ids
        graph.instr_token_mask = node_token_mask
        graphs.append(graph)

        # Auxiliary targets.
        live_out = compute_register_liveness(inp)
        all_live_out_bits.append(live_out.to(device))

        edge_pairs, num_pos = _sample_edges(graph, max_edges_per_sample, device)
        all_edge_pairs.append(edge_pairs)
        num_positive_edges_list.append(num_pos)

    # ------------------------------------------------------------------
    # Pad asm sequences.
    # ------------------------------------------------------------------
    max_asm = max(len(ids) for ids in asm_ids_list)
    if max_asm_length:
        max_asm = min(max_asm, max_asm_length)
    B = len(inputs)
    asm_input_ids = torch.full((B, max_asm), pad_id, dtype=torch.long, device=device)
    asm_attention_mask = torch.zeros((B, max_asm), dtype=torch.bool, device=device)
    token_to_block_tensor = torch.full((B, max_asm), -1, dtype=torch.long, device=device)

    max_node_len = max(g.instr_token_ids.size(1) for g in graphs)
    for g in graphs:
        n, cur_len = g.instr_token_ids.shape
        if cur_len < max_node_len:
            pad_ids = torch.full((n, max_node_len - cur_len), pad_id, dtype=torch.long, device=device)
            pad_mask = torch.zeros((n, max_node_len - cur_len), dtype=torch.bool, device=device)
            g.instr_token_ids = torch.cat([g.instr_token_ids, pad_ids], dim=1)
            g.instr_token_mask = torch.cat([g.instr_token_mask, pad_mask], dim=1)

    graph_batch = Batch.from_data_list(graphs).to(device)
    node_offsets = graph_batch.ptr[:-1].tolist()

    for i, asm_ids in enumerate(asm_ids_list):
        length = min(len(asm_ids), max_asm)
        asm_input_ids[i, :length] = torch.tensor(asm_ids[:length], dtype=torch.long, device=device)
        asm_attention_mask[i, :length] = True
        offset = node_offsets[i]
        for j in range(length):
            blk = token_to_block_list[i][j]
            if blk >= 0:
                token_to_block_tensor[i, j] = offset + blk

    # ------------------------------------------------------------------
    # Build output decoder prefix and full-sequence labels.
    # ------------------------------------------------------------------
    if output_tokenizer is None or ground_truth is None:
        raise ValueError("GCLSD training batch requires output_tokenizer and ground_truth")

    out_pad = output_tokenizer.tokenizer.pad_token_id
    if out_pad is None:
        out_pad = output_tokenizer.tokenizer.eos_token_id
    assert out_pad is not None
    bos_id = output_tokenizer.tokenizer.bos_token_id
    if bos_id is None:
        bos_id = out_pad

    out_ids_list = [
        output_tokenizer.encode(text, max_length=max_output_length)
        for text in ground_truth
    ]
    max_out = max(len(ids) for ids in out_ids_list)
    if max_output_length:
        max_out = min(max_out, max_output_length)
    decoder_len = max(0, max_out - 1)

    output_input_ids = torch.full((B, decoder_len), out_pad, dtype=torch.long, device=device)
    output_attention_mask = torch.zeros((B, decoder_len), dtype=torch.bool, device=device)
    labels = torch.full((B, max_asm + decoder_len), -100, dtype=torch.long, device=device)

    for i, ids in enumerate(out_ids_list):
        ids = ids[:max_out]
        if len(ids) >= 2:
            # decoder input = output[:-1], target = output[1:]
            input_ids = ids[:-1]
            target_ids = ids[1:]
            length = len(input_ids)
            output_input_ids[i, :length] = torch.tensor(input_ids, dtype=torch.long, device=device)
            output_attention_mask[i, :length] = True
            labels[i, max_asm : max_asm + length] = torch.tensor(
                target_ids, dtype=torch.long, device=device
            )
        elif len(ids) == 1:
            output_input_ids[i, 0] = ids[0]
            output_attention_mask[i, 0] = True
            labels[i, max_asm] = ids[0]

    # ------------------------------------------------------------------
    # Pad auxiliary targets.
    # ------------------------------------------------------------------
    num_registers = all_live_out_bits[0].shape[-1]
    max_blocks = max(g.num_nodes for g in graphs)
    liveness_targets = torch.zeros(B, max_blocks, num_registers, dtype=torch.float32, device=device)
    for i, bits in enumerate(all_live_out_bits):
        n = bits.size(0)
        liveness_targets[i, :n] = bits

    max_edges = max(p.size(0) for p in all_edge_pairs)
    edge_pairs_tensor = torch.full((B, max_edges, 2), -1, dtype=torch.long, device=device)
    for i, pairs in enumerate(all_edge_pairs):
        n = pairs.size(0)
        edge_pairs_tensor[i, :n] = pairs
    num_positive_edges = torch.tensor(num_positive_edges_list, dtype=torch.long, device=device)

    return GclsdBatch(
        asm_input_ids=asm_input_ids,
        asm_attention_mask=asm_attention_mask,
        token_to_block=token_to_block_tensor,
        graph=graph_batch,
        output_input_ids=output_input_ids,
        output_attention_mask=output_attention_mask,
        labels=labels,
        edge_pairs=edge_pairs_tensor,
        liveness_targets=liveness_targets,
        num_positive_edges=num_positive_edges,
    )


def _sample_edges(
    graph: Batch,
    max_negatives: int,
    device: torch.device,
) -> Tuple[torch.Tensor, int]:
    """Sample positive CFG edges + random negatives for the edge-existence head.

    Returns:
        pairs: (num_sampled, 2) tensor of block-index pairs (local indices).
        num_positive: number of positive pairs in ``pairs``.
    """
    num_blocks = graph.num_nodes
    if num_blocks <= 1:
        return torch.zeros((0, 2), dtype=torch.long, device=device), 0

    if graph.edge_index.numel() == 0:
        positives = torch.empty((0, 2), dtype=torch.long)
    else:
        positives = graph.edge_index.t().cpu()  # (E, 2)

    # Generate random negatives that are not real edges.
    pos_set = set((int(s), int(t)) for s, t in positives.tolist())
    negatives: List[Tuple[int, int]] = []
    attempts = 0
    while len(negatives) < min(max_negatives, num_blocks * num_blocks) and attempts < max_negatives * 10:
        s = int(torch.randint(0, num_blocks, (1,)).item())
        t = int(torch.randint(0, num_blocks, (1,)).item())
        attempts += 1
        if (s, t) in pos_set or s == t:
            continue
        negatives.append((s, t))
        pos_set.add((s, t))

    pairs = torch.cat([positives, torch.tensor(negatives, dtype=torch.long)], dim=0)
    return pairs.to(device), positives.size(0)
