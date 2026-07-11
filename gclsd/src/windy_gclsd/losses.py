"""GCLSD-v3 loss functions: 7 supervision signals.

This module implements the multi-signal training objective for the
GCLSD-v3 "DeltaJEPA-MoE" decompiler. Each signal corresponds to a novel
contribution from the architecture spec:

1. CE(student, GT)              — standard cross-entropy on output tokens
2. KL(teacher top-32 || student) — PCDistill: per-layer distillation (#2)
3. MTP 4-token CE               — MTP-decompile: multi-token prediction (#5)
4. JEPA MSE latent prediction   — JEPA-decompile: next-block latent (#3)
5. PC per-layer KL on hidden     — PCDistill: predictive coding on hiddens (#2)
6. Aux BCE(edge + liveness)      — structural auxiliary (in model.py AuxHeads)
7. SheafMerge topology loss      — SheafMerge state composition (#1)

Loss schedule (from spec):
    L = CE + alpha_kl * KL + lambda_mtp * MTP + lambda_jepa * JEPA
        + lambda_pc * PC + alpha_aux * AUX

    alpha_kl:   0.7 -> 0.1 (linear anneal over training)
    lambda_mtp: 0.3 -> 0.1 (linear anneal)
    lambda_jepa: 0.2 (fixed)
    lambda_pc:  dynamic with auto-disable fallback
    alpha_aux:  0.1 (fixed)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F


@dataclass
class LossConfig:
    """Weights for the 7 supervision signals."""

    alpha_kl: float = 0.7
    alpha_kl_final: float = 0.1
    lambda_mtp: float = 0.3
    lambda_mtp_final: float = 0.1
    lambda_jepa: float = 0.2
    lambda_pc: float = 1.0
    alpha_aux: float = 0.1
    mtp_depth: int = 4
    teacher_top_k: int = 32
    pc_disable_threshold: float = 0.01


@dataclass
class LossOutput:
    """Aggregated loss and per-signal breakdown."""

    total: torch.Tensor
    ce: torch.Tensor
    kl: Optional[torch.Tensor]
    mtp: Optional[torch.Tensor]
    jepa: Optional[torch.Tensor]
    pc: Optional[torch.Tensor]
    aux: Optional[torch.Tensor]
    sheaf: Optional[torch.Tensor]


# ---------------------------------------------------------------------------
# Signal 1: Cross-entropy on ground-truth output tokens
# ---------------------------------------------------------------------------

def ce_loss(
    logits: torch.Tensor,
    labels: torch.Tensor,
    ignore_index: int = -100,
) -> torch.Tensor:
    """Standard next-token cross-entropy.

    Args:
        logits: (B, L, vocab_size)
        labels: (B, L) with ignore_index for masked positions
    """
    return F.cross_entropy(
        logits.view(-1, logits.size(-1)),
        labels.view(-1),
        ignore_index=ignore_index,
    )


# ---------------------------------------------------------------------------
# Signal 2: Teacher KL distillation (top-K logits)
# ---------------------------------------------------------------------------

def teacher_kl_loss(
    student_logits: torch.Tensor,
    teacher_topk_indices: torch.Tensor,
    teacher_topk_logits: torch.Tensor,
    temperature: float = 1.0,
) -> torch.Tensor:
    """KL divergence over teacher's top-K logits (PCDistill contribution #2).

    Instead of full-vocab KL (expensive at 32256 dims), we compute KL over
    only the teacher's top-K=32 logit positions plus a "other" bucket.
    This captures the teacher's distribution shape with O(K) compute.

    Args:
        student_logits: (B, L, vocab_size)
        teacher_topk_indices: (B, L, K) — vocab indices of teacher's top-K
        teacher_topk_logits: (B, L, K) — corresponding teacher logits
        temperature: distillation temperature
    """
    B, L, V = student_logits.shape
    K = teacher_topk_indices.size(-1)
    T = temperature

    # Gather student logits at teacher's top-K positions.
    student_topk = torch.gather(
        student_logits, dim=-1, index=teacher_topk_indices
    )  # (B, L, K)

    # Student "other" logit mass: how much probability mass lies outside top-K.
    # log P_s(other) = logsumexp(all/T) - logsumexp(topK/T)
    student_full_lse = torch.logsumexp(student_logits / T, dim=-1)  # (B, L)
    student_topk_lse = torch.logsumexp(student_topk / T, dim=-1)  # (B, L)
    student_other_logp = student_full_lse - student_topk_lse  # (B, L)

    # Teacher top-K probabilities and "other" mass.
    teacher_topk_logp = F.log_softmax(teacher_topk_logits / T, dim=-1)  # (B, L, K)
    teacher_topk_p = teacher_topk_logp.exp()
    teacher_other_p = (1.0 - teacher_topk_p.sum(dim=-1)).clamp(min=1e-8, max=1.0)  # (B, L)
    teacher_other_logp = teacher_other_p.log()

    # Student top-K log-probabilities, normalized over the FULL vocab.
    # log P_s(topk_i) = student_topk[i]/T - logsumexp(all/T)
    student_topk_logp = student_topk / T - student_full_lse.unsqueeze(-1)  # (B, L, K)
    student_topk_p = student_topk_logp.exp()  # (B, L, K)

    # KL(teacher || student) over top-K + other bucket.
    # KL = sum_i p_t(i) * [log p_t(i) - log p_s(i)]
    kl_topk = (teacher_topk_p * (teacher_topk_logp - student_topk_logp)).sum(dim=-1)  # (B, L)
    kl_other = teacher_other_p * (teacher_other_logp - student_other_logp)  # (B, L)

    kl = (kl_topk + kl_other).mean() * (T ** 2)
    return kl


# ---------------------------------------------------------------------------
# Signal 3: Multi-token prediction (DeepSeek-V3 MTP)
# ---------------------------------------------------------------------------

class MTPHead(nn.Module):
    """Multi-token prediction head (Contribution #5).

    Predicts the next `depth` tokens simultaneously from the current hidden
    state. Each depth level has its own lightweight projection.

    During training, this densifies the training signal: each forward pass
    produces `depth` additional CE losses, giving 4x training signal.
    During inference, MTP heads enable speculative decoding.
    """

    def __init__(self, d_model: int, vocab_size: int, depth: int = 4) -> None:
        super().__init__()
        self.depth = depth
        self.heads = nn.ModuleList(
            [nn.Linear(d_model, vocab_size, bias=False) for _ in range(depth)]
        )

    def forward(
        self, hidden: torch.Tensor, labels: torch.Tensor, ignore_index: int = -100
    ) -> torch.Tensor:
        """Compute MTP loss.

        Args:
            hidden: (B, L, d_model) — student hidden states
            labels: (B, L) — ground truth next-token labels
        """
        total = torch.tensor(0.0, device=hidden.device, dtype=hidden.dtype)
        for d in range(self.depth):
            # Predict token at position t+d+1 from hidden at position t.
            shift = d + 1
            if shift >= hidden.size(1):
                continue
            pred_logits = self.heads[d](hidden[:, :-shift, :])  # (B, L-shift, V)
            target = labels[:, shift:]  # (B, L-shift)
            loss = F.cross_entropy(
                pred_logits.reshape(-1, pred_logits.size(-1)),
                target.reshape(-1),
                ignore_index=ignore_index,
            )
            total = total + loss
        return total / max(1, self.depth)


# ---------------------------------------------------------------------------
# Signal 4: JEPA latent prediction (I-JEPA)
# ---------------------------------------------------------------------------

class JEPAPredictor(nn.Module):
    """JEPA next-block latent predictor (Contribution #3).

    Predicts the next basic-block's latent representation from the current
    block's latent. Uses an asymmetric EMA target encoder to prevent
    representational collapse.

    The predictor is a lightweight MLP that takes (current_latent, pos_embed)
    and predicts the target encoder's representation of the next block.
    """

    def __init__(self, d_model: int, num_blocks: int = 64) -> None:
        super().__init__()
        self.predictor = nn.Sequential(
            nn.Linear(d_model, d_model * 2),
            nn.GELU(),
            nn.Linear(d_model * 2, d_model),
        )
        # Positional embedding for block index (relative within function).
        self.block_pos = nn.Embedding(num_blocks, d_model)
        # EMA decay rate for target encoder.
        self.ema_decay = 0.996

    def forward(
        self,
        current_latent: torch.Tensor,
        next_latent: torch.Tensor,
        block_indices: torch.Tensor,
    ) -> torch.Tensor:
        """Compute JEPA MSE loss.

        Args:
            current_latent: (B, d_model) — student's latent at block boundary
            next_latent: (B, d_model) — EMA target encoder's latent at next block
            block_indices: (B,) — block index for positional embedding

        Returns:
            MSE loss between predicted and target latents.
        """
        pos = self.block_pos(block_indices.clamp(min=0, max=self.block_pos.num_embeddings - 1))
        pred = self.predictor(current_latent + pos)
        return F.mse_loss(pred, next_latent.detach())


# ---------------------------------------------------------------------------
# Signal 5: Predictive coding per-layer KL (PCDistill)
# ---------------------------------------------------------------------------

def predictive_coding_loss(
    student_hiddens: torch.Tensor,
    teacher_hiddens: torch.Tensor,
    layer_weights: Optional[torch.Tensor] = None,
) -> torch.Tensor:
    """Per-layer KL between student and cached teacher hidden states.

    Treats cached teacher hidden states as predictive coding energy targets.
    The student minimizes KL(teacher_h || student_h) at each layer, which
    drives the student's internal representations to match the teacher's.

    Args:
        student_hiddens: (num_layers, B, L, d_model) — student hidden states
        teacher_hiddens: (num_layers, B, L, d_model) — cached teacher hiddens
        layer_weights: (num_layers,) — optional per-layer weighting

    Returns:
        Scalar PC loss (mean KL across layers).
    """
    # Both tensors should have shape (num_layers, B, L, d).
    # We compute cosine-similarity-based loss for dimension-agnostic matching
    # (student d_model=1024, teacher d_model=2048, so direct MSE won't work).
    # Strategy: project both to a common space via mean-pooled statistics.

    num_layers = student_hiddens.size(0)
    if layer_weights is None:
        layer_weights = torch.ones(num_layers, device=student_hiddens.device) / num_layers

    total = torch.tensor(0.0, device=student_hiddens.device, dtype=student_hiddens.dtype)
    for l in range(num_layers):
        s = student_hiddens[l]  # (B, L, d_s)
        t = teacher_hiddens[l]  # (B, L, d_t)
        # Normalize along feature dim for cosine similarity.
        s_norm = F.normalize(s.float(), dim=-1)
        t_norm = F.normalize(t.float(), dim=-1)
        # If dims differ, use cross-covariance: ||mean(s) - mean(t)||^2
        # on the mean-pooled representations (B, d_s) vs (B, d_t).
        # We use a projection-free approach: match the mean and variance.
        s_mean = s_norm.mean(dim=1)  # (B, d_s)
        t_mean = t_norm.mean(dim=1)  # (B, d_t)
        # Pad smaller dim with zeros for comparison.
        d_max = max(s_mean.size(-1), t_mean.size(-1))
        s_padded = F.pad(s_mean, (0, d_max - s_mean.size(-1)))
        t_padded = F.pad(t_mean, (0, d_max - t_mean.size(-1)))
        layer_loss = F.mse_loss(s_padded, t_padded)
        total = total + layer_weights[l] * layer_loss
    return total


# ---------------------------------------------------------------------------
# Signal 6: Aux BCE (edge existence + register liveness)
# ---------------------------------------------------------------------------

def aux_loss(
    edge_logits: torch.Tensor,
    edge_labels: torch.Tensor,
    liveness_logits: torch.Tensor,
    liveness_targets: torch.Tensor,
    pos_weight: float = 1.0,
) -> torch.Tensor:
    """Auxiliary BCE for edges and register liveness.

    Args:
        edge_logits: (B, num_edges)
        edge_labels: (B, num_edges) binary
        liveness_logits: (B, num_blocks, num_registers)
        liveness_targets: (B, num_blocks, num_registers) binary
        pos_weight: weight for positive edges (class imbalance)
    """
    pw = torch.tensor(pos_weight, device=edge_logits.device, dtype=edge_logits.dtype)
    edge_loss = F.binary_cross_entropy_with_logits(
        edge_logits, edge_labels.float(), pos_weight=pw
    )
    liveness_loss = F.binary_cross_entropy_with_logits(
        liveness_logits, liveness_targets.float(), reduction="mean"
    )
    return edge_loss + liveness_loss


# ---------------------------------------------------------------------------
# Signal 7: SheafMerge topology-aware state composition
# ---------------------------------------------------------------------------

class SheafMerge(nn.Module):
    """Sheaf Laplacian state composition at CFG joins (Contribution #1).

    At control-flow graph join nodes (where multiple predecessor blocks
    merge), the latent state is composed using a sheaf Laplacian:

        delta_x = sum_e (R_e^T @ R_e) (x_u - x_v)

    where R_e is a learned restriction map for edge kind e. This ensures
    the composed state respects the topology of incoming edges.

    The sheaf Laplacian generalizes graph convolution: instead of a single
    weight per edge, each edge kind has its own projection that "restricts"
    the source state into the target's tangent space.

    Args:
        d_model: hidden dimension
        num_edge_kinds: number of CFG edge kinds (fallthrough, conditional,
            unconditional, call, return, indirect, etc.)
        rank: rank of each restriction map (d_model x rank matrix)
    """

    def __init__(self, d_model: int, num_edge_kinds: int = 7, rank: int = 64) -> None:
        super().__init__()
        self.d_model = d_model
        self.num_edge_kinds = num_edge_kinds
        self.rank = rank
        # Per-edge-kind restriction maps: (edge_kind, d_model, rank)
        self.restriction_maps = nn.Parameter(
            torch.randn(num_edge_kinds, d_model, rank) * (1.0 / d_model ** 0.5)
        )

    def forward(
        self,
        node_states: torch.Tensor,
        edge_index: torch.Tensor,
        edge_kind: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Compute sheaf Laplacian update and regularization loss.

        Args:
            node_states: (N, d_model) — latent state at each CFG node
            edge_index: (2, E) — [source, target] for each edge
            edge_kind: (E,) — edge kind index for each edge

        Returns:
            merged_states: (N, d_model) — updated states with sheaf diffusion
            reg_loss: scalar regularization (sheaf Laplacian smoothness)
        """
        N, D = node_states.shape
        E = edge_index.size(1)

        src = edge_index[0]  # (E,)
        tgt = edge_index[1]  # (E,)

        # Gather per-edge restriction maps.
        R = self.restriction_maps[edge_kind]  # (E, D, rank)

        # Restrict source and target states to the sheaf section.
        x_src = node_states[src]  # (E, D)
        x_tgt = node_states[tgt]  # (E, D)

        # Project onto restriction maps: (E, rank)
        r_src = torch.bmm(x_src.unsqueeze(1), R).squeeze(1)  # (E, rank)
        r_tgt = torch.bmm(x_tgt.unsqueeze(1), R).squeeze(1)  # (E, rank)

        # Sheaf disagreement: ||R_e (x_u - x_v)||^2
        disagreement = r_src - r_tgt  # (E, rank)
        edge_disagreement = (disagreement ** 2).sum(dim=-1)  # (E,)

        # Regularization: minimize total disagreement (smoothness).
        reg_loss = edge_disagreement.mean()

        # Back-project disagreement to node space and scatter-add.
        # delta_x_v = sum_u R_e^T @ R_e @ (x_u - x_v)  for edge (u,v)
        # R @ disagreement_e gives R @ R^T @ (x_u - x_v) which lives in D space.
        # bmm(R: (E, D, rank), disagreement: (E, rank, 1)) = (E, D, 1)
        back_proj = torch.bmm(R, disagreement.unsqueeze(-1)).squeeze(-1)  # (E, D)

        # Scatter-add to target nodes (sheaf Laplacian diffusion).
        delta = torch.zeros_like(node_states)
        delta.scatter_add_(0, tgt.unsqueeze(-1).expand(-1, D), back_proj)
        delta.scatter_add_(0, src.unsqueeze(-1).expand(-1, D), -back_proj)

        # Scale diffusion step.
        merged = node_states - 0.1 * delta / max(E, 1)

        return merged, reg_loss


# ---------------------------------------------------------------------------
# Aggregator: combine all 7 signals
# ---------------------------------------------------------------------------

class GclsdLoss(nn.Module):
    """Aggregates all 7 supervision signals into a single loss.

    Usage:
        loss_fn = GclsdLoss(config, d_model=1024, vocab_size=32256)
        result = loss_fn(student_logits, labels, hidden_states, ...)
        result.total.backward()
    """

    def __init__(
        self,
        config: LossConfig,
        d_model: int,
        vocab_size: int,
        num_blocks: int = 64,
        num_edge_kinds: int = 7,
    ) -> None:
        super().__init__()
        self.config = config
        self.mtp_head = MTPHead(d_model, vocab_size, depth=config.mtp_depth)
        self.jepa = JEPAPredictor(d_model, num_blocks=num_blocks)
        self.sheaf = SheafMerge(d_model, num_edge_kinds=num_edge_kinds)

    def anneal_weights(self, progress: float) -> None:
        """Anneal KL and MTP weights from initial to final over training.

        Args:
            progress: 0.0 at start, 1.0 at end of training.
        """
        p = max(0.0, min(1.0, progress))
        self.config.alpha_kl = (
            self.config.alpha_kl * (1 - p) + self.config.alpha_kl_final * p
        )
        self.config.lambda_mtp = (
            self.config.lambda_mtp * (1 - p) + self.config.lambda_mtp_final * p
        )

    def forward(
        self,
        student_logits: torch.Tensor,
        labels: torch.Tensor,
        hidden_states: torch.Tensor,
        teacher_topk_indices: Optional[torch.Tensor] = None,
        teacher_topk_logits: Optional[torch.Tensor] = None,
        teacher_hiddens: Optional[torch.Tensor] = None,
        block_latents: Optional[torch.Tensor] = None,
        next_block_latents: Optional[torch.Tensor] = None,
        block_indices: Optional[torch.Tensor] = None,
        edge_logits: Optional[torch.Tensor] = None,
        edge_labels: Optional[torch.Tensor] = None,
        liveness_logits: Optional[torch.Tensor] = None,
        liveness_targets: Optional[torch.Tensor] = None,
        node_states: Optional[torch.Tensor] = None,
        edge_index: Optional[torch.Tensor] = None,
        edge_kind: Optional[torch.Tensor] = None,
        ignore_index: int = -100,
    ) -> LossOutput:
        """Compute all 7 losses and combine.

        Only CE is required; others are optional and skipped if inputs are None.

        Args:
            student_logits: (B, L, vocab_size)
            labels: (B, L) — ground truth output token labels
            hidden_states: (B, L, d_model) — student backbone hidden states
            teacher_topk_indices: (B, L, K) — for KL distillation
            teacher_topk_logits: (B, L, K)
            teacher_hiddens: (num_layers, B, L, d_model) — for PC
            block_latents: (B, d_model) — for JEPA (current block)
            next_block_latents: (B, d_model) — for JEPA (next block, EMA)
            block_indices: (B,) — for JEPA positional embedding
            edge_logits, edge_labels: for aux edge loss
            liveness_logits, liveness_targets: for aux liveness loss
            node_states, edge_index, edge_kind: for SheafMerge
            ignore_index: label padding index
        """
        cfg = self.config

        # --- Signal 1: CE ---
        ce = ce_loss(student_logits, labels, ignore_index)

        # --- Signal 2: Teacher KL ---
        kl = None
        if teacher_topk_indices is not None and teacher_topk_logits is not None:
            output_len = student_logits.size(1)
            # Slice to match teacher position count.
            t_len = teacher_topk_indices.size(1)
            if t_len < output_len:
                student_slice = student_logits[:, :t_len]
            else:
                student_slice = student_logits
            kl = teacher_kl_loss(
                student_slice, teacher_topk_indices, teacher_topk_logits
            )

        # --- Signal 3: MTP ---
        mtp = self.mtp_head(hidden_states, labels, ignore_index) if hidden_states is not None else None

        # --- Signal 4: JEPA ---
        jepa = None
        if block_latents is not None and next_block_latents is not None and block_indices is not None:
            jepa = self.jepa(block_latents, next_block_latents, block_indices)

        # --- Signal 5: PC ---
        pc = None
        if teacher_hiddens is not None and hidden_states is not None:
            # Wrap student hidden as single-layer for PC.
            student_h = hidden_states.unsqueeze(0)  # (1, B, L, d)
            pc = predictive_coding_loss(student_h, teacher_hiddens)
            # Auto-disable if PC loss is negligible.
            if pc.item() < cfg.pc_disable_threshold:
                pc = None

        # --- Signal 6: Aux BCE ---
        aux_val = None
        if edge_logits is not None and liveness_logits is not None:
            aux_val = aux_loss(
                edge_logits, edge_labels, liveness_logits, liveness_targets
            )

        # --- Signal 7: SheafMerge ---
        sheaf = None
        if node_states is not None and edge_index is not None and edge_kind is not None:
            _, sheaf = self.sheaf(node_states, edge_index, edge_kind)

        # --- Combine ---
        total = ce
        if kl is not None:
            total = total + cfg.alpha_kl * kl
        if mtp is not None:
            total = total + cfg.lambda_mtp * mtp
        if jepa is not None:
            total = total + cfg.lambda_jepa * jepa
        if pc is not None:
            total = total + cfg.lambda_pc * pc
        if aux_val is not None:
            total = total + cfg.alpha_aux * aux_val
        if sheaf is not None:
            total = total + 0.1 * sheaf

        return LossOutput(
            total=total,
            ce=ce,
            kl=kl,
            mtp=mtp,
            jepa=jepa,
            pc=pc,
            aux=aux_val,
            sheaf=sheaf,
        )
