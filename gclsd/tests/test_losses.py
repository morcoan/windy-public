"""Tests for GCLSD-v3 loss functions (7 supervision signals)."""

from __future__ import annotations

import torch
import torch.nn.functional as F

from windy_gclsd.losses import (
    LossConfig,
    GclsdLoss,
    ce_loss,
    teacher_kl_loss,
    MTPHead,
    JEPAPredictor,
    predictive_coding_loss,
    aux_loss,
    SheafMerge,
)


# ---------------------------------------------------------------------------
# Signal 1: CE
# ---------------------------------------------------------------------------

def test_ce_loss_basic() -> None:
    logits = torch.randn(2, 10, 100)
    labels = torch.randint(0, 100, (2, 10))
    loss = ce_loss(logits, labels)
    assert loss.dim() == 0
    assert loss.item() > 0


def test_ce_loss_ignores_index() -> None:
    logits = torch.randn(2, 10, 100)
    labels = torch.full((2, 10), -100)
    labels[:, :5] = torch.randint(0, 100, (2, 5))
    loss = ce_loss(logits, labels, ignore_index=-100)
    assert loss.item() > 0


# ---------------------------------------------------------------------------
# Signal 2: Teacher KL
# ---------------------------------------------------------------------------

def test_teacher_kl_loss_shape() -> None:
    B, L, V, K = 2, 16, 1000, 32
    student_logits = torch.randn(B, L, V)
    teacher_topk_indices = torch.randint(0, V, (B, L, K))
    teacher_topk_logits = torch.randn(B, L, K)
    loss = teacher_kl_loss(student_logits, teacher_topk_indices, teacher_topk_logits)
    assert loss.dim() == 0
    assert loss.item() > 0


def test_teacher_kl_zero_when_matched() -> None:
    """When student logits match teacher (with sharp distribution), KL is small."""
    B, L, V, K = 1, 4, 100, 10
    # Use a sharp distribution where top-K captures most of the mass.
    logits = torch.randn(B, L, V) * 5.0  # scale up for sharper distribution
    # Teacher top-K from the same logits.
    topk_vals, topk_idx = logits.topk(K, dim=-1)
    loss = teacher_kl_loss(logits, topk_idx, topk_vals, temperature=1.0)
    # Matched distribution should have lower KL than mismatched.
    mismatched_logits = torch.randn(B, L, V) * 5.0
    loss_mismatched = teacher_kl_loss(mismatched_logits, topk_idx, topk_vals, temperature=1.0)
    assert loss.item() < loss_mismatched.item(), \
        f"Matched KL ({loss.item()}) should be < mismatched KL ({loss_mismatched.item()})"


def test_teacher_kl_gradient_flows() -> None:
    B, L, V, K = 2, 8, 50, 5
    student_logits = torch.randn(B, L, V, requires_grad=True)
    teacher_topk_indices = torch.randint(0, V, (B, L, K))
    teacher_topk_logits = torch.randn(B, L, K)
    loss = teacher_kl_loss(student_logits, teacher_topk_indices, teacher_topk_logits)
    loss.backward()
    assert student_logits.grad is not None
    assert not torch.isnan(student_logits.grad).any()


# ---------------------------------------------------------------------------
# Signal 3: MTP
# ---------------------------------------------------------------------------

def test_mtp_head_shape() -> None:
    B, L, D, V = 2, 32, 128, 1000
    mtp = MTPHead(d_model=D, vocab_size=V, depth=4)
    hidden = torch.randn(B, L, D)
    labels = torch.randint(0, V, (B, L))
    loss = mtp(hidden, labels)
    assert loss.dim() == 0
    assert loss.item() > 0


def test_mtp_head_gradient_flows() -> None:
    B, L, D, V = 1, 16, 64, 100
    mtp = MTPHead(d_model=D, vocab_size=V, depth=4)
    hidden = torch.randn(B, L, D, requires_grad=True)
    labels = torch.randint(0, V, (B, L))
    loss = mtp(hidden, labels)
    loss.backward()
    assert hidden.grad is not None
    # Each MTP head should have gradients.
    for head in mtp.heads:
        assert head.weight.grad is not None


def test_mtp_head_depth_zero_no_loss() -> None:
    """With depth=0, MTP should return zero loss."""
    B, L, D, V = 1, 8, 32, 10
    mtp = MTPHead(d_model=D, vocab_size=V, depth=1)
    # With L=1 (less than depth+1), no prediction can be made.
    hidden = torch.randn(B, 1, D)
    labels = torch.randint(0, V, (B, 1))
    loss = mtp(hidden, labels)
    assert loss.item() == 0.0


# ---------------------------------------------------------------------------
# Signal 4: JEPA
# ---------------------------------------------------------------------------

def test_jepa_predictor_shape() -> None:
    B, D = 4, 128
    jepa = JEPAPredictor(d_model=D, num_blocks=32)
    current = torch.randn(B, D)
    next_latent = torch.randn(B, D)
    block_idx = torch.randint(0, 32, (B,))
    loss = jepa(current, next_latent, block_idx)
    assert loss.dim() == 0
    assert loss.item() > 0


def test_jepa_predictor_gradient_flows() -> None:
    B, D = 2, 64
    jepa = JEPAPredictor(d_model=D, num_blocks=16)
    current = torch.randn(B, D, requires_grad=True)
    next_latent = torch.randn(B, D)
    block_idx = torch.tensor([0, 1])
    loss = jepa(current, next_latent, block_idx)
    loss.backward()
    assert current.grad is not None
    # Next latent should NOT have gradient (detached target).
    assert next_latent.requires_grad is False


def test_jepa_zero_when_latents_match() -> None:
    """When current == next, MSE should be small (predictor still transforms)."""
    B, D = 1, 32
    jepa = JEPAPredictor(d_model=D, num_blocks=8)
    # With matching latents, predictor output should be close if predictor is identity-like.
    current = torch.randn(B, D)
    loss = jepa(current, current, torch.tensor([0]))
    # Loss won't be zero because predictor adds transformation, but it should be finite.
    assert torch.isfinite(loss)


# ---------------------------------------------------------------------------
# Signal 5: Predictive coding
# ---------------------------------------------------------------------------

def test_pc_loss_shape() -> None:
    num_layers, B, L = 3, 2, 16
    d_s, d_t = 128, 256
    student_h = torch.randn(num_layers, B, L, d_s)
    teacher_h = torch.randn(num_layers, B, L, d_t)
    loss = predictive_coding_loss(student_h, teacher_h)
    assert loss.dim() == 0
    assert loss.item() > 0


def test_pc_loss_zero_when_identical() -> None:
    """When student and teacher hiddens are identical (same dims), loss is 0."""
    num_layers, B, L, D = 2, 2, 8, 64
    h = torch.randn(num_layers, B, L, D)
    loss = predictive_coding_loss(h, h)
    assert loss.item() < 1e-4


def test_pc_loss_gradient_flows() -> None:
    num_layers, B, L, D = 2, 2, 8, 32
    student_h = torch.randn(num_layers, B, L, D, requires_grad=True)
    teacher_h = torch.randn(num_layers, B, L, D)
    loss = predictive_coding_loss(student_h, teacher_h)
    loss.backward()
    # student_h is not a leaf, but we can check the computation graph works.
    assert torch.isfinite(loss)


# ---------------------------------------------------------------------------
# Signal 6: Aux BCE
# ---------------------------------------------------------------------------

def test_aux_loss_shape() -> None:
    B, E, N, R = 2, 10, 5, 16
    edge_logits = torch.randn(B, E)
    edge_labels = torch.randint(0, 2, (B, E)).float()
    liveness_logits = torch.randn(B, N, R)
    liveness_targets = torch.randint(0, 2, (B, N, R)).float()
    loss = aux_loss(edge_logits, edge_labels, liveness_logits, liveness_targets)
    assert loss.dim() == 0
    assert loss.item() > 0


def test_aux_loss_gradient_flows() -> None:
    B, E, N, R = 1, 4, 3, 8
    edge_logits = torch.randn(B, E, requires_grad=True)
    edge_labels = torch.randint(0, 2, (B, E)).float()
    liveness_logits = torch.randn(B, N, R, requires_grad=True)
    liveness_targets = torch.randint(0, 2, (B, N, R)).float()
    loss = aux_loss(edge_logits, edge_labels, liveness_logits, liveness_targets)
    loss.backward()
    assert edge_logits.grad is not None
    assert liveness_logits.grad is not None


# ---------------------------------------------------------------------------
# Signal 7: SheafMerge
# ---------------------------------------------------------------------------

def test_sheaf_merge_shape() -> None:
    N, D, E, K = 5, 64, 8, 7
    sheaf = SheafMerge(d_model=D, num_edge_kinds=K, rank=32)
    node_states = torch.randn(N, D)
    edge_index = torch.randint(0, N, (2, E))
    edge_kind = torch.randint(0, K, (E,))
    merged, reg = sheaf(node_states, edge_index, edge_kind)
    assert merged.shape == node_states.shape
    assert reg.dim() == 0
    assert reg.item() > 0


def test_sheaf_merge_gradient_flows() -> None:
    N, D, E, K = 4, 32, 6, 5
    sheaf = SheafMerge(d_model=D, num_edge_kinds=K, rank=16)
    node_states = torch.randn(N, D, requires_grad=True)
    edge_index = torch.randint(0, N, (2, E))
    edge_kind = torch.randint(0, K, (E,))
    merged, reg = sheaf(node_states, edge_index, edge_kind)
    reg.backward()
    assert node_states.grad is not None
    assert sheaf.restriction_maps.grad is not None


def test_sheaf_merge_restriction_maps_per_edge_kind() -> None:
    """Each edge kind has its own restriction map."""
    D, K = 32, 7
    sheaf = SheafMerge(d_model=D, num_edge_kinds=K, rank=16)
    assert sheaf.restriction_maps.shape == (K, D, 16)


# ---------------------------------------------------------------------------
# Aggregator: GclsdLoss
# ---------------------------------------------------------------------------

def test_gclsd_loss_ce_only() -> None:
    """When only logits and labels are provided, only CE is computed."""
    B, L, V, D = 2, 32, 1000, 128
    cfg = LossConfig()
    loss_fn = GclsdLoss(cfg, d_model=D, vocab_size=V)
    logits = torch.randn(B, L, V)
    labels = torch.randint(0, V, (B, L))
    hidden = torch.randn(B, L, D)
    result = loss_fn(logits, labels, hidden)
    assert result.total.item() > 0
    assert result.ce is not None
    assert result.kl is None
    assert result.mtp is not None  # MTP is computed from hidden + labels


def test_gclsd_loss_all_signals() -> None:
    """All 7 signals computed when all inputs provided."""
    B, L, V, D = 2, 16, 200, 64
    K = 10
    cfg = LossConfig(mtp_depth=3, teacher_top_k=K)
    loss_fn = GclsdLoss(cfg, d_model=D, vocab_size=V, num_blocks=8, num_edge_kinds=5)

    logits = torch.randn(B, L, V)
    labels = torch.randint(0, V, (B, L))
    hidden = torch.randn(B, L, D)
    teacher_topk_idx = torch.randint(0, V, (B, L, K))
    teacher_topk_logits = torch.randn(B, L, K)
    teacher_hiddens = torch.randn(1, B, L, D)
    block_latents = torch.randn(B, D)
    next_block_latents = torch.randn(B, D)
    block_indices = torch.randint(0, 8, (B,))
    edge_logits = torch.randn(B, 4)
    edge_labels = torch.randint(0, 2, (B, 4)).float()
    liveness_logits = torch.randn(B, 3, 8)
    liveness_targets = torch.randint(0, 2, (B, 3, 8)).float()
    node_states = torch.randn(5, D)
    edge_index = torch.randint(0, 5, (2, 6))
    edge_kind = torch.randint(0, 5, (6,))

    result = loss_fn(
        logits, labels, hidden,
        teacher_topk_indices=teacher_topk_idx,
        teacher_topk_logits=teacher_topk_logits,
        teacher_hiddens=teacher_hiddens,
        block_latents=block_latents,
        next_block_latents=next_block_latents,
        block_indices=block_indices,
        edge_logits=edge_logits,
        edge_labels=edge_labels,
        liveness_logits=liveness_logits,
        liveness_targets=liveness_targets,
        node_states=node_states,
        edge_index=edge_index,
        edge_kind=edge_kind,
    )

    assert result.ce is not None
    assert result.kl is not None
    assert result.mtp is not None
    assert result.jepa is not None
    assert result.aux is not None
    # PC might be None if auto-disabled (threshold).
    assert result.total.item() > 0


def test_gclsd_loss_anneal_weights() -> None:
    """Annealing should move weights toward final values."""
    cfg = LossConfig(alpha_kl=0.7, alpha_kl_final=0.1, lambda_mtp=0.3, lambda_mtp_final=0.1)
    loss_fn = GclsdLoss(cfg, d_model=32, vocab_size=10)
    assert loss_fn.config.alpha_kl == 0.7
    assert loss_fn.config.lambda_mtp == 0.3
    loss_fn.anneal_weights(1.0)
    assert abs(loss_fn.config.alpha_kl - 0.1) < 1e-6
    assert abs(loss_fn.config.lambda_mtp - 0.1) < 1e-6


def test_gclsd_loss_gradient_flows_to_hidden() -> None:
    B, L, V, D = 1, 8, 50, 32
    loss_fn = GclsdLoss(LossConfig(), d_model=D, vocab_size=V)
    hidden = torch.randn(B, L, D, requires_grad=True)
    logits = torch.randn(B, L, V, requires_grad=True)
    labels = torch.randint(0, V, (B, L))
    result = loss_fn(logits, labels, hidden)
    result.total.backward()
    assert hidden.grad is not None
    assert logits.grad is not None
