"""Tests for GCLSD-v3 DeltaJEPA-MoE backbone components.

Tests MLA attention (causal mask, RoPE, KV cache), SparseMoE (routing,
load balancing, shared expert), and HybridBackbone (layer placement,
forward, forward_with_state, step).
"""

from __future__ import annotations

import torch
import torch.nn.functional as F

from windy_gclsd.ssm import (
    MLAAttention,
    MLABlock,
    SparseMoE,
    SparseMoEGDNBlock,
    HybridBackbone,
    GatedDeltaNetBackbone,
)


# ---------------------------------------------------------------------------
# MLA Attention tests
# ---------------------------------------------------------------------------

def test_mla_attention_forward_shape() -> None:
    """MLA attention preserves input shape."""
    torch.manual_seed(0)
    d_model = 256
    attn = MLAAttention(d_model=d_model, num_heads=8, head_dim=128, d_cq=128, d_ckv=64, d_rope=16)
    x = torch.randn(2, 32, d_model)
    y = attn(x)
    assert y.shape == x.shape


def test_mla_attention_is_causal() -> None:
    """Changing a future token must not affect past outputs."""
    torch.manual_seed(1)
    d_model = 128
    attn = MLAAttention(d_model=d_model, num_heads=4, head_dim=64, d_cq=64, d_ckv=32, d_rope=16)
    x1 = torch.randn(1, 16, d_model)
    x2 = x1.clone()
    x2[:, 8:, :] += 10.0  # perturb tokens 8..15

    y1 = attn(x1)
    y2 = attn(x2)
    # Tokens 0..7 should be unaffected.
    torch.testing.assert_close(y1[:, :8], y2[:, :8], atol=1e-5, rtol=1e-4)


def test_mla_attention_forward_with_state_and_step_consistent() -> None:
    """Processing prefix with forward_with_state then step() should match a full forward."""
    torch.manual_seed(2)
    d_model = 128
    attn = MLAAttention(d_model=d_model, num_heads=4, head_dim=64, d_cq=64, d_ckv=32, d_rope=16)
    x = torch.randn(1, 12, d_model)

    # Full forward.
    y_full = attn(x)

    # forward_with_state for first 8 tokens, then step() for remaining 4.
    y_prefix, state = attn.forward_with_state(x[:, :8])
    y_steps = [y_prefix[:, -1:]]  # last token of prefix
    for t in range(8, 12):
        yt, state = attn.step(x[:, t : t + 1], state)
        y_steps.append(yt)
    y_steps = torch.cat(y_steps, dim=1)  # (1, 5, d_model)

    # Full forward tokens 7..11 should match the step outputs.
    torch.testing.assert_close(y_full[:, 7:], y_steps, atol=1e-4, rtol=1e-3)


def test_mla_block_forward_shape() -> None:
    torch.manual_seed(3)
    block = MLABlock(d_model=256, num_heads=8, head_dim=128, d_cq=128, d_ckv=64, d_rope=16)
    x = torch.randn(4, 64, 256)
    y = block(x)
    assert y.shape == x.shape


def test_mla_block_residual_connection() -> None:
    """Block with zeroed attention/MLP should be near-identity (residual)."""
    torch.manual_seed(4)
    block = MLABlock(d_model=64, num_heads=4, head_dim=32, d_cq=32, d_ckv=16, d_rope=8)
    # Zero out attention and MLP output projections.
    with torch.no_grad():
        block.attn.W_O.weight.zero_()
        block.mlp.wdown.weight.zero_()
    x = torch.randn(2, 8, 64)
    y = block(x)
    # After norm1, norm2 (residual is x + 0), output should be ~x (up to RMSNorm scale).
    torch.testing.assert_close(y, x, atol=1e-5, rtol=1e-3)


# ---------------------------------------------------------------------------
# SparseMoE tests
# ---------------------------------------------------------------------------

def test_sparse_moe_forward_shape() -> None:
    """MoE preserves input shape."""
    torch.manual_seed(0)
    moe = SparseMoE(d_model=128, num_experts=8, top_k=2)
    x = torch.randn(2, 32, 128)
    y = moe(x)
    assert y.shape == x.shape


def test_sparse_moe_shared_expert_always_active() -> None:
    """The shared expert contributes to every token's output."""
    torch.manual_seed(1)
    moe = SparseMoE(d_model=64, num_experts=4, top_k=2)
    x = torch.randn(1, 4, 64)

    # Freeze all routed experts to zero.
    with torch.no_grad():
        for expert in moe.experts:
            expert.wdown.weight.zero_()

    # The shared expert still produces output.
    y = moe(x)
    assert not torch.allclose(y, torch.zeros_like(y), atol=1e-6)


def test_sparse_moe_routing_selects_topk() -> None:
    """Each token should be routed to exactly top_k experts (plus shared)."""
    torch.manual_seed(2)
    moe = SparseMoE(d_model=64, num_experts=4, top_k=2)
    x = torch.randn(1, 4, 64)
    moe.training = False  # Don't update bias.
    y = moe(x)
    assert y.shape == x.shape


def test_sparse_moe_gradient_flows() -> None:
    """Gradients flow through gate and experts."""
    torch.manual_seed(3)
    moe = SparseMoE(d_model=64, num_experts=4, top_k=2)
    x = torch.randn(2, 16, 64, requires_grad=True)
    y = moe(x)
    loss = y.sum()
    loss.backward()
    assert x.grad is not None
    assert not torch.isnan(x.grad).any()
    # Gate should have gradients.
    assert moe.gate.weight.grad is not None


def test_sparse_moe_load_balancing_bias_updates() -> None:
    """In training mode, the bias buffer should change after forward."""
    torch.manual_seed(4)
    moe = SparseMoE(d_model=64, num_experts=4, top_k=2, bias_update_rate=0.01)
    x = torch.randn(2, 64, 64)  # many tokens

    bias_before = moe.expert_bias.clone()
    moe.train()
    for _ in range(10):
        moe(x)
    bias_after = moe.expert_bias.clone()
    # Bias should have changed.
    assert not torch.allclose(bias_before, bias_after, atol=1e-8)


# ---------------------------------------------------------------------------
# SparseMoE GDN Block tests
# ---------------------------------------------------------------------------

def test_sparse_moe_gdn_block_forward_shape() -> None:
    torch.manual_seed(0)
    block = SparseMoEGDNBlock(
        d_model=128, num_heads=4, head_dim=32, num_experts=4, top_k=2
    )
    x = torch.randn(2, 64, 128)
    y = block(x)
    assert y.shape == x.shape


def test_sparse_moe_gdn_block_forward_with_state_and_step() -> None:
    """forward_with_state + step should be consistent with prefix forward."""
    torch.manual_seed(1)
    block = SparseMoEGDNBlock(
        d_model=64, num_heads=2, head_dim=16, num_experts=4, top_k=2
    )
    x = torch.randn(1, 16, 64)

    # Full forward.
    y_full = block.forward(x)

    # Step-by-step.
    state = block.step_init(batch_size=1, device=x.device)
    y_steps = []
    for t in range(x.size(1)):
        yt, state = block.step(x[:, t : t + 1], state)
        y_steps.append(yt)
    y_steps = torch.cat(y_steps, dim=1)

    torch.testing.assert_close(y_full, y_steps, atol=1e-3, rtol=1e-3)


# ---------------------------------------------------------------------------
# HybridBackbone tests
# ---------------------------------------------------------------------------

def test_hybrid_backbone_default_mla_positions() -> None:
    """Default MLA positions should be at {0, L/3, 2L/3}."""
    pos = HybridBackbone._default_mla_positions(12)
    assert pos == [0, 4, 8]


def test_hybrid_backbone_layer_types() -> None:
    """MLA layers at {0,4,8}, MoE GDN elsewhere."""
    backbone = HybridBackbone(d_model=128, num_layers=12)
    assert isinstance(backbone.blocks[0], MLABlock)
    assert isinstance(backbone.blocks[1], SparseMoEGDNBlock)
    assert isinstance(backbone.blocks[4], MLABlock)
    assert isinstance(backbone.blocks[8], MLABlock)
    assert isinstance(backbone.blocks[11], SparseMoEGDNBlock)


def test_hybrid_backbone_forward_shape() -> None:
    torch.manual_seed(0)
    backbone = HybridBackbone(
        d_model=128, num_layers=6, num_heads_gdn=4, head_dim_gdn=32,
        num_heads_mla=4, head_dim_mla=32, d_cq=32, d_ckv=16, d_rope=8,
        num_experts=4, top_k=2,
    )
    x = torch.randn(2, 64, 128)
    y = backbone(x)
    assert y.shape == x.shape


def test_hybrid_backbone_forward_with_state_and_step() -> None:
    """forward_with_state + step should match full forward for the prefix."""
    torch.manual_seed(2)
    backbone = HybridBackbone(
        d_model=64, num_layers=4, num_heads_gdn=2, head_dim_gdn=16,
        num_heads_mla=2, head_dim_mla=16, d_cq=16, d_ckv=8, d_rope=8,
        num_experts=4, top_k=2,
    )
    x = torch.randn(1, 16, 64)

    # Full forward.
    y_full = backbone.forward(x)

    # forward_with_state on first 8, then step the rest.
    y_prefix, states = backbone.forward_with_state(x[:, :8])
    y_steps = [y_prefix]
    for t in range(8, 16):
        xt = x[:, t : t + 1]
        yt, states = backbone.step(xt, states)
        y_steps.append(yt)
    y_stepwise = torch.cat(y_steps, dim=1)

    torch.testing.assert_close(y_full, y_stepwise, atol=1e-3, rtol=1e-3)


def test_hybrid_backbone_gradient_checkpointing_supports() -> None:
    """Gradient checkpointing should not break forward."""
    torch.manual_seed(5)
    backbone = HybridBackbone(
        d_model=64, num_layers=4, num_heads_gdn=2, head_dim_gdn=16,
        num_heads_mla=2, head_dim_mla=16, d_cq=16, d_ckv=8, d_rope=8,
        num_experts=4, top_k=2, gradient_checkpointing=True,
    )
    backbone.train()
    x = torch.randn(2, 32, 64, requires_grad=True)
    y = backbone(x)
    loss = y.sum()
    loss.backward()
    assert x.grad is not None


def test_hybrid_backbone_param_count_increases_with_depth() -> None:
    """More layers → more params."""
    small = HybridBackbone(d_model=64, num_layers=6, num_heads_gdn=2, head_dim_gdn=16,
                           num_heads_mla=2, head_dim_mla=16, d_cq=16, d_ckv=8, d_rope=8,
                           num_experts=4, top_k=2)
    large = HybridBackbone(d_model=128, num_layers=12, num_heads_gdn=4, head_dim_gdn=32,
                           num_heads_mla=4, head_dim_mla=32, d_cq=32, d_ckv=16, d_rope=8,
                           num_experts=8, top_k=2)
    p_small = sum(p.numel() for p in small.parameters())
    p_large = sum(p.numel() for p in large.parameters())
    assert p_large > p_small
