"""Property tests for the pure-PyTorch Gated DeltaNet mixer.

The single most fragile piece of the GCLSD rebuild is the SSM recurrence. We
check that the mixer's sequential scan matches a naive reference implementation
written with explicit outer products, and that forward / step agree after a
prefix has been processed.
"""

from __future__ import annotations

from typing import Tuple

import torch
import torch.nn.functional as F

from windy_gclsd.ssm import GatedDeltaNetMixer


def _naive_gated_delta_scan(
    q: torch.Tensor,
    k: torch.Tensor,
    v: torch.Tensor,
    alpha: torch.Tensor,
    beta: torch.Tensor,
) -> torch.Tensor:
    """Reference recurrence using explicit outer products."""
    B, L, H, Dk = q.shape
    Dv = v.shape[-1]
    S = torch.zeros(B, H, Dv, Dk, device=q.device, dtype=q.dtype)
    outs = []
    for t in range(L):
        kt = k[:, t]
        qt = q[:, t]
        vt = v[:, t]
        at = alpha[:, t]
        bt = beta[:, t]
        z = torch.matmul(S, kt.unsqueeze(-1)).squeeze(-1)  # (B, H, Dv)
        delta = bt.unsqueeze(-1) * (vt - at.unsqueeze(-1) * z)
        S = at.unsqueeze(-1).unsqueeze(-1) * S + delta.unsqueeze(-1) * kt.unsqueeze(-2)
        o_t = torch.matmul(S, qt.unsqueeze(-1)).squeeze(-1)
        outs.append(o_t)
    return torch.stack(outs, dim=1)


def _mixer_scan_without_conv(
    mixer: GatedDeltaNetMixer,
    q: torch.Tensor,
    k: torch.Tensor,
    v: torch.Tensor,
    alpha: torch.Tensor,
    beta: torch.Tensor,
) -> torch.Tensor:
    """Call the internal scan directly (tests only: bypasses conv1d gates)."""
    out, _ = mixer._gated_delta_scan(q, k, v, alpha, beta)
    return out


def test_gated_delta_scan_matches_naive() -> None:
    torch.manual_seed(42)
    B, L, H, Dk, Dv = 2, 17, 4, 32, 64
    q = torch.randn(B, L, H, Dk)
    k = torch.randn(B, L, H, Dk)
    v = torch.randn(B, L, H, Dv)
    alpha = torch.sigmoid(torch.randn(B, L, H) * 0.5 + 0.5)
    beta = torch.sigmoid(torch.randn(B, L, H) * 0.5)

    mixer = GatedDeltaNetMixer(d_model=16, num_heads=H, head_dim=Dk, dv_ratio=Dv / Dk)
    out = _mixer_scan_without_conv(mixer, q, k, v, alpha, beta)
    ref = _naive_gated_delta_scan(q, k, v, alpha, beta)

    assert out.shape == ref.shape
    torch.testing.assert_close(out, ref, atol=1e-5, rtol=1e-4)


def test_mixer_forward_runs_and_is_deterministic() -> None:
    torch.manual_seed(0)
    mixer = GatedDeltaNetMixer(d_model=64, num_heads=4, head_dim=32, dv_ratio=2.0)
    x = torch.randn(2, 13, 64)
    y1 = mixer(x)
    y2 = mixer(x)
    assert y1.shape == x.shape
    torch.testing.assert_close(y1, y2)


def test_single_token_step_matches_full_forward() -> None:
    """Process a prefix with forward(), then continue with step()."""
    torch.manual_seed(1)
    mixer = GatedDeltaNetMixer(d_model=32, num_heads=2, head_dim=16, dv_ratio=2.0)
    x = torch.randn(1, 10, 32)

    # Prefix through the full forward pass.
    y_full = mixer(x)  # (1, 10, 32)

    # Walk the same prefix one token at a time to build state.
    state = mixer.step_init(batch_size=1, device=x.device)
    y_steps = []
    for t in range(x.size(1)):
        xt = x[:, t : t + 1, :]
        yt, state = mixer.step(xt, state)
        y_steps.append(yt)
    y_steps = torch.cat(y_steps, dim=1)

    torch.testing.assert_close(y_full, y_steps, atol=1e-5, rtol=1e-4)


# ---------------------------------------------------------------------------
# Chunkwise scan correctness
# ---------------------------------------------------------------------------

def _naive_gated_delta_scan_with_state(
    q: torch.Tensor,
    k: torch.Tensor,
    v: torch.Tensor,
    alpha: torch.Tensor,
    beta: torch.Tensor,
) -> Tuple[torch.Tensor, torch.Tensor]:
    """Reference scan that also returns the final state S."""
    B, L, H, Dk = q.shape
    Dv = v.shape[-1]
    S = torch.zeros(B, H, Dv, Dk, device=q.device, dtype=q.dtype)
    outs = []
    for t in range(L):
        kt = k[:, t]
        qt = q[:, t]
        vt = v[:, t]
        at = alpha[:, t]
        bt = beta[:, t]
        z = torch.matmul(S, kt.unsqueeze(-1)).squeeze(-1)
        delta = bt.unsqueeze(-1) * (vt - at.unsqueeze(-1) * z)
        S = at.unsqueeze(-1).unsqueeze(-1) * S + delta.unsqueeze(-1) * kt.unsqueeze(-2)
        o_t = torch.matmul(S, qt.unsqueeze(-1)).squeeze(-1)
        outs.append(o_t)
    return torch.stack(outs, dim=1), S


def test_chunkwise_matches_sequential_same_chunk_size() -> None:
    """When L == chunk_size, there is one chunk — pure intra-chunk test."""
    torch.manual_seed(42)
    B, L, H, Dk, Dv = 2, 64, 4, 32, 64
    q = F.normalize(torch.randn(B, L, H, Dk), dim=-1)
    k = F.normalize(torch.randn(B, L, H, Dk), dim=-1)
    v = torch.randn(B, L, H, Dv)
    alpha = torch.sigmoid(torch.randn(B, L, H) * 0.5 + 0.5)
    beta = torch.sigmoid(torch.randn(B, L, H) * 0.5)

    mixer = GatedDeltaNetMixer(d_model=16, num_heads=H, head_dim=Dk, dv_ratio=Dv / Dk)
    o_seq, S_seq = mixer._gated_delta_scan(q, k, v, alpha, beta)
    o_chunk, S_chunk = mixer._chunk_gated_delta_scan(q, k, v, alpha, beta, chunk_size=64)

    assert o_chunk.shape == o_seq.shape
    torch.testing.assert_close(o_chunk, o_seq, atol=1e-4, rtol=1e-3)
    # State shapes: sequential returns (B, H, Dv, Dk), chunkwise returns (B, H, Dk, Dv)
    # They are transposed — check via the equivalent matmul.
    torch.testing.assert_close(S_chunk, S_seq.transpose(-1, -2), atol=1e-4, rtol=1e-3)


def test_chunkwise_matches_sequential_multi_chunk() -> None:
    """Multiple chunks: tests inter-chunk state propagation."""
    torch.manual_seed(99)
    B, L, H, Dk, Dv = 2, 256, 4, 32, 64
    q = F.normalize(torch.randn(B, L, H, Dk), dim=-1)
    k = F.normalize(torch.randn(B, L, H, Dk), dim=-1)
    v = torch.randn(B, L, H, Dv)
    alpha = torch.sigmoid(torch.randn(B, L, H) * 0.5 + 0.5)
    beta = torch.sigmoid(torch.randn(B, L, H) * 0.5)

    mixer = GatedDeltaNetMixer(d_model=16, num_heads=H, head_dim=Dk, dv_ratio=Dv / Dk)
    o_seq, S_seq = mixer._gated_delta_scan(q, k, v, alpha, beta)
    o_chunk, S_chunk = mixer._chunk_gated_delta_scan(q, k, v, alpha, beta, chunk_size=64)

    assert o_chunk.shape == o_seq.shape
    torch.testing.assert_close(o_chunk, o_seq, atol=1e-3, rtol=1e-3)
    torch.testing.assert_close(S_chunk, S_seq.transpose(-1, -2), atol=1e-3, rtol=1e-3)


def test_chunkwise_matches_sequential_non_multiple_length() -> None:
    """L not a multiple of C — padding path must be correct."""
    torch.manual_seed(7)
    B, L, H, Dk, Dv = 3, 200, 4, 32, 64  # 200 = 3*64 + 8 → pad to 256
    q = F.normalize(torch.randn(B, L, H, Dk), dim=-1)
    k = F.normalize(torch.randn(B, L, H, Dk), dim=-1)
    v = torch.randn(B, L, H, Dv)
    alpha = torch.sigmoid(torch.randn(B, L, H) * 0.5 + 0.5)
    beta = torch.sigmoid(torch.randn(B, L, H) * 0.5)

    mixer = GatedDeltaNetMixer(d_model=16, num_heads=H, head_dim=Dk, dv_ratio=Dv / Dk)
    o_seq, S_seq = mixer._gated_delta_scan(q, k, v, alpha, beta)
    o_chunk, S_chunk = mixer._chunk_gated_delta_scan(q, k, v, alpha, beta, chunk_size=64)

    assert o_chunk.shape == o_seq.shape
    torch.testing.assert_close(o_chunk, o_seq, atol=1e-3, rtol=1e-3)


def test_chunkwise_matches_sequential_small_chunk() -> None:
    """C=16 — exercises the doubling loop with fewer iterations."""
    torch.manual_seed(3)
    B, L, H, Dk, Dv = 2, 128, 4, 16, 32
    q = F.normalize(torch.randn(B, L, H, Dk), dim=-1)
    k = F.normalize(torch.randn(B, L, H, Dk), dim=-1)
    v = torch.randn(B, L, H, Dv)
    alpha = torch.sigmoid(torch.randn(B, L, H) * 0.5 + 0.5)
    beta = torch.sigmoid(torch.randn(B, L, H) * 0.5)

    mixer = GatedDeltaNetMixer(d_model=16, num_heads=H, head_dim=Dk, dv_ratio=Dv / Dk)
    o_seq, S_seq = mixer._gated_delta_scan(q, k, v, alpha, beta)
    o_chunk, S_chunk = mixer._chunk_gated_delta_scan(q, k, v, alpha, beta, chunk_size=16)

    assert o_chunk.shape == o_seq.shape
    torch.testing.assert_close(o_chunk, o_seq, atol=1e-4, rtol=1e-3)


def test_chunkwise_forward_with_grad() -> None:
    """Chunkwise scan must produce gradients through autograd."""
    torch.manual_seed(11)
    B, L, H, Dk, Dv = 2, 256, 4, 32, 64
    q_raw = torch.randn(B, L, H, Dk, requires_grad=True)
    k_raw = torch.randn(B, L, H, Dk, requires_grad=True)
    v = torch.randn(B, L, H, Dv, requires_grad=True)
    alpha_logit = torch.randn(B, L, H, requires_grad=True)
    beta_logit = torch.randn(B, L, H, requires_grad=True)

    q = F.normalize(q_raw, dim=-1)
    k = F.normalize(k_raw, dim=-1)
    alpha = torch.sigmoid(alpha_logit * 0.5 + 0.5)
    beta = torch.sigmoid(beta_logit * 0.5)

    mixer = GatedDeltaNetMixer(d_model=16, num_heads=H, head_dim=Dk, dv_ratio=Dv / Dk)
    o_chunk, _ = mixer._chunk_gated_delta_scan(q, k, v, alpha, beta, chunk_size=64)
    loss = o_chunk.sum()
    loss.backward()

    assert q_raw.grad is not None
    assert k_raw.grad is not None
    assert v.grad is not None
    assert alpha_logit.grad is not None
    assert beta_logit.grad is not None
    assert not torch.isnan(q_raw.grad).any()


def test_forward_uses_chunkwise_for_long_sequences() -> None:
    """forward() should dispatch to the chunkwise scan for L >= threshold."""
    torch.manual_seed(22)
    mixer = GatedDeltaNetMixer(d_model=64, num_heads=4, head_dim=32, dv_ratio=2.0)
    # Short sequence: uses sequential.
    x_short = torch.randn(2, 32, 64)
    y_short = mixer(x_short)
    assert y_short.shape == x_short.shape

    # Long sequence: uses chunkwise — result must match a pure sequential call.
    x_long = torch.randn(2, 256, 64)
    # Temporarily disable chunkwise to get the reference.
    orig_threshold = mixer._CHUNK_THRESHOLD
    mixer._CHUNK_THRESHOLD = 999  # force sequential
    y_seq = mixer(x_long)
    mixer._CHUNK_THRESHOLD = 0  # force chunkwise
    y_chunk = mixer(x_long)
    mixer._CHUNK_THRESHOLD = orig_threshold

    torch.testing.assert_close(y_chunk, y_seq, atol=1e-3, rtol=1e-3)
