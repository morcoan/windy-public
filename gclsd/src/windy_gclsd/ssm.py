"""Pure-PyTorch Gated DeltaNet SSM building blocks.

No Triton / CUDA kernels: the recurrence is evaluated sequentially for clarity
and correctness. Sequence lengths in the decompiler are modest (a few hundred
tokens), so the sequential loop is acceptable on a 3090. A faster chunkwise
implementation can be swapped in later while keeping the same interface.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.checkpoint import checkpoint as grad_checkpoint


def _init_dt_bias(num_heads: int, dt_min: float = 0.001, dt_max: float = 0.1) -> torch.Tensor:
    """Inverse-softplus initialization so that softplus(dt_bias) lies in range."""
    dt = torch.exp(torch.rand(num_heads) * (math.log(dt_max) - math.log(dt_min)) + math.log(dt_min))
    return torch.log(torch.expm1(dt))


import math


class RMSNorm(nn.Module):
    """Root-mean-square layer normalization."""

    def __init__(self, dim: int, eps: float = 1e-6) -> None:
        super().__init__()
        self.eps = eps
        self.weight = nn.Parameter(torch.ones(dim))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return x * torch.rsqrt(x.pow(2).mean(-1, keepdim=True) + self.eps) * self.weight


class RMSNormGated(nn.Module):
    """RMSNorm followed by a Swish/SiLU gate."""

    def __init__(self, dim: int, eps: float = 1e-6) -> None:
        super().__init__()
        self.eps = eps
        self.weight = nn.Parameter(torch.ones(dim))

    def forward(self, x: torch.Tensor, gate: torch.Tensor) -> torch.Tensor:
        x = x * torch.rsqrt(x.pow(2).mean(-1, keepdim=True) + self.eps) * self.weight
        return x * F.silu(gate)


class SwiGLU(nn.Module):
    """SwiGLU MLP used in modern LLaMA-style blocks."""

    def __init__(self, d_model: int, hidden_dim: Optional[int] = None) -> None:
        super().__init__()
        if hidden_dim is None:
            hidden_dim = 4 * d_model
        self.wgate = nn.Linear(d_model, hidden_dim, bias=False)
        self.wup = nn.Linear(d_model, hidden_dim, bias=False)
        self.wdown = nn.Linear(hidden_dim, d_model, bias=False)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.wdown(F.silu(self.wgate(x)) * self.wup(x))


class GatedDeltaNetMixer(nn.Module):
    """Gated DeltaNet token mixer in pure PyTorch.

    The recurrence per head is:
        S_t = alpha_t * S_{t-1} + beta_t * (v_t - alpha_t * S_{t-1} k_t) k_t^T
        o_t = S_t q_t

    q and k are L2-normalized; alpha is a Mamba2-style forget gate,
    beta is a per-key learning rate.
    """

    def __init__(
        self,
        d_model: int,
        num_heads: int = 4,
        head_dim: int = 64,
        dv_ratio: float = 2.0,
        d_conv: int = 4,
    ) -> None:
        super().__init__()
        self.d_model = d_model
        self.num_heads = num_heads
        self.head_dim = head_dim
        self.d_v = int(head_dim * dv_ratio)
        self.d_k_total = num_heads * head_dim
        self.d_inner = num_heads * self.d_v
        self.d_conv = d_conv

        self.q_proj = nn.Linear(d_model, self.d_k_total, bias=False)
        self.k_proj = nn.Linear(d_model, self.d_k_total, bias=False)
        self.v_proj = nn.Linear(d_model, self.d_inner, bias=False)
        self.b_proj = nn.Linear(d_model, num_heads, bias=False)
        self.a_proj = nn.Linear(d_model, num_heads, bias=False)
        self.g_proj = nn.Linear(d_model, self.d_inner, bias=False)

        # Mamba2-style parameterization for the alpha gate.
        A = torch.empty(num_heads).uniform_(1.0, 16.0)
        self.A_log = nn.Parameter(torch.log(A))
        self.dt_bias = nn.Parameter(_init_dt_bias(num_heads))

        self.q_conv1d = nn.Conv1d(
            self.d_k_total,
            self.d_k_total,
            kernel_size=d_conv,
            groups=self.d_k_total,
            padding=d_conv - 1,
            bias=False,
        )
        self.k_conv1d = nn.Conv1d(
            self.d_k_total,
            self.d_k_total,
            kernel_size=d_conv,
            groups=self.d_k_total,
            padding=d_conv - 1,
            bias=False,
        )
        self.v_conv1d = nn.Conv1d(
            self.d_inner,
            self.d_inner,
            kernel_size=d_conv,
            groups=self.d_inner,
            padding=d_conv - 1,
            bias=False,
        )

        self.o_norm = RMSNormGated(self.d_inner)
        self.o_proj = nn.Linear(self.d_inner, d_model, bias=False)

    def _causal_conv1d(self, x: torch.Tensor, conv: nn.Conv1d) -> torch.Tensor:
        """Apply a grouped causal 1-D convolution with SiLU activation."""
        B, L, C = x.shape
        out = conv(x.transpose(1, 2))  # (B, C, L + pad)
        out = out[:, :, :L].transpose(1, 2)  # trim padding, (B, L, C)
        return F.silu(out)

    def _compute_gates(self, x: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        beta = torch.sigmoid(self.b_proj(x))
        dt = F.softplus(self.a_proj(x) + self.dt_bias.view(1, 1, -1))
        A = -torch.exp(self.A_log)
        alpha = torch.exp(dt * A.view(1, 1, -1))
        return alpha, beta

    @torch.jit.export
    def _gated_delta_scan(
        self,
        q: torch.Tensor,
        k: torch.Tensor,
        v: torch.Tensor,
        alpha: torch.Tensor,
        beta: torch.Tensor,
    ) -> torch.Tensor:
        """Sequential gated-delta scan.

        Args:
            q, k: (B, L, H, Dk)
            v:    (B, L, H, Dv)
            alpha, beta: (B, L, H)

        Returns:
            o: (B, L, H, Dv)
        """
        B, L, H, Dk = q.shape
        Dv = v.shape[-1]
        S = torch.zeros(B, H, Dv, Dk, device=q.device, dtype=q.dtype)
        outputs: List[torch.Tensor] = []
        for t in range(L):
            kt = k[:, t]
            qt = q[:, t]
            vt = v[:, t]
            at = alpha[:, t]
            bt = beta[:, t]
            # S_{t-1} k_t -> z_t
            z = torch.einsum("bhvk,bhk->bhv", S, kt)
            # delta term beta_t * (v_t - alpha_t * z_t)
            delta = bt.unsqueeze(-1) * (vt - at.unsqueeze(-1) * z)
            # S_t = alpha_t S_{t-1} + delta_t k_t^T
            S = at.unsqueeze(-1).unsqueeze(-1) * S + delta.unsqueeze(-1) * kt.unsqueeze(-2)
            o_t = torch.einsum("bhvk,bhk->bhv", S, qt)
            outputs.append(o_t)
        return torch.stack(outputs, dim=1), S

    # ------------------------------------------------------------------
    # Chunkwise scan (pure PyTorch, no Triton)
    # ------------------------------------------------------------------

    def _chunk_gated_delta_scan(
        self,
        q: torch.Tensor,
        k: torch.Tensor,
        v: torch.Tensor,
        alpha: torch.Tensor,
        beta: torch.Tensor,
        chunk_size: int = 64,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Chunkwise gated-delta scan using WY representation.

        Implements the algorithm from NVlabs/GatedDeltaNet but replaces the
        O(C) forward-substitution loop for ``(I - A)^{-1}`` with **matrix
        doubling**: the Neumann-series identity

            (I - A)^{-1} = (I + A)(I + A^2)(I + A^4)...(I + A^{2^k})

        converges in exactly ``ceil(log2 C)`` batched matmuls (6 for C=64),
        versus 63 sequential row operations.  All intra-chunk work (Gram
        matrix, WY solve, corrected values) and inter-chunk work (state
        propagation, output) use batched matmuls — the only Python loop is
        over the ``num_chunks = L / C`` inter-chunk transitions.

        Args:
            q, k: (B, L, H, Dk) — L2-normalized
            v:    (B, L, H, Dv)
            alpha, beta: (B, L, H)
            chunk_size: intra-chunk parallel width C.

        Returns:
            o: (B, L, H, Dv)
            S_final: (B, H, Dv, Dk) — recurrent state after L tokens.
        """
        B, L, H, Dk = q.shape
        Dv = v.shape[-1]
        C = chunk_size
        orig_dtype = q.dtype

        # Pad L to a multiple of C.
        pad = (C - L % C) % C
        if pad > 0:
            q = F.pad(q, (0, 0, 0, 0, 0, pad))
            k = F.pad(k, (0, 0, 0, 0, 0, pad))
            v = F.pad(v, (0, 0, 0, 0, 0, pad))
            alpha = F.pad(alpha, (0, 0, 0, pad))
            beta = F.pad(beta, (0, 0, 0, pad))

        L_p = L + pad
        NC = L_p // C

        # All chunkwise math in float32 for numerical stability.
        q = q.to(torch.float32)
        k = k.to(torch.float32)
        v = v.to(torch.float32)
        alpha = alpha.to(torch.float32)
        beta = beta.to(torch.float32)

        # Transpose (B, L, H, D) → (B, H, L, D) for chunk matmuls.
        q_t = q.permute(0, 2, 1, 3)  # (B, H, L, Dk)
        k_t = k.permute(0, 2, 1, 3)
        v_t = v.permute(0, 2, 1, 3)  # (B, H, L, Dv)
        log_a = torch.log(alpha.clamp(min=1e-8)).permute(0, 2, 1)  # (B, H, L)
        beta_t = beta.permute(0, 2, 1)  # (B, H, L)

        # Reshape into chunks: (B, H, NC, C, D)
        q_c = q_t.reshape(B, H, NC, C, Dk)
        k_c = k_t.reshape(B, H, NC, C, Dk)
        v_c = v_t.reshape(B, H, NC, C, Dv)
        log_a_c = log_a.reshape(B, H, NC, C)
        beta_c = beta_t.reshape(B, H, NC, C)

        # Pre-scale v and k by beta (delta-rule input gate).
        v_beta = v_c * beta_c.unsqueeze(-1)  # (B, H, NC, C, Dv)
        k_beta = k_c * beta_c.unsqueeze(-1)  # (B, H, NC, C, Dk)

        # Cumulative log-decay within each chunk (inclusive).
        decay_c = log_a_c.cumsum(dim=-1)  # (B, H, NC, C)

        # Decay ratio matrix: L_mask[t, s] = exp(decay[t] - decay[s]).
        L_mask = (decay_c.unsqueeze(-1) - decay_c.unsqueeze(-2)).exp()  # (B, H, NC, C, C)

        # Boolean masks for the C×C intra-chunk attention.
        tril_incl_diag = torch.tril(
            torch.ones(C, C, device=q.device, dtype=torch.bool), diagonal=0
        )  # lower triangular, INCLUDING diagonal
        triu_diag = torch.triu(
            torch.ones(C, C, device=q.device, dtype=torch.bool), diagonal=0
        )  # upper triangular, including diagonal

        # ------------------------------------------------------------------
        # WY representation: W = (I - A)^{-1} where A is strictly lower-tri.
        #
        # TWO separate W matrices are needed:
        #   W1 (with L_mask decay)  → u = W1 @ v_beta  (corrected values)
        #   W2 (without L_mask)     → w = W2 @ k_beta  (inter-chunk key)
        #
        # The decay in the delta-rule recursion affects the *values* (u) but
        # the inter-chunk key projection (w) gets its decay from decay_exp
        # externally in v_prime = (w * decay_exp) @ S.  Using L_mask in both
        # would double-count the decay and break multi-chunk correctness.
        # ------------------------------------------------------------------
        gram = k_beta @ k_c.transpose(-1, -2)  # (B, H, NC, C, C)
        eye = torch.eye(C, device=q.device, dtype=torch.float32)
        n_doubling = max(1, int(math.ceil(math.log2(C)))) if C > 1 else 0

        # W1: WITH L_mask — for corrected values u = W1 @ v_beta.
        A1 = -(gram * L_mask).masked_fill(triu_diag, 0)
        W1 = eye + A1
        A1_pow = A1
        for _ in range(n_doubling):
            A1_pow = A1_pow @ A1_pow
            W1 = W1 @ (eye + A1_pow)

        # W2: WITHOUT L_mask — for inter-chunk key w = W2 @ k_beta.
        A2 = (-gram).masked_fill(triu_diag, 0)
        W2 = eye + A2
        A2_pow = A2
        for _ in range(n_doubling):
            A2_pow = A2_pow @ A2_pow
            W2 = W2 @ (eye + A2_pow)

        u = W1 @ v_beta  # (B, H, NC, C, Dv) — corrected values
        w = W2 @ k_beta  # (B, H, NC, C, Dk) — inter-chunk key

        # Precompute exponentials from LOG-space decay (avoids diff-of-exp bug).
        decay_exp = decay_c.exp()  # (B, H, NC, C)
        decay_last_log = decay_c[..., -1:]  # (B, H, NC, 1) — log-decay at chunk end
        decay_last_exp = decay_last_log.exp()  # (B, H, NC, 1)

        # ------------------------------------------------------------------
        # Inter-chunk state propagation (the only Python loop: NC iterations).
        # ------------------------------------------------------------------
        S = torch.zeros(B, H, Dk, Dv, device=q.device, dtype=torch.float32)
        o_chunks: List[torch.Tensor] = []

        for i in range(NC):
            q_i = q_c[:, :, i]  # (B, H, C, Dk)
            k_i = k_c[:, :, i]  # (B, H, C, Dk)
            v_i = v_beta[:, :, i]  # (B, H, C, Dv) — v already scaled by beta
            w_i = w[:, :, i]  # (B, H, C, Dk) — cumulative-decay key
            u_i = u[:, :, i]  # (B, H, C, Dv) — corrected values

            # Intra-chunk causal attention (lower triangular INCLUDING diagonal).
            attn = (q_i @ k_i.transpose(-1, -2) * L_mask[:, :, i]).masked_fill(
                ~tril_incl_diag, 0.0
            )  # (B, H, C, C)

            # Inter-chunk contribution: project S through w to get v_prime.
            # v_prime = (w_i * decay_exp_i) @ S
            v_prime = (w_i * decay_exp[:, :, i].unsqueeze(-1)) @ S  # (B, H, C, Dv)

            # Corrected values: remove inter-chunk state contribution.
            v_new = u_i - v_prime  # (B, H, C, Dv)

            # Inter-chunk output (direct).
            o_inter = (q_i * decay_exp[:, :, i].unsqueeze(-1)) @ S  # (B, H, C, Dv)

            # Total output = inter-chunk + intra-chunk @ corrected values.
            o_i = o_inter + attn @ v_new  # (B, H, C, Dv)
            o_chunks.append(o_i)

            # State update:
            # S = S * decay_last + (k * decay_ratio)^T @ v_new
            # decay_ratio[t] = exp(decay_last_log - decay_c[t])
            #              = prod_{s=t+1}^{C-1} alpha_s (decay from t+1 to chunk end)
            decay_ratio = (
                decay_last_log[:, :, i] - decay_c[:, :, i]
            ).exp()  # (B, H, C)
            k_weighted = k_i * decay_ratio.unsqueeze(-1)  # (B, H, C, Dk)
            S = S * decay_last_exp[:, :, i].unsqueeze(-1) + k_weighted.transpose(
                -1, -2
            ) @ v_new  # (B, H, Dk, Dv)

        o = torch.stack(o_chunks, dim=2)  # (B, H, NC, C, Dv)
        o = o.reshape(B, H, L_p, Dv)
        o = o.permute(0, 2, 1, 3)  # (B, L_p, H, Dv)
        o = o[:, :L, :, :]  # trim padding

        return o.to(orig_dtype), S.to(orig_dtype)

    # Minimum sequence length to activate the chunkwise scan.  Below this the
    # Python-loop overhead of the inter-chunk loop outweighs the matmul savings.
    _CHUNK_THRESHOLD: int = 128

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        B, L, _ = x.shape
        q = self._causal_conv1d(self.q_proj(x), self.q_conv1d)
        k = self._causal_conv1d(self.k_proj(x), self.k_conv1d)
        v = self._causal_conv1d(self.v_proj(x), self.v_conv1d)

        q = q.view(B, L, self.num_heads, self.head_dim)
        k = k.view(B, L, self.num_heads, self.head_dim)
        v = v.view(B, L, self.num_heads, self.d_v)

        q = F.normalize(q, dim=-1, eps=1e-6)
        k = F.normalize(k, dim=-1, eps=1e-6)

        alpha, beta = self._compute_gates(x)
        if L >= self._CHUNK_THRESHOLD:
            o, _ = self._chunk_gated_delta_scan(q, k, v, alpha, beta)
        else:
            o, _ = self._gated_delta_scan(q, k, v, alpha, beta)
        o = o.reshape(B, L, self.d_inner)

        gate = self.g_proj(x)
        y = self.o_norm(o, gate)
        return self.o_proj(y)

    def forward_with_state(
        self, x: torch.Tensor
    ) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]]:
        """Same as forward() but also returns the recurrent state for continued generation.

        Returns:
            y: (B, L, d_model)
            state: (S, q_buf, k_buf, v_buf) where buffers hold the last d_conv-1
                   raw projection values so that step() can continue seamlessly.
        """
        B, L, _ = x.shape
        q_raw = self.q_proj(x)
        k_raw = self.k_proj(x)
        v_raw = self.v_proj(x)

        q = self._causal_conv1d(q_raw, self.q_conv1d)
        k = self._causal_conv1d(k_raw, self.k_conv1d)
        v = self._causal_conv1d(v_raw, self.v_conv1d)

        q = q.view(B, L, self.num_heads, self.head_dim)
        k = k.view(B, L, self.num_heads, self.head_dim)
        v = v.view(B, L, self.num_heads, self.d_v)

        q = F.normalize(q, dim=-1, eps=1e-6)
        k = F.normalize(k, dim=-1, eps=1e-6)

        alpha, beta = self._compute_gates(x)
        if L >= self._CHUNK_THRESHOLD:
            o, S = self._chunk_gated_delta_scan(q, k, v, alpha, beta)
        else:
            o, S = self._gated_delta_scan(q, k, v, alpha, beta)
        o = o.reshape(B, L, self.d_inner)

        gate = self.g_proj(x)
        y = self.o_norm(o, gate)
        y = self.o_proj(y)

        # Conv buffers for step(): last d_conv-1 raw projection values.
        k_size = self.d_conv - 1
        q_buf = q_raw[:, -k_size:, :].transpose(1, 2) if L >= k_size else F.pad(
            q_raw.transpose(1, 2), (k_size - L, 0), value=0.0
        )
        k_buf = k_raw[:, -k_size:, :].transpose(1, 2) if L >= k_size else F.pad(
            k_raw.transpose(1, 2), (k_size - L, 0), value=0.0
        )
        v_buf = v_raw[:, -k_size:, :].transpose(1, 2) if L >= k_size else F.pad(
            v_raw.transpose(1, 2), (k_size - L, 0), value=0.0
        )

        return y, (S, q_buf, k_buf, v_buf)

    # ------------------------------------------------------------------
    # Single-token step helpers (inference / generation)
    # ------------------------------------------------------------------

    def _step_conv1d(
        self,
        x_proj: torch.Tensor,
        conv: nn.Conv1d,
        buf: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Advance a causal conv1d by one input.

        Args:
            x_proj: (B, C) single-step projection
            conv: grouped conv1d layer
            buf: (B, C, k-1) buffer of previous inputs

        Returns:
            out: (B, C) conv output at this step
            new_buf: (B, C, k-1)
        """
        C = x_proj.size(-1)
        k = self.d_conv
        # Append current input; full history has length k.
        full_buf = torch.cat([buf, x_proj.unsqueeze(-1)], dim=-1)  # (B, C, k)
        new_buf = full_buf[:, :, 1:]  # (B, C, k-1) for next step
        # Manual grouped convolution: weight shape (C, 1, k)
        weight = conv.weight.squeeze(1)  # (C, k)
        out = (full_buf * weight.unsqueeze(0)).sum(dim=-1)  # (B, C)
        return F.silu(out), new_buf

    def step_init(self, batch_size: int, device: torch.device) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Return initial recurrent state and conv buffers for generation.

        Returns (S, q_buf, k_buf, v_buf) where S has shape (B, H, Dv, Dk) and
        each buffer has shape (B, C, k-1).
        """
        S = torch.zeros(batch_size, self.num_heads, self.d_v, self.head_dim, device=device)
        q_buf = torch.zeros(batch_size, self.d_k_total, self.d_conv - 1, device=device)
        k_buf = torch.zeros(batch_size, self.d_k_total, self.d_conv - 1, device=device)
        v_buf = torch.zeros(batch_size, self.d_inner, self.d_conv - 1, device=device)
        return S, q_buf, k_buf, v_buf

    def step(
        self,
        x: torch.Tensor,
        state: Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor],
    ) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]]:
        """Advance the mixer by one token.

        Args:
            x: (B, 1, d_model)
            state: (S, q_buf, k_buf, v_buf)

        Returns:
            y: (B, 1, d_model)
            new_state
        """
        B, _, _ = x.shape
        S, q_buf, k_buf, v_buf = state

        q_raw = self.q_proj(x).squeeze(1)
        k_raw = self.k_proj(x).squeeze(1)
        v_raw = self.v_proj(x).squeeze(1)

        q, q_buf = self._step_conv1d(q_raw, self.q_conv1d, q_buf)
        k, k_buf = self._step_conv1d(k_raw, self.k_conv1d, k_buf)
        v, v_buf = self._step_conv1d(v_raw, self.v_conv1d, v_buf)

        q = q.view(B, self.num_heads, self.head_dim)
        k = k.view(B, self.num_heads, self.head_dim)
        v = v.view(B, self.num_heads, self.d_v)

        q = F.normalize(q, dim=-1, eps=1e-6)
        k = F.normalize(k, dim=-1, eps=1e-6)

        alpha, beta = self._compute_gates(x)
        alpha = alpha.squeeze(1)  # (B, H)
        beta = beta.squeeze(1)

        z = torch.einsum("bhvk,bhk->bhv", S, k)
        delta = beta.unsqueeze(-1) * (v - alpha.unsqueeze(-1) * z)
        S = alpha.unsqueeze(-1).unsqueeze(-1) * S + delta.unsqueeze(-1) * k.unsqueeze(-2)
        o = torch.einsum("bhvk,bhk->bhv", S, q)
        o = o.reshape(B, 1, self.d_inner)

        gate = self.g_proj(x)
        y = self.o_norm(o, gate)
        y = self.o_proj(y)
        return y, (S, q_buf, k_buf, v_buf)


class GatedDeltaNetBlock(nn.Module):
    """Residual GDN mixer block: mixer -> SwiGLU MLP."""

    def __init__(
        self,
        d_model: int,
        num_heads: int = 4,
        head_dim: int = 64,
        dv_ratio: float = 2.0,
        d_conv: int = 4,
        mlp_ratio: float = 4.0,
    ) -> None:
        super().__init__()
        self.norm1 = RMSNorm(d_model)
        self.mixer = GatedDeltaNetMixer(
            d_model=d_model,
            num_heads=num_heads,
            head_dim=head_dim,
            dv_ratio=dv_ratio,
            d_conv=d_conv,
        )
        self.norm2 = RMSNorm(d_model)
        hidden = int(d_model * mlp_ratio)
        self.mlp = SwiGLU(d_model, hidden)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.mixer(self.norm1(x))
        x = x + self.mlp(self.norm2(x))
        return x

    def forward_with_state(
        self, x: torch.Tensor
    ) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]]:
        residual = x
        y = self.norm1(x)
        y, mixer_state = self.mixer.forward_with_state(y)
        x = residual + y

        residual = x
        y = self.norm2(x)
        y = self.mlp(y)
        x = residual + y
        return x, mixer_state

    def step_init(
        self, batch_size: int, device: torch.device
    ) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
        return self.mixer.step_init(batch_size, device)

    def step(
        self,
        x: torch.Tensor,
        state: Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor],
    ) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]]:
        residual = x
        y = self.norm1(x)
        y, mixer_state = self.mixer.step(y, state)
        x = residual + y

        residual = x
        y = self.norm2(x)
        y = self.mlp(y)
        x = residual + y
        return x, mixer_state


class GatedDeltaNetBackbone(nn.Module):
    """Stack of GDN blocks with final RMSNorm."""

    def __init__(
        self,
        d_model: int,
        num_layers: int,
        num_heads: int = 4,
        head_dim: int = 64,
        dv_ratio: float = 2.0,
        d_conv: int = 4,
        mlp_ratio: float = 4.0,
        gradient_checkpointing: bool = False,
    ) -> None:
        super().__init__()
        self.blocks = nn.ModuleList(
            [
                GatedDeltaNetBlock(
                    d_model=d_model,
                    num_heads=num_heads,
                    head_dim=head_dim,
                    dv_ratio=dv_ratio,
                    d_conv=d_conv,
                    mlp_ratio=mlp_ratio,
                )
                for _ in range(num_layers)
            ]
        )
        self.norm_f = RMSNorm(d_model)
        self.gradient_checkpointing = gradient_checkpointing

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        for block in self.blocks:
            if self.training and self.gradient_checkpointing:
                x = grad_checkpoint(
                    block, x, use_reentrant=False
                )
            else:
                x = block(x)
        return self.norm_f(x)

    def forward_with_state(self, x: torch.Tensor) -> Tuple[torch.Tensor, List[Tuple]]:
        states: List[Tuple] = []
        for block in self.blocks:
            x, state = block.forward_with_state(x)
            states.append(state)
        x = self.norm_f(x)
        return x, states

    def step_init(self, batch_size: int, device: torch.device) -> List[Tuple]:
        return [block.step_init(batch_size, device) for block in self.blocks]

    def step(self, x: torch.Tensor, states: List[Tuple]) -> Tuple[torch.Tensor, List[Tuple]]:
        new_states: List[Tuple] = []
        for block, state in zip(self.blocks, states):
            x, new_state = block.step(x, state)
            new_states.append(new_state)
        x = self.norm_f(x)
        return x, new_states


# ======================================================================
# GCLSD-v3 "DeltaJEPA-MoE" backbone components
# ======================================================================
# Contribution #4: MoE-GDN — first sparse MoE GDN backbone (DeepSeekMoE 2024)
# Contribution: MLA — DeepSeek-V2 low-rank KV compression for attention blocks
#

class MLAAttention(nn.Module):
    """Multi-head Latent Attention (DeepSeek-V2 style).

    Compresses KV into a low-rank latent ``c_kv`` via ``W_DKV``, then
    up-projects to K and V via ``W_UK`` / ``W_UV``.  At inference, only
    ``c_kv`` (``d_ckv`` dims per token) and ``k_rope`` (``d_rope`` dims)
    need to be cached — drastically smaller than full K,V.

    Q is similarly compressed via ``W_DQ`` → ``c_q``, then up-projected.

    Decoupled RoPE: a small ``d_rope`` slice is dedicated to positional
    encoding via RoPE (shared across all heads), while the main ``d_qk``
    slice is non-positional ("nope").  This separation is key to MLA's
    KV-cache compression: the rope part of K (``k_rope``) is tiny.
    """

    def __init__(
        self,
        d_model: int,
        num_heads: int = 8,
        head_dim: int = 128,
        d_cq: int = 512,
        d_ckv: int = 256,
        d_rope: int = 32,
    ) -> None:
        super().__init__()
        self.d_model = d_model
        self.num_heads = num_heads
        self.head_dim = head_dim
        self.d_qk = head_dim  # per-head nope dimension
        self.d_v = head_dim  # per-head value dimension
        self.d_qk_rope = d_rope  # shared rope dimension
        self.d_cq = d_cq
        self.d_ckv = d_ckv
        self.d_v_total = num_heads * self.d_v
        self.scale = (self.d_qk + self.d_qk_rope) ** -0.5

        # Q: down-project then up-project.
        self.W_DQ = nn.Linear(d_model, d_cq, bias=False)
        self.W_UQ = nn.Linear(d_cq, num_heads * self.d_qk, bias=False)
        self.W_QR = nn.Linear(d_cq, d_rope, bias=False)  # shared rope from c_q

        # KV: down-project then up-project.
        self.W_DKV = nn.Linear(d_model, d_ckv, bias=False)
        self.W_UK = nn.Linear(d_ckv, num_heads * self.d_qk, bias=False)
        self.W_UV = nn.Linear(d_ckv, num_heads * self.d_v, bias=False)
        self.W_KR = nn.Linear(d_model, d_rope, bias=False)  # shared rope from h

        # Output projection.
        self.W_O = nn.Linear(self.d_v_total, d_model, bias=False)

        # RoPE frequencies.
        inv_freq = 1.0 / (10000 ** (torch.arange(0, d_rope, 2).float() / d_rope))
        self.register_buffer("inv_freq", inv_freq, persistent=False)

    def _get_rope(
        self, seq_len: int, device: torch.device, dtype: torch.dtype
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        pos = torch.arange(seq_len, device=device, dtype=self.inv_freq.dtype)
        freqs = torch.outer(pos, self.inv_freq)  # (L, d_rope//2)
        cos = torch.cat([freqs.cos(), freqs.cos()], dim=-1)  # (L, d_rope)
        sin = torch.cat([freqs.sin(), freqs.sin()], dim=-1)
        return cos[None, :, None, :].to(dtype), sin[None, :, None, :].to(dtype)

    @staticmethod
    def _rotate_half(x: torch.Tensor) -> torch.Tensor:
        d = x.shape[-1]
        x1 = x[..., : d // 2]
        x2 = x[..., d // 2 :]
        return torch.cat((-x2, x1), dim=-1)

    def _apply_rope(self, x: torch.Tensor, cos: torch.Tensor, sin: torch.Tensor) -> torch.Tensor:
        return x * cos + self._rotate_half(x) * sin

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        B, L, _ = x.shape
        # Q path.
        c_q = self.W_DQ(x)
        q_nope = self.W_UQ(c_q).view(B, L, self.num_heads, self.d_qk)
        q_rope = self.W_QR(c_q).view(B, L, 1, self.d_qk_rope)

        # KV path.
        c_kv = self.W_DKV(x)
        k_nope = self.W_UK(c_kv).view(B, L, self.num_heads, self.d_qk)
        v = self.W_UV(c_kv).view(B, L, self.num_heads, self.d_v)
        k_rope = self.W_KR(x).view(B, L, 1, self.d_qk_rope)

        # Apply RoPE to rope parts.
        cos, sin = self._get_rope(L, x.device, x.dtype)
        q_rope = self._apply_rope(q_rope, cos, sin)
        k_rope = self._apply_rope(k_rope, cos, sin)

        # Expand rope across heads and concatenate with nope.
        q_rope = q_rope.expand(B, L, self.num_heads, self.d_qk_rope)
        k_rope = k_rope.expand(B, L, self.num_heads, self.d_qk_rope)
        q = torch.cat([q_nope, q_rope], dim=-1)
        k = torch.cat([k_nope, k_rope], dim=-1)

        # Transpose to (B, H, L, D) for SDPA.
        q = q.transpose(1, 2)
        k = k.transpose(1, 2)
        v = v.transpose(1, 2)

        # Causal self-attention via PyTorch SDPA (fused CUDA kernels).
        y = F.scaled_dot_product_attention(q, k, v, is_causal=True)
        y = y.transpose(1, 2).reshape(B, L, -1)
        return self.W_O(y)

    def forward_with_state(
        self, x: torch.Tensor
    ) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]:
        """Same as forward() but also returns KV cache (compressed latents).

        Returns:
            y: (B, L, d_model)
            state: (c_kv_cache, k_rope_raw) where:
                c_kv_cache: (B, L, d_ckv) — compressed KV latent
                k_rope_raw: (B, L, d_rope) — raw (pre-RoPE) rope keys
        """
        B, L, _ = x.shape
        c_q = self.W_DQ(x)
        q_nope = self.W_UQ(c_q).view(B, L, self.num_heads, self.d_qk)
        q_rope = self.W_QR(c_q).view(B, L, 1, self.d_qk_rope)

        c_kv = self.W_DKV(x)
        k_nope = self.W_UK(c_kv).view(B, L, self.num_heads, self.d_qk)
        v = self.W_UV(c_kv).view(B, L, self.num_heads, self.d_v)
        k_rope_raw = self.W_KR(x).view(B, L, 1, self.d_qk_rope)

        cos, sin = self._get_rope(L, x.device, x.dtype)
        q_rope = self._apply_rope(q_rope, cos, sin)
        k_rope = self._apply_rope(k_rope_raw, cos, sin)

        q_rope = q_rope.expand(B, L, self.num_heads, self.d_qk_rope)
        k_rope = k_rope.expand(B, L, self.num_heads, self.d_qk_rope)
        q = torch.cat([q_nope, q_rope], dim=-1)
        k = torch.cat([k_nope, k_rope], dim=-1)

        q = q.transpose(1, 2)
        k = k.transpose(1, 2)
        v = v.transpose(1, 2)

        y = F.scaled_dot_product_attention(q, k, v, is_causal=True)
        y = y.transpose(1, 2).reshape(B, L, -1)
        return self.W_O(y), (c_kv, k_rope_raw.squeeze(2))

    def step_init(self, batch_size: int, device: torch.device) -> Tuple[torch.Tensor, torch.Tensor]:
        """Return initial KV cache (empty).

        Returns:
            state: (c_kv_cache, k_rope_raw) both initially empty (size 0 in seq dim).
        """
        c_kv = torch.zeros(batch_size, 0, self.d_ckv, device=device)
        k_rope = torch.zeros(batch_size, 0, self.d_qk_rope, device=device)
        return c_kv, k_rope

    def step(
        self, x: torch.Tensor, state: Tuple[torch.Tensor, torch.Tensor]
    ) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]:
        """Advance by one token, appending to the compressed KV cache.

        At inference, only ``c_kv`` (d_ckv) and ``k_rope`` (d_rope) per token
        are cached — ~8× smaller than full K,V.
        """
        B, _, D = x.shape
        c_kv_cache, k_rope_cache = state
        S = c_kv_cache.size(1)

        # Compute new token's latent and rope key.
        c_kv_new = self.W_DKV(x)  # (B, 1, d_ckv)
        k_rope_new = self.W_KR(x)  # (B, 1, d_rope)

        # Append to cache.
        c_kv_cache = torch.cat([c_kv_cache, c_kv_new], dim=1)  # (B, S+1, d_ckv)
        k_rope_cache = torch.cat([k_rope_cache, k_rope_new], dim=1)  # (B, S+1, d_rope)
        S_new = S + 1

        # Compute Q for the new token (position S_new - 1).
        c_q = self.W_DQ(x)
        q_nope = self.W_UQ(c_q).view(B, 1, self.num_heads, self.d_qk)
        q_rope = self.W_QR(c_q).view(B, 1, 1, self.d_qk_rope)

        # Compute K, V from ALL cached latents.
        k_nope = self.W_UK(c_kv_cache).view(B, S_new, self.num_heads, self.d_qk)
        v = self.W_UV(c_kv_cache).view(B, S_new, self.num_heads, self.d_v)
        k_rope = k_rope_cache.view(B, S_new, 1, self.d_qk_rope)

        # Apply RoPE: q at position S_new-1, k at all positions 0..S_new-1.
        cos, sin = self._get_rope(S_new, x.device, x.dtype)
        q_rope = self._apply_rope(q_rope, cos[:, S_new - 1 : S_new], sin[:, S_new - 1 : S_new])
        k_rope = self._apply_rope(k_rope, cos, sin)

        q_rope = q_rope.expand(B, 1, self.num_heads, self.d_qk_rope)
        k_rope = k_rope.expand(B, S_new, self.num_heads, self.d_qk_rope)
        q = torch.cat([q_nope, q_rope], dim=-1)  # (B, 1, H, d_qk + d_rope)
        k = torch.cat([k_nope, k_rope], dim=-1)  # (B, S_new, H, ...)

        q = q.transpose(1, 2)  # (B, H, 1, D)
        k = k.transpose(1, 2)  # (B, H, S_new, D)
        v = v.transpose(1, 2)  # (B, H, S_new, d_v)

        # No causal mask needed: single query attending to all keys.
        scores = torch.matmul(q, k.transpose(-1, -2)) * self.scale
        attn = F.softmax(scores, dim=-1)
        y = torch.matmul(attn, v)  # (B, H, 1, d_v)
        y = y.transpose(1, 2).reshape(B, 1, -1)
        return self.W_O(y), (c_kv_cache, k_rope_cache)


class MLABlock(nn.Module):
    """Residual block: MLA attention -> dense SwiGLu MLP."""

    def __init__(
        self,
        d_model: int,
        num_heads: int = 8,
        head_dim: int = 128,
        d_cq: int = 512,
        d_ckv: int = 256,
        d_rope: int = 32,
        mlp_ratio: float = 2.6875,
    ) -> None:
        super().__init__()
        self.norm1 = RMSNorm(d_model)
        self.attn = MLAAttention(
            d_model=d_model,
            num_heads=num_heads,
            head_dim=head_dim,
            d_cq=d_cq,
            d_ckv=d_ckv,
            d_rope=d_rope,
        )
        self.norm2 = RMSNorm(d_model)
        hidden = int(d_model * mlp_ratio)
        self.mlp = SwiGLU(d_model, hidden)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.attn(self.norm1(x))
        x = x + self.mlp(self.norm2(x))
        return x

    def forward_with_state(self, x: torch.Tensor) -> Tuple[torch.Tensor, Tuple[torch.Tensor, torch.Tensor]]:
        residual = x
        y = self.norm1(x)
        y, kv_state = self.attn.forward_with_state(y)
        x = residual + y
        residual = x
        y = self.norm2(x)
        y = self.mlp(y)
        x = residual + y
        return x, kv_state

    def step_init(self, batch_size: int, device: torch.device) -> Tuple[torch.Tensor, torch.Tensor]:
        return self.attn.step_init(batch_size, device)

    def step(self, x: torch.Tensor, state: Tuple) -> Tuple[torch.Tensor, Tuple]:
        residual = x
        y = self.norm1(x)
        y, kv_state = self.attn.step(y, state)
        x = residual + y
        residual = x
        y = self.norm2(x)
        y = self.mlp(y)
        x = residual + y
        return x, kv_state


class SparseMoE(nn.Module):
    """Sparse Mixture of Experts with auxiliary-loss-free load balancing.

    Implements two DeepSeek innovations:
      - DeepSeekMoE fine-grained expert segmentation: each routed expert is
        1/N the standard SwiGLU size. With top-K routing, the model achieves
        higher expert specialization without extra activated compute.
      - DeepSeek-V3 auxiliary-loss-free load balancing: per-expert bias terms
        are added to routing logits during top-K selection (only), then the
        original softmax weights (without bias) are used for gating. The bias
        is updated via a heuristic rule (no gradient, no auxiliary loss).

    Args:
        d_model: model dimension.
        num_experts: number of routed experts (fine-grained).
        top_k: number of experts to route each token to.
        expert_intermediate: hidden dim of each SwiGLU expert (default:
            ``d_model * mlp_ratio / num_experts`` per DeepSeekMoE recipe).
        shared_intermediate: hidden dim of the always-active shared expert.
        bias_update_rate: step size for the heuristic bias update.
    """

    def __init__(
        self,
        d_model: int,
        num_experts: int = 8,
        top_k: int = 2,
        expert_intermediate: Optional[int] = None,
        shared_intermediate: Optional[int] = None,
        mlp_ratio: float = 2.6875,
        bias_update_rate: float = 0.001,
    ) -> None:
        super().__init__()
        self.num_experts = num_experts
        self.top_k = top_k
        self.bias_update_rate = bias_update_rate

        if expert_intermediate is None:
            expert_intermediate = max(1, int(d_model * mlp_ratio / num_experts))
        if shared_intermediate is None:
            shared_intermediate = max(1, int(d_model * mlp_ratio / 2))

        self.gate = nn.Linear(d_model, num_experts, bias=False)
        self.experts = nn.ModuleList([
            SwiGLU(d_model, expert_intermediate) for _ in range(num_experts)
        ])
        self.shared_expert = SwiGLU(d_model, shared_intermediate)

        # Load-balancing bias: NOT a parameter (no gradient), updated heuristically.
        self.register_buffer("expert_bias", torch.zeros(num_experts))
        self.register_buffer("expert_load_ema", torch.ones(num_experts) / num_experts)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        B, L, D = x.shape
        N = B * L  # total tokens

        # Shared expert (always active).
        shared_out = self.shared_expert(x)  # (B, L, D)

        # Routing: compute softmax scores.
        gate_logits = self.gate(x)  # (B, L, num_experts)
        scores = F.softmax(gate_logits, dim=-1)  # original scores (for weighting)

        # Add bias for selection only.
        biased_scores = scores + self.expert_bias  # (B, L, num_experts)
        topk_scores, topk_indices = biased_scores.topk(self.top_k, dim=-1)  # (B, L, top_k)

        # Use ORIGINAL scores (not biased) for gating weights.
        topk_weights = scores.gather(-1, topk_indices)  # (B, L, top_k)
        topk_weights = topk_weights / topk_weights.sum(dim=-1, keepdim=True).clamp(min=1e-6)

        # Flatten for expert dispatch.
        x_flat = x.reshape(N, D)
        topk_indices_flat = topk_indices.reshape(N, self.top_k)
        topk_weights_flat = topk_weights.reshape(N, self.top_k)

        moe_out = torch.zeros_like(x_flat)
        # Loop over experts — each processes only its assigned tokens.
        for e in range(self.num_experts):
            token_mask = (topk_indices_flat == e).any(dim=-1)  # (N,)
            if not token_mask.any():
                continue
            tokens = x_flat[token_mask]  # (M, D)
            expert_out = self.experts[e](tokens)  # (M, D)

            # Extract the weight for this expert (the slot where mask is True).
            slot_mask = (topk_indices_flat[token_mask] == e).float()  # (M, top_k)
            weights = (topk_weights_flat[token_mask] * slot_mask).sum(dim=-1)  # (M,)

            moe_out[token_mask] += weights.unsqueeze(-1) * expert_out

        moe_out = moe_out.reshape(B, L, D)

        # Heuristic bias update (auxiliary-loss-free load balancing).
        if self.training:
            with torch.no_grad():
                load_flat = topk_indices_flat  # (N, top_k)
                for e in range(self.num_experts):
                    load_e = (load_flat == e).float().sum() / max(1, N)
                    self.expert_load_ema[e].mul_(0.99).add_(0.01 * load_e)
                avg_load = self.top_k / self.num_experts
                for e in range(self.num_experts):
                    if self.expert_load_ema[e] > avg_load:
                        self.expert_bias[e] -= self.bias_update_rate
                    else:
                        self.expert_bias[e] += self.bias_update_rate

        return shared_out + moe_out


class SparseMoEGDNBlock(nn.Module):
    """Residual block: GDN mixer -> SparseMoE FFN.

    Combines the GDN SSM recurrence (token mixer) with sparse MoE feedforward
    (DeepSeekMoE + DeepSeek-V3 auxiliary-loss-free load balancing).
    """

    def __init__(
        self,
        d_model: int,
        num_heads: int = 4,
        head_dim: int = 64,
        dv_ratio: float = 2.0,
        d_conv: int = 4,
        num_experts: int = 8,
        top_k: int = 2,
        expert_intermediate: Optional[int] = None,
        shared_intermediate: Optional[int] = None,
        mlp_ratio: float = 2.6875,
        bias_update_rate: float = 0.001,
    ) -> None:
        super().__init__()
        self.norm1 = RMSNorm(d_model)
        self.mixer = GatedDeltaNetMixer(
            d_model=d_model,
            num_heads=num_heads,
            head_dim=head_dim,
            dv_ratio=dv_ratio,
            d_conv=d_conv,
        )
        self.norm2 = RMSNorm(d_model)
        self.moe = SparseMoE(
            d_model=d_model,
            num_experts=num_experts,
            top_k=top_k,
            expert_intermediate=expert_intermediate,
            shared_intermediate=shared_intermediate,
            mlp_ratio=mlp_ratio,
            bias_update_rate=bias_update_rate,
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = x + self.mixer(self.norm1(x))
        x = x + self.moe(self.norm2(x))
        return x

    def forward_with_state(self, x: torch.Tensor) -> Tuple[torch.Tensor, Tuple]:
        residual = x
        y = self.norm1(x)
        y, mixer_state = self.mixer.forward_with_state(y)
        x = residual + y
        residual = x
        y = self.norm2(x)
        y = self.moe(y)
        x = residual + y
        return x, mixer_state

    def step_init(self, batch_size: int, device: torch.device) -> Tuple:
        return self.mixer.step_init(batch_size, device)

    def step(self, x: torch.Tensor, state: Tuple) -> Tuple[torch.Tensor, Tuple]:
        residual = x
        y = self.norm1(x)
        y, mixer_state = self.mixer.step(y, state)
        x = residual + y
        residual = x
        y = self.norm2(x)
        y = self.moe(y)
        x = residual + y
        return x, mixer_state


class HybridBackbone(nn.Module):
    """GCLSD-v3 hybrid backbone: MLA attention layers + SparseMoE GDN layers.

    Architecture (locked GCLSD-v3 "DeltaJEPA-MoE"):
      - num_layers = 12
      - MLA blocks at layers {0, 4, 8} (positions for global context)
      - SparseMoE GDN blocks at all other layers

    Each MLA block: RMSNorm + MLA Attention + RMSNorm + dense SwiGLU.
    Each MoE GDN block: RMSNorm + GDN Mixer + RMSNorm + SparseMoE.

    The backbone supports three modes:
      - ``forward(x)``: training (full sequence).
      - ``forward_with_state(x)``: prefix processing for generation.
      - ``step(x, states)``: single-token generation.
    """

    def __init__(
        self,
        d_model: int,
        num_layers: int = 12,
        mla_layer_indices: Optional[List[int]] = None,
        num_heads_gdn: int = 8,
        head_dim_gdn: int = 64,
        dv_ratio: float = 2.0,
        d_conv: int = 4,
        num_heads_mla: int = 8,
        head_dim_mla: int = 128,
        d_cq: int = 512,
        d_ckv: int = 256,
        d_rope: int = 32,
        num_experts: int = 8,
        top_k: int = 2,
        mlp_ratio: float = 2.6875,
        gradient_checkpointing: bool = False,
    ) -> None:
        super().__init__()
        if mla_layer_indices is None:
            mla_layer_indices = self._default_mla_positions(num_layers)
        self.mla_layer_indices = set(mla_layer_indices)

        self.blocks = nn.ModuleList()
        for i in range(num_layers):
            if i in self.mla_layer_indices:
                block = MLABlock(
                    d_model=d_model,
                    num_heads=num_heads_mla,
                    head_dim=head_dim_mla,
                    d_cq=d_cq,
                    d_ckv=d_ckv,
                    d_rope=d_rope,
                    mlp_ratio=mlp_ratio,
                )
            else:
                block = SparseMoEGDNBlock(
                    d_model=d_model,
                    num_heads=num_heads_gdn,
                    head_dim=head_dim_gdn,
                    dv_ratio=dv_ratio,
                    d_conv=d_conv,
                    num_experts=num_experts,
                    top_k=top_k,
                    mlp_ratio=mlp_ratio,
                )
            self.blocks.append(block)

        self.norm_f = RMSNorm(d_model)
        self.gradient_checkpointing = gradient_checkpointing

    @staticmethod
    def _default_mla_positions(num_layers: int) -> List[int]:
        """MLA blocks at layers {0, num/3, 2*num/3} for good coverage."""
        if num_layers <= 3:
            return [0]
        step = num_layers // 3
        return [0, step, 2 * step]

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        for block in self.blocks:
            if self.training and self.gradient_checkpointing:
                x = grad_checkpoint(block, x, use_reentrant=False)
            else:
                x = block(x)
        return self.norm_f(x)

    def forward_with_state(self, x: torch.Tensor) -> Tuple[torch.Tensor, List[Tuple]]:
        states: List[Tuple] = []
        for block in self.blocks:
            x, state = block.forward_with_state(x)
            states.append(state)
        x = self.norm_f(x)
        return x, states

    def step_init(self, batch_size: int, device: torch.device) -> List[Tuple]:
        return [block.step_init(batch_size, device) for block in self.blocks]

    def step(self, x: torch.Tensor, states: List[Tuple]) -> Tuple[torch.Tensor, List[Tuple]]:
        new_states: List[Tuple] = []
        for block, state in zip(self.blocks, states):
            x, new_state = block.step(x, state)
            new_states.append(new_state)
        x = self.norm_f(x)
        return x, new_states
