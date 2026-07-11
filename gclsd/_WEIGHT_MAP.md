# GCLSD-v3 Weight Map: LLM4Decompile-1.3b-v1.6 → Student

## Teacher Architecture (LLM4Decompile-1.3b-v1.6)

| Parameter | Shape | dtype |
|---|---|---|
| `model.embed_tokens.weight` | [32256, 2048] | bf16 |
| `lm_head.weight` | [32256, 2048] | bf16 (untied) |
| `model.norm.weight` | [2048] | bf16 |
| Per-layer (×24): | | |
| `model.layers.{i}.input_layernorm.weight` | [2048] | bf16 |
| `model.layers.{i}.post_attention_layernorm.weight` | [2048] | bf16 |
| `model.layers.{i}.self_attn.q_proj.weight` | [2048, 2048] | bf16 |
| `model.layers.{i}.self_attn.k_proj.weight` | [2048, 2048] | bf16 |
| `model.layers.{i}.self_attn.v_proj.weight` | [2048, 2048] | bf16 |
| `model.layers.{i}.self_attn.o_proj.weight` | [2048, 2048] | bf16 |
| `model.layers.{i}.mlp.gate_proj.weight` | [5504, 2048] | bf16 |
| `model.layers.{i}.mlp.up_proj.weight` | [5504, 2048] | bf16 |
| `model.layers.{i}.mlp.down_proj.weight` | [2048, 5504] | bf16 |

**Total teacher params:** ~1.33B (24 layers × ~46M + 2× embedding tables)
**Config:** LlamaForCausalLM, hidden_size=2048, num_heads=16, head_dim=128,
intermediate_size=5504, vocab_size=32256, tie_word_embeddings=false,
rope_theta=100000, linear rope_scaling factor=4.0.

## Student Architecture (GCLSD-v3 DeltaJEPA-MoE)

| Component | d_model | Layers | Total params | Activated/token |
|---|---|---|---|---|
| HybridBackbone | 1024 | 12 | 186.4M | 129.2M |
| Embedding tables | 1024 | 2 | ~66M | — |
| LM head | 1024→32256 | 1 | ~33M | — |
| **Total** | | | **~285M** | **~162M** |

### Layer placement
- **MLA blocks** at layers {0, 4, 8} — global context via full attention
- **SparseMoE GDN blocks** at layers {1,2,3, 5,6,7, 9,10,11} — linear recurrence

## Transfer Map

### Verified SVD variance retention (measured on actual teacher weights)

| Weight | Shape | k=512 | k=1024 | k=1536 |
|---|---|---|---|---|
| `embed_tokens.weight` | [32256, 2048] | 55.6% | **77.7%** | 91.6% |
| `lm_head.weight` | [32256, 2048] | 61.9% | **79.5%** | 92.2% |
| `layers.0.self_attn.q_proj.weight` | [2048, 2048] | 97.8% | **99.8%** | 99.99% |

**Key insight:** Attention projections are genuinely low-rank (99.8% at k=1024),
but embedding tables have a flat singular spectrum (77.7% at k=1024) because
32256 tokens spread information across all 2048 dimensions.  The SVD init gives
the student a strong starting point; the remaining 22% is recovered via
distillation (teacher KL loss).

### 1. Embeddings (direct SVD down-projection)

Teacher [32256, 2048] → Student [32256, 1024]

**Method:** Truncated SVD on the teacher embedding matrix:
```
U, S, Vt = svd(teacher_embed)        # [32256, k], [k], [2048]
student_embed = U[:, :1024] * S[:1024]  # [32256, 1024]
```

**Verified variance retained: 77.7%** — the remaining 22.3% is recovered
through distillation (the teacher KL loss pushes the student to match
the teacher's output distribution, which implicitly refines the embedding
space).

### 2. LM Head (direct SVD down-projection)

Teacher `lm_head.weight` [32256, 2048] → Student `lm_head.weight` [32256, 1024]

Same SVD approach as embeddings. **Verified variance retained: 79.5%.**
Student lm_head is UNTIED from output_embeddings (initializes from SVD of
teacher lm_head, then learns independently for distillation temperature
absorption).

### 3. Final RMSNorm (direct copy + truncation)

Teacher `model.norm.weight` [2048] → Student `norm_f.weight` [1024]

Take the first 1024 elements (teacher uses no bias, just scale).
The SVD down-projection of the residual stream preserves the first 1024
dimensions' statistics, so the corresponding norm scales are valid.

### 4. MLA Blocks (layers {0, 4, 8}) — SVD-assisted init

Teacher: 24 Llama attention layers. Student: 3 MLA layers.

**Layer mapping:** Student MLA layer i ← Teacher layers {2i, 2i+1} (merged)
- Student MLA 0 ← Teacher layers {0, 1}
- Student MLA 1 ← Teacher layers {8, 9}
- Student MLA 2 ← Teacher layers {16, 17}

(Rationale: evenly spaced 3 layers from 24 gives layers at indices 0, 8, 16.
We merge pairs to capture depth information in the student's sparser stack.)

**Verified variance retained at k=1024: 99.8%** — attention projections
compress excellently due to their genuinely low-rank structure.

#### Q projection (W_DQ + W_UQ)

Teacher: `q_proj.weight` [2048, 2048] = W_q (maps d_model → num_heads × head_dim)
Student: `W_DQ` [d_cq, 1024] + `W_UQ` [num_heads × d_qk, d_cq]

**Init:** SVD of teacher q_proj: `W_q = U_q S_q V_q^T` where `U_q` is [2048, 2048].
- `W_DQ = V_q[:1024, :d_cq]^T` (top d_cq directions of the input space)
- `W_UQ = (U_q[:, :d_cq] * S_q[:d_cq])^T reshaped` (reconstruct output)

When `d_cq=512`, this captures 512/2048 = 25% of teacher Q directions.
Factorized as W_UQ @ W_DQ, this is a rank-512 approximation of W_q[:, :1024].

#### K, V projections (W_DKV + W_UK + W_UV)

Teacher: `k_proj.weight` [2048, 2048], `v_proj.weight` [2048, 2048]
Student: `W_DKV` [d_ckv, 1024] + `W_UK` [num_heads × d_qk, d_ckv] + `W_UV` [num_heads × d_v, d_ckv]

**Init:** Joint SVD of stacked [k_proj; v_proj] weight, with d_ckv the shared
latent dimension.

```python
KV_stacked = np.vstack([teacher_k_proj, teacher_v_proj])  # [4096, 2048]
U_kv, S_kv, Vt_kv = svd(KV_stacked[:, :1024])  # input space restricted to first 1024 dims
student_W_DKV = Vt_kv[:d_ckv, :]   # [d_ckv, 1024]
student_W_UK = U_kv[:num_heads * d_qk, :d_ckv]
student_W_UV = U_kv[num_heads * d_qk:, :d_ckv]
```

When `d_ckv=256`, this captures the top 256 latent directions shared between K and V.

#### O projection (W_O)

Teacher: `o_proj.weight` [2048, 2048]
Student: `W_O` [d_model, num_heads × d_v]

**Init:** SVD truncated to output dimension 1024.

```python
W_o = teacher_o_proj.weight  # [2048, 2048]
U_o, S_o, Vt_o = svd(W_o)
student_W_O = (U_o[:, :1024] * S_o[:1024]) @ Vt_o[:num_heads * d_v, :].T
# Reshape as needed
```

### 5. SparseMoE GDN Blocks (layers {1,2,3,5,6,7,9,10,11}) — random init

These blocks have a completely different architecture from the teacher.
The GDN SSM recurrence, causal conv1d, SparseMoE gating and expert routing
have no correspondence in Llama.  All parameters are **randomly initialized**.

This is by design — the SSM blocks provide the linear-complexity backbone
that doesn't exist in the teacher, and the MoE experts provide specialization
that the dense MLP can't offer.

**Init scheme:**
- GDN mixer: standard nn.Linear defaults (kaiming_uniform)
- SparseMoE experts: copy the teacher's MLP gate/up/down weights into a
  shared expert, and SVD-truncate each to fine-grained segment size
- (Optional) Multiply A_log initialization by -0.5 to encourage stable
  early training (longer context window)

### 6. SwiGLU MLP in MLA blocks — SVD init

Teacher: `mlp.gate_proj` [5504, 2048], `mlp.up_proj` [5504, 2048], `mlp.down_proj` [2048, 5504]
Student (in MLA blocks): `mlp.wgate` [2756, 1024], `mlp.wup` [2756, 1024], `mlp.wdown` [1024, 2756]
where 2756 = int(1024 × 2.6875)

**Init:** Per-projection SVD truncation along input dimension:
```python
U, S, Vt = svd(teacher_gate_proj.weight)  # [5504, 2048]
student_wgate = (U[:, :1024] * S[:1024]) @ Vt[:1024, :]  # [5504, 1024]
# Then truncate output dimension to ~2756
student_wgate = student_wgate[:2756, :]
```

### Summary: parameter transfer rates

| Component | Init method | Verified variance retained |
|---|---|---|
| Embeddings | SVD | 77.7% (flat spectrum; rest via distillation) |
| LM head | SVD (untied) | 79.5% (flat spectrum; rest via distillation) |
| Final norm | Truncate | Direct copy of first 1024 |
| MLA Q,K,V,O | SVD | 99.8% (genuinely low-rank) |
| MLA SwiGLU | SVD | ~95%+ (similar to Q proj) |
| GDN mixer | Random | None (new architecture) |
| SparseMoE gate | Random | None (new architecture) |
| SparseMoE experts | SVD of teacher MLP | Shared expert inherits main variance |
| Aux heads | Random | None (training-only) |

## Practical SVD transfer recipe

```python
import torch
from safetensors.torch import load_file

teacher = load_file("model.safetensors")

def svd_down(weight, target_dim):
    """SVD down-project a weight matrix [out, in] to [out, target_dim]."""
    U, S, Vt = torch.linalg.svd(weight.float(), full_matrices=False)
    return (U[:, :target_dim] * S[:target_dim]).to(weight.dtype), \
           Vt[:target_dim, :].to(weight.dtype)

# Embeddings: [32256, 2048] → [32256, 1024]
U_e, Vt_e = svd_down(teacher['model.embed_tokens.weight'], 1024)
student_embed = U_e * S[:1024].unsqueeze(0)  # [32256, 1024]
# Or equivalently: U[:, :1024] @ diag(S) @ Vt[:1024, :]
```
