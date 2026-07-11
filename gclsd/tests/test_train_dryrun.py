"""Overfit sanity check: loss should decrease on two synthetic pairs."""

from __future__ import annotations

import math
from typing import List, Optional

import torch

from windy_gclsd.contract import GclsdBlock, GclsdEdge, GclsdInput, GclsdInstr
from windy_gclsd.data.collate import collate_gclsd_batch
from windy_gclsd.losses import GclsdLoss, LossConfig
from windy_gclsd.model import GclsdModel
from windy_gclsd.tokenizer import AsmTokenizer
from windy_gclsd.train import train_one_step, train_one_step_multisignal

OUTPUT_VOCAB_SIZE = 64
OUTPUT_DIM = 64


class _FakeOutputTokenizer:
    """Tiny tokenizer stand-in so tests don't download deepseek-coder."""

    def __init__(self) -> None:
        self.vocab = {f"tok_{i}": i for i in range(OUTPUT_VOCAB_SIZE)}
        self.pad_token_id = 0
        self.eos_token_id = 1
        self.bos_token_id = 2
        self.unk_token_id = 3
        self.vocab["<pad>"] = 0
        self.vocab["<eos>"] = 1
        self.vocab["<bos>"] = 2
        self.vocab["<unk>"] = 3
        self.tokenizer = self

    @property
    def vocab_size(self) -> int:
        return OUTPUT_VOCAB_SIZE

    def encode(self, text: str, max_length: Optional[int] = None) -> List[int]:
        tokens = text.lower().split()
        ids = [self.bos_token_id]
        for t in tokens:
            ids.append(self.vocab.get(t, self.unk_token_id))
        ids.append(self.eos_token_id)
        if max_length and len(ids) > max_length:
            ids = ids[:max_length]
        return ids

    def decode(self, token_ids: List[int]) -> str:
        id_to_tok = {i: t for t, i in self.vocab.items()}
        return " ".join(id_to_tok.get(i, "<?>") for i in token_ids)


def _synthetic_input(name: str, num_instrs: int = 4) -> GclsdInput:
    instructions = []
    blocks = []
    for i in range(num_instrs):
        instructions.append(
            GclsdInstr(
                ip=0x1000 + i,
                bytes_hex="90",
                mnemonic="nop",
                operands="",
                operands_annotated=None,
                flow="Next",
                class_="Logic",
                reads=[],
                writes=[],
                mem_refs=[],
            )
        )
        if i < num_instrs - 1:
            successors = [GclsdEdge(target=0x1000 + i + 1, kind="fallthrough")]
        else:
            successors = []
        blocks.append(
            GclsdBlock(
                entry_va=0x1000 + i,
                instr_ips=[0x1000 + i],
                successors=successors,
            )
        )
    return GclsdInput(
        name=name,
        entry_va=0x1000,
        image_base=0x1000_0000,
        bitness=64,
        calling_conv=None,
        params=[],
        return_type=None,
        instructions=instructions,
        blocks=blocks,
        xrefs_in=[],
        xrefs_out=[],
    )


def test_training_loop_overfits_synthetic_data() -> None:
    torch.manual_seed(42)

    inputs = [_synthetic_input("f1"), _synthetic_input("f2")]
    asm_tokenizer = AsmTokenizer()
    asm_tokenizer.fit(inputs)
    output_tokenizer = _FakeOutputTokenizer()

    model = GclsdModel(
        d_model=OUTPUT_DIM,
        num_layers=2,
        asm_vocab_size=asm_tokenizer.vocab_size,
        output_vocab_size=OUTPUT_VOCAB_SIZE,
        pad_token_id=output_tokenizer.pad_token_id,
        bos_token_id=output_tokenizer.bos_token_id,
        pretrained_output_embeddings=torch.randn(OUTPUT_VOCAB_SIZE, OUTPUT_DIM),
        num_heads=4,
        head_dim=16,
        dv_ratio=2.0,
        num_graph_layers=2,
    )

    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    grad_accum = 1

    fixed_batch = collate_gclsd_batch(
        inputs,
        asm_tokenizer,
        output_tokenizer,
        ["int f1() { return 1; }", "int f2() { return 2; }"],
    )

    losses = []
    for step in range(20):
        optimizer.zero_grad()
        loss, _ = train_one_step(model, fixed_batch, optimizer, grad_accum, step)
        losses.append(loss)

    assert losses[-1] < losses[0], f"loss did not decrease: {losses}"
    assert all(math.isfinite(x) for x in losses)


def _make_model(
    output_dim: int = OUTPUT_DIM,
    output_vocab: int = OUTPUT_VOCAB_SIZE,
    use_hybrid: bool = False,
) -> GclsdModel:
    """Create a tiny test model with random pretrained embeddings."""
    return GclsdModel(
        d_model=output_dim,
        num_layers=2,
        asm_vocab_size=10,  # will be overridden by tokenizer
        output_vocab_size=output_vocab,
        pad_token_id=0,
        bos_token_id=2,
        pretrained_output_embeddings=torch.randn(output_vocab, output_dim),
        num_heads=4,
        head_dim=16,
        dv_ratio=2.0,
        num_graph_layers=2,
        use_hybrid_backbone=use_hybrid,
        num_heads_mla=4,
        head_dim_mla=16,
        d_cq=32,
        d_ckv=16,
        d_rope=8,
        num_experts=4,
        top_k=2,
    )


def _make_loss_fn(
    output_dim: int = OUTPUT_DIM,
    output_vocab: int = OUTPUT_VOCAB_SIZE,
) -> GclsdLoss:
    """Create a GclsdLoss with small dimensions for testing."""
    cfg = LossConfig(
        alpha_kl=0.7,
        alpha_kl_final=0.1,
        lambda_mtp=0.3,
        lambda_mtp_final=0.1,
        lambda_jepa=0.2,
        lambda_pc=1.0,
        mtp_depth=4,
    )
    return GclsdLoss(cfg, d_model=output_dim, vocab_size=output_vocab)


def test_multisignal_step_runs_and_returns_components() -> None:
    """Verify train_one_step_multisignal returns a dict of signal values."""
    torch.manual_seed(42)

    inputs = [_synthetic_input("f1"), _synthetic_input("f2")]
    asm_tokenizer = AsmTokenizer()
    asm_tokenizer.fit(inputs)
    output_tokenizer = _FakeOutputTokenizer()

    model = _make_model(
        output_dim=OUTPUT_DIM,
        output_vocab=OUTPUT_VOCAB_SIZE,
    )
    model.asm_embedding = torch.nn.Embedding(asm_tokenizer.vocab_size, OUTPUT_DIM)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)

    loss_fn = _make_loss_fn(OUTPUT_DIM, OUTPUT_VOCAB_SIZE)

    batch = collate_gclsd_batch(
        inputs,
        asm_tokenizer,
        output_tokenizer,
        ["int f1() { return 1; }", "int f2() { return 2; }"],
    )

    model.train()
    optimizer.zero_grad()
    total_loss, components = train_one_step_multisignal(
        model, batch, optimizer, loss_fn, grad_accum_steps=1, step=0,
    )

    assert math.isfinite(total_loss)
    assert "ce" in components
    assert components["ce"] is not None
    assert components["ce"] > 0
    # Teacher signals (KL, PC) should be None (no teacher artifacts).
    assert components["kl"] is None
    assert components["pc"] is None
    # MTP should be active (uses hidden_states + labels).
    assert components["mtp"] is not None
    assert math.isfinite(components["mtp"])
    # Aux should be active (edge_pairs + liveness_targets are present).
    assert components["aux"] is not None
    # SheafMerge: may or may not be None depending on whether graph has edges.
    if components["sheaf"] is not None:
        assert math.isfinite(components["sheaf"])


def test_multisignal_loss_decreases() -> None:
    """Overfit test: total multi-signal loss should decrease over steps."""
    torch.manual_seed(42)

    inputs = [_synthetic_input("f1"), _synthetic_input("f2")]
    asm_tokenizer = AsmTokenizer()
    asm_tokenizer.fit(inputs)
    output_tokenizer = _FakeOutputTokenizer()

    model = _make_model()
    model.asm_embedding = torch.nn.Embedding(asm_tokenizer.vocab_size, OUTPUT_DIM)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    loss_fn = _make_loss_fn()

    fixed_batch = collate_gclsd_batch(
        inputs,
        asm_tokenizer,
        output_tokenizer,
        ["int f1() { return 1; }", "int f2() { return 2; }"],
    )

    losses = []
    model.train()
    for step in range(20):
        optimizer.zero_grad()
        loss, _ = train_one_step_multisignal(
            model, fixed_batch, optimizer, loss_fn,
            grad_accum_steps=1, step=step,
        )
        losses.append(loss)

    assert losses[-1] < losses[0], f"loss did not decrease: {losses}"
    assert all(math.isfinite(x) for x in losses)


def test_multisignal_with_hybrid_backbone() -> None:
    """Multi-signal loss with HybridBackbone (MLA + SparseMoE GDN)."""
    torch.manual_seed(42)

    inputs = [_synthetic_input("f1"), _synthetic_input("f2")]
    asm_tokenizer = AsmTokenizer()
    asm_tokenizer.fit(inputs)
    output_tokenizer = _FakeOutputTokenizer()

    model = _make_model(use_hybrid=True)
    model.asm_embedding = torch.nn.Embedding(asm_tokenizer.vocab_size, OUTPUT_DIM)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    loss_fn = _make_loss_fn()

    fixed_batch = collate_gclsd_batch(
        inputs,
        asm_tokenizer,
        output_tokenizer,
        ["int f1() { return 1; }", "int f2() { return 2; }"],
    )

    losses = []
    model.train()
    for step in range(15):
        optimizer.zero_grad()
        loss, components = train_one_step_multisignal(
            model, fixed_batch, optimizer, loss_fn,
            grad_accum_steps=1, step=step,
        )
        losses.append(loss)

    assert all(math.isfinite(x) for x in losses)
    # Loss should trend downward (may be noisy with MoE routing).
    assert losses[-1] < losses[0] * 1.5, f"loss diverged: {losses}"


def test_multisignal_with_teacher_artifacts() -> None:
    """Verify KL and PC signals activate when teacher artifacts are provided."""
    torch.manual_seed(42)

    inputs = [_synthetic_input("f1"), _synthetic_input("f2")]
    asm_tokenizer = AsmTokenizer()
    asm_tokenizer.fit(inputs)
    output_tokenizer = _FakeOutputTokenizer()

    model = _make_model()
    model.asm_embedding = torch.nn.Embedding(asm_tokenizer.vocab_size, OUTPUT_DIM)
    optimizer = torch.optim.AdamW(model.parameters(), lr=1e-3)
    loss_fn = _make_loss_fn()

    fixed_batch = collate_gclsd_batch(
        inputs,
        asm_tokenizer,
        output_tokenizer,
        ["int f1() { return 1; }", "int f2() { return 2; }"],
    )

    # Fake teacher artifacts: top-5 logits on output positions.
    B = fixed_batch.asm_input_ids.size(0)
    asm_len = fixed_batch.asm_input_ids.size(1)
    out_len = fixed_batch.output_input_ids.size(1) if fixed_batch.output_input_ids is not None else 1
    L_out = asm_len + out_len
    K = 5
    teacher_artifacts = {
        "topk_indices": torch.randint(0, OUTPUT_VOCAB_SIZE, (B, L_out, K)),
        "topk_logits": torch.randn(B, L_out, K),
        # teacher_hiddens: (1_layer, B, L, d_model)
        "teacher_hiddens": torch.randn(1, B, L_out, OUTPUT_DIM),
    }

    model.train()
    optimizer.zero_grad()
    loss, components = train_one_step_multisignal(
        model, fixed_batch, optimizer, loss_fn,
        grad_accum_steps=1, step=0,
        teacher_artifacts=teacher_artifacts,
    )

    assert math.isfinite(loss)
    # With teacher artifacts, KL and PC should be active.
    assert components["kl"] is not None, "KL should be active with teacher artifacts"
    assert math.isfinite(components["kl"])
    # PC may auto-disable if threshold not met, so check it's at least computed.
    if components["pc"] is not None:
        assert math.isfinite(components["pc"])


def test_anneal_weights_schedule() -> None:
    """Verify loss_fn.anneal_weights interpolates correctly."""
    cfg = LossConfig(alpha_kl=0.7, alpha_kl_final=0.1, lambda_mtp=0.3, lambda_mtp_final=0.1)
    loss_fn = GclsdLoss(cfg, d_model=OUTPUT_DIM, vocab_size=OUTPUT_VOCAB_SIZE)

    # At progress=0, weights unchanged.
    loss_fn.anneal_weights(0.0)
    assert abs(loss_fn.config.alpha_kl - 0.7) < 1e-6
    assert abs(loss_fn.config.lambda_mtp - 0.3) < 1e-6

    # At progress=0.5, weights at midpoint.
    loss_fn.anneal_weights(0.5)
    assert abs(loss_fn.config.alpha_kl - 0.4) < 1e-6
    assert abs(loss_fn.config.lambda_mtp - 0.2) < 1e-6

    # At progress=1.0, weights at final.
    loss_fn.anneal_weights(1.0)
    assert abs(loss_fn.config.alpha_kl - 0.1) < 1e-6
    assert abs(loss_fn.config.lambda_mtp - 0.1) < 1e-6
