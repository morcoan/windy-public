"""Sanity check: a real export-gclsd line can do a forward/backward pass."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import List, Optional

import torch

from windy_gclsd.contract import GclsdInput
from windy_gclsd.data.collate import collate_gclsd_batch
from windy_gclsd.model import GclsdModel
from windy_gclsd.tokenizer import AsmTokenizer

FIXTURE = Path(__file__).parent / "fixtures" / "authored_smoke.gclsd.jsonl"
OUTPUT_VOCAB_SIZE = 128
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
        # Match the OutputTokenizer interface used by collate.py.
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


def test_forward_pass_on_authored_sample() -> None:
    assert FIXTURE.exists()
    with FIXTURE.open() as f:
        inp = GclsdInput.model_validate(json.loads(next(f)))

    asm_tokenizer = AsmTokenizer()
    asm_tokenizer.fit([inp])
    output_tokenizer = _FakeOutputTokenizer()

    batch = collate_gclsd_batch(
        [inp],
        asm_tokenizer,
        output_tokenizer,
        ["int main() { return 0; }"],
    )

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
    model.eval()

    with torch.no_grad():
        logits, loss, aux_loss = model(batch)

    seq_len = batch.asm_input_ids.size(1) + batch.output_input_ids.size(1)
    assert logits.shape == (1, seq_len, OUTPUT_VOCAB_SIZE)
    assert torch.isfinite(logits).all()
    assert loss is not None
    assert math.isfinite(loss.item())
