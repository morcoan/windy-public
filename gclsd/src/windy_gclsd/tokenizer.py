"""Tokenizers for asm input and C-like output.

The output tokenizer is the same one used by LLM4Decompile so that generated
pseudo-code stays in a compatible token space. The input tokenizer is a simple
regex-splitter over mnemonics/operands; it will be swapped for a BPE-trained
vocabulary once the training corpus is available.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List, Optional

from transformers import AutoTokenizer

from windy_gclsd.contract import GclsdInput


# Keep special tokens out of the normal instruction token space.
SPECIAL_TOKENS = {
    "<pad>": 0,
    "<unk>": 1,
    "<s>": 2,
    "</s>": 3,
    "<func>": 4,
    "<instr>": 5,
}


class AsmTokenizer:
    """Identity-style asm tokenizer.

    Splits each instruction into mnemonic + operand sub-tokens on whitespace,
    punctuation and brackets. A real training run should replace this with a
    BPE tokenizer fit over the asm corpus.
    """

    _split_re = re.compile(r"[\s,\[\]\+\*\-\:\(\)\{\}]+|")

    def __init__(self, vocab: Optional[dict[str, int]] = None) -> None:
        if vocab is None:
            vocab = dict(SPECIAL_TOKENS)
        self.token_to_id = vocab
        self.id_to_token = {i: t for t, i in vocab.items()}
        self.pad_id = self.token_to_id["<pad>"]
        self.unk_id = self.token_to_id["<unk>"]
        self.func_id = self.token_to_id["<func>"]
        self.instr_id = self.token_to_id["<instr>"]

    @property
    def vocab_size(self) -> int:
        return len(self.token_to_id)

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.token_to_id, indent=2))

    @classmethod
    def load(cls, path: Path) -> "AsmTokenizer":
        return cls(vocab=json.loads(path.read_text()))

    def fit(self, inputs: Iterable[GclsdInput]) -> None:
        """Extend the vocabulary with all tokens seen in ``inputs``."""
        for inp in inputs:
            for instr in inp.instructions:
                for token in self._tokenize_text(f"{instr.mnemonic} {instr.operands}"):
                    if token not in self.token_to_id:
                        idx = len(self.token_to_id)
                        self.token_to_id[token] = idx
                        self.id_to_token[idx] = token

    def encode(
        self,
        inp: GclsdInput,
        max_length: Optional[int] = None,
    ) -> tuple[List[int], List[int]]:
        """Tokenize an entire function.

        Returns ``(token_ids, token_to_instr)`` where ``token_to_instr[i]`` is
        the instruction index that produced ``token_ids[i]``.
        """
        token_ids: List[int] = [self.func_id]
        token_to_instr: List[int] = [-1]
        for instr_idx, instr in enumerate(inp.instructions):
            token_ids.append(self.instr_id)
            token_to_instr.append(-1)
            tokens = self._tokenize_text(f"{instr.mnemonic} {instr.operands}")
            for token in tokens:
                token_ids.append(self.token_to_id.get(token, self.unk_id))
                token_to_instr.append(instr_idx)
            if max_length and len(token_ids) >= max_length:
                token_ids = token_ids[:max_length]
                token_to_instr = token_to_instr[:max_length]
                break
        return token_ids, token_to_instr

    def encode_instructions(self, inp: GclsdInput) -> List[List[int]]:
        """Return per-instruction token ids (used for graph node features)."""
        return [
            [
                self.token_to_id.get(token, self.unk_id)
                for token in self._tokenize_text(f"{instr.mnemonic} {instr.operands}")
            ]
            for instr in inp.instructions
        ]

    def _tokenize_text(self, text: str) -> List[str]:
        raw = self._split_re.split(text.lower())
        return [t for t in raw if t]


class OutputTokenizer:
    """Wraps the LLM4Decompose output tokenizer (or a tiny fallback for tests)."""

    def __init__(self, model_name: str = "LLM4Binary/llm4decompile-1.3b-v1.6") -> None:
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(model_name, trust_remote_code=False)
        except Exception as exc:  # pragma: no cover - network may be unavailable
            raise RuntimeError(
                f"Failed to load output tokenizer from '{model_name}'. "
                "Authenticate with `huggingface-cli login` or set HF_TOKEN."
            ) from exc
        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

    @property
    def vocab_size(self) -> int:
        return len(self.tokenizer)

    def encode(self, text: str, max_length: Optional[int] = None) -> List[int]:
        return self.tokenizer.encode(
            text,
            add_special_tokens=True,
            max_length=max_length,
            truncation=max_length is not None,
        )

    def decode(self, token_ids: List[int]) -> str:
        return self.tokenizer.decode(token_ids, skip_special_tokens=True)
