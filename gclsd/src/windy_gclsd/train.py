"""Training loop for the GCLSD decompiler model.

The Gated DeltaNet backbone is trained from scratch. Only the output token
embedding table / LM head are initialized from a pretrained causal LM to
preserve C-language priors.
"""

from __future__ import annotations

import argparse
import gc
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForCausalLM

from windy_gclsd.contract import GclsdInput
from windy_gclsd.data.collate import GclsdBatch, collate_gclsd_batch
from windy_gclsd.losses import GclsdLoss, LossConfig
from windy_gclsd.model import GclsdModel
from windy_gclsd.tokenizer import AsmTokenizer, OutputTokenizer


@dataclass
class GclsdSample:
    input: GclsdInput
    gt_c: str


class GclsdJsonlDataset(Dataset):
    """Read ``(gclsd_input, gt_c)`` pairs from one or more JSONL files."""

    def __init__(self, paths: Iterable[Path]) -> None:
        self.samples: List[GclsdSample] = []
        for path in paths:
            with path.open() as f:
                for line in f:
                    obj = json.loads(line)
                    self.samples.append(
                        GclsdSample(
                            input=GclsdInput.model_validate(obj["input"]),
                            gt_c=obj["gt_c"],
                        )
                    )

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Tuple[GclsdInput, str]:
        s = self.samples[idx]
        return s.input, s.gt_c


def load_pretrained_embeddings(
    base_name: str,
    dtype: torch.dtype = torch.float32,
) -> Tuple[torch.Tensor, int]:
    """Load only the token embedding matrix from a pretrained causal LM.

    Returns the embedding weight and the model's hidden dimension.
    """
    model = AutoModelForCausalLM.from_pretrained(
        base_name,
        torch_dtype=dtype,
        trust_remote_code=False,
        use_safetensors=True,
    )
    embeddings = model.get_input_embeddings().weight.detach().clone().to(dtype)
    hidden_size = model.config.hidden_size
    del model
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    return embeddings, hidden_size


def create_model(
    asm_tokenizer: AsmTokenizer,
    output_tokenizer: OutputTokenizer,
    pretrained_embeddings: torch.Tensor,
    hidden_size: int,
    num_layers: int = 12,
    num_heads: int = 8,
    head_dim: int = 128,
    dv_ratio: float = 2.0,
    d_conv: int = 4,
    mlp_ratio: float = 2.6875,
    num_graph_layers: int = 3,
    aux_loss_weight: float = 0.1,
    gradient_checkpointing: bool = False,
    use_hybrid_backbone: bool = False,
    num_heads_mla: int = 8,
    head_dim_mla: int = 128,
    d_cq: int = 512,
    d_ckv: int = 256,
    d_rope: int = 32,
    num_experts: int = 8,
    top_k: int = 2,
) -> GclsdModel:
    pad_id = output_tokenizer.tokenizer.pad_token_id
    if pad_id is None:
        pad_id = output_tokenizer.tokenizer.eos_token_id
    assert pad_id is not None
    bos_id = output_tokenizer.tokenizer.bos_token_id
    if bos_id is None:
        bos_id = pad_id
    assert bos_id is not None
    # The pretrained embedding matrix is the source of truth for vocab size;
    # some tokenizers report a smaller effective vocab than the model rows.
    output_vocab_size = pretrained_embeddings.shape[0]
    if output_tokenizer.vocab_size > output_vocab_size:
        raise ValueError(
            f"tokenizer vocab size {output_tokenizer.vocab_size} exceeds "
            f"pretrained embedding rows {output_vocab_size}"
        )

    model = GclsdModel(
        d_model=hidden_size,
        num_layers=num_layers,
        asm_vocab_size=asm_tokenizer.vocab_size,
        output_vocab_size=output_vocab_size,
        pad_token_id=pad_id,
        bos_token_id=bos_id,
        pretrained_output_embeddings=pretrained_embeddings,
        num_heads=num_heads,
        head_dim=head_dim,
        dv_ratio=dv_ratio,
        d_conv=d_conv,
        mlp_ratio=mlp_ratio,
        num_graph_layers=num_graph_layers,
        aux_loss_weight=aux_loss_weight,
        use_hybrid_backbone=use_hybrid_backbone,
        num_heads_mla=num_heads_mla,
        head_dim_mla=head_dim_mla,
        d_cq=d_cq,
        d_ckv=d_ckv,
        d_rope=d_rope,
        num_experts=num_experts,
        top_k=top_k,
    )
    if gradient_checkpointing:
        model.backbone.gradient_checkpointing = True
    return model


def train_one_step(
    model: GclsdModel,
    batch: GclsdBatch,
    optimizer: torch.optim.Optimizer,
    grad_accum_steps: int,
    step: int,
    aux_weight: float = 0.1,
) -> Tuple[float, float]:
    """Run one forward/backward step and return (main_loss, aux_loss)."""
    logits, loss, aux_loss = model(batch)
    if loss is None:
        raise ValueError("batch must contain labels")
    total = loss
    if aux_loss is not None:
        total = total + aux_weight * aux_loss
    (total / grad_accum_steps).backward()

    if (step + 1) % grad_accum_steps == 0:
        optimizer.step()
        optimizer.zero_grad()

    return loss.item(), (aux_loss.item() if aux_loss is not None else 0.0)


def _compute_edge_labels(
    edge_pairs: torch.Tensor,
    num_positive_edges: Optional[torch.Tensor],
) -> torch.Tensor:
    """Reconstruct binary edge labels from num_positive_edges counts.

    Mirrors the logic in AuxHeads.forward: the first N edges per batch item
    are positive (real CFG edges), the rest are sampled negatives.
    """
    edge_labels = torch.zeros_like(edge_pairs[:, :, 0], dtype=torch.float)
    if num_positive_edges is not None:
        B = edge_pairs.size(0)
        for b in range(B):
            n = int(num_positive_edges[b].item())
            if n > 0:
                edge_labels[b, :n] = 1.0
    return edge_labels


def _flatten_boundary_states(
    boundary_states: torch.Tensor,
    graph_batch: "Batch",
) -> torch.Tensor:
    """Convert (B, max_blocks, hidden) -> (total_nodes, hidden).

    Strips per-sample padding using graph_batch.ptr (PyG offset tensor).
    """
    ptrs = graph_batch.ptr  # (B+1,) cumulative node counts
    parts = []
    for b in range(boundary_states.size(0)):
        n = int((ptrs[b + 1] - ptrs[b]).item())
        parts.append(boundary_states[b, :n])
    return torch.cat(parts, dim=0)


def train_one_step_multisignal(
    model: GclsdModel,
    batch: GclsdBatch,
    optimizer: torch.optim.Optimizer,
    loss_fn: GclsdLoss,
    grad_accum_steps: int,
    step: int,
    teacher_artifacts: Optional[dict] = None,
) -> Tuple[float, dict]:
    """Multi-signal training step using GclsdLoss (7 supervision signals).

    Computes CE + teacher KL + MTP + JEPA + PC + aux BCE + SheafMerge.

    Args:
        teacher_artifacts: optional dict with keys:
            'topk_indices', 'topk_logits', 'teacher_hiddens'
            If None, teacher-dependent signals (KL, PC) are skipped.

    Returns:
        (total_loss, component_dict) where component_dict maps signal name
        to float value (or None if signal was skipped).
    """
    extras = model(batch, return_extras=True)
    if extras.loss is None:
        raise ValueError("batch must contain labels")

    # Build edge_labels from num_positive_edges for the aux loss.
    edge_labels: Optional[torch.Tensor] = None
    if extras.edge_logits is not None and batch.edge_pairs is not None:
        edge_labels = _compute_edge_labels(
            batch.edge_pairs, batch.num_positive_edges
        )

    # Teacher artifacts (may be None — signals skipped).
    teacher_indices = None
    teacher_logits_topk = None
    teacher_hiddens = None
    if teacher_artifacts is not None:
        teacher_indices = teacher_artifacts.get("topk_indices")
        teacher_logits_topk = teacher_artifacts.get("topk_logits")
        teacher_hiddens = teacher_artifacts.get("teacher_hiddens")

    # SheafMerge: needs flattened boundary states (N, d_model) + graph edges.
    # Only activate when there are actual CFG edges.
    sheaf_node_states = None
    sheaf_edge_index = None
    sheaf_edge_kind = None
    if (
        extras.boundary_states is not None
        and batch.graph.edge_index.numel() > 0
    ):
        sheaf_node_states = _flatten_boundary_states(
            extras.boundary_states, batch.graph
        )
        sheaf_edge_index = batch.graph.edge_index
        sheaf_edge_kind = batch.graph.edge_attr
        if sheaf_edge_kind.dim() > 1:
            sheaf_edge_kind = sheaf_edge_kind.squeeze(-1)

    result = loss_fn(
        student_logits=extras.logits,
        labels=batch.labels,
        hidden_states=extras.hidden,
        teacher_topk_indices=teacher_indices,
        teacher_topk_logits=teacher_logits_topk,
        teacher_hiddens=teacher_hiddens,
        edge_logits=extras.edge_logits,
        edge_labels=edge_labels,
        liveness_logits=extras.liveness_logits,
        liveness_targets=batch.liveness_targets,
        node_states=sheaf_node_states,
        edge_index=sheaf_edge_index,
        edge_kind=sheaf_edge_kind,
    )

    (result.total / grad_accum_steps).backward()

    if (step + 1) % grad_accum_steps == 0:
        optimizer.step()
        optimizer.zero_grad()

    components = {
        "ce": result.ce.item() if result.ce is not None else None,
        "kl": result.kl.item() if result.kl is not None else None,
        "mtp": result.mtp.item() if result.mtp is not None else None,
        "jepa": result.jepa.item() if result.jepa is not None else None,
        "pc": result.pc.item() if result.pc is not None else None,
        "aux": result.aux.item() if result.aux is not None else None,
        "sheaf": result.sheaf.item() if result.sheaf is not None else None,
    }
    return result.total.item(), components


def save_checkpoint(
    model: GclsdModel,
    optimizer: torch.optim.Optimizer,
    step: int,
    checkpoint_dir: Path,
    asm_tokenizer: "AsmTokenizer | None" = None,
    model_config: dict | None = None,
    epoch: int = 0,
    batch_idx: int = 0,
    cli_args: dict | None = None,
) -> None:
    """Persist a full recoverable checkpoint.

    Saves model + optimizer state, asm tokenizer vocab, model config, RNG
    states, and dataloader position so training can resume exactly after a
    crash or Ctrl+C.
    """
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    ckpt = checkpoint_dir / f"step-{step}"
    ckpt.mkdir(exist_ok=True)

    payload: dict = {
        "model": model.state_dict(),
        "optimizer": optimizer.state_dict(),
        "step": step,
        "epoch": epoch,
        "batch_idx": batch_idx,
        "rng_state": torch.get_rng_state(),
        "model_config": model_config or {},
        "cli_args": cli_args or {},
    }
    if torch.cuda.is_available():
        payload["cuda_rng_state"] = torch.cuda.get_rng_state()

    if asm_tokenizer is not None:
        payload["asm_tokenizer_vocab"] = asm_tokenizer.token_to_id

    torch.save(payload, ckpt / "gclsd_model.pt")

    # Write LATEST pointer for auto-resume.
    latest = checkpoint_dir / "step-LATEST"
    latest.write_text(ckpt.name, encoding="utf-8")


def load_jsonl_paths(pairs_arg: Path) -> List[Path]:
    if pairs_arg.is_dir():
        return sorted(pairs_arg.glob("*.jsonl"))
    return [pairs_arg]


def _write_samples_log(
    model: GclsdModel,
    output_tokenizer: OutputTokenizer,
    asm_tokenizer: AsmTokenizer,
    sample_input: GclsdInput,
    sample_gt: str,
    step: int,
    log_path: Path,
    device: torch.device,
) -> None:
    """Generate C pseudocode on a fixed sample and append to samples.log."""
    try:
        model.eval()
        eos = output_tokenizer.tokenizer.eos_token_id
        batch = collate_gclsd_batch(
            [sample_input], asm_tokenizer, output_tokenizer, [sample_gt],
            device=device, max_asm_length=256, max_output_length=128,
        )
        with torch.no_grad():
            tokens = model.generate(
                batch.asm_input_ids,
                batch.token_to_block,
                batch.graph,
                max_length=64,
                top_k=50,
                eos_token_id=eos,
            )
        decoded = output_tokenizer.decode(tokens)
        model.train()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write(f"--- step {step} ---\n")
            f.write(f"GT:   {sample_gt[:200]}\n")
            f.write(f"PRED: {decoded[:200]}\n\n")
    except Exception as exc:
        # Never crash training over a logging failure.
        print(f"  [samples.log] skipped: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Windy GCLSD model")
    parser.add_argument("--pairs", type=Path, required=True)
    parser.add_argument(
        "--base",
        type=str,
        default="LLM4Binary/llm4decompile-1.3b-v1.6",
        help="Pretrained model used to initialize output token embeddings",
    )
    parser.add_argument("--checkpoint-dir", type=Path, default=Path("checkpoints"))
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--grad-accum", type=int, default=4)
    parser.add_argument("--lr", type=float, default=5e-4)
    parser.add_argument("--save-every", type=int, default=500)
    parser.add_argument("--num-graph-layers", type=int, default=3)
    parser.add_argument("--num-layers", type=int, default=12)
    parser.add_argument("--num-heads", type=int, default=8)
    parser.add_argument("--head-dim", type=int, default=128)
    parser.add_argument("--mlp-ratio", type=float, default=2.6875,
                        help="SwiGLU intermediate / d_model (teacher=5504/2048≈2.6875)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--aux-weight", type=float, default=0.1)
    parser.add_argument("--gradient-checkpointing", action="store_true", default=True)
    parser.add_argument("--max-steps", type=int, default=None)
    parser.add_argument(
        "--resume",
        type=Path,
        default=None,
        help="Path to a gclsd_model.pt checkpoint to resume from. "
             "If omitted, auto-resumes from <checkpoint-dir>/step-LATEST if it exists.",
    )
    parser.add_argument(
        "--samples-log",
        type=Path,
        default=None,
        help="Append generated samples to this file every --save-every steps. "
             "Defaults to <checkpoint-dir>/samples.log.",
    )
    # --- GCLSD-v3 hybrid backbone args ---
    parser.add_argument(
        "--hybrid-backbone",
        action="store_true",
        default=False,
        help="Use HybridBackbone (MLA + SparseMoE GDN) instead of pure GDN.",
    )
    parser.add_argument("--num-heads-mla", type=int, default=8)
    parser.add_argument("--head-dim-mla", type=int, default=128)
    parser.add_argument("--d-cq", type=int, default=512, help="MLA Q compression dim")
    parser.add_argument("--d-ckv", type=int, default=256, help="MLA KV compression dim")
    parser.add_argument("--d-rope", type=int, default=32, help="MLA decoupled RoPE dim")
    parser.add_argument("--num-experts", type=int, default=8, help="Number of routed MoE experts")
    parser.add_argument("--top-k", type=int, default=2, help="Number of experts to route each token to")
    # --- Multi-signal loss args ---
    parser.add_argument("--alpha-kl", type=float, default=0.7, help="Initial teacher KL weight")
    parser.add_argument("--alpha-kl-final", type=float, default=0.1, help="Final teacher KL weight (annealed)")
    parser.add_argument("--lambda-mtp", type=float, default=0.3, help="Initial MTP weight")
    parser.add_argument("--lambda-mtp-final", type=float, default=0.1, help="Final MTP weight (annealed)")
    parser.add_argument("--lambda-jepa", type=float, default=0.2, help="JEPA loss weight (fixed)")
    parser.add_argument("--lambda-pc", type=float, default=1.0, help="PC loss weight (dynamic auto-disable)")
    parser.add_argument("--mtp-depth", type=int, default=4, help="MTP prediction depth")
    parser.add_argument(
        "--use-multisignal-loss",
        action="store_true",
        default=False,
        help="Use GCLSD-v3 multi-signal loss (7 supervision signals). "
             "When off, uses simple CE + aux loss.",
    )
    args = parser.parse_args()

    torch.manual_seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    paths = load_jsonl_paths(args.pairs)
    if not paths:
        raise FileNotFoundError(f"no *.jsonl files found in {args.pairs}")

    dataset = GclsdJsonlDataset(paths)
    print(f"Loaded {len(dataset)} training pairs from {len(paths)} file(s)")

    output_tokenizer = OutputTokenizer()
    asm_tokenizer = AsmTokenizer()
    asm_tokenizer.fit(inp for inp, _ in dataset)

    print("Loading pretrained output embeddings...")
    pretrained_embeddings, hidden_size = load_pretrained_embeddings(args.base)
    pretrained_embeddings = pretrained_embeddings.to(device)

    def collate_fn(samples: List[Tuple[GclsdInput, str]]) -> GclsdBatch:
        inputs, gts = zip(*samples)
        return collate_gclsd_batch(
            list(inputs),
            asm_tokenizer,
            output_tokenizer,
            list(gts),
            device=device,
            max_asm_length=256,
            max_output_length=128,
        )

    dataloader = DataLoader(
        dataset,
        batch_size=args.batch_size,
        shuffle=True,
        collate_fn=collate_fn,
    )

    model = create_model(
        asm_tokenizer,
        output_tokenizer,
        pretrained_embeddings,
        hidden_size,
        num_layers=args.num_layers,
        num_heads=args.num_heads,
        head_dim=args.head_dim,
        mlp_ratio=args.mlp_ratio,
        num_graph_layers=args.num_graph_layers,
        aux_loss_weight=args.aux_weight,
        gradient_checkpointing=args.gradient_checkpointing,
        use_hybrid_backbone=args.hybrid_backbone,
        num_heads_mla=args.num_heads_mla,
        head_dim_mla=args.head_dim_mla,
        d_cq=args.d_cq,
        d_ckv=args.d_ckv,
        d_rope=args.d_rope,
        num_experts=args.num_experts,
        top_k=args.top_k,
    )
    model.to(device)

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr)

    # Multi-signal loss function (GCLSD-v3 only when --use-multisignal-loss).
    loss_fn: GclsdLoss | None = None
    if args.use_multisignal_loss:
        loss_cfg = LossConfig(
            alpha_kl=args.alpha_kl,
            alpha_kl_final=args.alpha_kl_final,
            lambda_mtp=args.lambda_mtp,
            lambda_mtp_final=args.lambda_mtp_final,
            lambda_jepa=args.lambda_jepa,
            lambda_pc=args.lambda_pc,
            mtp_depth=args.mtp_depth,
        )
        loss_fn = GclsdLoss(
            loss_cfg,
            d_model=hidden_size,
            vocab_size=pretrained_embeddings.shape[0],
        )
        loss_fn.to(device)
        print(f"[multisignal] GclsdLoss initialized (mtp_depth={args.mtp_depth})")

    model_config = {
        "d_model": hidden_size,
        "num_layers": args.num_layers,
        "num_heads": args.num_heads,
        "head_dim": args.head_dim,
        "mlp_ratio": args.mlp_ratio,
        "num_graph_layers": args.num_graph_layers,
        "aux_loss_weight": args.aux_weight,
        "use_hybrid_backbone": args.hybrid_backbone,
        "num_heads_mla": args.num_heads_mla,
        "head_dim_mla": args.head_dim_mla,
        "d_cq": args.d_cq,
        "d_ckv": args.d_ckv,
        "d_rope": args.d_rope,
        "num_experts": args.num_experts,
        "top_k": args.top_k,
        "use_multisignal_loss": args.use_multisignal_loss,
        "alpha_kl": args.alpha_kl,
        "alpha_kl_final": args.alpha_kl_final,
        "lambda_mtp": args.lambda_mtp,
        "lambda_mtp_final": args.lambda_mtp_final,
        "lambda_jepa": args.lambda_jepa,
        "lambda_pc": args.lambda_pc,
        "mtp_depth": args.mtp_depth,
    }

    cli_args = {k: str(v) for k, v in vars(args).items()}

    samples_log_path = args.samples_log or (args.checkpoint_dir / "samples.log")

    # ------------------------------------------------------------------
    # Resume logic: explicit --resume, else auto-resume from step-LATEST.
    # ------------------------------------------------------------------
    step = 0
    start_epoch = 0
    skip_batches = 0
    resume_path: Path | None = args.resume
    if resume_path is None:
        latest = args.checkpoint_dir / "step-LATEST"
        if latest.exists():
            ckpt_dir_name = latest.read_text(encoding="utf-8").strip()
            candidate = args.checkpoint_dir / ckpt_dir_name / "gclsd_model.pt"
            if candidate.exists():
                resume_path = candidate
                print(f"[auto-resume] found {resume_path}")

    if resume_path is not None:
        if not resume_path.exists():
            raise FileNotFoundError(f"--resume {resume_path} does not exist")
        print(f"Resuming from {resume_path} ...")
        resume_state = torch.load(resume_path, map_location=device, weights_only=False)
        model.load_state_dict(resume_state["model"])
        optimizer.load_state_dict(resume_state["optimizer"])
        step = int(resume_state.get("step", 0)) + 1
        start_epoch = int(resume_state.get("epoch", 0))
        skip_batches = int(resume_state.get("batch_idx", 0)) + 1
        if "rng_state" in resume_state:
            torch.set_rng_state(resume_state["rng_state"])
        if "cuda_rng_state" in resume_state and torch.cuda.is_available():
            torch.cuda.set_rng_state(resume_state["cuda_rng_state"])
        # Restore tokenizer vocab if saved.
        saved_vocab = resume_state.get("asm_tokenizer_vocab")
        if saved_vocab:
            asm_tokenizer.token_to_id = dict(saved_vocab)
            asm_tokenizer.id_to_token = {i: t for t, i in asm_tokenizer.token_to_id.items()}
        del resume_state
        gc.collect()
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        print(f"  model + optimizer + RNG restored; resuming at step {step} "
              f"(epoch {start_epoch}, skip {skip_batches} batches)")

    model.train()

    # Estimate total steps for loss annealing schedule.
    try:
        steps_per_epoch = len(dataloader)
    except TypeError:
        steps_per_epoch = 0
    if args.max_steps is not None:
        total_steps_est = args.max_steps
    else:
        total_steps_est = max(steps_per_epoch * max(args.epochs - start_epoch, 1), 1)

    # Grab a fixed sample for samples.log qualitative snapshots.
    _sample_input, _sample_gt = dataset[0]

    try:
        for epoch in range(start_epoch, args.epochs):
            epoch_loss = 0.0
            epoch_aux_loss = 0.0
            num_batches = 0
            for batch_idx, batch in enumerate(dataloader):
                # Skip already-processed batches on first epoch after resume.
                if epoch == start_epoch and batch_idx < skip_batches:
                    continue

                if loss_fn is not None:
                    # Multi-signal loss path (GCLSD-v3).
                    progress = step / total_steps_est if total_steps_est > 0 else 0.0
                    loss_fn.anneal_weights(progress)

                    step_loss, components = train_one_step_multisignal(
                        model,
                        batch,
                        optimizer,
                        loss_fn,
                        grad_accum_steps=args.grad_accum,
                        step=step,
                    )
                    step_aux = components.get("aux") or 0.0
                else:
                    step_loss, step_aux = train_one_step(
                        model,
                        batch,
                        optimizer,
                        grad_accum_steps=args.grad_accum,
                        step=step,
                        aux_weight=args.aux_weight,
                    )
                epoch_loss += step_loss
                epoch_aux_loss += step_aux
                num_batches += 1
                step += 1

                if step % 50 == 0:
                    if loss_fn is not None:
                        comp_str = " ".join(
                            f"{k}={v:.4f}" for k, v in components.items()
                            if v is not None and k != "ce"
                        )
                        print(
                            f"epoch {epoch} step {step} loss={step_loss:.4f} "
                            f"{comp_str} avg={epoch_loss / num_batches:.4f}"
                        )
                    else:
                        print(
                            f"epoch {epoch} step {step} loss={step_loss:.4f} "
                            f"aux={step_aux:.4f} avg={epoch_loss / num_batches:.4f}"
                        )

                if step % args.save_every == 0:
                    save_checkpoint(
                        model, optimizer, step, args.checkpoint_dir,
                        asm_tokenizer=asm_tokenizer,
                        model_config=model_config,
                        epoch=epoch, batch_idx=batch_idx,
                        cli_args=cli_args,
                    )
                    _write_samples_log(
                        model, output_tokenizer, asm_tokenizer,
                        _sample_input, _sample_gt, step, samples_log_path, device,
                    )
                    print(f"  checkpoint + samples.log saved at step {step}")

                if args.max_steps is not None and step >= args.max_steps:
                    break

            print(f"epoch {epoch} finished; avg loss={epoch_loss / max(num_batches,1):.4f}")
            save_checkpoint(
                model, optimizer, step, args.checkpoint_dir,
                asm_tokenizer=asm_tokenizer,
                model_config=model_config,
                epoch=epoch, batch_idx=batch_idx,
                cli_args=cli_args,
            )

            if args.max_steps is not None and step >= args.max_steps:
                break
    except KeyboardInterrupt:
        print(f"\n[INTERRUPTED] at step {step}; saving emergency checkpoint ...")
        ckpt_path = args.checkpoint_dir / f"step-{step}-interrupt"
        save_checkpoint(
            model, optimizer, step, ckpt_path,
            asm_tokenizer=asm_tokenizer,
            model_config=model_config,
            epoch=start_epoch, batch_idx=0,
            cli_args=cli_args,
        )
        latest = args.checkpoint_dir / "step-LATEST"
        latest.write_text(ckpt_path.name, encoding="utf-8")
        print(f"  saved -> {ckpt_path / 'gclsd_model.pt'}")
        print(f"  Auto-resume enabled; just re-run the same command.")
        raise SystemExit(130)


if __name__ == "__main__":
    main()
