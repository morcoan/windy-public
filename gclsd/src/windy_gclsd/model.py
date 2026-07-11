"""Graph-Conditioned Latent State Decompiler (GCLSD) model.

Architecture (faithful to spec):

1. Raw assembly is tokenized and embedded from scratch.
2. A Gated DeltaNet SSM processes the asm token sequence.
3. A lightweight GNN runs over the explicit basic-block CFG and its node
   embeddings are injected additively at block-boundary asm tokens.
4. The SSM's recurrent state is the latent state; at asm end the model
   continues the recurrence to generate decompiled C tokens.
5. Auxiliary heads (edge existence + register liveness) read the latent state
   during training only, z-regularizing it to track dataflow.
6. The output token embedding table and LM head are initialized from the
   pretrained LLM4Decompile/DeepSeek tokenizer to preserve C-language priors.
"""

from __future__ import annotations

from typing import List, NamedTuple, Optional, Tuple, Union

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Batch
from torch_geometric.nn import GINEConv


class ModelForwardExtras(NamedTuple):
    """Richer forward output for multi-signal loss training."""

    logits: torch.Tensor
    loss: Optional[torch.Tensor]
    aux_loss: Optional[torch.Tensor]
    hidden: torch.Tensor
    edge_logits: Optional[torch.Tensor]
    liveness_logits: Optional[torch.Tensor]
    boundary_states: Optional[torch.Tensor]

from windy_gclsd.data.collate import GclsdBatch
from windy_gclsd.ssm import GatedDeltaNetBackbone, HybridBackbone


class BlockGraphEncoder(nn.Module):
    """GNN over the basic-block CFG with edge-kind attributes."""

    def __init__(
        self,
        hidden: int,
        num_layers: int = 3,
        num_edge_kinds: int = 7,
    ) -> None:
        super().__init__()
        self.edge_embed = nn.Embedding(num_edge_kinds, hidden)
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        for _ in range(num_layers):
            mlp = nn.Sequential(
                nn.Linear(hidden, hidden * 2),
                nn.GELU(),
                nn.Linear(hidden * 2, hidden),
            )
            self.convs.append(GINEConv(mlp))
            self.norms.append(nn.LayerNorm(hidden))

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_kind: torch.Tensor,
    ) -> torch.Tensor:
        edge_attr = self.edge_embed(edge_kind)
        for conv, norm in zip(self.convs, self.norms):
            x = norm(x + conv(x, edge_index, edge_attr))
            x = F.gelu(x)
        return x


class AuxHeads(nn.Module):
    """Cheap supervised heads used during training only.

    They force the SSM latent states at block boundaries to encode structural
    and dataflow facts. Dropped at inference.
    """

    def __init__(
        self,
        hidden: int,
        num_registers: int,
    ) -> None:
        super().__init__()
        # Edge existence: concat two boundary states -> binary logit.
        self.edge_mlp = nn.Sequential(
            nn.Linear(hidden * 2, hidden),
            nn.GELU(),
            nn.Linear(hidden, 1),
        )
        # Register liveness: boundary state -> one logit per register.
        self.liveness_mlp = nn.Sequential(
            nn.Linear(hidden, hidden),
            nn.GELU(),
            nn.Linear(hidden, num_registers),
        )

    def forward(
        self,
        boundary_states: torch.Tensor,
        edge_pairs: torch.Tensor,
        liveness_targets: Optional[torch.Tensor] = None,
        num_positive_edges: Optional[int] = None,
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor], Optional[torch.Tensor]]:
        """Compute edge + liveness logits and optional losses.

        Args:
            boundary_states: (B, num_blocks, hidden) final hidden states at each
                block's first token position.
            edge_pairs: (B, num_edges, 2) block-index pairs for sampled edges.
            liveness_targets: (B, num_blocks, num_registers) float bitset.
            num_positive_edges: number of positive edges in edge_pairs, used to
                balance positive/negative sampling in the BCE loss.

        Returns:
            edge_logits: (B, num_edges, 1)
            liveness_logits: (B, num_blocks, num_registers)
            loss: scalar auxiliary loss (or None if targets not provided)
        """
        B, num_blocks, hidden = boundary_states.shape

        # --- edge existence head ---
        src_idx = edge_pairs[:, :, 0].clamp(min=0, max=num_blocks - 1)
        tgt_idx = edge_pairs[:, :, 1].clamp(min=0, max=num_blocks - 1)
        src_state = boundary_states.gather(1, src_idx.unsqueeze(-1).expand(-1, -1, hidden))
        tgt_state = boundary_states.gather(1, tgt_idx.unsqueeze(-1).expand(-1, -1, hidden))
        pair_state = torch.cat([src_state, tgt_state], dim=-1)
        edge_logits = self.edge_mlp(pair_state).squeeze(-1)  # (B, num_edges)

        # --- liveness head ---
        liveness_logits = self.liveness_mlp(boundary_states)  # (B, num_blocks, R)

        if liveness_targets is None:
            return edge_logits, liveness_logits, None

        # Edge labels: per batch, the first num_positive_edges[b] are positive.
        device = edge_logits.device
        edge_labels = torch.zeros_like(edge_logits)
        if num_positive_edges is not None:
            for b in range(B):
                n = int(num_positive_edges[b].item())
                if n > 0:
                    edge_labels[b, :n] = 1.0

        # Balance pos/neg by weighting positives up. Compute average ratio.
        if num_positive_edges is not None:
            pos_counts = num_positive_edges.float().clamp(min=1.0)
            neg_counts = (edge_logits.size(1) - pos_counts).clamp(min=1.0)
            pos_weight_val = (neg_counts / pos_counts).mean().item()
        else:
            pos_weight_val = 1.0
        pos_weight = torch.tensor(pos_weight_val, device=device, dtype=edge_logits.dtype)
        edge_loss = F.binary_cross_entropy_with_logits(
            edge_logits, edge_labels, pos_weight=pos_weight
        )

        liveness_loss = F.binary_cross_entropy_with_logits(
            liveness_logits, liveness_targets, reduction="mean"
        )

        return edge_logits, liveness_logits, edge_loss + liveness_loss


class GclsdModel(nn.Module):
    """Full GCLSD decompiler model."""

    def __init__(
        self,
        d_model: int,
        num_layers: int,
        asm_vocab_size: int,
        output_vocab_size: int,
        pad_token_id: int,
        bos_token_id: Optional[int] = None,
        pretrained_output_embeddings: Optional[torch.Tensor] = None,
        num_heads: int = 4,
        head_dim: int = 64,
        dv_ratio: float = 2.0,
        d_conv: int = 4,
        mlp_ratio: float = 4.0,
        num_graph_layers: int = 3,
        num_registers: int = 16,
        aux_loss_weight: float = 0.1,
        use_hybrid_backbone: bool = False,
        num_heads_mla: int = 8,
        head_dim_mla: int = 128,
        d_cq: int = 512,
        d_ckv: int = 256,
        d_rope: int = 32,
        num_experts: int = 8,
        top_k: int = 2,
        mla_layer_indices: Optional[List[int]] = None,
    ) -> None:
        super().__init__()
        self.d_model = d_model
        self.pad_token_id = pad_token_id
        self.bos_token_id = bos_token_id if bos_token_id is not None else pad_token_id
        self.aux_loss_weight = aux_loss_weight
        self.use_hybrid_backbone = use_hybrid_backbone

        self.asm_embedding = nn.Embedding(asm_vocab_size, d_model)

        # Output (C) token embeddings: initialize from pretrained if provided.
        if pretrained_output_embeddings is not None:
            weight = pretrained_output_embeddings
            if weight.shape != (output_vocab_size, d_model):
                raise ValueError(
                    f"pretrained_output_embeddings shape {weight.shape} does not "
                    f"match (output_vocab_size={output_vocab_size}, d_model={d_model})"
                )
            self.output_embeddings = nn.Embedding.from_pretrained(weight, freeze=False)
        else:
            self.output_embeddings = nn.Embedding(output_vocab_size, d_model)

        # Untied LM head: initialized from pretrained embeddings but learns
        # independently. Tying prevents independent gradient flow required for
        # distillation (the student lm_head must diverge from the frozen
        # output embeddings to absorb teacher logit temperature).
        self.lm_head = nn.Linear(d_model, output_vocab_size, bias=False)
        if pretrained_output_embeddings is not None:
            with torch.no_grad():
                self.lm_head.weight.copy_(pretrained_output_embeddings)
        # NOTE: deliberately NOT tying lm_head.weight to output_embeddings.weight.

        self.graph_encoder = BlockGraphEncoder(
            hidden=d_model,
            num_layers=num_graph_layers,
            num_edge_kinds=7,
        )
        if use_hybrid_backbone:
            self.backbone = HybridBackbone(
                d_model=d_model,
                num_layers=num_layers,
                mla_layer_indices=mla_layer_indices,
                num_heads_gdn=num_heads,
                head_dim_gdn=head_dim,
                dv_ratio=dv_ratio,
                d_conv=d_conv,
                num_heads_mla=num_heads_mla,
                head_dim_mla=head_dim_mla,
                d_cq=d_cq,
                d_ckv=d_ckv,
                d_rope=d_rope,
                num_experts=num_experts,
                top_k=top_k,
                mlp_ratio=mlp_ratio,
            )
        else:
            self.backbone = GatedDeltaNetBackbone(
                d_model=d_model,
                num_layers=num_layers,
                num_heads=num_heads,
                head_dim=head_dim,
                dv_ratio=dv_ratio,
                d_conv=d_conv,
                mlp_ratio=mlp_ratio,
            )
        self.aux_heads = AuxHeads(
            hidden=d_model,
            num_registers=num_registers,
        )

    def _embed_inputs(
        self, asm_input_ids: torch.Tensor, output_input_ids: torch.Tensor
    ) -> torch.Tensor:
        """Concatenate asm and output embeddings using separate tables."""
        asm_embeds = self.asm_embedding(asm_input_ids)
        output_embeds = self.output_embeddings(output_input_ids)
        return torch.cat([asm_embeds, output_embeds], dim=1)

    def _add_block_fusion(
        self,
        embeds: torch.Tensor,
        token_to_block: torch.Tensor,
        graph: Batch,
    ) -> torch.Tensor:
        """Add GNN block-node embeddings at block-boundary asm tokens."""
        hidden_dtype = embeds.dtype
        # Compute per-block node features by mean-pooling instruction tokens.
        instr_embeds = self.asm_embedding(graph.instr_token_ids).to(hidden_dtype)
        mask = graph.instr_token_mask.unsqueeze(-1).float()
        node_features = (instr_embeds * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)

        block_embs = self.graph_encoder(
            node_features,
            graph.edge_index,
            graph.edge_attr,
        )

        block_idx = token_to_block.clamp(min=0)
        valid = (token_to_block >= 0).unsqueeze(-1).float()
        gathered = block_embs[block_idx] * valid
        return embeds + gathered

    def _extract_boundary_states(
        self,
        hidden: torch.Tensor,
        token_to_block: torch.Tensor,
        num_blocks: torch.Tensor,
    ) -> torch.Tensor:
        """Collect final hidden states at each block's boundary token.

        Returns a padded tensor (B, max_blocks, hidden).
        """
        B, _, dim = hidden.shape
        max_blocks = int(num_blocks.max().item())
        boundary_states = torch.zeros(B, max_blocks, dim, device=hidden.device, dtype=hidden.dtype)
        for b in range(B):
            n = int(num_blocks[b].item())
            for blk in range(n):
                # Find the first asm token mapped to this block.
                positions = (token_to_block[b] == blk).nonzero(as_tuple=False)
                if len(positions) > 0:
                    pos = positions[0].item()
                    boundary_states[b, blk] = hidden[b, pos]
        return boundary_states

    def forward(
        self,
        batch: GclsdBatch,
        return_extras: bool = False,
    ) -> Union[
        Tuple[torch.Tensor, Optional[torch.Tensor], Optional[torch.Tensor]],
        "ModelForwardExtras",
    ]:
        """Forward pass for training.

        Returns:
            logits: (B, L_asm + L_out, vocab_size)
            loss: scalar CE loss on output tokens (or None if no labels)
            aux_loss: scalar auxiliary loss (or None if not in training or no targets)

        When ``return_extras=True``, returns a ``ModelForwardExtras`` namedtuple
        with additional fields needed by the multi-signal loss:
            hidden, edge_logits, liveness_logits, boundary_states.
        """
        if batch.output_input_ids is None:
            raise ValueError("GCLSD training requires output_input_ids (decoder prefix)")

        full_embeds = self._embed_inputs(batch.asm_input_ids, batch.output_input_ids)
        asm_len = batch.asm_input_ids.size(1)
        asm_embeds = full_embeds[:, :asm_len]
        c_embeds = full_embeds[:, asm_len:]
        asm_embeds = self._add_block_fusion(asm_embeds, batch.token_to_block, batch.graph)
        full_embeds = torch.cat([asm_embeds, c_embeds], dim=1)

        hidden = self.backbone(full_embeds)
        logits = self.lm_head(hidden)

        loss: Optional[torch.Tensor] = None
        if batch.labels is not None:
            loss = F.cross_entropy(
                logits.view(-1, logits.size(-1)),
                batch.labels.view(-1),
                ignore_index=-100,
            )

        aux_loss: Optional[torch.Tensor] = None
        edge_logits: Optional[torch.Tensor] = None
        liveness_logits: Optional[torch.Tensor] = None
        boundary_states: Optional[torch.Tensor] = None

        if self.training and batch.edge_pairs is not None and batch.liveness_targets is not None:
            boundary_states = self._extract_boundary_states(
                hidden[:, : batch.asm_input_ids.size(1)],
                batch.token_to_block,
                batch.graph.num_blocks,
            )
            edge_logits, liveness_logits, aux_loss = self.aux_heads(
                boundary_states,
                batch.edge_pairs,
                batch.liveness_targets,
                num_positive_edges=batch.num_positive_edges,
            )

        if return_extras:
            return ModelForwardExtras(
                logits=logits,
                loss=loss,
                aux_loss=aux_loss,
                hidden=hidden,
                edge_logits=edge_logits,
                liveness_logits=liveness_logits,
                boundary_states=boundary_states,
            )
        return logits, loss, aux_loss

    @torch.no_grad()
    def generate(
        self,
        asm_input_ids: torch.Tensor,
        token_to_block: torch.Tensor,
        graph: Batch,
        max_length: int = 128,
        temperature: float = 1.0,
        top_k: Optional[int] = None,
        eos_token_id: Optional[int] = None,
    ) -> List[int]:
        """Greedy/top-k autoregressive generation of decompiled C tokens.

        Processes the asm prefix with ``forward_with_state`` once, then steps
        the SSM recurrence O(1) per output token.
        """
        self.eval()
        B = asm_input_ids.size(0)
        assert B == 1, "generate currently supports batch_size 1"
        device = asm_input_ids.device

        asm_embeds = self.asm_embedding(asm_input_ids)
        asm_embeds = self._add_block_fusion(asm_embeds, token_to_block, graph)
        _, states = self.backbone.forward_with_state(asm_embeds)

        # Start from the BOS token.
        generated = [self.bos_token_id]
        input_id = torch.tensor([[self.bos_token_id]], dtype=torch.long, device=device)

        for _ in range(max_length):
            x = self.output_embeddings(input_id)
            x, states = self.backbone.step(x, states)
            logits = self.lm_head(x) / max(temperature, 1e-6)
            next_logits = logits[:, -1, :]

            if top_k is not None and top_k > 0:
                v, _ = torch.topk(next_logits, min(top_k, next_logits.size(-1)))
                next_logits[next_logits < v[:, [-1]]] = -float("inf")

            probs = F.softmax(next_logits, dim=-1)
            next_token = torch.multinomial(probs, num_samples=1).item()
            generated.append(next_token)

            if eos_token_id is not None and next_token == eos_token_id:
                break
            input_id = torch.tensor([[next_token]], dtype=torch.long, device=device)

        return generated
