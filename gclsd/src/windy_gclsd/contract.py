"""Python mirror of the Rust-side GCLSD input contract.

The source of truth is gclsd/contract/gclsd_input.schema.json, emitted by
``windy emit-contract``. These pydantic models validate against that same
shape so the FastAPI server and training dataloader never drift from the host.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class Param(BaseModel):
    """Recovered function parameter."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str
    type_guess: Optional[str] = Field(default=None, alias="type")
    reg: Optional[str] = None


class MemRefExport(BaseModel):
    """Memory operand access summary."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    base: Optional[str] = None
    index: Optional[str] = None
    scale: int
    displacement: int
    size: str
    access: str


class GclsdInstr(BaseModel):
    """One decoded instruction in the GCLSD input stream."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    ip: int
    bytes_hex: str
    mnemonic: str
    operands: str
    operands_annotated: Optional[str] = None
    flow: str
    class_: str = Field(alias="class")
    reads: List[str]
    writes: List[str]
    mem_refs: List[MemRefExport]


GclsdEdgeKind = Literal[
    "fallthrough",
    "unconditional",
    "conditional",
    "call",
    "tail_call",
    "indirect",
    "return",
]


class GclsdEdge(BaseModel):
    """CFG edge leaving a basic block."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    target: int
    kind: GclsdEdgeKind


class GclsdBlock(BaseModel):
    """Basic block; node in the CFG consumed by the graph encoder."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    entry_va: int
    instr_ips: List[int]
    successors: List[GclsdEdge]


class GclsdInput(BaseModel):
    """Complete input for one function to the GCLSD decompiler."""

    model_config = ConfigDict(populate_by_name=True, extra="forbid")

    name: str
    entry_va: int
    image_base: int
    bitness: int
    calling_conv: Optional[str] = None
    params: List[Param]
    return_type: Optional[str] = None
    instructions: List[GclsdInstr]
    blocks: List[GclsdBlock]
    xrefs_in: List[int]
    xrefs_out: List[int]
    refine: Optional[str] = None


class GclsdOutput(BaseModel):
    """Model output: decompiled C-like pseudo-code for one function."""

    pseudocode: str
