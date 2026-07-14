# Agent reconstruction eval (degrade-and-recover)

North-star metric inspired by the reconstruction-runtime doctrine:

> **verified facts per 1k agent tokens**, at zero silent overwrites.

## Policies

| Policy | What the harness does |
|---|---|
| `evidence` | For each sampled function: load evidence card only; count citable facts; run true/false API claims |
| `dump` | For each sampled function: load full agent_text; treat length as token proxy; no structured claims |

## Run

```bash
# Agent loop (evidence vs dump)
cargo test eval_metrics -- --nocapture
windy bench agent-loop --pe gclsd/bench/sample.exe --limit 16

# Decompile scorecard: Windy native vs checked-in Ghidra export vs source gold
cargo test decomp_scorecard -- --nocapture
windy bench scorecard
windy bench scorecard --output decomp_scorecard.json

# Harder quality fixture (Ghidra is expected to beat Windy-native)
windy bench scorecard --gold eval/gold/complex_source_gold.json
cargo test complex_scorecard -- --nocapture
```

Ground truth:
- Smoke: `eval/gold/sample_source_gold.json` from `gclsd/bench/sample.c` / `sample.exe`
  (Ghidra: `gclsd/bench/ghidra_output.json`).
- Quality gap: `eval/gold/complex_source_gold.json` from `gclsd/bench/complex.c` /
  `complex.exe` (Ghidra: `gclsd/bench/complex_ghidra_output.json`).

No live Ghidra required at score time; re-export with headless when the PE changes.

## Decompile scorecard v2 (first increment)

The scorecard still accepts the original compact source-gold fields
(`must_tokens`, `control`, `min_params`, `calls`, and `strings`) so the sample
fixture remains a smoke test. It now extracts those facts from a C-like function
body instead of using unrestricted substring matching:

- comments and string literals do not satisfy code-token, control-flow, or call facts;
- call aliases are exact identifiers, not prefixes or any `FUN_` token;
- source-known fixtures default to complete call and string sets, so unexpected
  direct calls or literals lower precision and prevent a perfect score;
- `call_facts` can assert an exact callee and ordered argument expressions.

`score` is integrity-adjusted recall (`recall * precision`), preserving the old
recall value when there is no unexpected output. This is a deliberately bounded
lexical check, not proof of semantic equivalence.

### Quality gates (`quality[]`)

Engine-agnostic classical-decomp facts (used heavily by `complex_source_gold.json`):

| Spec | Hit when |
|---|---|
| `no_rsp` | body has no `rsp`/`esp`/`sp` identifiers |
| `no_stack_home` | body has no `*((…)` stack-home store shape |
| `null_term` | body contains `'\0'` |
| `char_cast` | body contains a `(char` cast |
| `field_dot` | body contains `ident.ident` |
| `return_binop:+` | some `return` expression uses that operator |
| `max_assign:N` | bare `=` assignment count ≤ N |

These are how the complex fixture shows **where** Windy loses (see each
function’s `miss_detail` / `fact_results` in the JSON report).

New gold may use structured calls instead of the legacy `calls` strings:

```json
{
  "call_facts": [
    {
      "aliases": ["strlen_local", "FUN_140001020"],
      "arguments": ["\"hello\""]
    }
  ],
  "calls_complete": true,
  "strings_complete": true
}
```

When `call_facts` is non-empty it supersedes `calls`. Argument comparisons are
case-insensitive for identifiers and exact for literals/operators after token
normalization. Do not add argument facts until the decompiler has explicit call
argument lifting; an honest miss is more valuable than a guessed pass.

Each source-known fixture should ship a sibling provenance manifest validated by
[`provenance_manifest.schema.json`](provenance_manifest.schema.json). It pins the
binary hash, build flags, source revision, and Ghidra export configuration needed
for a reproducible comparison.

## Outputs

JSON report fields:

- `policy`
- `functions_sampled`
- `tool_calls` (scripted)
- `token_proxy` (chars/4)
- `supported_claims` / `contradicted_claims` / `unknown_claims`
- `verified_facts_per_1k_tokens`
- `evidence_cards_with_contract_v1`

## Gold

For PE samples without PDB gold, “verified fact” means:

1. A claim the checker returns **supported**, or  
2. Structural facts present on an evidence card with a `cite` object  

Future: strip-and-recover against unstripped twin builds.
