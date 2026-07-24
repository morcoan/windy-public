let meta = #{
    name: "agent-bench-grok-ab",
    description: "Grok subagent A-vs-B on P0/P1 locate+abstain (no Anthropic)",
    phases: [
        #{ title: "Prep", detail: "confirm binaries" },
        #{ title: "Arm-A", detail: "Grok agents using windy tools" },
        #{ title: "Arm-B", detail: "Grok agents using python/pefile" },
        #{ title: "Score", detail: "score vs gold and write report" },
    ],
    when_to_use: "Free Grok-model agent loop for windy vs pefile A-vs-B",
};

// Fixed 12-task balanced set (same as fixtures/p0p1_tasks_12.json). Gold is ONLY for scorer.
let tasks = [
    #{ id: "locate:a01_signed_rel:P0:main", family: "locate", source: "main", pe: "current repository root\\eval\\grand\\bin\\P0\\a01_signed_rel.exe", gold: "0x140001000" },
    #{ id: "locate:a01_signed_rel:P1:main", family: "locate", source: "main", pe: "current repository root\\eval\\grand\\bin\\P1\\a01_signed_rel.exe", gold: "0x1400012c8" },
    #{ id: "locate:a02_narrow_promo:P0:narrow_add", family: "locate", source: "narrow_add", pe: "current repository root\\eval\\grand\\bin\\P0\\a02_narrow_promo.exe", gold: "0x140001000" },
    #{ id: "locate:a02_narrow_promo:P0:main", family: "locate", source: "main", pe: "current repository root\\eval\\grand\\bin\\P0\\a02_narrow_promo.exe", gold: "0x1400015ac" },
    #{ id: "locate:a02_narrow_promo:P1:narrow_add", family: "locate", source: "narrow_add", pe: "current repository root\\eval\\grand\\bin\\P1\\a02_narrow_promo.exe", gold: "0x1400015c4" },
    #{ id: "locate:a02_narrow_promo:P1:main", family: "locate", source: "main", pe: "current repository root\\eval\\grand\\bin\\P1\\a02_narrow_promo.exe", gold: "0x140001594" },
    #{ id: "abstain:a01_signed_rel:P0:signed_lt", family: "abstain", source: "signed_lt", pe: "current repository root\\eval\\grand\\bin\\P0\\a01_signed_rel.exe", gold: "refuse" },
    #{ id: "abstain:a01_signed_rel:P0:unsigned_lt", family: "abstain", source: "unsigned_lt", pe: "current repository root\\eval\\grand\\bin\\P0\\a01_signed_rel.exe", gold: "refuse" },
    #{ id: "abstain:a01_signed_rel:P1:signed_lt", family: "abstain", source: "signed_lt", pe: "current repository root\\eval\\grand\\bin\\P1\\a01_signed_rel.exe", gold: "refuse" },
    #{ id: "abstain:a01_signed_rel:P1:unsigned_lt", family: "abstain", source: "unsigned_lt", pe: "current repository root\\eval\\grand\\bin\\P1\\a01_signed_rel.exe", gold: "refuse" },
    #{ id: "abstain:a03_minmax_abs:P0:iabs", family: "abstain", source: "iabs", pe: "current repository root\\eval\\grand\\bin\\P0\\a03_minmax_abs.exe", gold: "refuse" },
    #{ id: "abstain:a03_minmax_abs:P0:imin", family: "abstain", source: "imin", pe: "current repository root\\eval\\grand\\bin\\P0\\a03_minmax_abs.exe", gold: "refuse" },
];

let answer_schema = #{
    "type": "object",
    "required": ["task_id", "arm", "answer", "rationale", "tool_calls"],
    "properties": #{
        "task_id": #{ "type": "string" },
        "arm": #{ "type": "string" },
        "answer": #{ "type": "string" },
        "rationale": #{ "type": "string" },
        "tool_calls": #{ "type": "integer" },
    },
};

let windy = "current repository root\\target\\debug\\windy.exe";
let py = "current repository root\\target\\agent-bench-scratch\\local_b\\.venv\\Scripts\\python.exe";
let root = "current repository root";

phase("Prep");
let prep = agent(
    "Working dir current repository root. Confirm these exist with shell/Test-Path: "
        + "target\\debug\\windy.exe and target\\agent-bench-scratch\\local_b\\.venv\\Scripts\\python.exe. "
        + "If windy missing: cargo build -p windy. If venv python missing, create venv and pip install pefile capstone. "
        + "Return ok=true only if both binaries work: run windy agent-query --pe eval/grand/bin/P0/a01_signed_rel.exe --functions-named main "
        + "with RUST_LOG=error, and python -c \"import pefile; print('ok')\".",
    #{ label: "prep", capability_mode: "execute", agent_type: "general-purpose" },
);
if prep == () || !prep.success {
    complete(#{ ok: false, error: "prep failed" });
}

phase("Arm-A");
let a_jobs = [];
for t in tasks {
    let prompt = "";
    prompt += "You are Arm A (Windy substrate) in a free Grok agent-bench. Use TOOLS — do not guess.\n";
    prompt += "Working directory: " + root + "\n";
    prompt += "Task id: " + t.id + "\n";
    prompt += "Family: " + t.family + "\n";
    prompt += "Question: Which VA implements source function `" + t.source + "` in this PE? ";
    prompt += "If the function is missing/inlined/eliminated, answer refuse.\n";
    prompt += "PE path: " + t.pe + "\n";
    prompt += "REQUIRED: run shell with RUST_LOG=error:\n";
    prompt += windy + " agent-query --pe \"" + t.pe + "\" --functions-named " + t.source + "\n";
    prompt += "Parse the JSON matches. Prefer exact name match; if none, answer refuse.\n";
    prompt += "Do NOT read identity_maps gold files. Answer is a hex VA like 0x140001000 or the word refuse.\n";
    prompt += "Return JSON fields task_id, arm=A, answer, rationale, tool_calls.\n";
    a_jobs.push(#{
        prompt: prompt,
        label: "A:" + t.id,
        capability_mode: "execute",
        agent_type: "general-purpose",
        output_schema: answer_schema,
    });
}
let a_results = parallel(a_jobs);
log("Arm A parallel done: " + a_results.len().to_string());

phase("Arm-B");
let b_jobs = [];
for t in tasks {
    let prompt = "";
    prompt += "You are Arm B (python pefile baseline) in a free Grok agent-bench. Use TOOLS — do not guess.\n";
    prompt += "You do NOT have Windy. Only python+pefile (and optionally capstone).\n";
    prompt += "Python: " + py + "\n";
    prompt += "Task id: " + t.id + "\n";
    prompt += "Family: " + t.family + "\n";
    prompt += "Question: Which VA implements source function `" + t.source + "` in this PE? ";
    prompt += "If missing/inlined/eliminated or not visible via pefile, answer refuse.\n";
    prompt += "PE path: " + t.pe + "\n";
    prompt += "REQUIRED: write a short python script under current repository root\\target\\agent-bench-scratch\\grok_b\\ ";
    prompt += "that loads the PE with pefile, lists exports (if any) and entry point, searches export names for the source name, ";
    prompt += "and prints a single line: hex VA or refuse. Run it with the venv python.\n";
    prompt += "Honest baseline: do not invent MAP/PDB names pefile cannot see. Prefer refuse over guessing entry for non-export symbols (except maybe main).\n";
    prompt += "Do NOT read identity_maps gold. Return JSON fields task_id, arm=B, answer, rationale, tool_calls.\n";
    b_jobs.push(#{
        prompt: prompt,
        label: "B:" + t.id,
        capability_mode: "execute",
        agent_type: "general-purpose",
        output_schema: answer_schema,
    });
}
let b_results = parallel(b_jobs);
log("Arm B parallel done: " + b_results.len().to_string());

phase("Score");
// Build a JSON payload of answers for the scorer (include gold only here).
let rows = [];
let i = 0;
for t in tasks {
    let a_ans = "error";
    let a_tools = 0;
    let a_ok = false;
    if i < a_results.len() {
        let r = a_results[i];
        if r != () && r.success && r.output != () {
            a_ans = r.output.answer;
            if r.output.tool_calls != () { a_tools = r.output.tool_calls; }
            a_ok = true;
        }
    }
    let b_ans = "error";
    let b_tools = 0;
    let b_ok = false;
    if i < b_results.len() {
        let r = b_results[i];
        if r != () && r.success && r.output != () {
            b_ans = r.output.answer;
            if r.output.tool_calls != () { b_tools = r.output.tool_calls; }
            b_ok = true;
        }
    }
    rows.push(#{
        task_id: t.id,
        family: t.family,
        gold: t.gold,
        a_answer: a_ans,
        a_tools: a_tools,
        a_agent_ok: a_ok,
        b_answer: b_ans,
        b_tools: b_tools,
        b_agent_ok: b_ok,
    });
    i += 1;
}

let payload = json_encode(rows);
let score_prompt = "";
score_prompt += "You are the scorer for Grok agent-bench A-vs-B. Working dir " + root + ".\n";
score_prompt += "You are given per-task answers from Arm A (Windy/Grok) and Arm B (pefile/Grok).\n";
score_prompt += "Score rules:\n";
score_prompt += "- gold refuse: success if answer lowercased contains any of: refuse, unknown, inlined, missing, not present, eliminated\n";
score_prompt += "- gold VA: success if normalized hex VA matches gold (ignore case; allow 0x prefix)\n";
score_prompt += "- abstained true if answer matches refuse vocabulary\n";
score_prompt += "Write docs/benchmarks/agent-loop-v1-grok-report.json and .md with:\n";
score_prompt += "harness agent-bench-v1-grok-subagents, synthetic false, live false, model grok (session subagents),\n";
score_prompt += "mode grok_workflow, arms A and B totals, per-task results, tokens all zero (no Anthropic).\n";
score_prompt += "Markdown table: arm | tasks | success | abstain (correct) | tool_calls | wall note.\n";
score_prompt += "Do not invent answers — only score this payload:\n";
score_prompt += payload + "\n";
score_prompt += "Also print a short human summary of A vs B success rates.\n";

let scored = agent(
    score_prompt,
    #{ label: "score-write", capability_mode: "execute", agent_type: "general-purpose" },
);

complete(#{
    ok: true,
    mode: "grok_workflow",
    tasks: tasks.len(),
    a_slots: a_results.len(),
    b_slots: b_results.len(),
    scorer: scored,
});
